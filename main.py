from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field
import sqlite3
import os
import requests
import json
import re
import hmac
import hashlib
import secrets
import shutil
import threading
import base64
import binascii
from pathlib import Path
from contextvars import ContextVar
from urllib.parse import urlsplit
from decimal import Decimal, ROUND_DOWN
from datetime import datetime, timezone, timedelta
from uuid import uuid4

BASE_DIR = Path(__file__).resolve().parent

def load_private_env(path):
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip("\\\"").strip("'")
                if key and key.replace("_", "").isalnum():
                    os.environ.setdefault(key, value)
    except FileNotFoundError:
        pass

load_private_env(BASE_DIR / ".env")
DATA_DIR = Path(os.environ.get("PF_DATA_DIR", str(BASE_DIR))).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB = str(DATA_DIR / "finance.db")
AUTH_DB = DATA_DIR / "auth.sqlite3"
USER_DB_DIR = DATA_DIR / "user_data"
SETUP_TOKEN_FILE = DATA_DIR / ".pf_setup_token"
PROFILE_DIR = DATA_DIR / "profile_data"
PROFILE_DIR.mkdir(mode=0o700, exist_ok=True)
try:
    PROFILE_DIR.chmod(0o700)
except OSError:
    pass
USER_DB_DIR.mkdir(mode=0o700, exist_ok=True)
try:
    USER_DB_DIR.chmod(0o700)
except OSError:
    pass
current_db_path = ContextVar("current_db_path", default=None)
registration_lock = threading.Lock()
COOKIE_SECURE = os.environ.get("PF_COOKIE_SECURE", "1") != "0"
SESSION_HOURS = 12
PASSWORD_ITERATIONS = 600_000
app = FastAPI(title="Pesa Flow")

@app.get("/dashboard")
def dashboard():
    return FileResponse(str(BASE_DIR / "dashboard.html"))


class AdminLoginIn(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    access_key: str = Field(min_length=1, max_length=256)
    answer: str = Field(min_length=1, max_length=256)

@app.get("/api/admin/question")
def admin_security_question():
    config = read_admin_config()
    if not config: raise HTTPException(status_code=503, detail="Admin credentials are not configured. Run the installer again.")
    return {"question": config.get("question", "Security question")}

@app.post("/api/admin/login")
def admin_login(data: AdminLoginIn, request: Request):
    config = read_admin_config()
    if not config: raise HTTPException(status_code=503, detail="Admin credentials are not configured.")
    ip = request.client.host if request.client else "unknown"; now = utc_now()
    with auth_connect() as con: attempt = con.execute("SELECT * FROM admin_login_attempts WHERE ip=?", (ip,)).fetchone()
    if attempt and attempt["locked_until"] and datetime.fromisoformat(attempt["locked_until"]) > now:
        raise HTTPException(status_code=429, detail="Too many attempts. Try again in 15 minutes.")
    try:
        iterations = config.get("iterations", 600_000)
        if type(iterations) is not int or not 600_000 <= iterations <= 2_000_000:
            raise ValueError("Invalid admin credential iteration count")
    except (TypeError, ValueError):
        raise HTTPException(status_code=503, detail="Admin credential configuration is invalid.")
    valid = (verify_admin_secret(data.password, config.get("password", {}), iterations) and
             verify_admin_secret(data.access_key, config.get("access_key", {}), iterations) and
             verify_admin_secret(data.answer.strip().casefold(), config.get("answer", {}), iterations))
    if not valid:
        with auth_connect() as con:
            attempt = con.execute("SELECT * FROM admin_login_attempts WHERE ip=?", (ip,)).fetchone()
            if not attempt or now-datetime.fromisoformat(attempt["window_start"]) > timedelta(minutes=15): failures, start = 1, now
            else: failures, start = attempt["failures"]+1, datetime.fromisoformat(attempt["window_start"])
            locked = (now+timedelta(minutes=15)).isoformat() if failures >= 5 else None
            con.execute("INSERT INTO admin_login_attempts(ip,failures,window_start,locked_until) VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET failures=excluded.failures,window_start=excluded.window_start,locked_until=excluded.locked_until", (ip,failures,start.isoformat(),locked))
        raise HTTPException(status_code=401, detail="Invalid administrator credentials.")
    raw = secrets.token_urlsafe(32); digest = hashlib.sha256(raw.encode()).hexdigest(); expires = (now+timedelta(hours=ADMIN_SESSION_HOURS)).isoformat()
    with auth_connect() as con:
        con.execute("DELETE FROM admin_login_attempts WHERE ip=?", (ip,))
        con.execute("DELETE FROM admin_sessions WHERE expires_at<=?", (now.isoformat(),))
        con.execute("INSERT INTO admin_sessions(token_hash,expires_at,created_at) VALUES(?,?,?)", (digest,expires,now.isoformat()))
    response = JSONResponse({"ok": True, "expires_in": ADMIN_SESSION_HOURS*3600})
    response.set_cookie("pf_admin_session", raw, max_age=ADMIN_SESSION_HOURS*3600, httponly=True, secure=COOKIE_SECURE, samesite="strict", path="/")
    return response

@app.post("/api/admin/logout")
def admin_logout(request: Request):
    require_admin(request); raw=request.cookies.get("pf_admin_session", "")
    if raw:
        with auth_connect() as con: con.execute("DELETE FROM admin_sessions WHERE token_hash=?", (hashlib.sha256(raw.encode()).hexdigest(),))
    response=JSONResponse({"ok":True}); response.delete_cookie("pf_admin_session",path="/",httponly=True,secure=COOKIE_SECURE,samesite="strict"); return response

@app.get("/api/admin/overview")
def pf_admin_overview(request: Request):
    require_admin(request)
    conn = auth_connect()
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA quick_check")
        result = cur.fetchone()
        db_ok = bool(result and str(result[0]).lower() == "ok")
        cur.execute("SELECT COUNT(*) FROM users")
        count = cur.fetchone()[0]
        return {
            "server": "online",
            "auth_database": "healthy" if db_ok else "check required",
            "registered_users": count
        }
    finally:
        conn.close()


@app.get("/api/admin/users")
def pf_admin_users(request: Request):
    require_admin(request)

    with auth_connect() as con:
        rows = con.execute(
            "SELECT id, email, full_name, handle, created_at "
            "FROM users ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
        return {"users": [dict(row) for row in rows]}



@app.get("/api/admin/settings")
def pf_admin_settings(request: Request):
    require_admin(request)
    return {
        "admin_configured": bool(read_admin_config()),
        "cookie_secure": os.environ.get("PF_COOKIE_SECURE", os.environ.get("COOKIE_SECURE", "default")),
        "upload_limit_mb": 20,
        "update_storage": "Protected staging; not automatically installed"
    }



@app.post("/api/admin/updates")
async def pf_admin_upload_update(request: Request):
    import io
    import zipfile

    require_admin(request)

    form = await request.form()
    upload = form.get("file")
    if not upload or not getattr(upload, "filename", ""):
        raise HTTPException(status_code=400, detail="Select a ZIP file.")
    if not upload.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only ZIP files are accepted.")

    data = await upload.read(20 * 1024 * 1024 + 1)
    if len(data) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Maximum upload size is 20 MB.")
    if not data:
        raise HTTPException(status_code=400, detail="The file is empty.")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if archive.testzip() is not None:
                raise HTTPException(status_code=400, detail="ZIP archive failed integrity check.")
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP archive.")

    folder = BASE_DIR / "updates_staging"
    folder.mkdir(parents=True, exist_ok=True)
    filename = "update_" + os.urandom(8).hex() + ".zip"
    with (folder / filename).open("xb") as output:
        output.write(data)

    return {"message": "ZIP uploaded to protected staging.", "filename": filename, "size_bytes": len(data)}



# PF_SECURE_UPDATE_WORKFLOW_V1
@app.get("/api/admin/updates")
def pf_admin_list_updates(request: Request):
    require_admin(request)
    folder = BASE_DIR / "updates_staging"
    items = []
    if folder.is_dir() and not folder.is_symlink():
        for path in sorted(folder.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if path.is_file() and not path.is_symlink() and re.fullmatch(r"update_[0-9a-f]{16}\.zip", path.name):
                items.append({"filename": path.name, "size_bytes": path.stat().st_size})
    return {"files": items}


# PF_SECURE_UPDATE_WORKFLOW_V1
@app.get("/api/admin/updates/{filename}/review")
def pf_admin_review_update(filename: str, request: Request):
    import difflib
    import zipfile

    require_admin(request)
    if not re.fullmatch(r"update_[0-9a-f]{16}\.zip", filename):
        raise HTTPException(status_code=400, detail="Invalid staged update filename.")
    archive_path = BASE_DIR / "updates_staging" / filename
    if not archive_path.is_file() or archive_path.is_symlink():
        raise HTTPException(status_code=404, detail="Staged update not found.")

    allowed = {"main.py", "jose.py", "dashboard.html", "admin.html", "login.html", "admin_login.html"}
    max_entries = 30
    max_unpacked = 30 * 1024 * 1024
    max_file = 10 * 1024 * 1024
    results = []
    total = 0
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = [i for i in archive.infolist() if not i.is_dir()]
            if not infos or len(infos) > max_entries:
                raise HTTPException(status_code=400, detail="ZIP must contain 1–30 files.")
            seen = set()
            for info in infos:
                name = info.filename
                mode = (info.external_attr >> 16) & 0o170000
                if (not name or name.startswith(("/", "\\")) or "\\" in name
                        or "/" in name or name in {".", ".."} or ":" in name
                        or name not in allowed or name in seen or mode == 0o120000):
                    raise HTTPException(status_code=400, detail=f"Rejected unsafe or unsupported ZIP entry: {name[:120]}")
                if info.file_size < 0 or info.file_size > max_file:
                    raise HTTPException(status_code=413, detail=f"File too large: {name}")
                total += info.file_size
                if total > max_unpacked:
                    raise HTTPException(status_code=413, detail="Expanded ZIP exceeds 30 MB.")
                seen.add(name)
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise HTTPException(status_code=400, detail=f"Size check failed: {name}")
                try:
                    source = data.decode("utf-8")
                except UnicodeDecodeError:
                    raise HTTPException(status_code=400, detail=f"Files must be UTF-8 text: {name}")
                if name.endswith(".py"):
                    try:
                        compile(source, name, "exec")
                    except SyntaxError as exc:
                        raise HTTPException(status_code=400, detail=f"Python syntax error in {name}, line {exc.lineno}: {exc.msg}")
                target = BASE_DIR / name
                old = target.read_text(encoding="utf-8") if target.is_file() and not target.is_symlink() else ""
                diff = "".join(difflib.unified_diff(
                    old.splitlines(keepends=True), source.splitlines(keepends=True),
                    fromfile=f"current/{name}", tofile=f"update/{name}", n=3
                ))
                if len(diff) > 120000:
                    diff = diff[:120000] + "\n[Diff truncated at 120,000 characters]\n"
                results.append({"name": name, "size_bytes": len(data), "exists": target.is_file(), "diff": diff})
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP archive.")
    return {"filename": filename, "files": results, "total_bytes": total,
            "warning": "Review every diff carefully. Python files will not be executed during installation, but installed code can run when the app is restarted."}


@app.post("/api/admin/updates/{filename}/install")
async def pf_admin_install_update(filename: str, request: Request):
    import zipfile

    require_admin(request)
    if not re.fullmatch(r"update_[0-9a-f]{16}\.zip", filename):
        raise HTTPException(status_code=400, detail="Invalid staged update filename.")
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    if not isinstance(payload, dict) or payload.get("confirmation") != "INSTALL":
        raise HTTPException(status_code=400, detail='Type INSTALL exactly to confirm installation.')

    review = pf_admin_review_update(filename, request)
    files = review["files"]
    if not files:
        raise HTTPException(status_code=400, detail="The ZIP contains no supported files.")

    archive_path = BASE_DIR / "updates_staging" / filename
    backup_root = BASE_DIR / "backups" / ("update_" + datetime.now().strftime("%Y%m%d_%H%M%S_%f"))
    backup_root.mkdir(parents=True, exist_ok=False)
    originals = {}
    written = []
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            for item in files:
                name = item["name"]
                target = BASE_DIR / name
                if target.is_symlink() or (target.exists() and not target.is_file()):
                    raise HTTPException(status_code=400, detail=f"Target is not a regular file: {name}")
                if target.exists():
                    backup = backup_root / name
                    backup.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(target, backup)
                    originals[name] = backup
                else:
                    originals[name] = None

            for item in files:
                name = item["name"]
                data = archive.read(name)
                target = BASE_DIR / name
                temp = BASE_DIR / (".pf_update_tmp_" + secrets.token_hex(8))
                try:
                    with temp.open("xb") as handle:
                        handle.write(data)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temp, target)
                    written.append(name)
                finally:
                    try:
                        temp.unlink()
                    except FileNotFoundError:
                        pass
    except Exception as exc:
        for name in reversed(written):
            target = BASE_DIR / name
            backup = originals.get(name)
            try:
                if backup is None:
                    target.unlink(missing_ok=True)
                elif backup.is_file():
                    shutil.copy2(backup, target)
            except OSError:
                pass
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(status_code=500, detail=f"Installation failed; rollback attempted. Backup: {backup_root.name}") from exc

    return {"message": "Update installed. No uploaded scripts were executed.",
            "files": written, "backup": str(backup_root.relative_to(BASE_DIR)), "restart_required": True}


@app.get("/admin-home")
def admin_home_portal(request: Request):
    require_admin(request)
    return FileResponse(str(BASE_DIR / "admin_home.html"))

@app.get("/admin")
def admin_portal(request: Request):
    # Retire the old Control Center page; send authenticated admins to Admin Home.
    require_admin(request)
    return RedirectResponse("/admin-home", status_code=303)


DEFAULT_RULES = {
    "Savings": 30,
    "Bills": 30,
    "Business": 25,
    "Spending": 15,
}

def connect():
    # Every authenticated request is routed to that user's private SQLite file.
    db_path = current_db_path.get() or DB
    con = sqlite3.connect(db_path, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA busy_timeout = 15000")
    return con

def ensure_ledger_schema(con):
    """Create per-user identity and ledger foundation."""
    con.executescript("""
        CREATE TABLE IF NOT EXISTS identity_verification (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','in_review','verified',
                                  'rejected','manual_review')),
            provider TEXT,
            provider_reference TEXT,
            verified_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT OR IGNORE INTO identity_verification (id, status)
        VALUES (1, 'pending');

        CREATE TABLE IF NOT EXISTS ledger_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_number TEXT NOT NULL UNIQUE,
            account_type TEXT NOT NULL
                CHECK (account_type IN ('base','category')),
            category_name TEXT,
            status TEXT NOT NULL DEFAULT 'active'
                CHECK (status IN ('active','closing','closed')),
            release_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            closed_at TEXT,
            CHECK (
                (account_type = 'base' AND category_name IS NULL)
                OR
                (account_type = 'category' AND category_name IS NOT NULL)
            )
        );
        CREATE UNIQUE INDEX IF NOT EXISTS uq_one_base_account
            ON ledger_accounts(account_type)
            WHERE account_type = 'base';
        CREATE UNIQUE INDEX IF NOT EXISTS uq_active_category_account
            ON ledger_accounts(category_name)
            WHERE account_type = 'category' AND status = 'active';

        CREATE TABLE IF NOT EXISTS ledger_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reference TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','posted','reversed')),
            description TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            posted_at TEXT
        );
        CREATE TABLE IF NOT EXISTS ledger_postings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id INTEGER NOT NULL,
            account_id INTEGER NOT NULL,
            side TEXT NOT NULL CHECK (side IN ('debit','credit')),
            amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (transaction_id) REFERENCES ledger_transactions(id),
            FOREIGN KEY (account_id) REFERENCES ledger_accounts(id),
            UNIQUE (transaction_id, account_id, side)
        );
        CREATE INDEX IF NOT EXISTS idx_ledger_postings_account
            ON ledger_postings(account_id, transaction_id);
    """)


def init_db():
    with connect() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                reference TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                amount TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                name TEXT PRIMARY KEY,
                percentage INTEGER NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS allocations (
                reference TEXT NOT NULL,
                category TEXT NOT NULL,
                amount TEXT NOT NULL,
                PRIMARY KEY (reference, category)
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS category_caps (
                category TEXT PRIMARY KEY,
                monthly_cap TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS spending (
                reference TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                amount TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        ensure_ledger_schema(con)
        if con.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0:
            con.executemany(
                "INSERT INTO rules (name, percentage) VALUES (?, ?)",
                DEFAULT_RULES.items()
            )

init_db()

class TransactionIn(BaseModel):
    reference: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=30)
    amount: Decimal = Field(gt=0, le=100000000)
    status: str = "pending"

class RulesIn(BaseModel):
    percentages: dict[str, int]

class CapsIn(BaseModel):
    caps: dict[str, Decimal]

class SpendIn(BaseModel):
    reference: str = Field(min_length=1, max_length=100)
    category: str = Field(min_length=1, max_length=40)
    amount: Decimal = Field(gt=0, le=100000000)

@app.get("/rules")
def get_rules():
    with connect() as con:
        rows = con.execute(
            "SELECT name, percentage FROM rules ORDER BY name"
        ).fetchall()
    return {r["name"]: r["percentage"] for r in rows}

@app.post("/rules")
@app.put("/rules")
def set_rules(data: RulesIn):
    rules = data.percentages
    if not rules or len(rules) > 20:
        raise HTTPException(400, "Provide 1-20 categories")
    if any(not k.strip() or len(k) > 40 for k in rules):
        raise HTTPException(400, "Invalid category name")
    if any(type(v) is not int or not 0 <= v <= 100
           for v in rules.values()):
        raise HTTPException(400, "Percentages must be whole numbers from 0 to 100")
    if sum(rules.values()) > 100:
        raise HTTPException(400, "Percentages must not exceed 100")

    with connect() as con:
        con.execute("DELETE FROM rules")
        con.executemany(
            "INSERT INTO rules (name, percentage) VALUES (?, ?)",
            rules.items()
        )
    return {
        "saved": rules,
        "total_percentage": sum(rules.values()),
        "base_balance_percentage": 100 - sum(rules.values())
    }

class MpesaStkPushIn(BaseModel):
    phone: str = Field(min_length=10, max_length=13)
    amount: int = Field(ge=1, le=150000)


def _mpesa_credentials():
    if os.environ.get("DARAJA_ENV") != "sandbox":
        raise HTTPException(503, "M-PESA is restricted to Daraja sandbox mode")
    values = {
        "key": os.environ.get("DARAJA_CONSUMER_KEY", ""),
        "secret": os.environ.get("DARAJA_CONSUMER_SECRET", ""),
        "shortcode": os.environ.get("DARAJA_SHORTCODE", ""),
        "passkey": os.environ.get("DARAJA_PASSKEY", ""),
        "callback": os.environ.get("PF_MPESA_CALLBACK_URL", ""),
    }
    if not all(values.values()):
        raise HTTPException(503, "Configure Daraja sandbox credentials and PF_MPESA_CALLBACK_URL in .env")
    if not values["callback"].startswith("https://"):
        raise HTTPException(503, "PF_MPESA_CALLBACK_URL must be a public HTTPS URL")
    return values


def _mpesa_access_token(credentials):
    import base64
    pair = base64.b64encode(
        f"{credentials['key']}:{credentials['secret']}".encode()
    ).decode()
    try:
        response = requests.get(
            "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
            headers={"Authorization": "Basic " + pair}, timeout=20
        )
        response.raise_for_status()
        token = response.json().get("access_token")
        if not token:
            raise ValueError("missing token")
        return token
    except Exception as exc:
        raise HTTPException(502, "Daraja sandbox authentication failed") from exc


@app.post("/api/mpesa/stk-push")
def mpesa_stk_push(data: MpesaStkPushIn, request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Authentication required")
    phone = data.phone.strip()
    if phone.startswith("+"):
        phone = phone[1:]
    if phone.startswith("0") and len(phone) == 10:
        phone = "254" + phone[1:]
    if not (phone.isdigit() and phone.startswith("254") and len(phone) == 12):
        raise HTTPException(400, "Use a Kenyan mobile number such as 2547XXXXXXXX")

    credentials = _mpesa_credentials()
    token = _mpesa_access_token(credentials)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password = base64.b64encode(
        f"{credentials['shortcode']}{credentials['passkey']}{timestamp}".encode()
    ).decode()
    reference = "PF-" + uuid4().hex[:18].upper()
    payload = {
        "BusinessShortCode": credentials["shortcode"],
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": data.amount,
        "PartyA": phone,
        "PartyB": int(credentials["shortcode"]),
        "PhoneNumber": phone,
        "CallBackURL": credentials["callback"],
        "AccountReference": reference[:12],
        "TransactionDesc": "Pesa Flow sandbox deposit",
    }
    try:
        response = requests.post(
            "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
            json=payload,
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            timeout=30,
        )
        response.raise_for_status()
        result = response.json()
    except Exception as exc:
        raise HTTPException(502, "Daraja sandbox STK request failed") from exc

    checkout = result.get("CheckoutRequestID")
    if str(result.get("ResponseCode")) != "0" or not checkout:
        raise HTTPException(502, "Daraja did not accept the STK Push request")

    # Save the pending transaction to the authenticated user's database.
    with connect() as con:
        con.execute("""INSERT INTO transactions
            (reference, source, amount, status, created_at)
            VALUES (?, 'mpesa_sandbox', ?, 'pending', ?)""",
            (reference, str(data.amount), datetime.now(timezone.utc).isoformat()))
    # Keep cross-user payment routing in auth.sqlite3, never in shared finance.db.
    try:
        with auth_connect() as con:
            con.execute("""INSERT INTO mpesa_payment_routes
                (internal_reference, checkout_id, merchant_id, user_id, amount, phone, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)""",
                (reference, checkout, result.get("MerchantRequestID"), user["id"],
                 str(data.amount), phone, datetime.now(timezone.utc).isoformat()))
    except sqlite3.IntegrityError as exc:
        raise HTTPException(500, "Could not safely register the payment route; contact support") from exc

    return {
        "accepted": True,
        "reference": reference,
        "checkout_request_id": checkout,
        "amount": data.amount,
        "currency": "KES",
        "status": "pending",
        "message": "Approve the prompt on your sandbox phone. Funds are not yet confirmed or allocated.",
        "real_transfers_enabled": False,
    }


@app.post("/api/mpesa/callback")
def mpesa_callback(request: Request, payload: dict):
    # Safaricom calls this public endpoint server-to-server; do not trust callback alone.
    body = payload.get("Body", {}).get("stkCallback", {}) if isinstance(payload, dict) else {}
    checkout = body.get("CheckoutRequestID")
    result_code = body.get("ResultCode")
    if not checkout:
        return {"ResultCode": 0, "ResultDesc": "Callback received"}

    with auth_connect() as con:
        route = con.execute("SELECT * FROM mpesa_payment_routes WHERE checkout_id=?", (checkout,)).fetchone()
        if not route:
            return {"ResultCode": 0, "ResultDesc": "Unknown checkout recorded for review"}
        if route["status"] == "allocated":
            return {"ResultCode": 0, "ResultDesc": "Duplicate callback ignored"}
        if route["status"] == "processing":
            return {"ResultCode": 0, "ResultDesc": "Callback already processing"}
        if str(result_code) != "0":
            con.execute("UPDATE mpesa_payment_routes SET status='failed', processed_at=? WHERE checkout_id=? AND status='pending'",
                        (datetime.now(timezone.utc).isoformat(), checkout))
            return {"ResultCode": 0, "ResultDesc": "Unsuccessful payment recorded"}
        changed = con.execute("UPDATE mpesa_payment_routes SET status='processing' WHERE checkout_id=? AND status IN ('pending', 'confirmed_unallocated')",
                              (checkout,)).rowcount
        if changed != 1:
            return {"ResultCode": 0, "ResultDesc": "Callback already received"}
        user_row = con.execute("SELECT db_path FROM users WHERE id=?", (route["user_id"],)).fetchone()

    try:
        items = body.get("CallbackMetadata", {}).get("Item", [])
        metadata = {item.get("Name"): item.get("Value") for item in items if isinstance(item, dict)}
        receipt = metadata.get("MpesaReceiptNumber")
        callback_amount = metadata.get("Amount")
        if not receipt or callback_amount is None or money_cents(callback_amount) != money_cents(route["amount"]):
            raise ValueError("Callback amount/receipt did not match the expected payment")
        if not user_row:
            raise ValueError("Payment user no longer exists")

        credentials = _mpesa_credentials()
        token = _mpesa_access_token(credentials)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        password = base64.b64encode(
            f"{credentials['shortcode']}{credentials['passkey']}{timestamp}".encode()
        ).decode()
        verify_response = requests.post(
            "https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query",
            json={"BusinessShortCode": credentials["shortcode"], "Password": password,
                  "Timestamp": timestamp, "CheckoutRequestID": checkout},
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
            timeout=25,
        )
        verify_response.raise_for_status()
        verification = verify_response.json()
        if str(verification.get("ResponseCode")) != "0" or str(verification.get("ResultCode")) != "0":
            raise ValueError("Daraja status query did not confirm success")

        db_path = str(Path(user_row["db_path"]).resolve())
        allowed_path = str(user_db_path(route["user_id"]).resolve())
        if db_path != allowed_path:
            raise ValueError("User database path failed safety check")
        db_token = current_db_path.set(db_path)
        try:
            with connect() as con:
                tx = con.execute("SELECT amount, status FROM transactions WHERE reference=?", (route["internal_reference"],)).fetchone()
                if not tx or money_cents(tx["amount"]) != money_cents(route["amount"]):
                    raise ValueError("User transaction does not match the payment route")
                if tx["status"] == "pending":
                    con.execute("UPDATE transactions SET status='confirmed' WHERE reference=? AND status='pending'",
                                (route["internal_reference"],))
                elif tx["status"] != "confirmed":
                    raise ValueError("Transaction is not in a confirmable state")
            try:
                allocation_result = allocate_reference(route["internal_reference"])
            except HTTPException as exc:
                # Duplicate allocations are safe only if prior allocations actually exist.
                if exc.status_code != 409:
                    raise
                with connect() as con:
                    exists = con.execute("SELECT 1 FROM allocations WHERE reference=? LIMIT 1", (route["internal_reference"],)).fetchone()
                if not exists:
                    raise
                allocation_result = {"already_allocated": True}
        finally:
            current_db_path.reset(db_token)

        with auth_connect() as con:
            con.execute("UPDATE mpesa_payment_routes SET status='allocated', receipt=?, processed_at=? WHERE checkout_id=?",
                        (str(receipt), datetime.now(timezone.utc).isoformat(), checkout))
        return {"ResultCode": 0, "ResultDesc": "Payment verified and recorded", "allocated": True}
    except Exception:
        with auth_connect() as con:
            con.execute("UPDATE mpesa_payment_routes SET status='confirmed_unallocated' WHERE checkout_id=? AND status='processing'", (checkout,))
        # Acknowledge receipt to avoid a callback storm; do not mark the payment allocated.
        return {"ResultCode": 0, "ResultDesc": "Callback received; payment requires verification/retry"}


@app.get("/api/mpesa/payment/{reference}")
def mpesa_payment_status(reference: str, request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(401, "Authentication required")
    with auth_connect() as con:
        row = con.execute("""SELECT internal_reference, amount, status, receipt,
            created_at, processed_at FROM mpesa_payment_routes
            WHERE internal_reference=? AND user_id=?""",
            (reference, user["id"])).fetchone()
    if not row:
        raise HTTPException(404, "M-PESA payment not found")
    return {
        "reference": row["internal_reference"],
        "amount": row["amount"],
        "status": row["status"],
        "receipt": row["receipt"],
        "created_at": row["created_at"],
        "processed_at": row["processed_at"],
        "real_transfers_enabled": False,
    }


@app.post("/transactions")
def add_transaction(data: TransactionIn):
    if data.status not in ("pending", "confirmed"):
        raise HTTPException(400, "Invalid status")
    if data.source not in ("manual_test", "mpesa_sandbox", "kcb_sandbox"):
        raise HTTPException(400, "Unsupported test source")
    amount = data.amount.quantize(Decimal("0.01"))
    if amount <= 0:
        raise HTTPException(400, "Amount must be at least 0.01")

    with connect() as con:
        try:
            con.execute("""
                INSERT INTO transactions
                (reference, source, amount, status, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                data.reference, data.source, str(amount), data.status,
                datetime.now(timezone.utc).isoformat()
            ))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Reference already exists")

    return {
        "reference": data.reference,
        "amount": str(amount),
        "status": data.status
    }

@app.get("/transactions")
def list_transactions():
    with connect() as con:
        rows = con.execute(
            "SELECT * FROM transactions ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def current_month_window():
    # Kenya uses UTC+3 year-round; no external timezone database required.
    kenya_tz = timezone(timedelta(hours=3))
    now = datetime.now(kenya_tz)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    return (
        start.astimezone(timezone.utc).isoformat(),
        end.astimezone(timezone.utc).isoformat()
    )

def money_cents(value):
    return int(
        (Decimal(str(value)) * 100).quantize(
            Decimal("1"), rounding=ROUND_DOWN
        )
    )

def monthly_usage_cents(con, start, end):
    rows = con.execute("""
        SELECT a.category, a.amount
        FROM allocations a
        JOIN transactions t ON t.reference = a.reference
        WHERE t.status = 'confirmed'
          AND t.created_at >= ? AND t.created_at < ?
    """, (start, end)).fetchall()
    totals = {}
    for row in rows:
        totals[row["category"]] = (
            totals.get(row["category"], 0) + money_cents(row["amount"])
        )
    return totals

def distribute_cents(total, rules, capacities):
    # Allocate each category's percentage of the ORIGINAL deposit.
    # Unused percentages and amounts blocked by caps stay unallocated.
    allocated = {r["name"]: 0 for r in rules}
    shares = {}
    remainders = {}

    for r in rules:
        name = r["name"]
        product = total * r["percentage"]
        shares[name] = product // 100
        remainders[name] = product % 100

    # Distribute rounding cents only, without exceeding the configured total.
    target_total = total * sum(r["percentage"] for r in rules) // 100
    leftover = target_total - sum(shares.values())
    ranked = sorted(rules, key=lambda r: (-remainders[r["name"]], r["name"]))

    for r in ranked:
        if leftover <= 0:
            break
        shares[r["name"]] += 1
        leftover -= 1

    unallocated = total
    for r in rules:
        name = r["name"]
        part = min(shares[name], max(0, capacities[name]))
        allocated[name] = part
        unallocated -= part

    return allocated, unallocated

def allocate_reference(reference: str):
    with connect() as con:
        tx = con.execute(
            "SELECT reference, amount, status FROM transactions WHERE reference = ?",
            (reference,)
        ).fetchone()

        if not tx:
            raise HTTPException(404, "Transaction not found")
        if tx["status"] != "confirmed":
            raise HTTPException(400, "Only confirmed test transactions can be allocated")
        if con.execute(
            "SELECT 1 FROM allocations WHERE reference = ? LIMIT 1",
            (reference,)
        ).fetchone():
            raise HTTPException(409, "Already allocated")

        rules = con.execute(
            "SELECT name, percentage FROM rules ORDER BY name"
        ).fetchall()
        if not rules or sum(r["percentage"] for r in rules) > 100:
            raise HTTPException(400, "Allocation percentages must not exceed 100%")

        total = money_cents(tx["amount"])
        start, end = current_month_window()
        usage = monthly_usage_cents(con, start, end)
        cap_rows = {
            r["category"]: money_cents(r["monthly_cap"])
            for r in con.execute("SELECT category, monthly_cap FROM category_caps")
        }

        capacities = {}
        for rule in rules:
            name = rule["name"]
            if name in cap_rows:
                capacities[name] = max(0, cap_rows[name] - usage.get(name, 0))
            else:
                capacities[name] = total

        parts, unallocated = distribute_cents(total, rules, capacities)
        results = []
        for rule in rules:
            name = rule["name"]
            value = Decimal(parts[name]) / 100
            con.execute("""
                INSERT INTO allocations (reference, category, amount)
                VALUES (?, ?, ?)
            """, (reference, name, f"{value:.2f}"))
            results.append({
                "category": name,
                "amount": f"{value:.2f}",
                "status": "planned_not_transferred"
            })

    return {
        "reference": reference,
        "allocations": results,
        "unallocated": f"{Decimal(unallocated) / 100:.2f}",
        "currency": "KES",
        "real_transfers_enabled": False
    }

@app.post("/transactions/{reference}/allocate")
def allocate_transaction(reference: str):
    return allocate_reference(reference)

@app.post("/allocate/{reference}")
def allocate_transaction_legacy(reference: str):
    return allocate_reference(reference)

@app.get("/allocations")
def list_allocations():
    with connect() as con:
        rows = con.execute(
            "SELECT reference, category, amount FROM allocations ORDER BY reference DESC, category"
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/caps")
def get_caps():
    start, end = current_month_window()
    with connect() as con:
        rules = con.execute("SELECT name FROM rules ORDER BY name").fetchall()
        caps = {
            r["category"]: r["monthly_cap"]
            for r in con.execute("SELECT category, monthly_cap FROM category_caps")
        }
        usage = monthly_usage_cents(con, start, end)

    result = {}
    for rule in rules:
        name = rule["name"]
        cap = caps.get(name)
        used = usage.get(name, 0)
        result[name] = {
            "monthly_cap": cap,
            "used_this_month": f"{Decimal(used) / 100:.2f}",
            "remaining_cap": (
                None if cap is None else
                f"{Decimal(max(0, money_cents(cap) - used)) / 100:.2f}"
            )
        }
    return {
        "timezone": "Africa/Nairobi",
        "period_start_utc": start,
        "period_end_utc": end,
        "categories": result
    }

@app.put("/caps")
@app.post("/caps")
def set_caps(data: CapsIn):
    with connect() as con:
        known = {
            r["name"] for r in con.execute("SELECT name FROM rules")
        }
        unknown = set(data.caps) - known
        if unknown:
            raise HTTPException(400, f"Unknown categories: {sorted(unknown)}")
        clean = {}
        for name, raw in data.caps.items():
            if not raw.is_finite() or raw < 0 or raw > Decimal("100000000"):
                raise HTTPException(400, "Caps must be between 0 and 100000000 KES")
            clean[name] = f"{raw.quantize(Decimal('0.01'), rounding=ROUND_DOWN):.2f}"

        con.execute("DELETE FROM category_caps")
        con.executemany(
            "INSERT INTO category_caps (category, monthly_cap) VALUES (?, ?)",
            clean.items()
        )
    return {
        "saved": clean,
        "note": "Omitted categories have no monthly cap. Changes do not delete financial records."
    }

@app.post("/spending")
def record_spending(data: SpendIn):
    amount = data.amount.quantize(Decimal("0.01"), rounding=ROUND_DOWN)
    if amount <= 0:
        raise HTTPException(400, "Amount must be at least 0.01")

    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        if not con.execute(
            "SELECT 1 FROM rules WHERE name = ?", (data.category,)
        ).fetchone():
            raise HTTPException(400, "Unknown category")

        allocated_rows = con.execute("""
            SELECT a.amount
            FROM allocations a
            JOIN transactions t ON t.reference = a.reference
            WHERE a.category = ? AND t.status = 'confirmed'
        """, (data.category,)).fetchall()
        spent_rows = con.execute(
            "SELECT amount FROM spending WHERE category = ?",
            (data.category,)
        ).fetchall()
        allocated = sum((Decimal(r["amount"]) for r in allocated_rows), Decimal("0"))
        spent = sum((Decimal(r["amount"]) for r in spent_rows), Decimal("0"))
        available = allocated - spent

        if amount > available:
            raise HTTPException(
                400, f"Insufficient category balance. Available: {max(available, Decimal('0')):.2f} KES"
            )

        start, end = current_month_window()
        cap_row = con.execute(
            "SELECT monthly_cap FROM category_caps WHERE category = ?",
            (data.category,)
        ).fetchone()

        if cap_row:
            cap = Decimal(cap_row["monthly_cap"])
            month_spent_rows = con.execute("""
                SELECT amount FROM spending
                WHERE category = ? AND created_at >= ? AND created_at < ?
            """, (data.category, start, end)).fetchall()
            month_spent = sum(
                (Decimal(r["amount"]) for r in month_spent_rows),
                Decimal("0")
            )
            if month_spent + amount > cap:
                remaining = max(Decimal("0"), cap - month_spent)
                raise HTTPException(
                    400,
                    f"Monthly cap exceeded. Remaining this month: {remaining:.2f} KES"
                )

        try:
            con.execute("""
                INSERT INTO spending (reference, category, amount, created_at)
                VALUES (?, ?, ?, ?)
            """, (
                data.reference, data.category, f"{amount:.2f}",
                datetime.now(timezone.utc).isoformat()
            ))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Spending reference already exists")

    return {
        "reference": data.reference,
        "category": data.category,
        "amount": f"{amount:.2f}",
        "status": "test_debit_recorded",
        "real_transfers_enabled": False
    }

@app.get("/spending")
def list_spending():
    with connect() as con:
        rows = con.execute(
            "SELECT reference, category, amount, created_at FROM spending ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]

@app.get("/balances")
def balances():
    with connect() as con:
        income_rows = con.execute(
            "SELECT amount FROM transactions WHERE status = 'confirmed'"
        ).fetchall()
        allocation_rows = con.execute("""
            SELECT a.category, a.amount
            FROM allocations a
            JOIN transactions t ON t.reference = a.reference
            WHERE t.status = 'confirmed'
        """).fetchall()
        spending_rows = con.execute(
            "SELECT category, amount FROM spending"
        ).fetchall()

    income = sum((Decimal(r["amount"]) for r in income_rows), Decimal("0"))
    allocated = {}
    spent = {}
    for row in allocation_rows:
        allocated[row["category"]] = (
            allocated.get(row["category"], Decimal("0")) + Decimal(row["amount"])
        )
    for row in spending_rows:
        spent[row["category"]] = (
            spent.get(row["category"], Decimal("0")) + Decimal(row["amount"])
        )

    categories = set(allocated) | set(spent)
    available = {
        name: f"{max(Decimal('0'), allocated.get(name, Decimal('0')) - spent.get(name, Decimal('0'))):.2f}"
        for name in sorted(categories)
    }
    planned = {name: round(float(value), 2) for name, value in allocated.items()}

    total_allocated = sum(allocated.values(), Decimal("0"))
    unallocated = max(Decimal("0"), income - total_allocated)

    return {
        "total_balance": round(float(income), 2),
        "total_allocated_balance": round(float(total_allocated), 2),
        "unallocated_balance": round(float(unallocated), 2),
        "verified_test_income": round(float(income), 2),
        "planned_allocations": planned,
        "category_available_balances": available,
        "currency": "KES",
        "live_bank_balance": False,
        "real_transfers_enabled": False
    }

# --- Pesa Flow extensions: user categories, account movements, and preferences ---
# Additive schema: the original finance tables and existing records are preserved.
def init_pesa_flow_extensions():
    with connect() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS user_categories (
                name TEXT PRIMARY KEY,
                color TEXT NOT NULL DEFAULT '#27856B',
                icon TEXT NOT NULL DEFAULT 'wallet',
                created_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS account_movements (
                reference TEXT PRIMARY KEY,
                from_account TEXT NOT NULL,
                to_account TEXT NOT NULL,
                amount TEXT NOT NULL,
                kind TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        now = datetime.now(timezone.utc).isoformat()
        for row in con.execute("SELECT name FROM rules").fetchall():
            con.execute(
                "INSERT OR IGNORE INTO user_categories (name, created_at) VALUES (?, ?)",
                (row["name"], now)
            )
        con.execute(
            "INSERT OR IGNORE INTO app_settings (key, value) VALUES ('currency', 'KES')"
        )

init_pesa_flow_extensions()


# --- Authentication and per-user data isolation ---
def auth_connect():
    con = sqlite3.connect(str(AUTH_DB), timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA busy_timeout = 15000")
    return con


def init_auth_db():
    with auth_connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            full_name TEXT NOT NULL DEFAULT '',
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            db_path TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        user_columns = {row[1] for row in con.execute("PRAGMA table_info(users)").fetchall()}
        if "full_name" not in user_columns:
            con.execute("ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT ''")
        for column, definition in (
            ("address", "TEXT NOT NULL DEFAULT ''"),
            ("phone", "TEXT NOT NULL DEFAULT ''"),
            ("profile_picture", "TEXT NOT NULL DEFAULT ''"),
            ("handle", "TEXT NOT NULL DEFAULT ''"),
        ):
            if column not in user_columns:
                con.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_handle_unique ON users(lower(handle)) WHERE handle <> ''")
        con.execute("""CREATE TABLE IF NOT EXISTS account_registry (
            account_number TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id),
            account_type TEXT NOT NULL
                CHECK (account_type IN ('base', 'category')),
            category_key TEXT,
            status TEXT NOT NULL DEFAULT 'reserved'
                CHECK (status IN ('reserved', 'active', 'closing', 'closed')),
            created_at TEXT NOT NULL,
            closed_at TEXT,
            UNIQUE(user_id, account_type, category_key)
        )""")
        con.execute("""CREATE UNIQUE INDEX IF NOT EXISTS
            uq_registry_one_base_per_user
            ON account_registry(user_id)
            WHERE account_type = 'base'""")
        con.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
            email TEXT NOT NULL,
            ip TEXT NOT NULL,
            failures INTEGER NOT NULL DEFAULT 0,
            window_start TEXT NOT NULL,
            locked_until TEXT,
            PRIMARY KEY(email, ip)
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS registration_attempts (
            ip TEXT PRIMARY KEY,
            attempts INTEGER NOT NULL DEFAULT 0,
            window_start TEXT NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS mpesa_payment_routes (
            internal_reference TEXT PRIMARY KEY,
            checkout_id TEXT UNIQUE,
            merchant_id TEXT,
            user_id TEXT NOT NULL REFERENCES users(id),
            amount TEXT NOT NULL,
            phone TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'processing', 'confirmed_unallocated', 'allocated', 'failed')),
            receipt TEXT,
            created_at TEXT NOT NULL,
            processed_at TEXT
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS didit_webhook_events (
            event_id TEXT PRIMARY KEY,
            payload_hash TEXT NOT NULL,
            event_type TEXT NOT NULL,
            session_id TEXT,
            processing_status TEXT NOT NULL DEFAULT 'received'
                CHECK (processing_status IN ('received', 'processed', 'ignored', 'failed')),
            received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            processed_at TEXT,
            result TEXT
        )""")
    try:
        AUTH_DB.chmod(0o600)
    except OSError:
        pass


def utc_now():
    return datetime.now(timezone.utc)


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS).hex()


def valid_email(email: str) -> str:
    email = email.strip().lower()
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(400, "Enter a valid email address")
    return email


def user_db_path(user_id: str) -> Path:
    # The id is generated server-side and cannot contain path components.
    return USER_DB_DIR / f"{user_id}.sqlite3"


def initialize_user_database(path: Path, copy_legacy: bool):
    if copy_legacy and Path(DB).exists():
        source = sqlite3.connect(DB, timeout=15)
        destination = sqlite3.connect(str(path), timeout=15)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
    else:
        token = current_db_path.set(str(path))
        try:
            init_db()
            init_pesa_flow_extensions()
        finally:
            current_db_path.reset(token)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def ensure_setup_token():
    with auth_connect() as con:
        count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        if not SETUP_TOKEN_FILE.exists():
            token = secrets.token_urlsafe(24)
            SETUP_TOKEN_FILE.write_text(token, encoding="utf-8")
            try:
                SETUP_TOKEN_FILE.chmod(0o600)
            except OSError:
                pass
        # The token is visible only in the local server terminal / protected file.
        print("\\nPesa Flow first-account setup token (required for the first account): " + SETUP_TOKEN_FILE.read_text(encoding="utf-8").strip())


ADMIN_SESSION_HOURS = 4
ADMIN_CONFIG_PATH = DATA_DIR / ".pf_admin_auth.json"

def init_admin_auth_db():
    with auth_connect() as con:
        con.execute("CREATE TABLE IF NOT EXISTS admin_sessions (token_hash TEXT PRIMARY KEY, expires_at TEXT NOT NULL, created_at TEXT NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS admin_login_attempts (ip TEXT PRIMARY KEY, failures INTEGER NOT NULL DEFAULT 0, window_start TEXT NOT NULL, locked_until TEXT)")
    try: AUTH_DB.chmod(0o600)
    except OSError: pass

def read_admin_config():
    try:
        value = json.loads(ADMIN_CONFIG_PATH.read_text(encoding="utf-8"))
        return value if value.get("version") == 1 else None
    except (OSError, ValueError, TypeError): return None

def verify_admin_secret(value, item, iterations=600_000):
    try:
        actual = hashlib.pbkdf2_hmac("sha256", value.encode("utf-8"), bytes.fromhex(item["salt"]), int(iterations)).hex()
        return hmac.compare_digest(actual, item["hash"])
    except (KeyError, TypeError, ValueError): return False

def admin_session_valid(raw):
    if not raw or len(raw) > 256: return False
    digest = hashlib.sha256(raw.encode()).hexdigest()
    try:
        with auth_connect() as con: row = con.execute("SELECT expires_at FROM admin_sessions WHERE token_hash=?", (digest,)).fetchone()
        if not row: return False
        if datetime.fromisoformat(row["expires_at"]) <= utc_now():
            with auth_connect() as con: con.execute("DELETE FROM admin_sessions WHERE token_hash=?", (digest,))
            return False
        return True
    except sqlite3.Error: return False

def require_admin(request):
    if not getattr(request.state, "admin_authenticated", False):
        raise HTTPException(status_code=401, detail="Administrator authentication required")


init_auth_db()
init_admin_auth_db()


def init_company_info_db():
    with auth_connect() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS company_info (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT ''
            )
        """)


init_company_info_db()
ensure_setup_token()


class RegisterIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=80)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)
    setup_token: str = Field(default="", max_length=200)


class ProfileIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=80)
    email: str = Field(min_length=3, max_length=254)
    address: str = Field(default="", max_length=300)
    phone: str = Field(default="", max_length=30)
    profile_picture_data: str = Field(default="", max_length=1_500_000)


class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


def issue_session(response, user_id: str):
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    now = utc_now()
    expires = now + timedelta(hours=SESSION_HOURS)
    with auth_connect() as con:
        con.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)",
                    (token_hash, user_id, expires.isoformat(), now.isoformat()))
    response.set_cookie(
        "pf_session", raw_token, max_age=SESSION_HOURS * 3600, httponly=True,
        secure=COOKIE_SECURE, samesite="strict", path="/"
    )


@app.middleware("http")
async def authentication_and_security_middleware(request: Request, call_next):
    path = request.url.path
    # Exact Didit POST only; its endpoint must verify the signature.
    if path == "/api/webhooks/didit" and request.method == "POST":
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response
    if path == "/admin-login":
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        return response
    if path in {"/admin", "/admin-home"} or path.startswith("/api/admin/"):
        public_admin = {"/api/admin/login", "/api/admin/question"}
        if path not in public_admin:
            if not admin_session_valid(request.cookies.get("pf_admin_session", "")):
                if path.startswith("/api/"): response = JSONResponse({"detail": "Administrator authentication required"}, status_code=401)
                else: response = RedirectResponse("/admin-login", status_code=303)
                response.delete_cookie("pf_admin_session", path="/", httponly=True, secure=COOKIE_SECURE, samesite="strict")
                response.headers["Cache-Control"] = "no-store"
                return response
            request.state.admin_authenticated = True
            if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
                origin = request.headers.get("origin")
                parsed = urlsplit(origin) if origin else None
                if not parsed or parsed.netloc.lower() != request.headers.get("host", "").lower() or parsed.scheme != request.url.scheme:
                    return JSONResponse({"detail": "Cross-origin request blocked"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        return response
    public_paths = {"/", "/login", "/api/status", "/api/register", "/api/login", "/api/mpesa/callback", "/favicon.ico", "/admin-login"}
    user = None
    raw_token = request.cookies.get("pf_session")
    if raw_token and (len(raw_token) > 256 or not raw_token.isascii()):
        raw_token = None
    if raw_token:
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        with auth_connect() as con:
            user = con.execute("""SELECT u.id, u.email, u.full_name, u.address, u.phone,
                u.profile_picture, u.db_path, s.expires_at
                FROM sessions s JOIN users u ON u.id=s.user_id
                WHERE s.token_hash=?""", (token_hash,)).fetchone()
            if user and datetime.fromisoformat(user["expires_at"]) <= utc_now():
                con.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                user = None

    is_public = (
        path in public_paths
        or (path == "/api/company-info" and request.method == "GET")
    )
    if not is_public and not user:
        if path.startswith("/api/"):
            response = JSONResponse({"detail": "Authentication required"}, status_code=401)
        else:
            response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(
            "pf_session", path="/", httponly=True,
            secure=COOKIE_SECURE, samesite="strict"
        )
        return response

    if user:
        request.state.user = {
            "id": user["id"], "email": user["email"],
            "full_name": user["full_name"], "address": user["address"],
            "phone": user["phone"], "profile_picture": user["profile_picture"]
        }
        request.state.session_token = raw_token
        # Reject cross-origin state changes to reduce CSRF risk.
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and path not in {"/api/login", "/api/register", "/api/mpesa/callback"}:
            origin = request.headers.get("origin")
            if not origin:
                return JSONResponse({"detail": "Missing Origin header"}, status_code=403)
            parsed = urlsplit(origin)
            host = request.headers.get("host", "")
            if parsed.netloc.lower() != host.lower() or parsed.scheme != request.url.scheme:
                return JSONResponse({"detail": "Cross-origin request blocked"}, status_code=403)
        token = current_db_path.set(user["db_path"])
        try:
            response = await call_next(request)
        finally:
            current_db_path.reset(token)
    else:
        response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def auth_home():
    return RedirectResponse("/login", status_code=303)


@app.get("/login")
def login_page():
    return FileResponse(str(BASE_DIR / "login.html"))


@app.get("/admin-login")
def admin_login_page():
    return FileResponse(str(BASE_DIR / "admin_login.html"))


@app.get("/api/status")
def auth_status():
    with auth_connect() as con:
        count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    return {"setup_required": count == 0, "registration_enabled": count == 0 or os.environ.get("PF_ALLOW_REGISTRATION", "1") != "0"}


@app.post("/api/register")
def register_user(data: RegisterIn, request: Request):
    full_name = " ".join(data.full_name.split())
    if len(full_name) < 2:
        raise HTTPException(400, "Enter your full name")
    email = valid_email(data.email)
    if len(data.password) < 12:
        raise HTTPException(400, "Use a password with at least 12 characters")
    ip = request.client.host if request.client else "unknown"
    now_limit = utc_now()
    with auth_connect() as con:
        con.execute("BEGIN IMMEDIATE")
        attempt = con.execute("SELECT * FROM registration_attempts WHERE ip=?", (ip,)).fetchone()
        if not attempt or now_limit - datetime.fromisoformat(attempt["window_start"]) > timedelta(hours=1):
            attempts, window_start = 1, now_limit
        else:
            attempts, window_start = attempt["attempts"] + 1, datetime.fromisoformat(attempt["window_start"])
        con.execute("""INSERT INTO registration_attempts(ip,attempts,window_start) VALUES(?,?,?)
            ON CONFLICT(ip) DO UPDATE SET attempts=excluded.attempts,window_start=excluded.window_start""",
            (ip, attempts, window_start.isoformat()))
        if attempts > 10:
            raise HTTPException(429, "Too many registration attempts from this connection. Try again later.")
    with registration_lock:
        with auth_connect() as con:
            con.execute("BEGIN IMMEDIATE")
            count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count == 0:
                try:
                    expected = SETUP_TOKEN_FILE.read_text(encoding="utf-8").strip()
                except OSError:
                    expected = ""
                if not expected or not hmac.compare_digest(data.setup_token, expected):
                    raise HTTPException(403, "The first account requires the setup token shown in the server terminal")
            elif os.environ.get("PF_ALLOW_REGISTRATION", "1") == "0":
                raise HTTPException(403, "New account registration is disabled")
            if con.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                raise HTTPException(409, "An account with that email already exists")
            user_id = uuid4().hex
            db_path = user_db_path(user_id)
            initialize_user_database(db_path, copy_legacy=(count == 0))
            salt = secrets.token_bytes(16)
            now = utc_now().isoformat()
            con.execute("INSERT INTO users(id,email,full_name,password_salt,password_hash,db_path,created_at) VALUES(?,?,?,?,?,?,?)",
                        (user_id, email, full_name, salt.hex(), hash_password(data.password, salt), str(db_path), now))
        if count == 0:
            try:
                SETUP_TOKEN_FILE.unlink()
            except OSError:
                pass
    response = JSONResponse({"ok": True, "email": email, "full_name": full_name})
    issue_session(response, user_id)
    return response


@app.post("/api/login")
def login_user(data: LoginIn, request: Request):
    email = data.email.strip().lower()[:254]
    ip = request.client.host if request.client else "unknown"
    now = utc_now()
    with auth_connect() as con:
        attempt = con.execute("SELECT * FROM login_attempts WHERE email=? AND ip=?", (email, ip)).fetchone()
        if attempt and attempt["locked_until"] and datetime.fromisoformat(attempt["locked_until"]) > now:
            raise HTTPException(429, "Too many login attempts. Try again in 15 minutes.")
        user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    salt = bytes.fromhex(user["password_salt"]) if user else b"pesa-flow-dummy-salt"
    calculated = hash_password(data.password, salt)
    valid = bool(user) and hmac.compare_digest(calculated, user["password_hash"])
    if not valid:
        with auth_connect() as con:
            attempt = con.execute("SELECT * FROM login_attempts WHERE email=? AND ip=?", (email, ip)).fetchone()
            if not attempt or now - datetime.fromisoformat(attempt["window_start"]) > timedelta(minutes=15):
                failures, window_start = 1, now
            else:
                failures, window_start = attempt["failures"] + 1, datetime.fromisoformat(attempt["window_start"])
            locked_until = (now + timedelta(minutes=15)).isoformat() if failures >= 5 else None
            con.execute("""INSERT INTO login_attempts(email,ip,failures,window_start,locked_until) VALUES(?,?,?,?,?)
                ON CONFLICT(email,ip) DO UPDATE SET failures=excluded.failures,window_start=excluded.window_start,locked_until=excluded.locked_until""",
                (email, ip, failures, window_start.isoformat(), locked_until))
        raise HTTPException(401, "Invalid email or password")
    with auth_connect() as con:
        con.execute("DELETE FROM login_attempts WHERE email=? AND ip=?", (email, ip))
        con.execute("DELETE FROM sessions WHERE user_id=? AND expires_at<=?", (user["id"], now.isoformat()))
    response = JSONResponse({"ok": True, "email": email})
    issue_session(response, user["id"])
    return response


@app.post("/api/logout")
def logout_user(request: Request):
    raw_token = getattr(request.state, "session_token", "")
    if raw_token:
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        with auth_connect() as con:
            con.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
    response = JSONResponse({"ok": True})
    response.delete_cookie("pf_session", path="/", httponly=True, secure=COOKIE_SECURE, samesite="strict")
    return response



class CompanyInfoIn(BaseModel):
    socials: dict[str, str] = Field(default_factory=dict)
    contact_email: str = Field(default="", max_length=254)
    contact_phone: str = Field(default="", max_length=50)
    contact_whatsapp: str = Field(default="", max_length=100)
    contact_address: str = Field(default="", max_length=500)
    about: str = Field(default="", max_length=10000)
    privacy_policy: str = Field(default="", max_length=50000)
    terms: str = Field(default="", max_length=50000)


COMPANY_INFO_DEFAULTS = {
    "socials": {},
    "contact_email": "",
    "contact_phone": "",
    "contact_whatsapp": "",
    "contact_address": "",
    "about": "",
    "privacy_policy": "",
    "terms": "",
}


@app.get("/api/company-info")
def get_company_info():
    result = dict(COMPANY_INFO_DEFAULTS)
    with auth_connect() as con:
        rows = con.execute("SELECT key, value FROM company_info").fetchall()
    for row in rows:
        key, value = row["key"], row["value"]
        if key not in result:
            continue
        if key == "socials":
            try:
                value = json.loads(value)
            except (TypeError, json.JSONDecodeError):
                value = {}
        result[key] = value
    return result


@app.get("/api/admin/company-info/status")
def company_info_admin_status(request: Request):
    require_admin(request)
    return {"is_admin": True}


@app.get("/api/admin/company-info")
def get_admin_company_info(request: Request):
    require_admin(request)
    return get_company_info()


@app.put("/api/admin/company-info")
def update_admin_company_info(data: CompanyInfoIn, request: Request):
    require_admin(request)

    allowed = {
        "instagram", "tiktok", "facebook", "x",
        "whatsapp", "telegram", "youtube", "linkedin"
    }
    socials = {}
    for name, url in data.socials.items():
        name = name.strip().lower()
        if name not in allowed:
            raise HTTPException(400, "Unsupported social platform: " + name)
        url = url.strip()
        if len(url) > 500:
            raise HTTPException(400, "Social link is too long")
        if url and urlsplit(url).scheme not in {"https", "http"}:
            raise HTTPException(400, "Social links must use http:// or https://")
        socials[name] = url

    values = data.dict()
    values["socials"] = json.dumps(socials, ensure_ascii=False)
    with auth_connect() as con:
        con.executemany(
            """INSERT INTO company_info(key, value) VALUES(?, ?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
            [(key, value if isinstance(value, str) else str(value))
             for key, value in values.items()]
        )
    return {"ok": True}


class HandleIn(BaseModel):
    handle: str = Field(min_length=3, max_length=25)


@app.put("/api/handle")
def update_handle(data: HandleIn, request: Request):
    handle = data.handle.strip().lower()
    if handle.startswith("@"):
        handle = handle[1:]
    if not re.fullmatch(r"[a-z0-9_]{3,24}", handle):
        raise HTTPException(400, "Use 3–24 letters, numbers, or underscores")
    user_id = request.state.user["id"]
    try:
        with auth_connect() as con:
            existing = con.execute(
                "SELECT id FROM users WHERE lower(handle)=? AND id<>?",
                (handle, user_id)
            ).fetchone()
            if existing:
                raise HTTPException(409, "That handle is already taken")
            con.execute("UPDATE users SET handle=? WHERE id=?", (handle, user_id))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "That handle is already taken")
    return {"ok": True, "handle": handle}


@app.get("/api/financial-readiness")
def financial_readiness(request: Request):
    user_id = request.state.user["id"]

    with connect() as con:
        identity = con.execute(
            "SELECT status FROM identity_verification WHERE id=1"
        ).fetchone()
        local_account = con.execute(
            """SELECT account_number FROM ledger_accounts
               WHERE account_type='base' AND status='active'"""
        ).fetchone()

    with auth_connect() as con:
        registry = con.execute(
            """SELECT account_number FROM account_registry
               WHERE user_id=? AND account_type='base' AND status='active'""",
            (user_id,)
        ).fetchone()

    verified = bool(identity and identity["status"] == "verified")
    account_active = bool(
        verified and local_account and registry
        and local_account["account_number"] == registry["account_number"]
    )

    return {
        "identity_status": identity["status"] if identity else "pending",
        "identity_verified": verified,
        "base_account_active": account_active,
        "base_account_number": (
            registry["account_number"] if account_active else None
        ),
        "real_transfers_enabled": False
    }


@app.post("/api/identity-verification/session")
def create_identity_verification_session(request: Request):
    user_id = str(request.state.user["id"])
    api_key = os.environ.get("DIDIT_API_KEY", "")
    workflow_id = os.environ.get("DIDIT_WORKFLOW_ID", "")

    if not api_key or not workflow_id:
        raise HTTPException(status_code=503, detail="Identity verification is not configured.")

    with connect() as con:
        identity = con.execute(
            "SELECT status FROM identity_verification WHERE id=1"
        ).fetchone()

    if identity and identity["status"] == "verified":
        raise HTTPException(status_code=409, detail="Identity is already verified.")

    try:
        response = requests.post(
            "https://verification.didit.me/v3/session/",
            headers={"x-api-key": api_key, "Content-Type": "application/json"},
            json={"workflow_id": workflow_id, "vendor_data": user_id},
            timeout=20,
        )
        if response.status_code not in (200, 201):
            raise HTTPException(
                status_code=502,
                detail="Verification provider could not create a session."
            )
        result = response.json()
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="Verification provider is unavailable.")
    except ValueError:
        raise HTTPException(status_code=502, detail="Invalid response from verification provider.")

    session_id = result.get("session_id")
    verification_url = result.get("url")
    parsed_url = urlsplit(verification_url or "")
    if (
        not isinstance(session_id, str) or not session_id
        or parsed_url.scheme != "https"
        or parsed_url.hostname != "verify.didit.me"
    ):
        raise HTTPException(status_code=502, detail="Invalid session response from verification provider.")

    with connect() as con:
        con.execute(
            """UPDATE identity_verification
               SET provider='didit', provider_reference=?, updated_at=CURRENT_TIMESTAMP
               WHERE id=1 AND status!='verified'""",
            (session_id,),
        )

    return {"verification_url": verification_url}




@app.get("/api/identity-verification/status")
def identity_verification_status(request: Request):
    with connect() as con:
        identity = con.execute(
            """SELECT status, provider, provider_reference, updated_at
               FROM identity_verification WHERE id=1"""
        ).fetchone()

    return {
        "status": identity["status"] if identity else "pending",
        "provider": identity["provider"] if identity else None,
        "session_started": bool(
            identity and identity["provider_reference"]
        ),
        "updated_at": identity["updated_at"] if identity else None,
        "real_transfers_enabled": False,
    }


def _didit_normalize(value):
    if isinstance(value, dict):
        return {k: _didit_normalize(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_didit_normalize(v) for v in value]
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


@app.post("/api/webhooks/didit")
async def didit_webhook(request: Request):
    secret = os.environ.get("DIDIT_WEBHOOK_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="Webhook not configured.")

    raw = await request.body()
    if len(raw) > 1_000_000:
        raise HTTPException(status_code=413, detail="Payload too large.")

    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON.")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload.")

    timestamp = payload.get("timestamp")
    header_timestamp = request.headers.get("X-Timestamp", "")
    try:
        ts = int(timestamp)
        valid_ts = (
            not isinstance(timestamp, bool)
            and str(ts) == str(timestamp)
            and header_timestamp == str(ts)
            and abs(datetime.now(timezone.utc).timestamp() - ts) <= 300
        )
    except (ValueError, TypeError, OverflowError):
        valid_ts = False

    if not valid_ts:
        raise HTTPException(status_code=401, detail="Invalid timestamp.")

    try:
        canonical = json.dumps(
            _didit_normalize(payload),
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid payload values.")

    expected = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    supplied = request.headers.get("X-Signature-V2", "").strip().lower()
    if len(supplied) != len(expected) or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid signature.")

    event_type = payload.get("webhook_type")
    session_id = payload.get("session_id")
    user_id = payload.get("vendor_data")
    status = payload.get("status")

    # Only session status changes can affect identity status.
    if event_type != "status.updated":
        return {"received": True, "ignored": True}

    if not all(isinstance(v, str) and v for v in (session_id, user_id, status)):
        raise HTTPException(status_code=400, detail="Missing event fields.")

    status_map = {
        "approved": "verified",
        "declined": "rejected",
        "in review": "in_review",
        "not started": "pending",
        "in progress": "pending",
        "awaiting user": "pending",
        "resubmitted": "pending",
        "abandoned": "pending",
        "expired": "pending",
        "kyc expired": "rejected",
    }
    mapped = status_map.get(status.strip().casefold())
    if mapped is None:
        return {"received": True, "ignored": True}

    # Stable across delivery retries, which may refresh the timestamp.
    supplied_event_id = payload.get("event_id")
    if isinstance(supplied_event_id, str) and supplied_event_id.strip():
        event_id = supplied_event_id.strip()
    else:
        # Fallback for test deliveries that omit event_id.
        event_id = hashlib.sha256(
            chr(0).join(
                (session_id, event_type, status.casefold())
            ).encode("utf-8")
        ).hexdigest()
    # Ignore delivery timestamp when identifying the same event across retries.
    fingerprint_payload = {
        key: value for key, value in payload.items()
        if key != "timestamp"
    }
    fingerprint_canonical = json.dumps(
        _didit_normalize(fingerprint_payload),
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    payload_hash = hashlib.sha256(fingerprint_canonical).hexdigest()

    with auth_connect() as con:
        # Serialize claims so simultaneous retries cannot both process an event.
        con.execute("BEGIN IMMEDIATE")
        prior = con.execute(
            """SELECT processing_status, payload_hash,
                      (julianday('now') - julianday(received_at)) * 86400
                      AS age_seconds
               FROM didit_webhook_events WHERE event_id=?""",
            (event_id,),
        ).fetchone()

        if prior:
            if prior["payload_hash"] != payload_hash:
                raise HTTPException(
                    status_code=409, detail="Event ID payload conflict."
                )
            if prior["processing_status"] in ("processed", "ignored"):
                return {"received": True, "duplicate": True}
            if (
                prior["processing_status"] == "received"
                and prior["age_seconds"] is not None
                and prior["age_seconds"] < 300
            ):
                return {"received": True, "duplicate": True}

            # Retry failed or stale claims.
            con.execute(
                """UPDATE didit_webhook_events
                   SET processing_status='received',
                       received_at=CURRENT_TIMESTAMP,
                       processed_at=NULL, result=NULL
                   WHERE event_id=?""",
                (event_id,),
            )
        else:
            con.execute(
                """INSERT INTO didit_webhook_events
                   (event_id, payload_hash, event_type, session_id,
                    processing_status)
                   VALUES (?, ?, ?, ?, 'received')""",
                (event_id, payload_hash, event_type, session_id),
            )

        user = con.execute(
            "SELECT id, db_path FROM users WHERE id=?",
            (user_id,),
        ).fetchone()

    result = "ignored"
    if user:
        expected_path = user_db_path(user_id).resolve()
        registered_path = Path(user["db_path"]).resolve()

        # Trust only the expected per-user database, never a webhook-supplied path.
        if registered_path == expected_path and expected_path.is_file():
            token = current_db_path.set(str(expected_path))
            try:
                with connect() as con:
                    identity = con.execute(
                        """SELECT status, provider, provider_reference
                           FROM identity_verification WHERE id=1"""
                    ).fetchone()

                    if (
                        identity
                        and identity["provider"] == "didit"
                        and identity["provider_reference"] == session_id
                    ):
                        con.execute(
                            """UPDATE identity_verification
                               SET status=?, updated_at=CURRENT_TIMESTAMP,
                                   verified_at=CASE WHEN ?='verified'
                                       THEN CURRENT_TIMESTAMP ELSE verified_at END
                               WHERE id=1 AND provider='didit'
                                 AND provider_reference=?""",
                            (mapped, mapped, session_id),
                        )
                        result = "processed"
            finally:
                current_db_path.reset(token)

    with auth_connect() as con:
        con.execute(
            """UPDATE didit_webhook_events
               SET processing_status=?, processed_at=CURRENT_TIMESTAMP, result=?
               WHERE event_id=?""",
            (result, "status handled" if result == "processed" else "unmatched", event_id),
        )

    return {"received": True}


@app.post("/api/base-account")
def create_base_account(request: Request):
    user_id = request.state.user["id"]

    with connect() as con:
        identity = con.execute(
            "SELECT status FROM identity_verification WHERE id=1"
        ).fetchone()
    if not identity or identity["status"] != "verified":
        raise HTTPException(
            status_code=403,
            detail="Identity verification must be completed before account activation."
        )

    # Reserve globally before writing the user's account record.
    with auth_connect() as auth:
        auth.execute("BEGIN IMMEDIATE")
        existing = auth.execute(
            """SELECT account_number, status FROM account_registry
               WHERE user_id=? AND account_type='base'""",
            (user_id,)
        ).fetchone()

        if existing and existing["status"] == "active":
            number = existing["account_number"]
        elif existing and existing["status"] == "reserved":
            number = existing["account_number"]
        elif existing:
            raise HTTPException(
                status_code=409,
                detail="A base account exists but is not available for activation."
            )
        else:
            number = None
            for _ in range(20):
                candidate = "PF" + "".join(
                    secrets.choice("0123456789") for _ in range(12)
                )
                try:
                    auth.execute(
                        """INSERT INTO account_registry
                           (account_number,user_id,account_type,category_key,
                            status,created_at)
                           VALUES(?,?, 'base', NULL, 'reserved', ?)""",
                        (candidate, user_id, utc_now().isoformat())
                    )
                    number = candidate
                    break
                except sqlite3.IntegrityError:
                    continue
            if number is None:
                raise HTTPException(
                    status_code=503,
                    detail="Unable to reserve an account number. Try again."
                )

    # Create or verify the matching per-user record.
    try:
        with connect() as con:
            con.execute("BEGIN IMMEDIATE")
            local = con.execute(
                """SELECT account_number, status FROM ledger_accounts
                   WHERE account_type='base'"""
            ).fetchone()
            if local and local["account_number"] != number:
                raise HTTPException(
                    status_code=409,
                    detail="Account records need reconciliation before activation."
                )
            if not local:
                con.execute(
                    """INSERT INTO ledger_accounts
                       (account_number,account_type,category_name,status)
                       VALUES(?, 'base', NULL, 'active')""",
                    (number,)
                )
            elif local["status"] != "active":
                con.execute(
                    """UPDATE ledger_accounts SET status='active'
                       WHERE account_type='base' AND account_number=?""",
                    (number,)
                )
    except Exception:
        # Keep the central reservation inactive if local creation fails.
        raise

    with auth_connect() as auth:
        auth.execute("BEGIN IMMEDIATE")
        auth.execute(
            """UPDATE account_registry SET status='active'
               WHERE user_id=? AND account_number=?
                 AND account_type='base' AND status='reserved'""",
            (user_id, number)
        )
        row = auth.execute(
            """SELECT status FROM account_registry
               WHERE user_id=? AND account_number=? AND account_type='base'""",
            (user_id, number)
        ).fetchone()
        if not row or row["status"] != "active":
            raise HTTPException(
                status_code=503,
                detail="Account activation is pending reconciliation."
            )

    return {
        "ok": True,
        "account_type": "base",
        "account_number": number,
        "identity_verified": True,
        "real_transfers_enabled": False
    }


@app.post("/api/category-accounts")
async def create_category_account(request: Request):
    user_id = request.state.user["id"]

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    if not isinstance(payload, dict) or not isinstance(payload.get("name"), str):
        raise HTTPException(status_code=400, detail="Provide a category name.")

    name = " ".join(payload["name"].split())
    if not name or len(name) > 60:
        raise HTTPException(
            status_code=400,
            detail="Category name must contain 1 to 60 characters."
        )
    if any(ord(ch) < 32 for ch in name):
        raise HTTPException(status_code=400, detail="Invalid category name.")

    category_key = name.casefold()

    with connect() as con:
        identity = con.execute(
            "SELECT status FROM identity_verification WHERE id=1"
        ).fetchone()
        base = con.execute(
            """SELECT account_number FROM ledger_accounts
               WHERE account_type='base' AND status='active'"""
        ).fetchone()

    if not identity or identity["status"] != "verified":
        raise HTTPException(status_code=403, detail="Identity verification is required.")
    if not base:
        raise HTTPException(status_code=409, detail="Activate the base account first.")

    # Reserve a globally unique account number before creating the local record.
    with auth_connect() as auth:
        auth.execute("BEGIN IMMEDIATE")
        registered_base = auth.execute(
            """SELECT status FROM account_registry
               WHERE user_id=? AND account_type='base'""",
            (user_id,)
        ).fetchone()
        if not registered_base or registered_base["status"] != "active":
            raise HTTPException(status_code=409, detail="Base account registry needs reconciliation.")

        existing = auth.execute(
            """SELECT account_number, status FROM account_registry
               WHERE user_id=? AND account_type='category' AND category_key=?""",
            (user_id, category_key)
        ).fetchone()

        if existing:
            if existing["status"] != "reserved":
                raise HTTPException(status_code=409, detail="This category already exists or is closed.")
            number = existing["account_number"]
        else:
            number = None
            for _ in range(20):
                candidate = "PF" + "".join(
                    secrets.choice("0123456789") for _ in range(12)
                )
                try:
                    auth.execute(
                        """INSERT INTO account_registry
                           (account_number,user_id,account_type,category_key,status,created_at)
                           VALUES(?,?, 'category', ?, 'reserved', ?)""",
                        (candidate, user_id, category_key, utc_now().isoformat())
                    )
                    number = candidate
                    break
                except sqlite3.IntegrityError:
                    continue

            if number is None:
                raise HTTPException(status_code=503, detail="Could not reserve an account number.")

    # A reserved number can be safely retried if a previous attempt stopped partway.
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        local = con.execute(
            """SELECT account_number, status FROM ledger_accounts
               WHERE account_type='category' AND lower(category_name)=lower(?)""",
            (name,)
        ).fetchone()

        if local and local["account_number"] != number:
            raise HTTPException(status_code=409, detail="Category records need reconciliation.")
        if local and local["status"] != "active":
            raise HTTPException(status_code=409, detail="Category account is not active.")
        if not local:
            con.execute(
                """INSERT INTO ledger_accounts
                   (account_number,account_type,category_name,status)
                   VALUES(?, 'category', ?, 'active')""",
                (number, name)
            )

    with auth_connect() as auth:
        auth.execute("BEGIN IMMEDIATE")
        auth.execute(
            """UPDATE account_registry SET status='active'
               WHERE user_id=? AND account_number=?
                 AND account_type='category' AND status='reserved'""",
            (user_id, number)
        )
        row = auth.execute(
            """SELECT status FROM account_registry
               WHERE user_id=? AND account_number=? AND account_type='category'""",
            (user_id, number)
        ).fetchone()
        if not row or row["status"] != "active":
            raise HTTPException(status_code=503, detail="Category activation needs reconciliation.")

    return {
        "ok": True,
        "category": name,
        "account_number": number,
        "balance_cents": 0,
        "real_transfers_enabled": False
    }


@app.post("/api/ledger/transfer")
async def ledger_transfer(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON object required.")

    source_number = payload.get("source_account")
    destination_number = payload.get("destination_account")
    reference = payload.get("reference")
    amount = payload.get("amount_cents")

    if not isinstance(source_number, str) or not source_number.strip():
        raise HTTPException(status_code=400, detail="Source account is required.")
    if not isinstance(destination_number, str) or not destination_number.strip():
        raise HTTPException(status_code=400, detail="Destination account is required.")
    if source_number == destination_number:
        raise HTTPException(status_code=400, detail="Source and destination must differ.")
    if (not isinstance(reference, str) or not 8 <= len(reference) <= 100
            or not all(ch.isalnum() or ch in "-_." for ch in reference)):
        raise HTTPException(
            status_code=400,
            detail="Reference must be 8-100 letters, digits, dots, dashes or underscores."
        )
    if type(amount) is not int or not 1 <= amount <= 100_000_000_000:
        raise HTTPException(
            status_code=400,
            detail="amount_cents must be a positive integer."
        )

    source_number = source_number.strip()
    destination_number = destination_number.strip()
    description = payload.get("description", "Internal account transfer")
    if not isinstance(description, str):
        description = "Internal account transfer"
    description = description.strip()[:200] or "Internal account transfer"

    with connect() as con:
        con.execute("BEGIN IMMEDIATE")

        source = con.execute(
            "SELECT id, status FROM ledger_accounts WHERE account_number=?",
            (source_number,)
        ).fetchone()
        destination = con.execute(
            "SELECT id, status FROM ledger_accounts WHERE account_number=?",
            (destination_number,)
        ).fetchone()

        if not source or not destination:
            raise HTTPException(status_code=404, detail="Account not found.")
        if source["id"] == destination["id"]:
            raise HTTPException(status_code=400, detail="Source and destination must differ.")

        # Idempotency: the same reference and exact same transfer never posts twice.
        existing = con.execute(
            """SELECT id, kind, status FROM ledger_transactions
               WHERE reference=?""",
            (reference,)
        ).fetchone()

        if existing:
            postings = con.execute(
                """SELECT account_id, side, amount_cents
                   FROM ledger_postings WHERE transaction_id=?""",
                (existing["id"],)
            ).fetchall()
            expected = {
                (source["id"], "debit", amount),
                (destination["id"], "credit", amount),
            }
            actual = {
                (row["account_id"], row["side"], row["amount_cents"])
                for row in postings
            }
            if (existing["kind"] == "internal_transfer"
                    and existing["status"] == "posted"
                    and actual == expected and len(postings) == 2):
                return {
                    "ok": True,
                    "reference": reference,
                    "status": "posted",
                    "amount_cents": amount,
                    "idempotent_replay": True
                }
            raise HTTPException(
                status_code=409,
                detail="Reference already exists with different or incomplete details."
            )

        identity = con.execute(
            "SELECT status FROM identity_verification WHERE id=1"
        ).fetchone()
        if not identity or identity["status"] != "verified":
            raise HTTPException(status_code=403, detail="Identity verification is required.")
        if source["status"] != "active" or destination["status"] != "active":
            raise HTTPException(status_code=409, detail="Both accounts must be active.")

        # Customer account balances are credits minus debits.
        balance = con.execute(
            """SELECT COALESCE(SUM(
                   CASE WHEN p.side='credit' THEN p.amount_cents
                        ELSE -p.amount_cents END
               ), 0)
               FROM ledger_postings p
               JOIN ledger_transactions t ON t.id=p.transaction_id
               WHERE p.account_id=? AND t.status='posted'""",
            (source["id"],)
        ).fetchone()[0]

        if balance < amount:
            raise HTTPException(status_code=409, detail="Insufficient account balance.")

        cur = con.execute(
            """INSERT INTO ledger_transactions
               (reference, kind, status, description)
               VALUES(?, 'internal_transfer', 'pending', ?)""",
            (reference, description)
        )
        transaction_id = cur.lastrowid

        con.execute(
            """INSERT INTO ledger_postings
               (transaction_id, account_id, side, amount_cents)
               VALUES(?, ?, 'debit', ?)""",
            (transaction_id, source["id"], amount)
        )
        con.execute(
            """INSERT INTO ledger_postings
               (transaction_id, account_id, side, amount_cents)
               VALUES(?, ?, 'credit', ?)""",
            (transaction_id, destination["id"], amount)
        )

        totals = con.execute(
            """SELECT
                 COALESCE(SUM(CASE WHEN side='debit' THEN amount_cents ELSE 0 END),0),
                 COALESCE(SUM(CASE WHEN side='credit' THEN amount_cents ELSE 0 END),0),
                 COUNT(*)
               FROM ledger_postings WHERE transaction_id=?""",
            (transaction_id,)
        ).fetchone()

        if totals[0] != totals[1] or totals[2] != 2:
            raise HTTPException(status_code=500, detail="Ledger balance check failed.")

        con.execute(
            """UPDATE ledger_transactions
               SET status='posted', posted_at=? WHERE id=? AND status='pending'""",
            (utc_now().isoformat(), transaction_id)
        )

    return {
        "ok": True,
        "reference": reference,
        "status": "posted",
        "amount_cents": amount,
        "idempotent_replay": False,
        "real_transfers_enabled": False
    }


@app.get("/api/ledger/overview")
def ledger_overview(request: Request):
    with connect() as con:
        identity = con.execute(
            "SELECT status FROM identity_verification WHERE id=1"
        ).fetchone()

        rows = con.execute(
            """SELECT a.id, a.account_number, a.account_type,
                      a.category_name, a.status, a.release_at,
                      COALESCE(SUM(
                          CASE WHEN t.status='posted' AND p.side='credit'
                               THEN p.amount_cents
                               WHEN t.status='posted' AND p.side='debit'
                               THEN -p.amount_cents
                               ELSE 0 END
                      ), 0) AS balance_cents
               FROM ledger_accounts a
               LEFT JOIN ledger_postings p ON p.account_id=a.id
               LEFT JOIN ledger_transactions t ON t.id=p.transaction_id
               GROUP BY a.id
               ORDER BY CASE a.account_type WHEN 'base' THEN 0 ELSE 1 END,
                        a.category_name"""
        ).fetchall()

        accounts = [
            {
                "account_number": row["account_number"],
                "type": row["account_type"],
                "category": row["category_name"],
                "status": row["status"],
                "release_at": row["release_at"],
                "balance_cents": row["balance_cents"],
            }
            for row in rows
        ]

        tx_rows = con.execute(
            """SELECT id, reference, kind, description, posted_at
               FROM ledger_transactions
               WHERE status='posted'
               ORDER BY id DESC LIMIT 50"""
        ).fetchall()

        transactions = []
        for tx in tx_rows:
            postings = con.execute(
                """SELECT a.account_number, a.account_type,
                          a.category_name, p.side, p.amount_cents
                   FROM ledger_postings p
                   JOIN ledger_accounts a ON a.id=p.account_id
                   WHERE p.transaction_id=?
                   ORDER BY p.id""",
                (tx["id"],)
            ).fetchall()

            transactions.append({
                "reference": tx["reference"],
                "kind": tx["kind"],
                "description": tx["description"],
                "posted_at": tx["posted_at"],
                "postings": [
                    {
                        "account_number": p["account_number"],
                        "account_type": p["account_type"],
                        "category": p["category_name"],
                        "side": p["side"],
                        "amount_cents": p["amount_cents"],
                    }
                    for p in postings
                ],
            })

    return {
        "ok": True,
        "identity_status": identity["status"] if identity else "unknown",
        "accounts": accounts,
        "recent_posted_transactions": transactions,
        "real_transfers_enabled": False,
    }


@app.post("/api/category-accounts/close")
async def close_category_account(request: Request):
    user_id = request.state.user["id"]

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body.")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON object required.")

    number = payload.get("account_number")
    if not isinstance(number, str) or not number.strip():
        raise HTTPException(status_code=400, detail="Category account number is required.")
    number = number.strip()

    with auth_connect() as auth:
        registry = auth.execute(
            """SELECT account_type, status FROM account_registry
               WHERE account_number=? AND user_id=?""",
            (number, user_id)
        ).fetchone()

    if not registry or registry["account_type"] != "category":
        raise HTTPException(status_code=404, detail="Category account not found.")
    if registry["status"] == "closed":
        with connect() as con:
            local = con.execute(
                """SELECT status FROM ledger_accounts
                   WHERE account_number=? AND account_type='category'""",
                (number,)
            ).fetchone()
        if local and local["status"] == "closed":
            return {"ok": True, "status": "closed", "balance_cents": 0}
        raise HTTPException(
            status_code=409,
            detail="Registry and ledger disagree; reconciliation is required."
        )
    if registry["status"] not in ("active", "closing"):
        raise HTTPException(status_code=409, detail="Category account is not active.")

    with connect() as con:
        con.execute("BEGIN IMMEDIATE")

        identity = con.execute(
            "SELECT status FROM identity_verification WHERE id=1"
        ).fetchone()
        if not identity or identity["status"] != "verified":
            raise HTTPException(status_code=403, detail="Identity verification is required.")

        category = con.execute(
            """SELECT id, status FROM ledger_accounts
               WHERE account_number=? AND account_type='category'""",
            (number,)
        ).fetchone()
        base = con.execute(
            """SELECT id, account_number, status FROM ledger_accounts
               WHERE account_type='base'"""
        ).fetchone()

        if not category:
            raise HTTPException(
                status_code=409,
                detail="Category registry exists but its ledger account is missing."
            )
        if not base or base["status"] != "active":
            raise HTTPException(status_code=409, detail="Active base account is required.")
        if category["status"] == "closed":
            balance = 0
        elif category["status"] != "active":
            raise HTTPException(status_code=409, detail="Category account is not active.")
        else:
            balance = con.execute(
                """SELECT COALESCE(SUM(
                       CASE WHEN p.side='credit' THEN p.amount_cents
                            ELSE -p.amount_cents END
                   ), 0)
                   FROM ledger_postings p
                   JOIN ledger_transactions t ON t.id=p.transaction_id
                   WHERE p.account_id=? AND t.status='posted'""",
                (category["id"],)
            ).fetchone()[0]

            if balance < 0:
                raise HTTPException(
                    status_code=409,
                    detail="Negative category balance; reconciliation is required."
                )

            if balance > 0:
                reference = "PFCLOSE" + uuid4().hex
                cur = con.execute(
                    """INSERT INTO ledger_transactions
                       (reference, kind, status, description, posted_at)
                       VALUES(?, 'category_close', 'posted',
                              'Transfer remaining category balance to base account', ?)""",
                    (reference, utc_now().isoformat())
                )
                tx_id = cur.lastrowid
                con.execute(
                    """INSERT INTO ledger_postings
                       (transaction_id, account_id, side, amount_cents)
                       VALUES(?, ?, 'debit', ?)""",
                    (tx_id, category["id"], balance)
                )
                con.execute(
                    """INSERT INTO ledger_postings
                       (transaction_id, account_id, side, amount_cents)
                       VALUES(?, ?, 'credit', ?)""",
                    (tx_id, base["id"], balance)
                )

                totals = con.execute(
                    """SELECT
                         SUM(CASE WHEN side='debit' THEN amount_cents ELSE 0 END),
                         SUM(CASE WHEN side='credit' THEN amount_cents ELSE 0 END),
                         COUNT(*)
                       FROM ledger_postings WHERE transaction_id=?""",
                    (tx_id,)
                ).fetchone()
                if totals[0] != totals[1] or totals[2] != 2:
                    raise HTTPException(status_code=500, detail="Ledger balance check failed.")

            con.execute(
                """UPDATE ledger_accounts
                   SET status='closed', closed_at=?
                   WHERE id=? AND status='active'""",
                (utc_now().isoformat(), category["id"])
            )

    # Global registry is in a separate database, so this update is not
    # atomic with the local ledger transaction. Retry/reconciliation is needed
    # if the process stops between these commits.
    with auth_connect() as auth:
        auth.execute("BEGIN IMMEDIATE")
        auth.execute(
            """UPDATE account_registry SET status='closed', closed_at=?
               WHERE account_number=? AND user_id=?
                 AND account_type='category'
                 AND status IN ('active','closing')""",
            (utc_now().isoformat(), number, user_id)
        )
        final = auth.execute(
            """SELECT status FROM account_registry
               WHERE account_number=? AND user_id=?""",
            (number, user_id)
        ).fetchone()
        if not final or final["status"] != "closed":
            raise HTTPException(
                status_code=503,
                detail="Ledger category closed, but registry needs reconciliation."
            )

    return {
        "ok": True,
        "status": "closed",
        "transferred_to_base_cents": balance,
        "account_number": number,
        "account_number_reusable": False,
        "real_transfers_enabled": False
    }


@app.get("/api/ledger/integrity")
def ledger_integrity(request: Request):
    user_id = request.state.user["id"]
    issues = []

    with connect() as con:
        # Every posted transaction must have at least two postings,
        # with equal total debits and credits.
        tx_rows = con.execute(
            """SELECT t.id, t.reference,
                      COUNT(p.id) AS posting_count,
                      COALESCE(SUM(CASE WHEN p.side='debit'
                                        THEN p.amount_cents ELSE 0 END), 0) AS debits,
                      COALESCE(SUM(CASE WHEN p.side='credit'
                                        THEN p.amount_cents ELSE 0 END), 0) AS credits
               FROM ledger_transactions t
               LEFT JOIN ledger_postings p ON p.transaction_id=t.id
               WHERE t.status='posted'
               GROUP BY t.id
               HAVING posting_count < 2 OR debits != credits
               ORDER BY t.id"""
        ).fetchall()

        for row in tx_rows:
            issues.append({
                "type": "unbalanced_posted_transaction",
                "reference": row["reference"],
                "posting_count": row["posting_count"],
                "debits_cents": row["debits"],
                "credits_cents": row["credits"],
            })

        # Customer-facing account balances are credits minus debits.
        account_rows = con.execute(
            """SELECT a.account_number, a.account_type, a.category_name,
                      a.status,
                      COALESCE(SUM(
                        CASE WHEN t.status='posted' AND p.side='credit'
                             THEN p.amount_cents
                             WHEN t.status='posted' AND p.side='debit'
                             THEN -p.amount_cents
                             ELSE 0 END
                      ), 0) AS balance_cents
               FROM ledger_accounts a
               LEFT JOIN ledger_postings p ON p.account_id=a.id
               LEFT JOIN ledger_transactions t ON t.id=p.transaction_id
               GROUP BY a.id
               ORDER BY a.id"""
        ).fetchall()

        for row in account_rows:
            if row["balance_cents"] < 0:
                issues.append({
                    "type": "negative_account_balance",
                    "account_number": row["account_number"],
                    "balance_cents": row["balance_cents"],
                })

        local_accounts = [dict(row) for row in account_rows]

    with auth_connect() as auth:
        registry_rows = auth.execute(
            """SELECT account_number, account_type, category_key, status
               FROM account_registry WHERE user_id=?
               ORDER BY account_number""",
            (user_id,)
        ).fetchall()

    registry = {row["account_number"]: dict(row) for row in registry_rows}
    local_by_number = {row["account_number"]: row for row in local_accounts}

    for number, local in local_by_number.items():
        remote = registry.get(number)
        if not remote:
            issues.append({
                "type": "local_account_missing_from_registry",
                "account_number": number,
            })
            continue

        if local["account_type"] != remote["account_type"]:
            issues.append({
                "type": "account_type_mismatch",
                "account_number": number,
            })
        elif local["status"] != remote["status"]:
            # Reserved records are allowed during incomplete account creation;
            # all other status disagreements require reconciliation.
            if remote["status"] != "reserved":
                issues.append({
                    "type": "account_status_mismatch",
                    "account_number": number,
                    "local_status": local["status"],
                    "registry_status": remote["status"],
                })

    for number, remote in registry.items():
        if number not in local_by_number and remote["status"] in ("active", "closing", "closed"):
            issues.append({
                "type": "registry_account_missing_locally",
                "account_number": number,
                "registry_status": remote["status"],
            })

    return {
        "ok": len(issues) == 0,
        "accounts_checked": len(local_accounts),
        "posted_transactions_checked": con.execute(
            "SELECT COUNT(*) FROM ledger_transactions WHERE status='posted'"
        ).fetchone()[0],
        "issues_count": len(issues),
        "issues": issues,
        "read_only": True,
        "real_transfers_enabled": False,
    }


@app.get("/api/me")
def current_user(request: Request):
    user_id = request.state.user["id"]
    with auth_connect() as con:
        row = con.execute(
            "SELECT id,email,full_name,address,phone,profile_picture,handle,created_at FROM users WHERE id=?",
            (user_id,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Account not found")
    result = dict(row)
    result["profile_picture_url"] = "/api/profile-picture" if result.pop("profile_picture", "") else ""
    return result


@app.get("/api/profile-picture")
def get_profile_picture(request: Request):
    user_id = request.state.user["id"]
    with auth_connect() as con:
        row = con.execute("SELECT profile_picture FROM users WHERE id=?", (user_id,)).fetchone()
    extension = row["profile_picture"] if row else ""
    if extension not in {"png", "jpg", "webp"}:
        raise HTTPException(404, "No profile picture set")
    path = PROFILE_DIR / f"{user_id}.{extension}"
    if not path.is_file():
        raise HTTPException(404, "No profile picture set")
    media_type = {"png": "image/png", "jpg": "image/jpeg", "webp": "image/webp"}[extension]
    return FileResponse(path, media_type=media_type, headers={"Cache-Control": "no-store, private"})


@app.post("/api/profile-picture/remove")
def remove_profile_picture(request: Request):
    user_id = request.state.user["id"]
    with auth_connect() as con:
        row = con.execute("SELECT profile_picture FROM users WHERE id=?", (user_id,)).fetchone()
        con.execute("UPDATE users SET profile_picture='' WHERE id=?", (user_id,))
    extension = row["profile_picture"] if row else ""
    if extension in {"png", "jpg", "webp"}:
        try:
            (PROFILE_DIR / f"{user_id}.{extension}").unlink()
        except OSError:
            pass
    request.state.user["profile_picture"] = ""
    return {"ok": True}


@app.put("/api/profile")
def update_profile(data: ProfileIn, request: Request):
    full_name = " ".join(data.full_name.split())
    if len(full_name) < 2:
        raise HTTPException(400, "Enter your name")
    email = valid_email(data.email)
    address = data.address.strip()
    phone = data.phone.strip()
    user_id = request.state.user["id"]
    picture_extension = None
    picture_bytes = None
    if data.profile_picture_data:
        match = re.fullmatch(r"data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)", data.profile_picture_data)
        if not match:
            raise HTTPException(400, "Profile picture must be a PNG, JPEG, or WebP image")
        picture_extension = {"jpeg": "jpg"}.get(match.group(1), match.group(1))
        try:
            picture_bytes = base64.b64decode(match.group(2), validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(400, "Invalid profile picture data")
        if not picture_bytes or len(picture_bytes) > 1_000_000:
            raise HTTPException(400, "Profile picture must be smaller than 1 MB")
        signatures = {
            "png": picture_bytes.startswith(b"\x89PNG\r\n\x1a\n"),
            "jpg": picture_bytes.startswith(b"\xff\xd8\xff"),
            "webp": len(picture_bytes) >= 12 and picture_bytes[:4] == b"RIFF" and picture_bytes[8:12] == b"WEBP",
        }
        if not signatures[picture_extension]:
            raise HTTPException(400, "The uploaded file is not a valid supported image")
    with auth_connect() as con:
        duplicate = con.execute("SELECT 1 FROM users WHERE email=? AND id<>?", (email, user_id)).fetchone()
        if duplicate:
            raise HTTPException(409, "That email address is already used by another account")
        current = con.execute("SELECT profile_picture FROM users WHERE id=?", (user_id,)).fetchone()
        old_extension = current["profile_picture"] if current else ""
        if picture_bytes is not None:
            final_path = PROFILE_DIR / f"{user_id}.{picture_extension}"
            temp_path = PROFILE_DIR / f".{user_id}.upload"
            temp_path.write_bytes(picture_bytes)
            try:
                temp_path.chmod(0o600)
            except OSError:
                pass
            temp_path.replace(final_path)
            try:
                final_path.chmod(0o600)
            except OSError:
                pass
            if old_extension and old_extension != picture_extension:
                try:
                    (PROFILE_DIR / f"{user_id}.{old_extension}").unlink()
                except OSError:
                    pass
            new_extension = picture_extension
        else:
            new_extension = old_extension or ""
        con.execute("UPDATE users SET full_name=?,email=?,address=?,phone=?,profile_picture=? WHERE id=?",
                    (full_name, email, address, phone, new_extension, user_id))
    request.state.user.update({"full_name": full_name, "email": email, "address": address, "phone": phone, "profile_picture": new_extension})
    return {"ok": True, "full_name": full_name, "email": email, "address": address,
            "phone": phone, "profile_picture_url": "/api/profile-picture" if new_extension else ""}


class CategoryCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    color: str = Field(default="#27856B", max_length=20)
    icon: str = Field(default="wallet", max_length=30)
    percentage: int = Field(default=0, ge=0, le=100)


class CategoryUpdateIn(BaseModel):
    name: str = Field(min_length=1, max_length=40)
    color: str = Field(default="#27856B", max_length=20)
    icon: str = Field(default="wallet", max_length=30)
    percentage: int = Field(default=0, ge=0, le=100)


class MovementIn(BaseModel):
    reference: str = Field(min_length=1, max_length=100)
    from_account: str = Field(min_length=1, max_length=40)
    to_account: str = Field(min_length=1, max_length=40)
    amount: Decimal = Field(gt=0, le=100000000)
    kind: str = Field(default="transfer", max_length=20)
    note: str = Field(default="", max_length=200)


class CurrencyIn(BaseModel):
    currency: str = Field(min_length=3, max_length=3)


def pf_categories(con):
    rows = con.execute("""
        SELECT c.name, c.color, c.icon, COALESCE(r.percentage, 0) AS percentage
        FROM user_categories c
        LEFT JOIN rules r ON r.name = c.name
        ORDER BY c.name COLLATE NOCASE
    """).fetchall()
    return [dict(r) for r in rows]


def pf_category_balance_cents(con, name):
    allocated = con.execute("""
        SELECT a.amount FROM allocations a
        JOIN transactions t ON t.reference = a.reference
        WHERE a.category = ? AND t.status = 'confirmed'
    """, (name,)).fetchall()
    spent = con.execute("SELECT amount FROM spending WHERE category = ?", (name,)).fetchall()
    credits = con.execute("""
        SELECT amount FROM account_movements WHERE to_account = ?
    """, (name,)).fetchall()
    debits = con.execute("""
        SELECT amount FROM account_movements WHERE from_account = ?
    """, (name,)).fetchall()
    return (
        sum(money_cents(r["amount"]) for r in allocated)
        - sum(money_cents(r["amount"]) for r in spent)
        + sum(money_cents(r["amount"]) for r in credits)
        - sum(money_cents(r["amount"]) for r in debits)
    )


def pf_base_balance_cents(con):
    income = con.execute(
        "SELECT amount FROM transactions WHERE status = 'confirmed'"
    ).fetchall()
    allocations = con.execute("""
        SELECT a.amount FROM allocations a
        JOIN transactions t ON t.reference = a.reference
        WHERE t.status = 'confirmed'
    """).fetchall()
    credits = con.execute(
        "SELECT amount FROM account_movements WHERE to_account = 'base'"
    ).fetchall()
    debits = con.execute(
        "SELECT amount FROM account_movements WHERE from_account = 'base'"
    ).fetchall()
    return (
        sum(money_cents(r["amount"]) for r in income)
        - sum(money_cents(r["amount"]) for r in allocations)
        + sum(money_cents(r["amount"]) for r in credits)
        - sum(money_cents(r["amount"]) for r in debits)
    )


def pf_validate_account(con, account):
    if account == "base":
        return
    if not con.execute("SELECT 1 FROM user_categories WHERE name = ?", (account,)).fetchone():
        raise HTTPException(404, f"Category '{account}' not found")


@app.get("/categories")
def pf_list_categories():
    with connect() as con:
        cats = pf_categories(con)
        result = []
        for cat in cats:
            balance = pf_category_balance_cents(con, cat["name"])
            cap = con.execute(
                "SELECT monthly_cap FROM category_caps WHERE category = ?",
                (cat["name"],)
            ).fetchone()
            result.append({
                **cat,
                "balance": f"{Decimal(balance) / 100:.2f}",
                "monthly_cap": cap["monthly_cap"] if cap else None,
            })
    return result


@app.post("/categories")
def pf_create_category(data: CategoryCreateIn):
    name = data.name.strip()
    if not name:
        raise HTTPException(400, "Category name cannot be blank")
    with connect() as con:
        if con.execute("SELECT 1 FROM user_categories WHERE name = ?", (name,)).fetchone():
            raise HTTPException(409, "That category already exists")
        current = con.execute("SELECT COALESCE(SUM(percentage), 0) FROM rules").fetchone()[0]
        if current + data.percentage > 100:
            raise HTTPException(400, "Category percentages cannot total more than 100%")
        now = datetime.now(timezone.utc).isoformat()
        con.execute(
            "INSERT INTO user_categories (name, color, icon, created_at) VALUES (?, ?, ?, ?)",
            (name, data.color, data.icon, now)
        )
        con.execute(
            "INSERT INTO rules (name, percentage) VALUES (?, ?)",
            (name, data.percentage)
        )
    return {"created": name, "percentage": data.percentage}


@app.put("/categories/{old_name}")
def pf_update_category(old_name: str, data: CategoryUpdateIn):
    name = data.name.strip()
    if not name:
        raise HTTPException(400, "Category name cannot be blank")
    with connect() as con:
        if not con.execute("SELECT 1 FROM user_categories WHERE name = ?", (old_name,)).fetchone():
            raise HTTPException(404, "Category not found")
        if name != old_name and con.execute(
            "SELECT 1 FROM user_categories WHERE name = ?", (name,)
        ).fetchone():
            raise HTTPException(409, "That category already exists")
        other_percent = con.execute(
            "SELECT COALESCE(SUM(percentage), 0) FROM rules WHERE name != ?",
            (old_name,)
        ).fetchone()[0]
        if other_percent + data.percentage > 100:
            raise HTTPException(400, "Category percentages cannot total more than 100%")
        if name != old_name:
            # Preserve historical references by renaming category labels in all related tables.
            for table, column in [
                ("rules", "name"), ("allocations", "category"),
                ("category_caps", "category"), ("spending", "category"),
                ("user_categories", "name")
            ]:
                con.execute(f"UPDATE {table} SET {column} = ? WHERE {column} = ?", (name, old_name))
            con.execute("UPDATE account_movements SET from_account = ? WHERE from_account = ?", (name, old_name))
            con.execute("UPDATE account_movements SET to_account = ? WHERE to_account = ?", (name, old_name))
        con.execute(
            "UPDATE user_categories SET color = ?, icon = ? WHERE name = ?",
            (data.color, data.icon, name)
        )
        con.execute("UPDATE rules SET percentage = ? WHERE name = ?", (data.percentage, name))
    return {"updated": name, "percentage": data.percentage}


@app.delete("/categories/{name}")
def pf_delete_category(name: str, confirm_funds: bool = False):
    """Delete active category settings while preserving financial history."""
    with connect() as con:
        category = con.execute(
            "SELECT name FROM user_categories WHERE name = ?", (name,)
        ).fetchone()
        if not category:
            raise HTTPException(404, "Category not found")

        balance = pf_category_balance_cents(con, name)
        if balance < 0:
            raise HTTPException(409, "Category has a negative balance. Reconcile its transactions before deleting it.")
        if balance > 0 and not confirm_funds:
            amount = f"{Decimal(balance) / 100:.2f}"
            raise HTTPException(409, f"CONFIRM_FUNDS:{amount}")

        returned_amount = f"{Decimal(balance) / 100:.2f}"
        if balance > 0:
            con.execute(
                """INSERT INTO account_movements
                   (reference, from_account, to_account, amount, kind, note, created_at)
                   VALUES (?, ?, 'base', ?, 'category_delete_return', ?, ?)""",
                (f"PFDEL-{uuid4().hex}", name, returned_amount,
                 f"Remaining funds returned to base before deleting {name}",
                 datetime.now(timezone.utc).isoformat())
            )
        # Preserve allocations, spending, and account movements as audit history.
        con.execute("DELETE FROM user_categories WHERE name = ?", (name,))
        con.execute("DELETE FROM rules WHERE name = ?", (name,))
        con.execute("DELETE FROM category_caps WHERE category = ?", (name,))
    return {"deleted": name, "returned_to_base": returned_amount}


@app.get("/settings")
def pf_get_settings():
    with connect() as con:
        row = con.execute("SELECT value FROM app_settings WHERE key = 'currency'").fetchone()
    return {"currency": row["value"] if row else "KES"}


@app.put("/settings/currency")
def pf_set_currency(data: CurrencyIn):
    currency = data.currency.upper().strip()
    if not currency.isalpha():
        raise HTTPException(400, "Currency must be a 3-letter code, e.g. KES, USD, EUR")
    with connect() as con:
        con.execute("""
            INSERT INTO app_settings (key, value) VALUES ('currency', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """, (currency,))
    return {"currency": currency, "note": "Display preference only; this does not convert existing balances."}


@app.get("/account-balances")
def pf_account_balances():
    with connect() as con:
        currency_row = con.execute("SELECT value FROM app_settings WHERE key = 'currency'").fetchone()
        cats = pf_categories(con)
        base = pf_base_balance_cents(con)
        category_data = [{
            "name": c["name"],
            "balance": f"{Decimal(pf_category_balance_cents(con, c['name'])) / 100:.2f}",
            "percentage": c["percentage"],
            "color": c["color"],
            "icon": c["icon"],
        } for c in cats]
        total_income = con.execute(
            "SELECT amount FROM transactions WHERE status = 'confirmed'"
        ).fetchall()
        total_spent = con.execute("SELECT amount FROM spending").fetchall()
        total_external = sum(money_cents(r["amount"]) for r in total_income) - sum(money_cents(r["amount"]) for r in total_spent)
        # Transfers between internal accounts cancel; only category expenses reduce net funds.
        currency = currency_row["value"] if currency_row else "KES"
    return {
        "currency": currency,
        "base_balance": f"{Decimal(base) / 100:.2f}",
        "categories": category_data,
        "total_funds": f"{Decimal(base + sum(money_cents(c['balance']) for c in category_data)) / 100:.2f}",
        "real_transfers_enabled": False,
    }


@app.post("/movements")
def pf_move_money(data: MovementIn):
    amount = data.amount.quantize(Decimal("0.01"), rounding=ROUND_DOWN)
    cents = money_cents(amount)
    if cents <= 0:
        raise HTTPException(400, "Amount must be at least 0.01")
    if data.from_account == data.to_account:
        raise HTTPException(400, "Choose two different accounts")
    if data.kind not in ("transfer", "expense", "adjustment"):
        raise HTTPException(400, "Invalid movement type")
    with connect() as con:
        con.execute("BEGIN IMMEDIATE")
        pf_validate_account(con, data.from_account)
        pf_validate_account(con, data.to_account)
        if data.from_account == "external":
            raise HTTPException(400, "External cannot be a source account")
        if data.to_account == "external" and data.kind != "expense":
            raise HTTPException(400, "Only expense transactions can go to external")
        if data.kind == "expense" and data.to_account != "external":
            raise HTTPException(400, "Expense destination must be external")
        if data.kind == "transfer" and "external" in (data.from_account, data.to_account):
            raise HTTPException(400, "Transfers must be between your own accounts")
        available = pf_base_balance_cents(con) if data.from_account == "base" else pf_category_balance_cents(con, data.from_account)
        if cents > available:
            raise HTTPException(400, f"Insufficient funds. Available: {Decimal(max(available, 0)) / 100:.2f}")
        try:
            con.execute("""
                INSERT INTO account_movements
                (reference, from_account, to_account, amount, kind, note, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                data.reference, data.from_account, data.to_account, f"{amount:.2f}",
                data.kind, data.note.strip(), datetime.now(timezone.utc).isoformat()
            ))
        except sqlite3.IntegrityError:
            raise HTTPException(409, "That transaction reference already exists")
    return {
        "reference": data.reference,
        "from_account": data.from_account,
        "to_account": data.to_account,
        "amount": f"{amount:.2f}",
        "kind": data.kind,
        "status": "recorded_locally",
        "real_transfers_enabled": False,
    }


@app.get("/category-transactions/{name}")
def pf_category_transactions(name: str):
    with connect() as con:
        pf_validate_account(con, name)
        movements = con.execute("""
            SELECT reference, from_account, to_account, amount, kind, note, created_at
            FROM account_movements
            WHERE from_account = ? OR to_account = ?
            ORDER BY created_at DESC
        """, (name, name)).fetchall()
        allocations = con.execute("""
            SELECT t.reference, a.amount, t.created_at, t.source
            FROM allocations a JOIN transactions t ON t.reference = a.reference
            WHERE a.category = ? ORDER BY t.created_at DESC
        """, (name,)).fetchall()
        spending = con.execute("""
            SELECT reference, amount, created_at FROM spending
            WHERE category = ? ORDER BY created_at DESC
        """, (name,)).fetchall()
    rows = []
    for r in movements:
        rows.append({
            "reference": r["reference"], "amount": r["amount"],
            "created_at": r["created_at"], "kind": r["kind"], "note": r["note"],
            "direction": "in" if r["to_account"] == name else "out",
            "from_account": r["from_account"], "to_account": r["to_account"],
        })
    for r in allocations:
        rows.append({
            "reference": r["reference"], "amount": r["amount"],
            "created_at": r["created_at"], "kind": "allocation", "note": f"Incoming allocation from {r['source']}",
            "direction": "in", "from_account": "income", "to_account": name,
        })
    for r in spending:
        rows.append({
            "reference": r["reference"], "amount": r["amount"],
            "created_at": r["created_at"], "kind": "expense", "note": "Recorded category spending",
            "direction": "out", "from_account": name, "to_account": "external",
        })
    return sorted(rows, key=lambda x: x["created_at"], reverse=True)


@app.get("/all-movements")
def pf_all_movements():
    with connect() as con:
        rows = con.execute("""
            SELECT reference, from_account, to_account, amount, kind, note, created_at
            FROM account_movements ORDER BY created_at DESC LIMIT 200
        """).fetchall()
    return [dict(r) for r in rows]

