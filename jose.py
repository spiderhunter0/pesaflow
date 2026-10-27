
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sqlite3
from decimal import Decimal, ROUND_DOWN
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote

DB = "finance.db"

def init_db():
    with sqlite3.connect(DB) as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                reference TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                amount TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                name TEXT PRIMARY KEY,
                percentage INTEGER NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS allocations (
                reference TEXT NOT NULL,
                category TEXT NOT NULL,
                amount TEXT NOT NULL,
                PRIMARY KEY (reference, category)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS mpesa_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                external_id TEXT NOT NULL,
                result_code TEXT,
                amount TEXT,
                reference TEXT,
                received_at TEXT NOT NULL,
                UNIQUE(event_type, external_id)
            )
        """)

def send(handler, status, data):
    body = json.dumps(data, indent=2).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)

class App(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/dashboard", "/dashboard.html"):
            try:
                body = open("dashboard.html", "rb").read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except OSError:
                self.send_error(500, "Dashboard file not found")
            return
        path = urlparse(self.path).path

        with sqlite3.connect(DB) as c:
            c.row_factory = sqlite3.Row

            if path == "/":
                result = {
                    "app": "Finance Manager",
                    "mode": "local testing",
                    "real_transfers_enabled": False
                }

            elif path == "/rules":
                result = dict(c.execute(
                    "SELECT name, percentage FROM rules"
                ).fetchall())

            elif path == "/transactions":
                result = [dict(r) for r in c.execute(
                    "SELECT * FROM transactions ORDER BY created_at DESC"
                ).fetchall()]

            elif path == "/allocations":
                result = [dict(r) for r in c.execute(
                    "SELECT * FROM allocations"
                ).fetchall()]

            elif path == "/mpesa/events":
                result = [dict(r) for r in c.execute(
                    "SELECT * FROM mpesa_events ORDER BY id DESC LIMIT 100"
                ).fetchall()]

            elif path == "/balances":
                income = sum(
                    (Decimal(r[0]) for r in c.execute(
                        "SELECT amount FROM transactions "
                        "WHERE status='confirmed'"
                    )),
                    Decimal("0")
                )
                rows = c.execute(
                    "SELECT category, SUM(CAST(amount AS REAL)) "
                    "FROM allocations GROUP BY category"
                ).fetchall()
                allocated = {
                    r[0]: round(r[1], 2) for r in rows
                }
                result = {
                    "verified_test_income": str(income),
                    "planned_allocations": allocated,
                    "currency": "KES",
                    "live_bank_balance": False
                }

            else:
                return send(self, 404, {"error": "Not found"})

        send(self, 200, result)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 10000:
                return send(self, 413, {"error": "Request too large"})
            data = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return send(self, 400, {"error": "Invalid JSON"})

        if path in ("/mpesa/stk/callback",
                    "/mpesa/c2b/confirmation"):
            if not isinstance(data, dict):
                return send(self, 400, {"error": "Invalid callback"})

            event_type = "stk" if path == "/mpesa/stk/callback" else "c2b"
            external_id = ""
            result_code = None
            amount = None
            reference = None

            if event_type == "stk":
                body = data.get("Body", {})
                cb = body.get("stkCallback", {}) if isinstance(body, dict) else {}
                if not isinstance(cb, dict):
                    return send(self, 400, {"error": "Invalid STK callback"})
                external_id = str(cb.get("CheckoutRequestID", ""))
                result_code = cb.get("ResultCode")
                if result_code is not None:
                    result_code = str(result_code)
                reference = external_id

                metadata = cb.get("CallbackMetadata", {})
                items = metadata.get("Item", []) if isinstance(metadata, dict) else []
                if isinstance(items, list):
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        if item.get("Name") == "Amount":
                            amount = item.get("Value")
                        elif item.get("Name") == "MpesaReceiptNumber":
                            reference = str(item.get("Value", "")) or reference

            else:
                external_id = str(data.get("TransID", ""))
                amount = data.get("TransAmount")
                reference = str(data.get("BillRefNumber", ""))

            if not external_id or len(external_id) > 200:
                return send(self, 400, {"error": "Missing callback transaction ID"})

            if amount is not None:
                try:
                    amount = Decimal(str(amount))
                    if not amount.is_finite() or amount <= 0:
                        raise ValueError()
                    amount = str(amount.quantize(Decimal("0.01")))
                except (ValueError, ArithmeticError):
                    return send(self, 400, {"error": "Invalid callback amount"})

            with sqlite3.connect(DB) as c:
                cur = c.execute("""
                    INSERT OR IGNORE INTO mpesa_events
                    (event_type, external_id, result_code, amount,
                     reference, received_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    event_type, external_id, result_code,
                    amount, reference,
                    datetime.now(timezone.utc).isoformat()
                ))

            return send(self, 200, {
                "ResultCode": 0,
                "ResultDesc": "Callback received in local test inbox",
                "recorded": cur.rowcount == 1,
                "test_mode": True,
                "payment_confirmed": False
            })

        if path == "/transactions":
            ref = str(data.get("reference", ""))
            source = data.get("source", "manual_test")
            status = data.get("status", "pending")
            try:
                amount = Decimal(str(data["amount"]))
            except (KeyError, ValueError, ArithmeticError):
                return send(self, 400, {"error": "Invalid amount"})

            if (not ref or len(ref) > 100 or
                source not in ("manual_test", "mpesa_sandbox", "kcb_sandbox") or
                status not in ("pending", "confirmed") or
                not amount.is_finite() or amount <= 0 or
                amount > Decimal("100000000")):
                return send(self, 400, {"error": "Invalid transaction data"})

            amount = amount.quantize(Decimal("0.01"))
            with sqlite3.connect(DB) as c:
                try:
                    c.execute(
                        "INSERT INTO transactions VALUES (?, ?, ?, ?, ?)",
                        (ref, source, str(amount), status,
                         datetime.now(timezone.utc).isoformat())
                    )
                except sqlite3.IntegrityError:
                    return send(self, 409, {"error": "Duplicate reference"})

            return send(self, 201, {"reference": ref, "status": status})

        if path == "/rules":
            rules = data.get("percentages", {})
            if (not isinstance(rules, dict) or len(rules) > 20 or
                any(not isinstance(k, str) or not k.strip() or len(k.strip()) > 40
                    for k in rules) or
                any(type(v) is not int or not 0 <= v <= 100
                    for v in rules.values()) or sum(rules.values()) > 100):
                return send(self, 400, {
                    "error": "Use up to 20 named categories with whole percentages totaling no more than 100"
                })

            rules = {k.strip(): v for k, v in rules.items()}
            if len(rules) != len(set(rules)):
                return send(self, 400, {"error": "Category names must be unique"})

            with sqlite3.connect(DB) as c:
                c.execute("DELETE FROM rules")
                c.executemany("INSERT INTO rules VALUES (?, ?)", rules.items())
            return send(self, 200, {
                "saved": rules,
                "unallocated_percentage": 100 - sum(rules.values())
            })

        if path.startswith("/allocate/"):
            ref = unquote(path[len("/allocate/"):])
            with sqlite3.connect(DB) as c:
                tx = c.execute(
                    "SELECT amount, status FROM transactions WHERE reference=?",
                    (ref,)
                ).fetchone()
                if not tx:
                    return send(self, 404, {"error": "Transaction not found"})
                if tx[1] != "confirmed":
                    return send(self, 400, {"error": "Transaction not confirmed"})
                if c.execute(
                    "SELECT 1 FROM allocations WHERE reference=?", (ref,)
                ).fetchone():
                    return send(self, 409, {"error": "Already allocated"})

                rules = c.execute(
                    "SELECT name, percentage FROM rules ORDER BY name"
                ).fetchall()
                cents = int(Decimal(tx[0]) * 100)
                used = 0
                results = []
                for name, pct in rules:
                    part = cents * pct // 100
                    used += part
                    value = Decimal(part) / 100
                    c.execute(
                        "INSERT INTO allocations VALUES (?, ?, ?)",
                        (ref, name, str(value))
                    )
                    results.append({
                        "category": name,
                        "amount": str(value),
                        "status": "planned_only"
                    })
            return send(self, 200, {"reference": ref, "allocations": results})

        send(self, 404, {"error": "Not found"})

    def log_message(self, format, *args):
        print(*args)

init_db()
print("Finance app running at http://127.0.0.1:8000")
HTTPServer(("127.0.0.1", 8000), App).serve_forever()

