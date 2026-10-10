"""
Harbor Admin: a single-file FastAPI + SQLite admin dashboard.

SETUP
  pip install fastapi "uvicorn[standard]"
  # optional configuration (see bottom of the run instructions):
  #   ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_NAME, SESSION_SECRET,
  #   COOKIE_SECURE=1 (when served over HTTPS), DB_PATH, HOST, PORT
  python main.py            # or: uvicorn main:app --reload

SECURITY NOTES
  * Passwords are hashed with scrypt (standard library, salted).
  * Sessions are server-side (SQLite). The browser only holds a random token in an
    HttpOnly, SameSite=Lax cookie; the DB stores an HMAC of it keyed by SESSION_SECRET.
  * State-changing requests need an X-CSRF-Token header that matches the session.
  * All /api/* data routes require an authenticated account with the "admin" role.
  * This is a solid starting point, not a certified production setup. Before going live:
    set SESSION_SECRET, change the demo admin password, serve over HTTPS with
    COOKIE_SECURE=1, and put the app behind a reverse proxy with rate limiting.
"""
import csv
import hashlib
import hmac
import io
import os
import random
import re
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "dashboard.db"))
ADMIN_NAME = os.environ.get("ADMIN_NAME", "Demo Admin")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com").strip().lower()
DEFAULT_ADMIN_PASSWORD = "ChangeMe123!"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
SECRET_FROM_ENV = bool(SESSION_SECRET)
if not SESSION_SECRET:
    SESSION_SECRET = secrets.token_hex(32)  # sessions then reset on each restart
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
COOKIE_NAME = "harbor_session"
SESSION_TTL = 8 * 3600
ROLES = ("Admin", "Editor", "User")
STATUSES = ("Active", "Inactive", "Pending")
SORT_COLUMNS = {
    "name": "full_name COLLATE NOCASE",
    "email": "email COLLATE NOCASE",
    "role": "role",
    "status": "status",
    "created": "created_at",
    "revenue": "revenue",
}
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_login_attempts = {}  # ip -> [timestamps]; simple in-memory brute-force throttle
# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #
@contextmanager
def db():
    """One short-lived connection per call; commits on success, rolls back on error."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def utc_today():
    return datetime.now(timezone.utc).date()


def now_ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log_activity(conn, actor, action, detail):
    conn.execute(
        "INSERT INTO activity(actor, action, detail, created_at) VALUES (?,?,?,?)",
        (actor, action, detail, now_ts()),
    )


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password, stored):
    try:
        _, salt_hex, digest_hex = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc.hex(), digest_hex)
    except Exception:
        return False


DUMMY_HASH = hash_password("not-a-real-password")  # keeps login timing similar for unknown emails


def init_db():
    """Create tables, the initial admin and sample data (sample data only once)."""
    with db() as conn:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS admins(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin'
            );
            CREATE TABLE IF NOT EXISTS sessions(
                token_hash TEXT PRIMARY KEY,
                admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
                csrf TEXT NOT NULL,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                role TEXT NOT NULL CHECK(role IN ('Admin','Editor','User')),
                status TEXT NOT NULL CHECK(status IN ('Active','Inactive','Pending')),
                revenue REAL NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_users_created ON users(created_at);
            CREATE TABLE IF NOT EXISTS activity(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
            """
        )
        if not conn.execute("SELECT 1 FROM admins LIMIT 1").fetchone():
            conn.execute(
                "INSERT INTO admins(name,email,password_hash,role) VALUES (?,?,?, 'admin')",
                (ADMIN_NAME, ADMIN_EMAIL, hash_password(ADMIN_PASSWORD)),
            )
            log_activity(conn, "System", "system", f"Administrator account created for {ADMIN_EMAIL}")
        if not conn.execute("SELECT 1 FROM meta WHERE key='seeded'").fetchone():
            seed_users(conn)
            conn.execute("INSERT INTO meta(key,value) VALUES('seeded','1')")
    if ADMIN_PASSWORD == DEFAULT_ADMIN_PASSWORD:
        print("[harbor] WARNING: using the default demo admin password. Set ADMIN_PASSWORD before first run.")
    if not SECRET_FROM_ENV:
        print("[harbor] NOTE: SESSION_SECRET not set; a temporary secret is used and logins reset on restart.")


def seed_users(conn):
    rng = random.Random(2024)
    first = ["Amara", "Liam", "Sofia", "Noah", "Priya", "Mateo", "Hana", "Omar",
             "Elena", "Kofi", "Yuki", "Lucas", "Zara", "Ivan", "Nadia", "Theo"]
    last = ["Okafor", "Bennett", "Rossi", "Nguyen", "Patel", "Alvarez", "Sato", "Haddad",
            "Petrova", "Mensah", "Tanaka", "Schmidt", "Khan", "Novak", "Silva", "Murphy"]
    domains = ["northfield.io", "brightpath.co", "lumenlabs.com", "cedarworks.net", "gmail.com", "outlook.com"]
    pairs = rng.sample([(f, l) for f in first for l in last], 48)
    today = utc_today()
    rows = []
    for i, (f, l) in enumerate(pairs):
        role = "Admin" if i < 3 else rng.choices(ROLES, [0, 3, 12])[0]
        status = rng.choices(STATUSES, [68, 14, 18])[0]
        revenue = {"Active": round(rng.uniform(150, 4200), 2),
                   "Inactive": round(rng.uniform(0, 900), 2), "Pending": 0}[status]
        created = (today - timedelta(days=int((rng.random() ** 1.6) * 350) + 1)).isoformat()
        rows.append((f"{f} {l}", f"{f}.{l}@{rng.choice(domains)}".lower(), role, status, revenue, created))
    conn.executemany(
        "INSERT INTO users(full_name,email,role,status,revenue,created_at) VALUES (?,?,?,?,?,?)", rows)
    log_activity(conn, "System", "system", f"Loaded {len(rows)} sample users")
    # --------------------------------------------------------------------------- #
# App, errors and security headers
# --------------------------------------------------------------------------- #
class ApiError(Exception):
    def __init__(self, status, message, fields=None):
        self.status, self.message, self.fields = status, message, fields or {}


@asynccontextmanager
async def lifespan(_app):
    init_db()
    yield


app = FastAPI(title="Harbor Admin", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


@app.exception_handler(ApiError)
async def handle_api_error(_request, exc):
    return JSONResponse({"error": exc.message, "fields": exc.fields}, status_code=exc.status)


@app.exception_handler(StarletteHTTPException)
async def handle_http_error(_request, exc):
    return JSONResponse({"error": str(exc.detail)}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def handle_validation_error(_request, _exc):
    return JSONResponse({"error": "Invalid request. Check the values you sent."}, status_code=422)


@app.exception_handler(sqlite3.Error)
async def handle_db_error(_request, exc):
    print("[harbor] database error:", exc)
    return JSONResponse({"error": "A database error occurred. Please try again."}, status_code=500)


@app.exception_handler(Exception)
async def handle_unexpected(_request, exc):
    print("[harbor] unexpected error:", repr(exc))
    return JSONResponse({"error": "Something went wrong on the server."}, status_code=500)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# --------------------------------------------------------------------------- #
# Authentication and authorization
# --------------------------------------------------------------------------- #
def token_hash(token):
    return hmac.new(SESSION_SECRET.encode(), token.encode(), hashlib.sha256).hexdigest()


def current_session(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    with db() as conn:
        row = conn.execute(
            "SELECT s.csrf, s.expires_at, a.id, a.email, a.name, a.role FROM sessions s "
            "JOIN admins a ON a.id = s.admin_id WHERE s.token_hash = ?",
            (token_hash(token),),
        ).fetchone()
        if not row:
            return None
        if row["expires_at"] < time.time():
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
            return None
    return dict(row)


def require_admin(request: Request):
    session = current_session(request)
    if not session:
        raise HTTPException(401, "Please sign in to continue.")
    if session["role"] != "admin":
        raise HTTPException(403, "Administrator privileges are required.")
    return session


def require_admin_write(request: Request, admin=Depends(require_admin)):
    sent = request.headers.get("x-csrf-token", "")
    if not hmac.compare_digest(sent, admin["csrf"]):
        raise HTTPException(403, "Invalid or missing CSRF token. Reload the page and try again.")
    return admin


@app.post("/api/login")
def login(request: Request, response: Response, payload: dict = Body(...)):
    ip = request.client.host if request.client else "unknown"
    recent = [t for t in _login_attempts.get(ip, []) if time.time() - t < 300]
    _login_attempts[ip] = recent
    if len(recent) >= 5:
        raise ApiError(429, "Too many failed attempts. Try again in a few minutes.")
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))
    if not email or not password:
        raise ApiError(400, "Enter your email and password.")
    with db() as conn:
        admin = conn.execute("SELECT * FROM admins WHERE email = ?", (email,)).fetchone()
        ok = verify_password(password, admin["password_hash"] if admin else DUMMY_HASH)
        if not admin or not ok or admin["role"] != "admin":
            _login_attempts[ip].append(time.time())
            raise ApiError(401, "Incorrect email or password.")
        _login_attempts.pop(ip, None)
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
        conn.execute(
            "INSERT INTO sessions(token_hash, admin_id, csrf, expires_at) VALUES (?,?,?,?)",
            (token_hash(token), admin["id"], csrf, time.time() + SESSION_TTL),
        )
        log_activity(conn, admin["name"], "login", "Signed in")
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_TTL, httponly=True,
                        samesite="lax", secure=COOKIE_SECURE, path="/")
    return {"ok": True}


@app.post("/api/logout")
def logout(request: Request, response: Response, admin=Depends(require_admin_write)):
    token = request.cookies.get(COOKIE_NAME, "")
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))
        log_activity(conn, admin["name"], "logout", "Signed out")
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(admin=Depends(require_admin)):
    return {"name": admin["name"], "email": admin["email"], "role": admin["role"], "csrf": admin["csrf"]}
    # --------------------------------------------------------------------------- #
# Users: validation and query building
# --------------------------------------------------------------------------- #
def pick(value, allowed, label):
    for item in allowed:
        if str(value).strip().lower() == item.lower():
            return item
    raise ApiError(400, f"Invalid {label}.")


def validate_user(data, conn, exclude_id=None):
    if not isinstance(data, dict):
        raise ApiError(400, "Request body must be a JSON object.")
    errors = {}
    name = str(data.get("full_name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    role = str(data.get("role", "")).strip().title()
    status = str(data.get("status", "")).strip().title()
    raw_rev = data.get("revenue", 0)
    revenue = 0.0
    if len(name) < 2 or len(name) > 80:
        errors["full_name"] = "Enter a full name between 2 and 80 characters."
    if not email:
        errors["email"] = "Email is required."
    elif len(email) > 254 or not EMAIL_RE.match(email):
        errors["email"] = "Enter a valid email address."
    else:
        dup = conn.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, exclude_id or -1)).fetchone()
        if dup:
            errors["email"] = "Another user already has this email."
    if role not in ROLES:
        errors["role"] = "Choose Admin, Editor or User."
    if status not in STATUSES:
        errors["status"] = "Choose Active, Inactive or Pending."
    try:
        if isinstance(raw_rev, bool):
            raise ValueError
        revenue = round(float(raw_rev if raw_rev not in ("", None) else 0), 2)
        if revenue < 0 or revenue > 10_000_000:
            raise ValueError
    except (TypeError, ValueError):
        errors["revenue"] = "Revenue must be a number between 0 and 10,000,000."
    if errors:
        raise ApiError(422, "Please fix the highlighted fields.", errors)
    return {"full_name": name, "email": email, "role": role, "status": status, "revenue": revenue}


def like_escape(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build_query(q, status, role, date_from, date_to, sort, order):
    where, params = [], []
    q = q.strip()[:100]
    if q:
        like = f"%{like_escape(q)}%"
        where.append("(full_name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' OR role LIKE ? ESCAPE '\\')")
        params += [like, like, like]
    if status and status.lower() != "all":
        where.append("status = ?")
        params.append(pick(status, STATUSES, "status filter"))
    if role and role.lower() != "all":
        where.append("role = ?")
        params.append(pick(role, ROLES, "role filter"))
    for value, op, label in ((date_from, ">=", "start date"), (date_to, "<=", "end date")):
        if value:
            if not DATE_RE.match(value):
                raise ApiError(400, f"Invalid {label}. Use YYYY-MM-DD.")
            where.append(f"created_at {op} ?")
            params.append(value)
    if sort not in SORT_COLUMNS:  # whitelist: never interpolate user input into ORDER BY
        raise ApiError(400, "Invalid sort column.")
    if order.lower() not in ("asc", "desc"):
        raise ApiError(400, "Invalid sort order.")
    direction = order.upper()
    order_sql = f"ORDER BY {SORT_COLUMNS[sort]} {direction}, id {direction}"
    return (" WHERE " + " AND ".join(where)) if where else "", params, order_sql


def user_dict(row):
    return {k: row[k] for k in ("id", "full_name", "email", "role", "status", "revenue", "created_at")}


@app.get("/api/users")
def list_users(q: str = "", status: str = "", role: str = "", date_from: str = "", date_to: str = "",
               sort: str = "created", order: str = "desc", page: int = Query(1, ge=1),
               page_size: int = Query(10, ge=1, le=100), admin=Depends(require_admin)):
    where, params, order_sql = build_query(q, status, role, date_from, date_to, sort, order)
    with db() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM users{where}", params).fetchone()[0]
        pages = max(1, -(-total // page_size))
        page = min(page, pages)
        rows = conn.execute(
            f"SELECT * FROM users{where} {order_sql} LIMIT ? OFFSET ?",
            params + [page_size, (page - 1) * page_size],
        ).fetchall()
    return {"items": [user_dict(r) for r in rows], "total": total, "page": page,
            "page_size": page_size, "pages": pages}


def csv_safe(value):
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text  # block formula injection


@app.get("/api/users/export")
def export_users(q: str = "", status: str = "", role: str = "", date_from: str = "", date_to: str = "",
                 sort: str = "created", order: str = "desc", admin=Depends(require_admin)):
    where, params, order_sql = build_query(q, status, role, date_from, date_to, sort, order)
    with db() as conn:
        rows = conn.execute(f"SELECT * FROM users{where} {order_sql}", params).fetchall()
        log_activity(conn, admin["name"], "export", f"Exported {len(rows)} users to CSV")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "Full name", "Email", "Role", "Status", "Revenue", "Registered"])
    for r in rows:
        writer.writerow([r["id"], csv_safe(r["full_name"]), csv_safe(r["email"]), r["role"],
                         r["status"], f"{r['revenue']:.2f}", r["created_at"]])
    return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="users.csv"'})


@app.post("/api/users/bulk-delete")
def bulk_delete(payload: dict = Body(...), admin=Depends(require_admin_write)):
    ids = payload.get("ids")
    if (not isinstance(ids, list) or not ids or len(ids) > 500
            or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids)):
        raise ApiError(400, "Provide between 1 and 500 user IDs.")
    marks = ",".join("?" * len(ids))
    with db() as conn:
        deleted = conn.execute(f"DELETE FROM users WHERE id IN ({marks})", ids).rowcount
        log_activity(conn, admin["name"], "delete", f"Deleted {deleted} selected users")
    return {"deleted": deleted}


@app.post("/api/users", status_code=201)
def create_user(payload: dict = Body(...), admin=Depends(require_admin_write)):
    try:
        with db() as conn:
            clean = validate_user(payload, conn)
            cur = conn.execute(
                "INSERT INTO users(full_name,email,role,status,revenue,created_at) VALUES (?,?,?,?,?,?)",
                (clean["full_name"], clean["email"], clean["role"], clean["status"], clean["revenue"],
                 utc_today().isoformat()),
            )
            log_activity(conn, admin["name"], "create", f"Added {clean['full_name']} ({clean['role']})")
            row = conn.execute("SELECT * FROM users WHERE id = ?", (cur.lastrowid,)).fetchone()
    except sqlite3.IntegrityError:
        raise ApiError(409, "Another user already has this email.", {"email": "Another user already has this email."})
    return user_dict(row)


@app.get("/api/users/{user_id}")
def get_user(user_id: int, admin=Depends(require_admin)):
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise ApiError(404, "User not found.")
    return user_dict(row)


@app.put("/api/users/{user_id}")
def update_user(user_id: int, payload: dict = Body(...), admin=Depends(require_admin_write)):
    try:
        with db() as conn:
            if not conn.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone():
                raise ApiError(404, "User not found.")
            clean = validate_user(payload, conn, exclude_id=user_id)
            conn.execute(
                "UPDATE users SET full_name=?, email=?, role=?, status=?, revenue=? WHERE id=?",
                (clean["full_name"], clean["email"], clean["role"], clean["status"], clean["revenue"], user_id),
            )
            log_activity(conn, admin["name"], "update", f"Updated {clean['full_name']}")
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    except sqlite3.IntegrityError:
        raise ApiError(409, "Another user already has this email.", {"email": "Another user already has this email."})
    return user_dict(row)


@app.patch("/api/users/{user_id}/status")
def set_status(user_id: int, payload: dict = Body(...), admin=Depends(require_admin_write)):
    status = pick(payload.get("status", ""), STATUSES, "status")
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise ApiError(404, "User not found.")
        conn.execute("UPDATE users SET status = ? WHERE id = ?", (status, user_id))
        log_activity(conn, admin["name"], "status", f"Set {row['full_name']} to {status}")
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return user_dict(row)


@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, admin=Depends(require_admin_write)):
    with db() as conn:
        row = conn.execute("SELECT full_name FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise ApiError(404, "User not found.")
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        log_activity(conn, admin["name"], "delete", f"Deleted {row['full_name']}")
    return {"deleted": 1}
# --------------------------------------------------------------------------- #
# Stats, charts, activity, notifications
# --------------------------------------------------------------------------- #
@app.get("/api/stats")
def stats(admin=Depends(require_admin)):
    today = utc_today()
    d30, d60 = (today - timedelta(days=30)).isoformat(), (today - timedelta(days=60)).isoformat()

    def metric(conn, cond, params, expr="COUNT(*)"):
        base = f"SELECT {expr} FROM users WHERE {cond}"
        value = conn.execute(base, params).fetchone()[0] or 0
        cur = conn.execute(base + " AND created_at > ?", [*params, d30]).fetchone()[0] or 0
        prev = conn.execute(base + " AND created_at > ? AND created_at <= ?", [*params, d60, d30]).fetchone()[0] or 0
        return {"value": value, "current": cur, "previous": prev}

    with db() as conn:
        return {
            "total": metric(conn, "1=1", []),
            "active": metric(conn, "status = ?", ["Active"]),
            "pending": metric(conn, "status = ?", ["Pending"]),
            "revenue": metric(conn, "1=1", [], "SUM(revenue)"),
        }


def last_months(n=12):
    year, month = utc_today().year, utc_today().month
    out = []
    for _ in range(n):
        out.append(f"{year:04d}-{month:02d}")
        month -= 1
        if month == 0:
            year, month = year - 1, 12
    return out[::-1]


@app.get("/api/charts")
def charts(admin=Depends(require_admin)):
    months = last_months(12)
    with db() as conn:
        new_by_month = dict(conn.execute(
            "SELECT substr(created_at,1,7), COUNT(*) FROM users GROUP BY 1").fetchall())
        rev_by_month = dict(conn.execute(
            "SELECT substr(created_at,1,7), SUM(revenue) FROM users GROUP BY 1").fetchall())
        before = conn.execute("SELECT COUNT(*) FROM users WHERE substr(created_at,1,7) < ?", (months[0],)).fetchone()[0]
        statuses = dict(conn.execute("SELECT status, COUNT(*) FROM users GROUP BY status").fetchall())
        roles = dict(conn.execute("SELECT role, COUNT(*) FROM users GROUP BY role").fetchall())
    cumulative, running = [], before
    for m in months:
        running += new_by_month.get(m, 0)
        cumulative.append(running)
    return {
        "months": months,
        "growth": {"total": cumulative, "new": [new_by_month.get(m, 0) for m in months]},
        "revenue": [round(rev_by_month.get(m) or 0, 2) for m in months],
        "status": {s: statuses.get(s, 0) for s in STATUSES},
        "roles": {r: roles.get(r, 0) for r in ROLES},
    }


@app.get("/api/activity")
def activity(limit: int = Query(20, ge=1, le=100), admin=Depends(require_admin)):
    with db() as conn:
        rows = conn.execute("SELECT actor, action, detail, created_at FROM activity ORDER BY id DESC LIMIT ?",
                            (limit,)).fetchall()
    return {"items": [dict(r) for r in rows]}


@app.get("/api/notifications")
def notifications(admin=Depends(require_admin)):
    with db() as conn:
        pending = conn.execute("SELECT COUNT(*) FROM users WHERE status = 'Pending'").fetchone()[0]
        rows = conn.execute("SELECT actor, action, detail, created_at FROM activity ORDER BY id DESC LIMIT 6").fetchall()
    return {"pending": pending, "items": [dict(r) for r in rows]}


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    session = current_session(request)
    page = DASHBOARD_HTML if session and session["role"] == "admin" else LOGIN_HTML
    return HTMLResponse(page, headers={"Cache-Control": "no-store"})


@app.get("/favicon.ico")
def favicon():
    return Response(status_code=204)
# --------------------------------------------------------------------------- #
# Frontend: shared theme tokens, login page, dashboard (HTML + CSS + JS)
# --------------------------------------------------------------------------- #
THEME_HEAD = r"""<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<script>try{var t=localStorage.getItem('theme')||(matchMedia('(prefers-color-scheme:dark)').matches?'dark':'light');document.documentElement.dataset.theme=t}catch(e){}</script>
<style>
:root{--bg:#f2f5f4;--card:#fff;--ink:#14212b;--muted:#68788a;--line:#e1e8e6;--accent:#12907c;--accent-ink:#fff;--soft:#e3f3f0;--warn:#b7791f;--warnbg:#fbefd5;--bad:#c0392b;--badbg:#fbe3df;--ok:#15803d;--okbg:#dcf3e4;--side:#0f1e2a;--side-ink:#9fb0bd;--shadow:0 1px 2px rgba(16,32,44,.05),0 10px 26px -14px rgba(16,32,44,.22);--r:14px}
[data-theme=dark]{--bg:#0a121a;--card:#111d27;--ink:#e6edf2;--muted:#8a9ba8;--line:#1e2e3a;--accent:#2fc4a8;--accent-ink:#06211c;--soft:#12332f;--warn:#e8b255;--warnbg:#3a2e14;--bad:#f0877b;--badbg:#3b1d1a;--ok:#5fd18a;--okbg:#14301f;--side:#070f16;--shadow:0 1px 2px rgba(0,0,0,.4),0 10px 26px -14px rgba(0,0,0,.7)}
*{box-sizing:border-box}html,body{margin:0}body{font-family:Manrope,system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--ink);font-size:14px;line-height:1.45;overflow-x:hidden;-webkit-font-smoothing:antialiased}
button,input,select{font:inherit;color:inherit}.hidden{display:none!important}
.btn{display:inline-flex;align-items:center;gap:8px;height:38px;padding:0 14px;border-radius:10px;border:1px solid var(--line);background:var(--card);cursor:pointer;font-weight:600;transition:.15s;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent)}.btn.primary{background:linear-gradient(135deg,var(--accent),#0b6b5c);color:#fff;border-color:transparent}.btn.primary:hover{filter:brightness(1.08);color:#fff}
.btn.danger{background:var(--bad);border-color:transparent;color:#fff}.btn.danger:hover{filter:brightness(1.1);color:#fff}.btn:disabled{opacity:.6;cursor:not-allowed}
.btn svg,.icon-btn svg{width:18px;height:18px}
.spin{width:16px;height:16px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;display:inline-block;animation:sp .7s linear infinite}@keyframes sp{to{transform:rotate(360deg)}}
input,select{height:40px;border:1px solid var(--line);background:var(--card);border-radius:10px;padding:0 12px;width:100%;outline:none;transition:.15s}
input:focus,select:focus,.btn:focus-visible,.icon-btn:focus-visible{border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 22%,transparent)}
.field{display:block;margin-bottom:14px}.field>span{display:block;font-weight:600;margin-bottom:6px;font-size:13px}.err{display:block;color:var(--bad);font-style:normal;font-size:12px;min-height:0;margin-top:4px}
.field.bad input,.field.bad select{border-color:var(--bad)}
@media (prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;transition-duration:.01ms!important}}
</style>"""

LOGIN_HTML = r"""<!doctype html><html lang="en"><head><title>Sign in · Harbor Admin</title>__HEAD__
<style>
body{min-height:100vh;display:grid;grid-template-columns:1.05fr 1fr}
.hero{background:radial-gradient(900px 500px at 10% 0%,#17604f 0,transparent 60%),linear-gradient(160deg,#0f1e2a,#0a141d);color:#d6e3ea;padding:56px;display:flex;flex-direction:column;justify-content:space-between}
.brand{display:flex;align-items:center;gap:12px;font-weight:800;font-size:20px;color:#fff}.logo{width:38px;height:38px;border-radius:11px;background:linear-gradient(135deg,#2fc4a8,#0b6b5c);display:grid;place-items:center}.logo svg{width:20px;height:20px;color:#fff}
.hero h1{font-size:38px;line-height:1.15;margin:0 0 14px;max-width:440px;color:#fff;letter-spacing:-.02em}.hero p{max-width:420px;color:#9fb0bd;margin:0}
.panel{display:grid;place-items:center;padding:32px}.card{width:100%;max-width:400px}
.card h2{font-size:26px;margin:0 0 6px;letter-spacing:-.01em}.card .sub{color:var(--muted);margin:0 0 26px}
.pw{position:relative}.pw button{position:absolute;right:4px;top:4px;height:32px;width:36px;border:0;background:transparent;cursor:pointer;color:var(--muted);border-radius:8px}.pw input{padding-right:44px}.pw svg{width:18px;height:18px}
.alert{background:var(--badbg);color:var(--bad);padding:10px 12px;border-radius:10px;margin-bottom:16px;font-weight:600}.btn.primary{width:100%;justify-content:center;height:44px}
@media(max-width:860px){body{grid-template-columns:1fr}.hero{display:none}}
</style></head><body>
<section class="hero"><div class="brand"><span class="logo"><i data-lucide="anchor"></i></span>Harbor</div>
<div><h1>Every account, request and dollar in one place.</h1><p>Review sign-ups, approve pending requests and keep your user base tidy from a single console.</p></div>
<small style="color:#6e8394">Authorized administrators only. Sign-ins are recorded.</small></section>
<section class="panel"><div class="card"><h2>Sign in</h2><p class="sub">Use your administrator account.</p>
<div id="alert" class="alert hidden" role="alert"></div>
<form id="f" novalidate>
<label class="field"><span>Email</span><input id="email" type="email" autocomplete="username" required autofocus></label>
<label class="field"><span>Password</span><div class="pw"><input id="password" type="password" autocomplete="current-password" required><button type="button" id="eye" aria-label="Show password"><i data-lucide="eye"></i></button></div></label>
<button class="btn primary" id="go" type="submit"><span class="spin hidden"></span><span>Sign in</span></button></form></div></section>
<script src="https://unpkg.com/lucide@0.469.0/dist/umd/lucide.min.js"></script>
<script>
if(window.lucide)lucide.createIcons();
const $=s=>document.querySelector(s);
$('#eye').onclick=()=>{const p=$('#password'),show=p.type==='password';p.type=show?'text':'password';$('#eye').innerHTML='<i data-lucide="'+(show?'eye-off':'eye')+'"></i>';if(window.lucide)lucide.createIcons()};
$('#f').addEventListener('submit',async e=>{
  e.preventDefault();const a=$('#alert');a.classList.add('hidden');
  const email=$('#email').value.trim(),password=$('#password').value;
  if(!email||!password){a.textContent='Enter your email and password.';a.classList.remove('hidden');return}
  const btn=$('#go');btn.disabled=true;btn.querySelector('.spin').classList.remove('hidden');
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',body:JSON.stringify({email,password})});
    const d=await r.json().catch(()=>({}));
    if(!r.ok)throw new Error(d.error||'Sign-in failed. Try again.');
    location.reload();
  }catch(err){a.textContent=err.message||'Network error. Check your connection.';a.classList.remove('hidden');btn.disabled=false;btn.querySelector('.spin').classList.add('hidden')}
});
</script></body></html>""".replace("__HEAD__", THEME_HEAD)
DASHBOARD_HTML = r"""<!doctype html><html lang="en"><head><title>Harbor Admin</title>__HEAD__
<style>
.sidebar{width:248px;background:linear-gradient(180deg,var(--side),#0b1822);color:var(--side-ink);position:fixed;inset:0 auto 0 0;display:flex;flex-direction:column;padding:18px 14px;transition:width .25s,transform .25s;z-index:40;overflow:hidden}
.brand{display:flex;align-items:center;gap:12px;font-weight:800;font-size:19px;color:#fff;padding:4px 8px 22px}.logo{flex:none;width:36px;height:36px;border-radius:11px;background:linear-gradient(135deg,#2fc4a8,#0b6b5c);display:grid;place-items:center}.logo svg{width:19px;height:19px;color:#fff}
.nav-item{display:flex;align-items:center;gap:12px;padding:11px 12px;border-radius:11px;color:var(--side-ink);text-decoration:none;cursor:pointer;font-weight:600;margin-bottom:4px;transition:.15s;white-space:nowrap}
.nav-item svg{width:19px;height:19px;flex:none}.nav-item:hover{background:rgba(255,255,255,.06);color:#fff}.nav-item.active{background:linear-gradient(135deg,rgba(47,196,168,.22),rgba(47,196,168,.06));color:#fff;box-shadow:inset 3px 0 0 #2fc4a8}
.main{margin-left:248px;min-width:0;transition:margin .25s}
@media(min-width:901px){.collapsed .sidebar{width:76px}.collapsed .main{margin-left:76px}.collapsed .lbl{display:none}}
.topbar{position:sticky;top:0;z-index:30;display:flex;align-items:center;gap:12px;padding:12px 24px;background:color-mix(in srgb,var(--bg) 85%,transparent);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.icon-btn{position:relative;flex:none;width:40px;height:40px;border-radius:10px;border:1px solid var(--line);background:var(--card);display:grid;place-items:center;cursor:pointer;transition:.15s}.icon-btn:hover{border-color:var(--accent);color:var(--accent)}
.search{position:relative;flex:1;max-width:460px}.search svg{position:absolute;left:12px;top:11px;width:18px;height:18px;color:var(--muted)}.search input{padding-left:40px}
.top-actions{margin-left:auto;display:flex;gap:10px;align-items:center}.dd-wrap{position:relative}
.dd{position:absolute;right:0;top:48px;width:320px;max-width:calc(100vw - 24px);background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow);padding:8px;z-index:50}
.dd h4{margin:8px 10px;font-size:13px}.dd .row{display:flex;gap:10px;align-items:flex-start;padding:9px 10px;border-radius:10px;font-size:13px}.dd .row:hover{background:var(--bg)}.dd button.row{width:100%;border:0;background:none;text-align:left;cursor:pointer}
.dd .row small{color:var(--muted);display:block}.dd svg{width:17px;height:17px;flex:none;margin-top:1px;color:var(--muted)}
.dot{position:absolute;top:-5px;right:-5px;min-width:19px;height:19px;border-radius:10px;background:var(--bad);color:#fff;font-size:11px;font-weight:700;display:grid;place-items:center;padding:0 5px;border:2px solid var(--bg)}
.me{display:flex;align-items:center;gap:10px;height:40px;padding:0 10px 0 4px;border-radius:12px;border:1px solid var(--line);background:var(--card);cursor:pointer}.me b{font-size:13px}
.av{--h:170;flex:none;width:32px;height:32px;border-radius:50%;display:grid;place-items:center;font-size:12px;font-weight:800;color:#fff;background:hsl(var(--h) 45% 42%)}
.content{padding:26px 24px 48px;max-width:1500px}.page-head{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;margin-bottom:20px}
.page-head h1{font-size:24px;margin:0;letter-spacing:-.02em}.page-head p{margin:2px 0 0;color:var(--muted)}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);padding:20px;min-width:0}.card h3{margin:0;font-size:15px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:18px;margin-bottom:18px}
.stat{display:flex;gap:14px;align-items:flex-start}.chip{flex:none;width:44px;height:44px;border-radius:13px;display:grid;place-items:center;color:#fff;background:linear-gradient(135deg,var(--c1),var(--c2))}.chip svg{width:21px;height:21px}
.stat .lab{color:var(--muted);font-weight:600;font-size:13px}.stat .val{font-size:28px;font-weight:800;letter-spacing:-.02em;line-height:1.2}
.pct{display:inline-flex;align-items:center;gap:4px;font-size:12px;font-weight:700;padding:2px 8px;border-radius:20px;margin-top:4px}.pct svg{width:13px;height:13px}.pct.good{background:var(--okbg);color:var(--ok)}.pct.bad{background:var(--badbg);color:var(--bad)}.pct.flat{background:var(--bg);color:var(--muted)}.stat small{color:var(--muted);margin-left:6px}
.grid3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px;margin-bottom:18px}.span2{grid-column:span 2}
.card-head{display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:14px}.chart{position:relative;height:290px}
.seg{display:inline-flex;background:var(--bg);border-radius:9px;padding:3px}.seg button{border:0;background:none;padding:5px 12px;border-radius:7px;cursor:pointer;font-weight:600;color:var(--muted)}.seg button.on{background:var(--card);color:var(--ink);box-shadow:var(--shadow)}
.feed{list-style:none;margin:0;padding:0}.feed li{display:flex;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)}.feed li:last-child{border:0}.feed .ic{flex:none;width:34px;height:34px;border-radius:10px;background:var(--soft);color:var(--accent);display:grid;place-items:center}.feed .ic svg{width:16px;height:16px}.feed small{color:var(--muted)}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;margin-bottom:16px}.toolbar .f{display:flex;flex-direction:column;gap:4px;min-width:130px;flex:1 1 130px;max-width:190px}.toolbar label{font-size:12px;font-weight:700;color:var(--muted)}
.bulk{display:flex;align-items:center;gap:12px;background:var(--soft);border:1px solid var(--accent);padding:10px 14px;border-radius:12px;margin-bottom:14px;font-weight:600}
.tablecard{padding:0;overflow:hidden;position:relative}.tablewrap{overflow-x:auto}.tablewrap.loading{opacity:.55;pointer-events:none;transition:.15s}
table{width:100%;border-collapse:collapse;min-width:900px}th,td{padding:12px 14px;text-align:left;border-bottom:1px solid var(--line);white-space:nowrap}
th{font-size:12px;color:var(--muted);font-weight:700;background:color-mix(in srgb,var(--bg) 60%,var(--card));user-select:none}th[data-sort]{cursor:pointer}th[data-sort]:hover{color:var(--accent)}
th[data-sort]::after{content:"\2195";margin-left:6px;opacity:.35}th.asc::after{content:"\2191";opacity:1;color:var(--accent)}th.desc::after{content:"\2193";opacity:1;color:var(--accent)}
tbody tr{transition:background .12s}tbody tr:hover{background:color-mix(in srgb,var(--soft) 45%,transparent)}tbody tr.sel{background:var(--soft)}tr:last-child td{border-bottom:0}
.c-chk{width:44px}input[type=checkbox]{width:17px;height:17px;padding:0;accent-color:var(--accent);cursor:pointer}.mut{color:var(--muted)}.num{font-variant-numeric:tabular-nums;font-weight:600}
.who{display:flex;gap:10px;align-items:center}.badge,.role{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:700}
.s-active{background:var(--okbg);color:var(--ok)}.s-inactive{background:var(--bg);color:var(--muted);border:1px solid var(--line)}.s-pending{background:var(--warnbg);color:var(--warn)}
.role{background:var(--bg);border:1px solid var(--line)}.r-admin{color:var(--accent);border-color:var(--accent)}.r-editor{color:#5b7fa6}
.acts{display:flex;gap:4px;justify-content:flex-end}.acts button{width:32px;height:32px;border-radius:8px;border:0;background:none;color:var(--muted);cursor:pointer;display:grid;place-items:center}.acts button:hover{background:var(--bg);color:var(--accent)}.acts button[data-act=delete]:hover{color:var(--bad)}.acts svg{width:17px;height:17px}
.foot{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;padding:14px 16px;border-top:1px solid var(--line)}.foot select{width:auto;height:34px}
.pager{display:flex;gap:4px;flex-wrap:wrap}.pager button{min-width:34px;height:34px;border-radius:8px;border:1px solid var(--line);background:var(--card);cursor:pointer;font-weight:600;display:grid;place-items:center;padding:0 8px}.pager button:hover:not(:disabled){border-color:var(--accent);color:var(--accent)}.pager button.on{background:var(--accent);color:var(--accent-ink);border-color:var(--accent)}.pager button:disabled{opacity:.4;cursor:not-allowed}.pager svg{width:16px;height:16px}
.empty{text-align:center;padding:48px 16px;color:var(--muted)}.empty svg{width:40px;height:40px;opacity:.5}.empty h4{color:var(--ink);margin:10px 0 4px;font-size:16px}
.backdrop{position:fixed;inset:0;background:rgba(7,15,22,.55);backdrop-filter:blur(3px);display:grid;place-items:center;z-index:100;padding:16px}
.modal{background:var(--card);border-radius:18px;width:100%;max-width:460px;max-height:92vh;overflow:auto;box-shadow:0 30px 80px -20px rgba(0,0,0,.5);animation:pop .18s ease-out}@keyframes pop{from{transform:translateY(10px) scale(.98);opacity:0}}
.m-head{display:flex;justify-content:space-between;align-items:center;padding:18px 22px 6px}.m-head h3{margin:0;font-size:18px}.m-body{padding:12px 22px;margin:0}.m-foot{display:flex;justify-content:flex-end;gap:10px;padding:14px 22px 20px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:12px}.dl{display:grid;grid-template-columns:110px 1fr;gap:10px 12px;margin:0}.dl dt{color:var(--muted);font-weight:600}.dl dd{margin:0;word-break:break-word}
#toasts{position:fixed;right:16px;bottom:16px;display:flex;flex-direction:column;gap:10px;z-index:200;max-width:calc(100vw - 32px)}
.toast{display:flex;gap:10px;align-items:center;background:var(--ink);color:var(--bg);padding:12px 16px;border-radius:12px;box-shadow:0 14px 34px -10px rgba(0,0,0,.5);font-weight:600;animation:pop .2s}.toast.err{background:var(--bad);color:#fff}.toast.ok svg{color:#2fc4a8}.toast.out{opacity:0;transform:translateX(20px);transition:.25s}.toast svg{width:18px;height:18px;flex:none}
.scrim{display:none}.spinning svg{animation:sp .7s linear infinite}
@media(max-width:1100px){.grid3{grid-template-columns:1fr}.span2{grid-column:auto}}
@media(max-width:900px){.sidebar{transform:translateX(-100%);box-shadow:none}.main{margin-left:0}.nav-open .sidebar{transform:none;box-shadow:0 0 60px rgba(0,0,0,.5)}.nav-open .scrim{display:block;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:35}.topbar,.content{padding-left:14px;padding-right:14px}}
@media(max-width:560px){.me b,.me small{display:none}.me{padding:0 4px}.top-actions{gap:6px}.topbar{gap:8px}.two{grid-template-columns:1fr}.toolbar .f{max-width:none}.dl{grid-template-columns:1fr}.dd{position:fixed;left:12px;right:12px;top:64px;width:auto}}
</style></head><body>
<div class="app" id="app">
<aside class="sidebar" id="sidebar">
 <div class="brand"><span class="logo"><i data-lucide="anchor"></i></span><span class="lbl">Harbor</span></div>
 <nav>
  <a class="nav-item" data-view="dashboard" tabindex="0"><i data-lucide="layout-dashboard"></i><span class="lbl">Dashboard</span></a>
  <a class="nav-item" data-view="users" tabindex="0"><i data-lucide="users"></i><span class="lbl">Users</span></a>
  <a class="nav-item" data-view="activity" tabindex="0"><i data-lucide="history"></i><span class="lbl">Activity log</span></a>
 </nav>
</aside>
<div class="scrim" id="scrim"></div>
<div class="main">
<header class="topbar">
 <button class="icon-btn" id="menuBtn" aria-label="Toggle sidebar"><i data-lucide="menu"></i></button>
 <div class="search"><i data-lucide="search"></i><input id="globalSearch" type="search" placeholder="Search users by name, email or role" autocomplete="off" aria-label="Search users"></div>
 <div class="top-actions">
  <button class="icon-btn" id="refreshBtn" aria-label="Refresh data" title="Refresh"><i data-lucide="refresh-cw"></i></button>
  <button class="icon-btn" id="themeBtn" aria-label="Toggle theme" title="Toggle theme"></button>
  <div class="dd-wrap"><button class="icon-btn" id="bellBtn" aria-label="Notifications"><i data-lucide="bell"></i><span class="dot hidden" id="bellDot"></span></button><div class="dd hidden" id="bellDD"></div></div>
  <div class="dd-wrap"><button class="me" id="meBtn" aria-label="Account menu"><span class="av" id="meAv"></span><b id="meName"></b></button>
   <div class="dd hidden" id="meDD"></div></div>
 </div>
</header>
<main class="content">
 <section id="view-dashboard" class="view">
  <div class="page-head"><div><h1>Dashboard</h1><p>How your user base is doing right now.</p></div><button class="btn primary" data-go-add><i data-lucide="user-plus"></i>Add user</button></div>
  <div class="stats" id="stats"></div>
  <div class="grid3">
   <div class="card span2"><div class="card-head"><h3>User growth, last 12 months</h3></div><div class="chart"><canvas id="chGrowth"></canvas></div></div>
   <div class="card"><div class="card-head"><h3 id="donutTitle">Users by status</h3><div class="seg" id="donutSeg"><button class="on" data-d="status">Status</button><button data-d="roles">Role</button></div></div><div class="chart"><canvas id="chDonut"></canvas></div></div>
  </div>
  <div class="grid3">
   <div class="card span2"><div class="card-head"><h3>Revenue by sign-up month</h3></div><div class="chart"><canvas id="chRevenue"></canvas></div></div>
   <div class="card"><div class="card-head"><h3>Recent activity</h3><button class="btn" data-view-link="activity" style="height:32px">View all</button></div><ul class="feed" id="recentFeed"></ul></div>
  </div>
 </section>
 <section id="view-users" class="view hidden">
  <div class="page-head"><div><h1>Users</h1><p>Search, filter and manage every account.</p></div>
   <div style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn" id="exportBtn"><i data-lucide="download"></i>Export CSV</button><button class="btn primary" data-go-add><i data-lucide="user-plus"></i>Add user</button></div></div>
  <div class="card" style="margin-bottom:16px"><div class="toolbar" style="margin:0">
   <div class="f"><label for="fStatus">Status</label><select id="fStatus"><option>All</option><option>Active</option><option>Inactive</option><option>Pending</option></select></div>
   <div class="f"><label for="fRole">Role</label><select id="fRole"><option>All</option><option>Admin</option><option>Editor</option><option>User</option></select></div>
   <div class="f"><label for="fFrom">Registered from</label><input type="date" id="fFrom"></div>
   <div class="f"><label for="fTo">Registered to</label><input type="date" id="fTo"></div>
   <button class="btn" id="clearBtn"><i data-lucide="filter-x"></i>Clear filters</button></div></div>
  <div class="bulk hidden" id="bulkBar"><span id="bulkCount"></span><button class="btn danger" id="bulkDel"><i data-lucide="trash-2"></i>Delete selected</button><button class="btn" id="bulkClear">Clear selection</button></div>
  <div class="card tablecard"><div class="tablewrap" id="tableWrap"><table>
   <thead><tr><th class="c-chk"><input type="checkbox" id="chkAll" aria-label="Select all on this page"></th>
    <th data-sort="name">Name</th><th data-sort="email">Email</th><th data-sort="role">Role</th><th data-sort="status">Status</th><th data-sort="created">Registered</th><th data-sort="revenue">Revenue</th><th style="text-align:right">Actions</th></tr></thead>
   <tbody id="tbody"><tr><td colspan="8"><div class="empty"><span class="spin"></span><p>Loading users…</p></div></td></tr></tbody></table></div>
   <div class="foot"><div class="mut" id="range"></div><div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap"><label class="mut" style="display:flex;gap:8px;align-items:center">Rows <select id="pageSize"><option>10</option><option>25</option><option>50</option><option>100</option></select></label><div class="pager" id="pager"></div></div></div></div>
 </section>
 <section id="view-activity" class="view hidden">
  <div class="page-head"><div><h1>Activity log</h1><p>The latest 100 actions taken in this console.</p></div></div>
  <div class="card"><ul class="feed" id="fullFeed"></ul></div>
 </section>
</main></div></div>
<div class="backdrop hidden" id="modal"></div><div id="toasts" aria-live="polite"></div>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://unpkg.com/lucide@0.469.0/dist/umd/lucide.min.js"></script>
<script>
(function(){
'use strict';
const $=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const icons=()=>{if(window.lucide)window.lucide.createIcons()};
const money=n=>new Intl.NumberFormat('en-US',{style:'currency',currency:'USD',maximumFractionDigits:0}).format(n||0);
const money2=n=>new Intl.NumberFormat('en-US',{style:'currency',currency:'USD'}).format(n||0);
const fmtDate=s=>new Date(s+'T00:00:00').toLocaleDateString('en',{month:'short',day:'numeric',year:'numeric'});
const initials=n=>n.split(/\s+/).filter(Boolean).slice(0,2).map(w=>w[0]).join('').toUpperCase();
const hue=s=>{let h=0;for(const c of s)h=(h*31+c.charCodeAt(0))%360;return h};
const ago=ts=>{const s=Math.max(0,(Date.now()-new Date(ts.replace(' ','T')+'Z'))/1000);if(s<60)return 'just now';if(s<3600)return Math.floor(s/60)+' min ago';if(s<86400)return Math.floor(s/3600)+' hr ago';return Math.floor(s/86400)+' d ago'};
const state={csrf:'',me:null,view:'dashboard',q:'',status:'All',role:'All',from:'',to:'',sort:'created',order:'desc',page:1,size:10,selected:new Set(),items:[],total:0,pages:1,donut:'status',charts:null,dashStale:true};

/* ---------- API ---------- */
async function api(path,opt={}){
  const method=opt.method||'GET',o={method,headers:{},credentials:'same-origin'};
  if(method!=='GET')o.headers['X-CSRF-Token']=state.csrf;
  if(opt.body!==undefined){o.headers['Content-Type']='application/json';o.body=JSON.stringify(opt.body)}
  let res;try{res=await fetch(path,o)}catch(e){throw{message:'Cannot reach the server. Check your connection.'}}
  let data=null;try{data=await res.json()}catch(e){}
  if(res.status===401){location.reload();throw{message:'Your session has ended.'}}
  if(!res.ok)throw{message:(data&&data.error)||'Request failed ('+res.status+').',fields:data&&data.fields,status:res.status};
  return data;
}
/* ---------- toast, modal, dialogs ---------- */
function toast(msg,type='ok'){const el=document.createElement('div');el.className='toast '+type;el.innerHTML='<i data-lucide="'+(type==='ok'?'circle-check':'circle-alert')+'"></i><span>'+esc(msg)+'</span>';$('#toasts').appendChild(el);icons();setTimeout(()=>{el.classList.add('out');setTimeout(()=>el.remove(),260)},3800)}
let modalHook=null;
function openModal(html){const m=$('#modal');m.innerHTML='<div class="modal" role="dialog" aria-modal="true">'+html+'</div>';m.classList.remove('hidden');icons();const f=m.querySelector('input,select');if(f)f.focus()}
function closeModal(){modalHook=null;const m=$('#modal');m.classList.add('hidden');m.innerHTML=''}
function cancelModal(){if(modalHook)modalHook('no');else closeModal()}
$('#modal').addEventListener('click',e=>{const x=e.target.closest('[data-x]');if(x&&modalHook){modalHook(x.dataset.x);return}if(e.target.id==='modal'||e.target.closest('[data-close]'))cancelModal()});
function confirmDialog(o){return new Promise(res=>{openModal('<div class="m-head"><h3>'+esc(o.title)+'</h3></div><p class="m-body mut">'+esc(o.message)+'</p><div class="m-foot"><button class="btn" data-x="no">Cancel</button><button class="btn '+(o.danger===false?'primary':'danger')+'" data-x="yes">'+esc(o.action||'Delete')+'</button></div>');modalHook=v=>{closeModal();res(v==='yes')}})}

/* ---------- theme, sidebar, dropdowns ---------- */
function setTheme(t){document.documentElement.dataset.theme=t;try{localStorage.setItem('theme',t)}catch(e){}$('#themeBtn').innerHTML='<i data-lucide="'+(t==='dark'?'sun':'moon')+'"></i>';icons();drawCharts()}
$('#themeBtn').onclick=()=>setTheme(document.documentElement.dataset.theme==='dark'?'light':'dark');
$('#menuBtn').onclick=()=>{if(matchMedia('(max-width:900px)').matches)document.body.classList.toggle('nav-open');else{const c=$('#app').classList.toggle('collapsed');try{localStorage.setItem('collapsed',c?'1':'0')}catch(e){}setTimeout(drawCharts,280)}};
$('#scrim').onclick=()=>document.body.classList.remove('nav-open');
function toggleDD(id){$$('.dd').forEach(d=>{if(d.id!==id)d.classList.add('hidden')});$('#'+id).classList.toggle('hidden')}
$('#bellBtn').onclick=()=>{toggleDD('bellDD');loadNotifs()};$('#meBtn').onclick=()=>toggleDD('meDD');
document.addEventListener('click',e=>{if(!e.target.closest('.dd-wrap'))$$('.dd').forEach(d=>d.classList.add('hidden'))});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){if(!$('#modal').classList.contains('hidden'))cancelModal();$$('.dd').forEach(d=>d.classList.add('hidden'))}});

/* ---------- navigation ---------- */
function show(view){state.view=view;$$('.view').forEach(v=>v.classList.toggle('hidden',v.id!=='view-'+view));$$('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.view===view));document.body.classList.remove('nav-open');$$('.dd').forEach(d=>d.classList.add('hidden'));history.replaceState(null,'','#'+view);if(view==='dashboard')loadDashboard();if(view==='users')loadUsers();if(view==='activity')loadActivity();window.scrollTo(0,0)}
$$('.nav-item').forEach(n=>{n.onclick=()=>show(n.dataset.view);n.onkeydown=e=>{if(e.key==='Enter')show(n.dataset.view)}});
document.addEventListener('click',e=>{const l=e.target.closest('[data-view-link]');if(l)show(l.dataset.viewLink);if(e.target.closest('[data-go-add]'))userForm()});
async function refresh(){const b=$('#refreshBtn');b.classList.add('spinning');state.dashStale=true;try{await Promise.all([state.view==='dashboard'?loadDashboard():state.view==='users'?loadUsers():loadActivity(),loadNotifs()]);toast('Data refreshed')}finally{b.classList.remove('spinning')}}
$('#refreshBtn').onclick=refresh;

/* ---------- notifications & profile ---------- */
const ACT={create:'user-plus',update:'pencil',delete:'trash-2',status:'toggle-right',login:'log-in',logout:'log-out',export:'download',system:'server'};
const feedItem=a=>'<li><span class="ic"><i data-lucide="'+(ACT[a.action]||'activity')+'"></i></span><div><div>'+esc(a.detail)+'</div><small>'+esc(a.actor)+' · '+esc(ago(a.created_at))+'</small></div></li>';
async function loadNotifs(){try{const d=await api('/api/notifications');const dot=$('#bellDot');dot.textContent=d.pending>99?'99+':d.pending;dot.classList.toggle('hidden',!d.pending);
 $('#bellDD').innerHTML='<h4>Notifications</h4>'+(d.pending?'<button class="row" id="pendingLink"><i data-lucide="clock"></i><div><b>'+d.pending+' pending request'+(d.pending>1?'s':'')+'</b><small>Review and approve new accounts</small></div></button>':'<div class="row"><i data-lucide="circle-check"></i><div><b>No pending requests</b><small>Everything is reviewed</small></div></div>')+'<h4>Recent activity</h4>'+d.items.map(a=>'<div class="row"><i data-lucide="'+(ACT[a.action]||'activity')+'"></i><div>'+esc(a.detail)+'<small>'+esc(ago(a.created_at))+'</small></div></div>').join('');icons();
 const pl=$('#pendingLink');if(pl)pl.onclick=()=>{state.status='Pending';state.page=1;state.selected.clear();syncFilterUI();show('users')}}catch(e){}}

/* ---------- dashboard ---------- */
function pctHtml(m,invert){if(m.previous===0)return '<span class="pct flat">'+(m.current>0?'New':'No change')+'</span>';const c=(m.current-m.previous)/m.previous*100,up=c>=0,good=invert?!up:up;return '<span class="pct '+(c===0?'flat':good?'good':'bad')+'"><i data-lucide="'+(up?'arrow-up-right':'arrow-down-right')+'"></i>'+Math.abs(c).toFixed(0)+'%</span>'}
async function loadDashboard(){
  try{const [s,c,a]=await Promise.all([api('/api/stats'),api('/api/charts'),api('/api/activity?limit=7')]);
   const defs=[['Total users',s.total,'users','#12907c','#0b6b5c',v=>v,0],['Active users',s.active,'user-check','#3b82a6','#2b5f86',v=>v,0],['Pending requests',s.pending,'clock','#d99a2b','#b7791f',v=>v,1],['Total revenue',s.revenue,'dollar-sign','#7a6bd1','#5446a8',money,0]];
   $('#stats').innerHTML=defs.map(d=>'<div class="card stat"><span class="chip" style="--c1:'+d[3]+';--c2:'+d[4]+'"><i data-lucide="'+d[2]+'"></i></span><div><div class="lab">'+d[0]+'</div><div class="val">'+d[5](d[1].value)+'</div>'+pctHtml(d[1],d[6])+'<small>vs previous 30 days</small></div></div>').join('');
   state.charts=c;drawCharts();
   $('#recentFeed').innerHTML=a.items.length?a.items.map(feedItem).join(''):'<li class="mut">No activity yet.</li>';icons();state.dashStale=false;
  }catch(e){toast(e.message,'err')}}
const inst={};
const cv=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const mlabel=(m,i)=>{const [y,mo]=m.split('-');return new Date(+y,+mo-1,1).toLocaleString('en',{month:'short'})+(i===0||mo==='01'?" '"+y.slice(2):'')};
function drawCharts(){
  const d=state.charts;if(!d||!window.Chart||state.view!=='dashboard')return;
  const muted=cv('--muted'),grid=cv('--line'),acc=cv('--accent'),warn=cv('--warn'),card=cv('--card');
  Chart.defaults.font.family='Manrope, system-ui, sans-serif';Chart.defaults.color=muted;
  Object.values(inst).forEach(c=>c&&c.destroy());
  const labels=d.months.map(mlabel),axes={x:{grid:{display:false}},y:{grid:{color:grid},beginAtZero:true,border:{display:false}}};
  inst.g=new Chart($('#chGrowth'),{type:'line',data:{labels,datasets:[{label:'Total users',data:d.growth.total,borderColor:acc,backgroundColor:acc+'22',fill:true,tension:.35,pointRadius:3,borderWidth:2.5},{label:'New sign-ups',data:d.growth.new,borderColor:warn,borderDash:[5,4],tension:.35,pointRadius:2,borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,interaction:{mode:'index',intersect:false},plugins:{legend:{position:'bottom',labels:{usePointStyle:true,boxWidth:8}}},scales:axes}});
  const src=state.donut==='status'?d.status:d.roles,keys=Object.keys(src),pal=state.donut==='status'?[acc,'#8b9aa8',warn]:[acc,'#5b7fa6',warn];
  inst.d=new Chart($('#chDonut'),{type:'doughnut',data:{labels:keys,datasets:[{data:keys.map(k=>src[k]),backgroundColor:pal,borderColor:card,borderWidth:3}]},options:{responsive:true,maintainAspectRatio:false,cutout:'66%',plugins:{legend:{position:'bottom',labels:{usePointStyle:true,boxWidth:8}}}}});
  inst.r=new Chart($('#chRevenue'),{type:'bar',data:{labels,datasets:[{label:'Revenue',data:d.revenue,backgroundColor:acc,borderRadius:7,maxBarThickness:34}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>money(c.parsed.y)}}},scales:{x:axes.x,y:{...axes.y,ticks:{callback:v=>money(v)}}}}});
}
$('#donutSeg').onclick=e=>{const b=e.target.closest('button');if(!b)return;state.donut=b.dataset.d;$$('#donutSeg button').forEach(x=>x.classList.toggle('on',x===b));$('#donutTitle').textContent=state.donut==='status'?'Users by status':'Users by role';drawCharts()};
window.addEventListener('resize',()=>{Object.values(inst).forEach(c=>c&&c.resize())});

/* ---------- activity ---------- */
async function loadActivity(){try{const d=await api('/api/activity?limit=100');$('#fullFeed').innerHTML=d.items.length?d.items.map(feedItem).join(''):'<li class="mut">No activity yet.</li>';icons()}catch(e){toast(e.message,'err')}}

/* ---------- users table ---------- */
function syncFilterUI(){$('#fStatus').value=state.status;$('#fRole').value=state.role;$('#fFrom').value=state.from;$('#fTo').value=state.to;$('#globalSearch').value=state.q}
function params(paged){const p=new URLSearchParams({q:state.q,status:state.status==='All'?'':state.status,role:state.role==='All'?'':state.role,date_from:state.from,date_to:state.to,sort:state.sort,order:state.order});if(paged){p.set('page',state.page);p.set('page_size',state.size)}return p}
let reqId=0;
async function loadUsers(){
  const my=++reqId;$('#tableWrap').classList.add('loading');
  try{const d=await api('/api/users?'+params(true));if(my!==reqId)return;state.items=d.items;state.total=d.total;state.page=d.page;state.pages=d.pages;renderUsers()}
  catch(e){if(my!==reqId)return;$('#tbody').innerHTML='<tr><td colspan="8"><div class="empty"><i data-lucide="circle-alert"></i><h4>Could not load users</h4><p>'+esc(e.message)+'</p><button class="btn" id="retry">Try again</button></div></td></tr>';icons();$('#retry').onclick=loadUsers}
  finally{if(my===reqId)$('#tableWrap').classList.remove('loading')}}
function rowHtml(u){const sel=state.selected.has(u.id),next=u.status==='Active'?'Deactivate':u.status==='Pending'?'Approve':'Activate';
 return '<tr data-id="'+u.id+'" class="'+(sel?'sel':'')+'"><td class="c-chk"><input type="checkbox" class="rowchk" '+(sel?'checked':'')+' aria-label="Select '+esc(u.full_name)+'"></td>'
 +'<td><div class="who"><span class="av" style="--h:'+hue(u.email)+'">'+esc(initials(u.full_name))+'</span><b>'+esc(u.full_name)+'</b></div></td><td class="mut">'+esc(u.email)+'</td>'
 +'<td><span class="role r-'+esc(u.role.toLowerCase())+'">'+esc(u.role)+'</span></td><td><span class="badge s-'+esc(u.status.toLowerCase())+'">'+esc(u.status)+'</span></td>'
 +'<td class="mut">'+esc(fmtDate(u.created_at))+'</td><td class="num">'+money2(u.revenue)+'</td>'
 +'<td><div class="acts"><button data-act="view" title="View details" aria-label="View details"><i data-lucide="eye"></i></button><button data-act="edit" title="Edit" aria-label="Edit"><i data-lucide="pencil"></i></button><button data-act="toggle" title="'+next+'" aria-label="'+next+'"><i data-lucide="'+(u.status==='Active'?'power':'circle-check')+'"></i></button><button data-act="delete" title="Delete" aria-label="Delete"><i data-lucide="trash-2"></i></button></div></td></tr>'}
function pageList(p,n){if(n<=7)return Array.from({length:n},(_,i)=>i+1);const s=new Set([1,2,n-1,n,p-1,p,p+1]),out=[];let last=0;[...s].filter(x=>x>=1&&x<=n).sort((a,b)=>a-b).forEach(x=>{if(x-last>1)out.push('…');out.push(x);last=x});return out}
function renderUsers(){
  $$('th[data-sort]').forEach(th=>{th.classList.remove('asc','desc');if(th.dataset.sort===state.sort)th.classList.add(state.order)});
  const filtered=state.q||state.status!=='All'||state.role!=='All'||state.from||state.to;
  $('#tbody').innerHTML=state.items.length?state.items.map(rowHtml).join(''):'<tr><td colspan="8"><div class="empty"><i data-lucide="search-x"></i><h4>'+(filtered?'No users match these filters':'No users yet')+'</h4><p>'+(filtered?'Try a different search or clear the filters.':'Add your first user to get started.')+'</p>'+(filtered?'<button class="btn" id="emptyClear">Clear filters</button>':'<button class="btn primary" data-go-add>Add user</button>')+'</div></td></tr>';
  const a=state.total?(state.page-1)*state.size+1:0,b=Math.min(state.total,state.page*state.size);
  $('#range').textContent=state.total?'Showing '+a+'–'+b+' of '+state.total+' user'+(state.total>1?'s':''):'0 users';
  let h='<button data-p="'+(state.page-1)+'" '+(state.page<=1?'disabled':'')+' aria-label="Previous page"><i data-lucide="chevron-left"></i></button>';
  pageList(state.page,state.pages).forEach(x=>{h+=x==='…'?'<button disabled>…</button>':'<button data-p="'+x+'" class="'+(x===state.page?'on':'')+'">'+x+'</button>'});
  h+='<button data-p="'+(state.page+1)+'" '+(state.page>=state.pages?'disabled':'')+' aria-label="Next page"><i data-lucide="chevron-right"></i></button>';
  $('#pager').innerHTML=h;updateBulk();icons();const ec=$('#emptyClear');if(ec)ec.onclick=clearFilters}
function updateBulk(){const n=state.selected.size;$('#bulkBar').classList.toggle('hidden',!n);$('#bulkCount').textContent=n+' selected';const ids=state.items.map(u=>u.id),all=ids.length&&ids.every(i=>state.selected.has(i));$('#chkAll').checked=!!all;$('#chkAll').indeterminate=!all&&ids.some(i=>state.selected.has(i))}
$('#pager').onclick=e=>{const b=e.target.closest('button[data-p]');if(!b||b.disabled)return;state.page=+b.dataset.p;loadUsers()};
$('#tableWrap').addEventListener('click',e=>{const th=e.target.closest('th[data-sort]');if(th){const c=th.dataset.sort;if(state.sort===c)state.order=state.order==='asc'?'desc':'asc';else{state.sort=c;state.order=c==='created'||c==='revenue'?'desc':'asc'}state.page=1;loadUsers();return}
 const tr=e.target.closest('tbody tr[data-id]');if(!tr)return;const id=+tr.dataset.id;
 if(e.target.classList.contains('rowchk')){e.target.checked?state.selected.add(id):state.selected.delete(id);tr.classList.toggle('sel',e.target.checked);updateBulk();return}
 const btn=e.target.closest('button[data-act]');if(!btn)return;const u=state.items.find(x=>x.id===id);if(!u)return;
 ({view:()=>viewUser(u),edit:()=>userForm(u),toggle:()=>toggleStatus(u),delete:()=>deleteUser(u)})[btn.dataset.act]()});
$('#chkAll').onchange=e=>{state.items.forEach(u=>e.target.checked?state.selected.add(u.id):state.selected.delete(u.id));renderUsers()};
$('#bulkClear').onclick=()=>{state.selected.clear();renderUsers()};
/* filters */
function resetPage(){state.page=1;state.selected.clear()}
function clearFilters(){state.q='';state.status='All';state.role='All';state.from='';state.to='';state.sort='created';state.order='desc';resetPage();syncFilterUI();loadUsers()}
$('#clearBtn').onclick=clearFilters;
$('#fStatus').onchange=e=>{state.status=e.target.value;resetPage();loadUsers()};
$('#fRole').onchange=e=>{state.role=e.target.value;resetPage();loadUsers()};
$('#fFrom').onchange=e=>{state.from=e.target.value;resetPage();loadUsers()};
$('#fTo').onchange=e=>{state.to=e.target.value;resetPage();loadUsers()};
$('#pageSize').onchange=e=>{state.size=+e.target.value;resetPage();loadUsers()};
let st;$('#globalSearch').addEventListener('input',e=>{clearTimeout(st);st=setTimeout(()=>{state.q=e.target.value.trim();resetPage();if(state.view!=='users')show('users');else loadUsers()},300)});

/* ---------- user actions ---------- */
function changed(){state.dashStale=true;loadNotifs()}
function viewUser(u){openModal('<div class="m-head"><h3>User details</h3><button class="icon-btn" data-close aria-label="Close"><i data-lucide="x"></i></button></div><div class="m-body"><div class="who" style="margin-bottom:16px"><span class="av" style="--h:'+hue(u.email)+';width:46px;height:46px;font-size:15px">'+esc(initials(u.full_name))+'</span><div><b style="font-size:16px">'+esc(u.full_name)+'</b><div class="mut">'+esc(u.email)+'</div></div></div><dl class="dl"><dt>Role</dt><dd>'+esc(u.role)+'</dd><dt>Status</dt><dd><span class="badge s-'+esc(u.status.toLowerCase())+'">'+esc(u.status)+'</span></dd><dt>Registered</dt><dd>'+esc(fmtDate(u.created_at))+'</dd><dt>Revenue</dt><dd>'+money2(u.revenue)+'</dd><dt>User ID</dt><dd>#'+u.id+'</dd></dl></div><div class="m-foot"><button class="btn" data-close>Close</button><button class="btn primary" id="vEdit"><i data-lucide="pencil"></i>Edit user</button></div>');$('#vEdit').onclick=()=>userForm(u)}
const opts=(list,sel)=>list.map(o=>'<option'+(o===sel?' selected':'')+'>'+o+'</option>').join('');
function userForm(u){
  const edit=!!u;u=u||{full_name:'',email:'',role:'User',status:'Pending',revenue:0};
  openModal('<div class="m-head"><h3>'+(edit?'Edit user':'Add user')+'</h3><button class="icon-btn" data-close aria-label="Close"><i data-lucide="x"></i></button></div><form id="uform" novalidate><div class="m-body">'
  +'<label class="field"><span>Full name</span><input name="full_name" maxlength="80" value="'+esc(u.full_name)+'" required><em class="err"></em></label>'
  +'<label class="field"><span>Email</span><input name="email" type="email" maxlength="254" value="'+esc(u.email)+'" required><em class="err"></em></label>'
  +'<div class="two"><label class="field"><span>Role</span><select name="role">'+opts(['Admin','Editor','User'],u.role)+'</select><em class="err"></em></label>'
  +'<label class="field"><span>Account status</span><select name="status">'+opts(['Active','Inactive','Pending'],u.status)+'</select><em class="err"></em></label></div>'
  +'<label class="field"><span>Lifetime revenue (USD, optional)</span><input name="revenue" type="number" min="0" step="0.01" value="'+esc(u.revenue)+'"><em class="err"></em></label></div>'
  +'<div class="m-foot"><button type="button" class="btn" data-close>Cancel</button><button class="btn primary" type="submit" id="usave"><span class="spin hidden"></span><span>'+(edit?'Save changes':'Add user')+'</span></button></div></form>');
  const form=$('#uform');
  const showErr=errs=>{$$('.field',form).forEach(f=>{const n=f.querySelector('[name]').name;f.classList.toggle('bad',!!errs[n]);f.querySelector('.err').textContent=errs[n]||''})};
  form.addEventListener('submit',async e=>{e.preventDefault();
    const data=Object.fromEntries(new FormData(form).entries());data.full_name=data.full_name.trim();data.email=data.email.trim();
    const errs={};if(data.full_name.length<2)errs.full_name='Enter a full name (at least 2 characters).';
    if(!data.email)errs.email='Email is required.';else if(!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(data.email))errs.email='Enter a valid email address.';
    if(data.revenue!==''&&(isNaN(+data.revenue)||+data.revenue<0))errs.revenue='Revenue must be 0 or more.';
    showErr(errs);if(Object.keys(errs).length)return;
    data.revenue=data.revenue===''?0:+data.revenue;
    const btn=$('#usave');btn.disabled=true;btn.querySelector('.spin').classList.remove('hidden');
    try{await api(edit?'/api/users/'+u.id:'/api/users',{method:edit?'PUT':'POST',body:data});closeModal();toast(edit?'User updated':'User added');changed();if(state.view==='users')loadUsers();else if(state.view==='dashboard')loadDashboard()}
    catch(err){if(err.fields&&Object.keys(err.fields).length)showErr(err.fields);else toast(err.message,'err');btn.disabled=false;btn.querySelector('.spin').classList.add('hidden')}
  });
}
async function toggleStatus(u){const next=u.status==='Active'?'Inactive':'Active';try{await api('/api/users/'+u.id+'/status',{method:'PATCH',body:{status:next}});toast(u.full_name+' is now '+next.toLowerCase());changed();loadUsers()}catch(e){toast(e.message,'err')}}
async function deleteUser(u){if(!await confirmDialog({title:'Delete user?',message:'This permanently removes '+u.full_name+' ('+u.email+'). This cannot be undone.'}))return;try{await api('/api/users/'+u.id,{method:'DELETE'});state.selected.delete(u.id);toast('User deleted');changed();loadUsers()}catch(e){toast(e.message,'err');loadUsers()}}
$('#bulkDel').onclick=async()=>{const ids=[...state.selected],n=ids.length;if(!await confirmDialog({title:'Delete '+n+' user'+(n>1?'s':'')+'?',message:'The selected users will be permanently removed. This cannot be undone.',action:'Delete '+n}))return;
  try{const d=await api('/api/users/bulk-delete',{method:'POST',body:{ids}});state.selected.clear();toast(d.deleted+' user'+(d.deleted===1?'':'s')+' deleted');changed();loadUsers()}catch(e){toast(e.message,'err')}};
$('#exportBtn').onclick=async()=>{try{const r=await fetch('/api/users/export?'+params(false),{credentials:'same-origin'});if(!r.ok){let m='Export failed.';try{m=(await r.json()).error||m}catch(_){}throw{message:m}}const b=await r.blob(),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='users.csv';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(a.href),1500);toast('Exported the filtered users')}catch(e){toast(e.message||'Export failed','err')}};
/* ---------- boot ---------- */
async function init(){
  try{const saved=localStorage.getItem('collapsed');if(saved==='1')$('#app').classList.add('collapsed')}catch(e){}
  setTheme(document.documentElement.dataset.theme||'light');
  try{state.me=await api('/api/me')}catch(e){return}
  state.csrf=state.me.csrf;$('#meName').textContent=state.me.name;$('#meAv').textContent=initials(state.me.name);$('#meAv').style.setProperty('--h',hue(state.me.email));
  $('#meDD').innerHTML='<div class="row"><span class="av" style="--h:'+hue(state.me.email)+'">'+esc(initials(state.me.name))+'</span><div><b>'+esc(state.me.name)+'</b><small>'+esc(state.me.email)+'</small></div></div><button class="row" id="goAct"><i data-lucide="history"></i><div>Activity log</div></button><button class="row" id="outBtn"><i data-lucide="log-out"></i><div>Sign out</div></button>';
  $('#goAct').onclick=()=>show('activity');
  $('#outBtn').onclick=async()=>{try{await api('/api/logout',{method:'POST'})}catch(e){}location.reload()};
  icons();loadNotifs();
  const v=location.hash.slice(1);show(['dashboard','users','activity'].includes(v)?v:'dashboard');
}
init();
})();
</script></body></html>""".replace("__HEAD__", THEME_HEAD)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")))