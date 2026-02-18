import os
import sqlite3
import time
from datetime import datetime
from flask import Flask, request, jsonify, session, send_from_directory

from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DB_FILE = os.path.join(BASE_DIR, "database.db")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")

app.secret_key = os.environ.get("SECRET_KEY", "service_app_secret_key_dev_only_change_me")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

def get_db():
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row
    return con

def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ensure_column(cur, table: str, col: str, col_sql: str):
    cols = [r["name"] for r in cur.execute(f"PRAGMA table_info({table})").fetchall()]
    if col not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {col_sql}")

def looks_hashed(pw: str) -> bool:
    return bool(pw) and (":" in pw) and (len(pw) > 20)

def hash_pw(pw: str) -> str:
    return generate_password_hash(pw)

def init_db():
    con = get_db()
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        display_name TEXT
    )
    """)
    ensure_column(cur, "users", "display_name", "display_name TEXT")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS app_state (
        username TEXT PRIMARY KEY,
        json TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS parts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sku TEXT NOT NULL,
        name TEXT NOT NULL,
        qty INTEGER NOT NULL DEFAULT 0
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS part_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        part_id INTEGER NOT NULL,
        qty INTEGER NOT NULL,
        note TEXT,
        requested_by TEXT NOT NULL,
        requested_name TEXT,
        status TEXT NOT NULL,
        decided_at TEXT,
        decided_by TEXT,
        FOREIGN KEY(part_id) REFERENCES parts(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS tech_inventory (
        tech_username TEXT NOT NULL,
        part_id INTEGER NOT NULL,
        qty INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (tech_username, part_id),
        FOREIGN KEY(part_id) REFERENCES parts(id)
    )
    """)

    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO users (username,password,role,display_name) VALUES (?,?,?,?)",
            ("admin", hash_pw("admin123"), "admin", "Админ"),
        )
        cur.execute(
            "INSERT INTO users (username,password,role,display_name) VALUES (?,?,?,?)",
            ("tech1", hash_pw("tech123"), "technician", "Техник 1"),
        )

    con.commit()
    con.close()

def is_logged_in():
    return session.get("username") is not None

def is_admin():
    return session.get("role") == "admin"

def require_login():
    if not is_logged_in():
        return jsonify({"status": "fail", "message": "Login required"}), 401
    return None

def require_admin():
    err = require_login()
    if err:
        return err
    if not is_admin():
        return jsonify({"status": "fail", "message": "Admin only"}), 403
    return None

init_db()

LOGIN_WINDOW_SEC = 10 * 60
LOGIN_MAX_FAILS = 12
_login_fails = {}

def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def rate_limit_key(username: str):
    return f"{client_ip()}::{(username or '').lower()}"

def _prune(arr):
    now = time.time()
    cutoff = now - LOGIN_WINDOW_SEC
    return [t for t in arr if t >= cutoff]

def record_fail(key: str):
    arr = _login_fails.get(key, [])
    arr.append(time.time())
    _login_fails[key] = _prune(arr)

def is_blocked(key: str) -> bool:
    arr = _login_fails.get(key, [])
    arr = _prune(arr)
    _login_fails[key] = arr
    return len(arr) >= LOGIN_MAX_FAILS

def clear_fails(key: str):
    _login_fails.pop(key, None)

@app.route("/")
def home():
    return send_from_directory(STATIC_DIR, "index.html")

@app.route("/admin")
def admin_page():
    return send_from_directory(STATIC_DIR, "admin_users.html")

@app.before_request
def auto_secure_cookie_for_https():
    proto = (request.headers.get("X-Forwarded-Proto") or "").lower()
    if request.is_secure or proto == "https":
        app.config["SESSION_COOKIE_SECURE"] = True

@app.route("/me")
def me():
    return jsonify({
        "logged_in": bool(session.get("username")),
        "username": session.get("username"),
        "role": session.get("role"),
        "display_name": session.get("display_name"),
    })

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()

    key = rate_limit_key(username)
    if is_blocked(key):
        return jsonify({"status": "fail", "message": "Too many attempts. Try later."}), 429

    con = get_db()
    cur = con.cursor()
    row = cur.execute(
        "SELECT id, username, role, display_name, password FROM users WHERE username=?",
        (username,),
    ).fetchone()

    if not row:
        con.close()
        record_fail(key)
        return jsonify({"status": "fail"}), 401

    stored = row["password"] or ""

    if looks_hashed(stored):
        ok = check_password_hash(stored, password)
    else:
        ok = (stored == password)

    if ok:
        if not looks_hashed(stored):
            cur.execute("UPDATE users SET password=? WHERE id=?", (hash_pw(password), row["id"]))
            con.commit()

        session["username"] = row["username"]
        session["role"] = row["role"]
        session["display_name"] = row["display_name"] or row["username"]

        con.close()
        clear_fails(key)
        return jsonify({
            "status": "ok",
            "role": row["role"],
            "username": row["username"],
            "display_name": session["display_name"],
        })

    con.close()
    record_fail(key)
    return jsonify({"status": "fail"}), 401

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "ok"})

def state_get():
    err = require_login()
    if err:
        return err

    # 🔥 ЕДИН ОБЩ STATE ЗА ВСИЧКИ
    username = "__shared__"

    con = get_db()
    cur = con.cursor()
    row = cur.execute(
        "SELECT json, updated_at FROM app_state WHERE username=?",
        (username,),
    ).fetchone()
    con.close()

    if not row:
        return jsonify({"state": None, "updated_at": None})

    import json
    try:
        return jsonify({
            "state": json.loads(row["json"]),
            "updated_at": row["updated_at"]
        })
    except Exception:
        return jsonify({"state": None, "updated_at": row["updated_at"]})

@app.route("/state", methods=["POST"])
def state_set():
    err = require_login()
    if err:
        return err

    # 🔥 ЕДИН ОБЩ STATE ЗА ВСИЧКИ
    username = "__shared__"

    data = request.get_json(silent=True) or {}
    st = data.get("state")
    if st is None:
        return jsonify({"status": "fail", "message": "Missing state"}), 400

    import json
    raw = json.dumps(st, ensure_ascii=False)

    con = get_db()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO app_state(username, json, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(username) DO UPDATE SET json=excluded.json, updated_at=excluded.updated_at",
        (username, raw, now_iso()),
    )
    con.commit()
    con.close()
    return jsonify({"status": "ok"})
@app.route("/admin/users", methods=["GET"])
def admin_users_list():
    err = require_admin()
    if err:
        return err
    con = get_db()
    cur = con.cursor()
    rows = cur.execute(
        "SELECT id, username, role, display_name FROM users ORDER BY id ASC"
    ).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])

@app.route("/admin/users", methods=["POST"])
def admin_users_add():
    err = require_admin()
    if err:
        return err

    d = request.get_json(silent=True) or {}
    username = (d.get("username") or "").strip()
    password = (d.get("password") or "").strip()
    role = (d.get("role") or "technician").strip()
    display_name = (d.get("display_name") or "").strip()

    if not username or not password:
        return jsonify({"status": "fail", "message": "Липсва потребител или парола"}), 400
    if role not in ("admin", "technician"):
        return jsonify({"status": "fail", "message": "Невалидна роля"}), 400
    if role == "technician" and not display_name:
        return jsonify({"status": "fail", "message": "Липсва име на техник"}), 400

    con = get_db()
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password, role, display_name) VALUES (?,?,?,?)",
            (username, hash_pw(password), role, display_name or None),
        )
        con.commit()
    except sqlite3.IntegrityError:
        con.close()
        return jsonify({"status": "fail", "message": "Това потребителско име вече съществува"}), 400

    con.close()
    return jsonify({"status": "ok"})

@app.route("/admin/users/<int:user_id>", methods=["DELETE"])
def admin_users_delete(user_id: int):
    err = require_admin()
    if err:
        return err
    con = get_db()
    cur = con.cursor()
    row = cur.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if not row:
        con.close()
        return jsonify({"status": "fail", "message": "Няма такъв потребител"}), 404
    if row["username"] == session.get("username"):
        con.close()
        return jsonify({"status": "fail", "message": "Не можеш да изтриеш текущия си профил"}), 400
    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    con.commit()
    con.close()
    return jsonify({"status": "ok"})

@app.route("/admin/users/<int:user_id>/password", methods=["POST"])
def admin_users_set_password(user_id: int):
    err = require_admin()
    if err:
        return err
    d = request.get_json(silent=True) or {}
    password = (d.get("password") or "").strip()
    if not password:
        return jsonify({"status": "fail", "message": "Липсва парола"}), 400
    con = get_db()
    cur = con.cursor()
    cur.execute("UPDATE users SET password=? WHERE id=?", (hash_pw(password), user_id))
    con.commit()
    con.close()
    return jsonify({"status": "ok"})

@app.route("/api/technicians", methods=["GET"])
def api_technicians():
    err = require_admin()
    if err:
        return err
    con = get_db()
    cur = con.cursor()
    rows = cur.execute(
        "SELECT username, display_name FROM users WHERE role='technician' ORDER BY display_name, username"
    ).fetchall()
    con.close()
    return jsonify([{"username": r["username"], "display_name": r["display_name"] or r["username"]} for r in rows])

@app.route("/api/parts", methods=["GET"])
def api_parts_get():
    err = require_login()
    if err:
        return err
    con = get_db()
    cur = con.cursor()
    rows = cur.execute("SELECT id, sku, name, qty FROM parts ORDER BY sku, name").fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/parts", methods=["POST"])
def api_parts_add():
    err = require_admin()
    if err:
        return err
    d = request.get_json(silent=True) or {}
    sku = (d.get("sku") or "").strip()
    name = (d.get("name") or "").strip()
    try:
        qty = int(d.get("qty") or 0)
    except Exception:
        qty = 0
    if not sku or not name:
        return jsonify({"status": "fail", "message": "Липсва артикул или име"}), 400
    if qty < 0:
        return jsonify({"status": "fail", "message": "Невалидна наличност"}), 400

    con = get_db()
    cur = con.cursor()
    cur.execute("INSERT INTO parts(sku, name, qty) VALUES (?,?,?)", (sku, name, qty))
    con.commit()
    con.close()
    return jsonify({"status": "ok"})

@app.route("/api/part_requests", methods=["GET"])
def api_part_requests_get():
    err = require_login()
    if err:
        return err
    con = get_db()
    cur = con.cursor()
    if is_admin():
        rows = cur.execute("""
            SELECT id, created_at, part_id, qty, note, requested_by, requested_name, status, decided_at, decided_by
            FROM part_requests
            ORDER BY id DESC
        """).fetchall()
    else:
        rows = cur.execute("""
            SELECT id, created_at, part_id, qty, note, requested_by, requested_name, status, decided_at, decided_by
            FROM part_requests
            WHERE requested_by=?
            ORDER BY id DESC
        """, (session["username"],)).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/part_requests", methods=["POST"])
def api_part_requests_add():
    err = require_login()
    if err:
        return err
    d = request.get_json(silent=True) or {}
    try:
        part_id = int(d.get("part_id"))
        qty = int(d.get("qty"))
    except Exception:
        return jsonify({"status": "fail", "message": "Невалидни данни"}), 400
    note = (d.get("note") or "").strip()

    if qty <= 0:
        return jsonify({"status": "fail", "message": "Невалидно количество"}), 400

    con = get_db()
    cur = con.cursor()

    part = cur.execute("SELECT id FROM parts WHERE id=?", (part_id,)).fetchone()
    if not part:
        con.close()
        return jsonify({"status": "fail", "message": "Няма такава част"}), 404

    cur.execute("""
        INSERT INTO part_requests(created_at, part_id, qty, note, requested_by, requested_name, status)
        VALUES (?,?,?,?,?,?,?)
    """, (
        now_iso(), part_id, qty, note,
        session["username"], session.get("display_name") or session["username"],
        "pending"
    ))
    con.commit()
    con.close()
    return jsonify({"status": "ok"})

@app.route("/api/part_requests/<int:req_id>/approve", methods=["POST"])
def api_part_requests_approve(req_id: int):
    err = require_admin()
    if err:
        return err

    con = get_db()
    cur = con.cursor()
    req = cur.execute("""
        SELECT id, part_id, qty, requested_by, status
        FROM part_requests
        WHERE id=?
    """, (req_id,)).fetchone()
    if not req:
        con.close()
        return jsonify({"status": "fail", "message": "Няма такава заявка"}), 404
    if req["status"] != "pending":
        con.close()
        return jsonify({"status": "fail", "message": "Заявката вече е обработена"}), 400

    part = cur.execute("SELECT id, qty FROM parts WHERE id=?", (req["part_id"],)).fetchone()
    if not part:
        con.close()
        return jsonify({"status": "fail", "message": "Няма такава част"}), 404
    if int(part["qty"]) < int(req["qty"]):
        con.close()
        return jsonify({"status": "fail", "message": "Недостатъчна наличност в склада"}), 400

    cur.execute("UPDATE parts SET qty=qty-? WHERE id=?", (int(req["qty"]), int(req["part_id"])))
    cur.execute("""
        INSERT INTO tech_inventory(tech_username, part_id, qty)
        VALUES (?,?,?)
        ON CONFLICT(tech_username, part_id) DO UPDATE SET qty=tech_inventory.qty + excluded.qty
    """, (req["requested_by"], int(req["part_id"]), int(req["qty"])))

    cur.execute("""
        UPDATE part_requests
        SET status='approved', decided_at=?, decided_by=?
        WHERE id=?
    """, (now_iso(), session["username"], int(req_id)))

    con.commit()
    con.close()
    return jsonify({"status": "ok"})

@app.route("/api/part_requests/<int:req_id>/reject", methods=["POST"])
def api_part_requests_reject(req_id: int):
    err = require_admin()
    if err:
        return err

    con = get_db()
    cur = con.cursor()
    req = cur.execute("SELECT id, status FROM part_requests WHERE id=?", (req_id,)).fetchone()
    if not req:
        con.close()
        return jsonify({"status": "fail", "message": "Няма такава заявка"}), 404
    if req["status"] != "pending":
        con.close()
        return jsonify({"status": "fail", "message": "Заявката вече е обработена"}), 400

    cur.execute("""
        UPDATE part_requests
        SET status='rejected', decided_at=?, decided_by=?
        WHERE id=?
    """, (now_iso(), session["username"], int(req_id)))

    con.commit()
    con.close()
    return jsonify({"status": "ok"})

@app.route("/api/tech_inventory", methods=["GET"])
def api_my_inventory():
    err = require_login()
    if err:
        return err

    con = get_db()
    cur = con.cursor()
    rows = cur.execute("""
        SELECT ti.part_id, ti.qty, p.sku, p.name
        FROM tech_inventory ti
        JOIN parts p ON p.id = ti.part_id
        WHERE ti.tech_username=?
        ORDER BY p.sku, p.name
    """, (session["username"],)).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/tech_inventory/<tech_username>", methods=["GET"])
def api_admin_inventory(tech_username: str):
    err = require_admin()
    if err:
        return err
    con = get_db()
    cur = con.cursor()
    rows = cur.execute("""
        SELECT ti.part_id, ti.qty, p.sku, p.name
        FROM tech_inventory ti
        JOIN parts p ON p.id = ti.part_id
        WHERE ti.tech_username=?
        ORDER BY p.sku, p.name
    """, (tech_username,)).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows])

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
