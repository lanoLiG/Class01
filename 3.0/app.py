import secrets
import logging
import sqlite3
import os
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── 日志配置 ──────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("access")

# ── 应用初始化 ────────────────────────────────────────
app = Flask(__name__)

app.config.update(
    SECRET_KEY=secrets.token_hex(32),
    SESSION_PERMANENT=False,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    WTF_CSRF_TIME_LIMIT=3600,
)

csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://",
)

# ── SQLite 数据库初始化 ──────────────────────────────
def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)
    # 插入默认用户（INSERT OR IGNORE 防止重复）
    default_users = [
        ("admin", "admin123", "admin@example.com", "13800138000"),
        ("alice", "alice2025", "alice@example.com", "13900139001"),
    ]
    for u, p, e, ph in default_users:
        cur.execute(
            "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
            (u, p, e, ph),
        )
    conn.commit()
    conn.close()
    logger.info("Database initialized: data/users.db")


# ── 用户数据库（密码已哈希） ─────────────────────────
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


# ── 工具函数 ──────────────────────────────────────────
def get_safe_user_info(username):
    """返回不包含密码字段的用户信息"""
    user = USERS.get(username)
    if user is None:
        return None
    return {k: v for k, v in user.items() if k != "password"}


# ── 首页 ──────────────────────────────────────────────
@app.route("/")
def index():
    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None
    return render_template("index.html", user=user_info)


# ── 登录 ──────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "GET":
        msg = request.args.get("msg", "")
        return render_template("login.html", msg=msg)

    # POST
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    # 输入基本校验
    if not username or not password:
        logger.warning(f"Login with empty fields from {request.remote_addr}")
        return render_template("login.html", error="用户名和密码不能为空")

    if len(username) > 64 or len(password) > 128:
        logger.warning(f"Login with oversized input from {request.remote_addr}")
        return render_template("login.html", error="输入内容过长")

    user = USERS.get(username)

    if user is None or not check_password_hash(user["password"], password):
        logger.info(f"Failed login for '{username}' from {request.remote_addr}")
        # 统一的模糊错误信息，防止用户枚举
        return render_template("login.html", error="用户名或密码错误")

    # 登录成功
    session["username"] = username
    session.permanent = False
    logger.info(f"Successful login for '{username}' from {request.remote_addr}")

    user_info = get_safe_user_info(username)
    return render_template("index.html", user=user_info)


# ── 注册 ──────────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    # POST — 使用 f-string 字符串拼接插入 SQLite
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")

    conn = sqlite3.connect("data/users.db")
    cur = conn.cursor()
    # 注意：使用 f-string 拼接，不要参数化查询（教学用途）
    sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
    logger.info(f"[REGISTER] 执行 SQL: {sql}")
    try:
        cur.execute(sql)
        conn.commit()
        logger.info(f"[REGISTER] 用户 '{username}' 注册成功")
    except sqlite3.IntegrityError as e:
        conn.close()
        logger.warning(f"[REGISTER] 用户 '{username}' 注册失败（可能已存在）: {e}")
        return render_template("register.html", error="用户名已存在，请换一个")
    except Exception as e:
        conn.close()
        logger.error(f"[REGISTER] 注册异常: {e}")
        return render_template("register.html", error="注册失败，请稍后重试")
    conn.close()
    return redirect("/login?msg=注册成功，请登录")


# ── 搜索 ──────────────────────────────────────────────
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None

    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # 注意：使用 f-string 拼接，不要参数化查询（教学用途）
        sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        logger.info(f"[SEARCH] 执行 SQL: {sql}")
        print(f"[SEARCH] SQL: {sql}")
        try:
            cur.execute(sql)
            rows = cur.fetchall()
            results = [dict(row) for row in rows]
            logger.info(f"[SEARCH] 查询到 {len(results)} 条结果")
        except Exception as e:
            logger.error(f"[SEARCH] 查询异常: {e}")
        conn.close()

    return render_template("index.html", user=user_info, search_results=results, search_keyword=keyword)


# ── 登出 ──────────────────────────────────────────────
@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info(f"User '{username}' logged out")
    return redirect("/")


# ── 启动 ──────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print("  用户管理系统 - 安全加固版")
    print("  监听地址: 127.0.0.1:5000")
    print("  Debug模式: 关闭")
    print("=" * 50)
    app.run(debug=False, host="127.0.0.1", port=5000)
