import secrets
import logging
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
        return render_template("login.html")

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


# ── 登出 ──────────────────────────────────────────────
@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info(f"User '{username}' logged out")
    return redirect("/")


# ── 启动 ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("  用户管理系统 - 安全加固版")
    print("  监听地址: 127.0.0.1:5000")
    print("  Debug模式: 关闭")
    print("=" * 50)
    app.run(debug=False, host="127.0.0.1", port=5000)
