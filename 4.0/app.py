import secrets
import logging
import sqlite3
import os
import re
import uuid
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, abort, url_for
from werkzeug.utils import secure_filename
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
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
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

    # POST
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()

    # 输入验证
    if not username or not password:
        logger.warning(f"Register with empty fields from {request.remote_addr}")
        return render_template("register.html", error="用户名和密码不能为空")

    if len(username) > 50 or len(password) > 128:
        logger.warning(f"Register with oversized input from {request.remote_addr}")
        return render_template("register.html", error="用户名或密码过长")

    if len(username) < 2:
        return render_template("register.html", error="用户名至少 2 个字符")

    if len(password) < 6:
        return render_template("register.html", error="密码至少 6 个字符")

    if email:
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return render_template("register.html", error="邮箱格式不正确")

    if phone:
        if not re.match(r'^\+?\d{7,15}$', phone):
            return render_template("register.html", error="手机号格式不正确")

    conn = sqlite3.connect("data/users.db")
    cur = conn.cursor()
    # 使用参数化查询修复 SQL 注入
    sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
    try:
        cur.execute(sql, (username, password, email, phone))
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
    # 要求登录才能搜索（减少攻击面）
    username = session.get("username")
    if not username:
        return redirect("/login")

    user_info = get_safe_user_info(username)
    keyword = (request.args.get("keyword") or "").strip()

    # 关键词长度限制
    if len(keyword) > 100:
        keyword = keyword[:100]

    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # 使用参数化查询修复 SQL 注入
        sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
        like_param = f"%{keyword}%"
        logger.info(f"[SEARCH] 搜索关键词: '{keyword}'")
        try:
            cur.execute(sql, (like_param, like_param))
            rows = cur.fetchall()
            results = [dict(row) for row in rows]
            logger.info(f"[SEARCH] 查询到 {len(results)} 条结果")
        except Exception as e:
            logger.error(f"[SEARCH] 查询异常: {e}")
        conn.close()

    return render_template("index.html", user=user_info, search_results=results, search_keyword=keyword)


# ── 用户头像上传 ──────────────────────────────────────
# 允许的图片扩展名
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}


def allowed_file(filename):
    """检查文件扩展名是否在允许列表中"""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def is_actual_image(file_stream):
    """通过文件头部魔数（Magic Bytes）验证是否为真实图片，防止 MIME 伪造"""
    header = file_stream.read(12)
    file_stream.seek(0)

    # JPEG: FF D8 FF
    if header[:3] == b'\xff\xd8\xff':
        return True
    # PNG: 89 50 4E 47 0D 0A 1A 0A
    if header[:8] == b'\x89PNG\r\n\x1a\n':
        return True
    # GIF: GIF87a / GIF89a
    if header[:6] in (b'GIF87a', b'GIF89a'):
        return True
    # WebP: RIFF .... WEBP
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
        return True
    # BMP: 42 4D
    if header[:2] == b'BM':
        return True

    return False


@app.route("/upload", methods=["GET", "POST"])
def upload():
    username = session.get("username")
    if not username:
        return redirect("/login")

    if request.method == "GET":
        return render_template("upload.html")

    # POST
    file = request.files.get("file")
    if not file or file.filename == "":
        logger.warning(f"[UPLOAD] 用户 '{username}' 未选择文件")
        return render_template("upload.html", error="请选择要上传的文件")

    # ── 漏洞修复①：检查文件扩展名 ────────────────
    if not allowed_file(file.filename):
        logger.warning(f"[UPLOAD] 用户 '{username}' 上传了不允许的文件类型: {file.filename}")
        return render_template("upload.html", error="仅允许上传图片文件（png/jpg/jpeg/gif/webp/bmp）")

    # ── 漏洞修复②：魔数检查，防止伪造文件 ─────────
    if not is_actual_image(file):
        logger.warning(f"[UPLOAD] 用户 '{username}' 上传的文件内容不是真实图片: {file.filename}")
        return render_template("upload.html", error="文件内容不是有效的图片格式")

    # 确保上传目录存在
    upload_dir = os.path.join(app.root_path, "static", "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    # ── 漏洞修复③：secure_filename 防止路径遍历 ──
    original_filename = file.filename
    safe_name = secure_filename(original_filename)
    ext = safe_name.rsplit('.', 1)[1].lower() if '.' in safe_name else 'png'

    # ── 漏洞修复④：UUID 唯一化命名，防止覆盖 ─────
    unique_name = f"{uuid.uuid4().hex}_{safe_name}"
    file.save(os.path.join(upload_dir, unique_name))

    file_url = url_for("static", filename=f"uploads/{unique_name}")
    logger.info(f"[UPLOAD] 用户 '{username}' 上传文件: '{original_filename}' -> 保存为: '{unique_name}'")
    return render_template(
        "upload.html",
        success=True,
        file_url=file_url,
        filename=unique_name,
        original_filename=original_filename,
    )


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
    print("  用户管理系统 - 头像上传版")
    print("  监听地址: 127.0.0.1:5000")
    print("  Debug模式: 关闭")
    print("=" * 50)
    app.run(debug=False, host="127.0.0.1", port=5000)
