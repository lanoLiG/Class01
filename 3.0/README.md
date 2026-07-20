# 用户信息管理平台 v3.0

> 在 [v2.0](../2.0) 的基础上，**保持原有登录功能不变**，新增 SQLite 数据库存储、用户注册和用户搜索三大功能，并对 SQL 注入漏洞进行了完整修复。
>
> 适用课程阶段：Web 安全 — SQL 注入原理与防御

---

## 目录

1. [v3.0 功能总览](#v30-功能总览)
2. [v3.0 详细改动说明](#v30-详细改动说明)
   - [新增：SQLite 数据库](#1-新增sqlite-数据库)
   - [新增：用户注册 /register（含注入修复）](#2-新增用户注册-register含注入修复)
   - [新增：用户搜索 /search（含注入修复）](#3-新增用户搜索-search含注入修复)
   - [修改：首页 index.html 增加搜索功能](#4-修改首页-indexhtml)
   - [修改：导航栏 base.html 增加注册链接](#5-修改导航栏-basehtml)
   - [新增：注册页面 register.html](#6-新增注册页面-registerhtml)
3. [v2.0 存在的问题与 v3.0 的改进](#v20-存在的问题与-v30-的改进)
4. [项目结构](#项目结构)
5. [路由说明一览](#路由说明一览)
6. [环境配置与运行](#环境配置与运行)

---

## v3.0 功能总览

v3.0 是一个具备完整用户管理功能的 Flask Web 应用，包含以下功能模块：

| 功能 | 路由 | 说明 |
|------|------|------|
| **首页** | `GET /` | 已登录用户展示个人信息 + 搜索框；未登录提示登录 |
| **用户登录** | `GET/POST /login` | 沿用 v2.0 的安全登录（bcrypt 哈希验证、CSRF 保护、限流） |
| **用户注册** | `GET/POST /register` | **v3.0 新增** — 填写信息写入 SQLite 数据库 |
| **用户搜索** | `GET /search` | **v3.0 新增** — 按用户名/邮箱模糊搜索，需登录后使用 |
| **用户登出** | `GET /logout` | 清除 session |

**安全特性**：注册和搜索的 SQL 已使用 **参数化查询**（`?` 占位符）修复 SQL 注入漏洞，
并增加了输入验证和登录权限校验。

---

## v3.0 详细改动说明

### 1. 新增：SQLite 数据库

| 改动项 | 说明 |
|--------|------|
| **涉及文件** | `app.py` — 新增 `init_db()` 函数 |
| **数据库位置** | `data/users.db`（自动创建 `data/` 目录） |
| **用户表结构** | `id`(自增主键)、`username`(唯一)、`password`、`email`、`phone` |
| **默认数据** | 插入 `admin/admin123` 和 `alice/alice2025`，使用 `INSERT OR IGNORE` 防止重复 |

```python
def init_db():
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
    for u, p, e, ph in [("admin","admin123","admin@example.com","13800138000"),
                         ("alice","alice2025","alice@example.com","13900139001")]:
        cur.execute("INSERT OR IGNORE INTO users ...", (u, p, e, ph))
    conn.commit()
    conn.close()
```

### 2. 新增：用户注册 `/register`（含注入修复）

| 改动项 | 说明 |
|--------|------|
| **涉及文件** | `app.py` — 新增 `/register` 路由；`templates/register.html` — 新增注册页面 |
| **路由方法** | GET 显示注册表单，POST 提交注册 |
| **表单字段** | 用户名、密码、邮箱、手机号 |
| **SQL 构建** | **参数化查询** `VALUES (?, ?, ?, ?)` — 修复了 f-string 拼接导致的 SQL 注入 |
| **输入验证** | 空值检测、长度限制（用户名 2–50、密码 6–128）、邮箱/手机格式正则校验 |
| **注册成功** | 重定向至 `/login?msg=注册成功，请登录` |
| **重复用户** | 捕获 `IntegrityError`，提示"用户名已存在，请换一个" |

```python
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    # POST — 使用参数化查询（修复 SQL 注入）
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    # 输入验证...
    conn = sqlite3.connect("data/users.db")
    cur = conn.cursor()
    sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
    cur.execute(sql, (username, password, email, phone))
    conn.commit()
    # ...
```

### 3. 新增：用户搜索 `/search`（含注入修复）

| 改动项 | 说明 |
|--------|------|
| **涉及文件** | `app.py` — 新增 `/search` 路由；`templates/index.html` — 增加搜索框和结果表格 |
| **路由方法** | 仅 GET |
| **传入参数** | `?keyword=xxx` |
| **SQL 构建** | **参数化查询** `LIKE ?` — 修复了 f-string 拼接导致的 SQL 注入 |
| **登录限制** | 未登录用户重定向到 `/login` |
| **搜索范围** | 用户名或邮箱含有关键词 |
| **结果展示** | 首页表格显示 ID、用户名、邮箱、手机 |
| **空结果** | 显示"无搜索结果" |

```python
@app.route("/search")
def search():
    username = session.get("username")
    if not username:          # 要求登录
        return redirect("/login")
    user_info = get_safe_user_info(username)
    keyword = (request.args.get("keyword") or "").strip()
    if keyword:
        conn = sqlite3.connect("data/users.db")
        cur = conn.cursor()
        sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
        cur.execute(sql, (f"%{keyword}%", f"%{keyword}%"))
        # ...
```

### 4. 修改：首页 index.html

搜索结果区域新增在已登录状态下：
- 搜索输入框 + 搜索按钮
- 关键词存在时显示结果表格（ID、用户名、邮箱、手机）
- 关键词存在但无结果时显示"无搜索结果"

### 5. 修改：导航栏 base.html

未登录状态下增加"注册"链接：

```html
{% else %}
    <a href="/register" class="nav-link">注册</a>   <!-- ← 新增 -->
    <a href="/login" class="nav-link">登录</a>
{% endif %}
```

### 6. 新增：注册页面 register.html

- 继承 `base.html`
- 包含用户名、密码、邮箱、手机号四个输入框
- 注册按钮
- 底部"已有账号？立即登录"链接
- 携带 CSRF token

---

## v2.0 存在的问题与 v3.0 的改进

v2.0 虽然对 v1.0 做了完整的安全加固，但在功能完整性和教学用途上仍存在以下不足：

### 问题一：用户数据无法持久化

| 维度 | v2.0 的问题 | v3.0 的改进 |
|------|------------|-------------|
| **数据存储** | 使用内存字典 `USERS = {...}`，所有用户信息硬编码在源码中 | 引入 SQLite 数据库 `data/users.db`，数据持久化到磁盘，重启不丢失 |
| **可扩展性** | 无法动态添加用户，只能修改源码 | `init_db()` 自动建表 + `INSERT OR IGNORE`，支持后续注册功能 |

### 问题二：无法注册新用户

| 维度 | v2.0 的问题 | v3.0 的改进 |
|------|------------|-------------|
| **注册功能** | ❌ 完全缺失，系统只有 admin 和 alice 两个固定账号 | ✅ 新增 `/register` 路由，支持 GET 显示表单 + POST 提交注册 |
| **用户体验** | 新用户无法自助注册，必须由开发者修改代码 | 填写用户名、密码、邮箱、手机号即可自助注册 |

### 问题三：无法搜索用户

| 维度 | v2.0 的问题 | v3.0 的改进 |
|------|------------|-------------|
| **搜索功能** | ❌ 完全缺失 | ✅ 新增 `/search` 路由 + 首页搜索框（仅登录用户可用） |
| **搜索维度** | 无 | 支持用户名和邮箱双维度 `LIKE` 模糊匹配 |

### 关于登录功能的说明

v3.0 **保持原有登录功能不变**，仍使用内存字典 `USERS` + `generate_password_hash()` bcrypt 验证。这意味着通过 `/register` 注册的新用户数据虽然写入了 SQLite，但登录时不会查询数据库，所以**新注册用户暂时无法登录系统**。这是为了"保持原有登录功能不变"的设计约束，后续版本可将登录改为查 SQLite 来解决。

---

## 项目结构

```
3.0/
├── app.py                     # Flask 主应用（登录 + 注册 + 搜索，SQL 注入已修复）
├── setup.sh                   # 环境配置脚本
├── requirements.txt           # pip 依赖清单
├── data/
│   └── users.db              # SQLite 数据库文件（首次启动自动生成）
├── templates/
│   ├── base.html              # 基础模板（导航栏含"注册"链接）
│   ├── index.html             # 首页（已登录含搜索框 + 结果表格）
│   ├── login.html             # 登录页（含 CSRF token）
│   └── register.html          # 注册页（新增，含 CSRF token）
└── static/css/
    └── style.css              # 样式文件
```

## 路由说明一览

| 路由 | 方法 | 功能 | 来源 | 说明 |
|------|------|------|------|------|
| `/` | GET | 首页 | 继承 v2.0 | 已登录显示用户信息 + 搜索框；未登录提示登录 |
| `/login` | GET / POST | 登录 | 继承 v2.0 | GET 显示表单，POST bcrypt 验证 + CSRF + 限流 |
| `/logout` | GET | 登出 | 继承 v2.0 | 清除 session 并跳转首页 |
| `/register` | GET / POST | 注册 | **v3.0 新增** | 参数化查询，含输入验证，SQL 注入已修复 |
| `/search` | GET | 搜索 | **v3.0 新增** | 需登录，参数化查询 LIKE，SQL 注入已修复 |

---

## 环境配置与运行

### 方式一：setup.sh 自动配置（推荐）

```bash
cd /opt/Class01/3.0
./setup.sh
python3 app.py
```

### 方式二：手动安装（apt）

```bash
cd /opt/Class01/3.0
sudo apt install -y python3-flask python3-flaskext.wtf python3-flask-limiter
python3 app.py
```

### 方式三：虚拟环境

```bash
cd /opt/Class01/3.0
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
python3 app.py
```

> 服务仅监听 `http://127.0.0.1:5000`，仅本机可访问。

> ⚠️ 不要直接执行 `pip install -r requirements.txt`（Kali 会报 PEP 668 错误），请使用上述三种方式之一。
