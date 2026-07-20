# 用户信息管理平台 v3.0

> 在 [v2.0](../2.0) 的基础上，**保持原有登录功能不变**，新增 SQLite 数据库存储、用户注册和用户搜索三大功能，同时引入 SQL 注入教学场景。
>
> 适用课程阶段：Web 安全 — SQL 注入原理与防御

---

## 目录

1. [v3.0 功能总览](#v30-功能总览)
2. [v3.0 详细改动说明](#v30-详细改动说明)
   - [新增：SQLite 数据库](#1-新增sqlite-数据库)
   - [新增：用户注册 /register](#2-新增用户注册-register)
   - [新增：用户搜索 /search](#3-新增用户搜索-search)
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
| **用户搜索** | `GET /search` | **v3.0 新增** — 按用户名/邮箱模糊搜索，结果表格展示 |
| **用户登出** | `GET /logout` | 清除 session |

**教学特性**：注册和搜索的 SQL 均使用 **f-string 字符串拼接**（非参数化查询），并在控制台打印原始 SQL，用于演示 SQL 注入攻击。

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
# app.py — 数据库初始化
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
    # 插入默认用户
    for u, p, e, ph in [("admin","admin123","admin@example.com","13800138000"),
                         ("alice","alice2025","alice@example.com","13900139001")]:
        cur.execute("INSERT OR IGNORE INTO users ...", (u, p, e, ph))
    conn.commit()
    conn.close()
```

### 2. 新增：用户注册 `/register`

| 改动项 | 说明 |
|--------|------|
| **涉及文件** | `app.py` — 新增 `/register` 路由；`templates/register.html` — 新增注册页面 |
| **路由方法** | GET 显示注册表单，POST 提交注册 |
| **表单字段** | 用户名、密码、邮箱、手机号 |
| **数据库写入** | **f-string 拼接 SQL**（非参数化查询） |
| **注册成功** | 重定向至 `/login?msg=注册成功，请登录` |
| **重复用户** | 捕获 `IntegrityError`，提示"用户名已存在，请换一个" |

```python
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    # POST — 使用 f-string 拼接（教学用途，存在 SQL 注入风险）
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")
    conn = sqlite3.connect("data/users.db")
    cur = conn.cursor()
    sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
    logger.info(f"[REGISTER] 执行 SQL: {sql}")
    # ...try/except 执行
```

### 3. 新增：用户搜索 `/search`

| 改动项 | 说明 |
|--------|------|
| **涉及文件** | `app.py` — 新增 `/search` 路由；`templates/index.html` — 增加搜索框和结果表格 |
| **路由方法** | 仅 GET |
| **传入参数** | `?keyword=xxx` |
| **数据库查询** | **f-string 拼接 SQL** 实现 LIKE 模糊匹配 |
| **搜索范围** | 用户名或邮箱含有关键词 |
| **结果展示** | 首页表格显示 ID、用户名、邮箱、手机 |
| **空结果** | 显示"无搜索结果" |
| **教学特性** | **控制台打印执行 SQL**，便于观察注入效果 |

```python
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    # ...
    sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
    logger.info(f"[SEARCH] 执行 SQL: {sql}")
    print(f"[SEARCH] SQL: {sql}")   # ← 控制台打印，观察 SQL 注入
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

### 🔴 问题一：用户数据无法持久化

```
v2.0 状态：
  USERS = {
      "admin": { "username": "admin", ... },   ← 写死在代码中
      "alice": { "username": "alice", ... },   ← 程序重启后一切还原
  }
```

| 维度 | v2.0 的问题 | v3.0 的改进 |
|------|------------|-------------|
| **数据存储** | 使用内存字典 `USERS = {...}`，所有用户信息硬编码在源码中 | 引入 SQLite 数据库 `data/users.db`，数据持久化到磁盘，重启不丢失 |
| **可扩展性** | 无法动态添加用户，只能修改源码 | `init_db()` 自动建表 + `INSERT OR IGNORE`，支持后续注册功能 |
| **代码耦合** | 用户数据和业务逻辑混在一起 | 数据库独立存储，代码结构更清晰 |

### 🟠 问题二：无法注册新用户

| 维度 | v2.0 的问题 | v3.0 的改进 |
|------|------------|-------------|
| **注册功能** | ❌ 完全缺失，系统只有 admin 和 alice 两个固定账号 | ✅ 新增 `/register` 路由，支持 GET 显示表单 + POST 提交注册 |
| **用户体验** | 新用户无法自助注册，必须由开发者修改代码 | 填写用户名、密码、邮箱、手机号即可自助注册 |
| **反馈机制** | 无 | 注册成功跳转登录页提示"注册成功，请登录"；重复用户名提示"用户名已存在" |

### 🟡 问题三：无法搜索用户

| 维度 | v2.0 的问题 | v3.0 的改进 |
|------|------------|-------------|
| **搜索功能** | ❌ 完全缺失 | ✅ 新增 `/search` 路由 + 首页搜索框 |
| **搜索维度** | 无 | 支持用户名和邮箱双维度 `LIKE` 模糊匹配 |
| **结果展示** | 无 | 表格形式展示 ID、用户名、邮箱、手机 |
| **空结果处理** | 无 | 关键词存在但无匹配时显示"无搜索结果" |

### 🔵 问题四：无法演示 SQL 注入教学

| 维度 | v2.0 的问题 | v3.0 的改进 |
|------|------------|-------------|
| **数据库交互** | ❌ 完全不涉及数据库 | ✅ 引入 SQLite，注册和搜索均操作数据库 |
| **SQL 注入演示** | ❌ 无 SQL 拼接，无法展示注入攻击 | ✅ **刻意**使用 f-string 拼接 SQL，不转义不过滤，控制台打印原始 SQL |
| **教学价值** | 只能讲解安全加固（CSRF、哈希、限流等） | 可同时演示**安全加固**和**SQL 注入**两个主题 |

```python
# v3.0 刻意保留的 SQL 注入漏洞（教学用途）
# 用户输入直接拼入 SQL，没有任何过滤或转义

# /register 注入点
sql = f"INSERT INTO users ... VALUES ('{username}', '{password}', '{email}', '{phone}')"

# /search 注入点
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
print(f"[SEARCH] SQL: {sql}")  # 控制台可见注入效果
```

### 📌 关于登录功能的说明

v3.0 **保持原有登录功能不变**，仍使用内存字典 `USERS` + `generate_password_hash()` bcrypt 验证。这意味着通过 `/register` 注册的新用户数据虽然写入了 SQLite，但登录时不会查询数据库，所以**新注册用户暂时无法登录系统**。这是为了"保持原有登录功能不变"的设计约束，后续版本可将登录改为查 SQLite 来解决。

---

## 项目结构

```
3.0/
├── app.py                     # Flask 主应用（登录 + 注册 + 搜索）
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
| `/register` | GET / POST | 注册 | **v3.0 新增** | GET 显示表单，POST f-string 拼接写入 SQLite |
| `/search` | GET | 搜索 | **v3.0 新增** | `?keyword=` f-string 拼接 LIKE 查询，控制台打印 SQL |

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
>
> ⚠️ 不要直接执行 `pip install -r requirements.txt`（Kali 会报 PEP 668 错误），请使用上述三种方式之一。
