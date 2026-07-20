# v3.0 安全加固说明

## 概述

v3.0 基于 v2.0 构建，在保留原有登录功能的前提下，引入了 SQLite 数据库支撑，并新增用户注册与用户搜索两项功能。功能开发完成后，对新增代码实施了安全审计，发现并修复了若干安全问题。本文档记录此次安全审计的详细过程。

---

## 安全问题分析

### 问题一：用户注册接口的 SQL 语句构造缺陷

**位置**：`app.py` register 路由（第 161 行）

**现象**：注册表单提交的用户名、密码、邮箱、手机号四个字段，通过 Python f-string 直接嵌入 SQL 语句。

```
username = request.form.get("username", "")
password = request.form.get("password", "")
email = request.form.get("email", "")
phone = request.form.get("phone", "")

sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
cur.execute(sql)
```

**问题分析**：上述代码中，四个变量均由用户通过 HTTP 请求提供，攻击者可任意构造其内容。若用户名输入为 `x'), ('y', 'z', 'a', 'b')--`，实际执行的 SQL 变为：

```sql
INSERT INTO users (...) VALUES ('x'), ('y', 'z', 'a', 'b')--', '...', '...', '...')
```

该语句向 users 表插入了两条记录，后半段 SQL 被 `--` 注释符忽略。更极端的输入 `x'); DROP TABLE users; --` 将直接删除 users 表，造成数据永久丢失。

### 问题二：用户搜索接口的 SQL 语句构造缺陷

**位置**：`app.py` search 路由（第 192 行）

**现象**：URL 参数 keyword 通过 f-string 拼接到 LIKE 子句中。

```
keyword = request.args.get("keyword", "")

sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
print(f"[SEARCH] SQL: {sql}")
cur.execute(sql)
```

**问题分析**：keyword 参数直接来自 URL 查询字符串，攻击者可在浏览器地址栏中自由构造。输入 `' OR 1=1 --` 后 SQL 变为：

```sql
SELECT * FROM users WHERE username LIKE '%' OR 1=1 -- %'
```

`OR 1=1` 使 WHERE 条件恒成立，`--` 注释掉后续语句，导致全表数据泄露。进一步使用 `UNION SELECT` 子句还可窃取其他数据库表中的数据。

### 问题三：缺乏输入有效性验证

注册接口的四个字段及搜索接口的关键词参数，均未做格式检查或长度限制。空值、超长字符串、特殊字符均可无障碍进入后端处理流程。

### 问题四：搜索接口未做认证限制

未登录用户可直接访问 `/search?keyword=xxx`，无需任何身份凭证即可查询系统用户数据，扩大了攻击面。

---

## 修复实施

### 针对问题一的修复

将 f-string 拼接的 SQL 替换为参数化查询，同时对用户输入实施格式校验。

**修复前代码：**

```python
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    email = request.form.get("email", "")
    phone = request.form.get("phone", "")

    conn = sqlite3.connect("data/users.db")
    cur = conn.cursor()
    sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
    logger.info(f"[REGISTER] 执行 SQL: {sql}")
    try:
        cur.execute(sql)
        conn.commit()
    except sqlite3.IntegrityError:
        return render_template("register.html", error="用户名已存在，请换一个")
    conn.close()
    return redirect("/login?msg=注册成功，请登录")
```

**修复后代码：**

```python
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()

    if not username or not password:
        return render_template("register.html", error="用户名和密码不能为空")
    if len(username) > 50 or len(password) > 128:
        return render_template("register.html", error="用户名或密码过长")
    if len(username) < 2:
        return render_template("register.html", error="用户名至少 2 个字符")
    if len(password) < 6:
        return render_template("register.html", error="密码至少 6 个字符")
    if email and not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return render_template("register.html", error="邮箱格式不正确")
    if phone and not re.match(r'^\+?\d{7,15}$', phone):
        return render_template("register.html", error="手机号格式不正确")

    conn = sqlite3.connect("data/users.db")
    cur = conn.cursor()
    sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
    try:
        cur.execute(sql, (username, password, email, phone))
        conn.commit()
    except sqlite3.IntegrityError:
        return render_template("register.html", error="用户名已存在，请换一个")
    conn.close()
    return redirect("/login?msg=注册成功，请登录")
```

**代码变更说明：**

- 第 9 行：`VALUES ('{username}', '{password}', '{email}', '{phone}')` 改为 `VALUES (?, ?, ?, ?)`，参数通过元组传入
- 第 5~8 行：每个字段增加 `.strip()` 处理及空值兜底
- 第 12~23 行：新增 6 项输入验证，覆盖空值、长度、邮箱格式、手机号格式
- 移除日志中打印完整 SQL 的语句

### 针对问题二的修复

将 f-string 拼接的 LIKE 查询替换为参数化查询，增加登录认证检查，移除控制台 SQL 输出。

**修复前代码：**

```python
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
        sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        logger.info(f"[SEARCH] 执行 SQL: {sql}")
        print(f"[SEARCH] SQL: {sql}")
        try:
            cur.execute(sql)
            rows = cur.fetchall()
            results = [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"[SEARCH] 查询异常: {e}")
        conn.close()

    return render_template("index.html", user=user_info, search_results=results, search_keyword=keyword)
```

**修复后代码：**

```python
@app.route("/search")
def search():
    username = session.get("username")
    if not username:
        return redirect("/login")

    user_info = get_safe_user_info(username)
    keyword = (request.args.get("keyword") or "").strip()

    if len(keyword) > 100:
        keyword = keyword[:100]

    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
        like_param = f"%{keyword}%"
        logger.info(f"[SEARCH] 搜索关键词: '{keyword}'")
        try:
            cur.execute(sql, (like_param, like_param))
            rows = cur.fetchall()
            results = [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"[SEARCH] 查询异常: {e}")
        conn.close()

    return render_template("index.html", user=user_info, search_results=results, search_keyword=keyword)
```

**代码变更说明：**

- 第 11~12 行：`LIKE '%{keyword}%'` 改为 `LIKE ?`，通配符 `%keyword%` 作为参数值传入
- 第 5~7 行：新增 session 检查，未登录用户重定向至登录页
- 第 10 行：新增关键词长度限制，超 100 字符自动截断
- 移除 `print(f"[SEARCH] SQL: {sql}")`，日志改为仅记录关键词文本

### 针对问题三的修复

在 register 路由中新增完整的输入验证逻辑，所有验证在 SQL 执行之前完成，不合法输入直接返回错误页面。

```python
# register 路由 — 新增的输入验证代码
username = (request.form.get("username") or "").strip()
password = request.form.get("password") or ""
email = (request.form.get("email") or "").strip()
phone = (request.form.get("phone") or "").strip()

if not username or not password:
    return render_template("register.html", error="用户名和密码不能为空")
if len(username) > 50 or len(password) > 128:
    return render_template("register.html", error="用户名或密码过长")
if len(username) < 2:
    return render_template("register.html", error="用户名至少 2 个字符")
if len(password) < 6:
    return render_template("register.html", error="密码至少 6 个字符")
if email and not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
    return render_template("register.html", error="邮箱格式不正确")
if phone and not re.match(r'^\+?\d{7,15}$', phone):
    return render_template("register.html", error="手机号格式不正确")
```

验证规则汇总：

| 字段 | 验证规则 |
|------|---------|
| 用户名 | 必填，长度 2~50 字符 |
| 密码 | 必填，长度 6~128 字符 |
| 邮箱 | 选填，须符合 `xxx@yyy.zzz` 格式 |
| 手机号 | 选填，7~15 位数字，允许前导 `+` |
| 搜索关键词 | 最长 100 字符，超长自动截断 |

### 针对问题四的修复

search 路由入口处增加 session 检查，未持有有效会话的用户将被重定向至登录页面，无法访问搜索功能。

```python
# search 路由 — 开头新增的登录检查
username = session.get("username")
if not username:
    return redirect("/login")
```

---

## 验证结论

### 注入有效性测试

使用修复前可成功攻击的 payload 逐一验证：

| 测试用例 | 预期 | 结果 |
|---------|------|------|
| 搜索 `' OR 1=1 --` | 不应返回全部用户 | 通过，未命中任何用户 |
| 搜索 `' UNION SELECT 1,'a','b','c','d' --` | 不应执行 UNION 查询 | 通过，无异常结果 |
| 注册用户名 `x'); DROP TABLE users; --` | 不应删除表 | 通过，用户名被正常存储 |
| 注册用户名 `admin', 'hacked')--` | 不应覆盖数据 | 通过，作为普通用户名处理 |

### 正常功能测试

| 测试场景 | 结果 |
|---------|------|
| 搜索已有用户名 | 正常返回结果 |
| 搜索不存在的关键词 | 返回空结果，显示"无搜索结果" |
| 不输入关键词访问搜索页 | 页面正常加载，不执行查询 |
| 填写合法信息注册 | 注册成功，跳转登录页 |
| 注册已存在的用户名 | 提示"用户名已存在" |
| 未登录直接访问 `/search` | 重定向至登录页 |

---

## 附：版本变更概要

v3.0 在 v2.0（安全加固版）基础上新增：

| 变更项 | 说明 |
|-------|------|
| SQLite 数据库 | 新增 `init_db()`，自动初始化 `data/users.db`，建 users 表 |
| 用户注册 | 新增 `/register` 路由及对应模板，SQL 注入已修复 |
| 用户搜索 | 新增 `/search` 路由，搜索结果嵌入首页，SQL 注入已修复 |

登录验证逻辑保持不变，仍基于内存字典 `USERS` + bcrypt 密码哈希。通过注册功能写入 SQLite 的用户数据暂不参与登录校验。

---

## 项目结构

```
3.0/
├── app.py                     # 主程序
├── data/users.db              # SQLite 数据库（自动生成）
├── templates/
│   ├── base.html              # 导航栏新增"注册"入口
│   ├── index.html             # 首页集成搜索面板
│   ├── login.html
│   └── register.html          # 新增注册页面
├── static/css/style.css
├── setup.sh
└── requirements.txt
```

## 启动方式

```bash
cd /opt/Class01/3.0
./setup.sh
python3 app.py
```

服务监听地址：`http://127.0.0.1:5000`，仅本机可访问。
