# SQL 注入漏洞修复报告 — v3.0

> **项目名称**：Class01 用户管理系统  
> **修复日期**：2026-07-20  
> **风险等级**：严重（Critical）  
> **漏洞类型**：SQL 注入（SQL Injection）

---

## 一、漏洞概述

v3.0 在 [v2.0](../2.0) 基础上新增了 SQLite 数据库、用户注册 `/register` 和用户搜索 `/search` 功能。在初始构建中，注册和搜索使用了 **f-string 字符串拼接** 的方式构建 SQL 语句，用户输入直接嵌入 SQL 代码中，导致存在 SQL 注入漏洞。

| 漏洞位置 | SQL 构建方式 | 风险 |
|---------|-------------|------|
| `/register` — INSERT 语句 | `f"VALUES ('{username}', '{password}', ...)"` | 攻击者可插入任意数据、删表 |
| `/search` — SELECT LIKE 语句 | `f"WHERE username LIKE '%{keyword}%'"` | 攻击者可查看全部用户数据、UNION 注入 |

---

## 二、修复清单

| # | 漏洞位置 | 漏洞类型 | 风险等级 | 修复状态 |
|---|---------|---------|:--------:|:--------:|
| 1 | `/register` — INSERT | SQL 注入（f-string 拼接） | 🔴 严重 | ✅ 已修复 |
| 2 | `/search` — SELECT LIKE | SQL 注入（f-string 拼接） | 🔴 严重 | ✅ 已修复 |
| 3 | 注册 + 搜索 — 用户输入 | 缺乏输入验证 | 🟡 中危 | ✅ 已修复 |
| 4 | `/search` — 未登录可访问 | 认证缺失 | 🟡 中危 | ✅ 已修复 |

---

## 三、详细修复说明

### 修复 1：注册功能 SQL 注入

**涉及文件**：`app.py:147-199` — register 路由

**漏洞代码（f-string 拼接）：**
```python
# ❌ 用户输入直接拼入 SQL 语句
username = request.form.get("username", "")
password = request.form.get("password", "")
email = request.form.get("email", "")
phone = request.form.get("phone", "")

sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
logger.info(f"[REGISTER] 执行 SQL: {sql}")
cur.execute(sql)  # 直接执行拼接后的 SQL
```

**注入原理：**
```
当 username 输入为: hacker', 'pass', 'h@x.com', '123')--
拼接结果: INSERT INTO users (...) VALUES ('hacker', 'pass', 'h@x.com', '123')--', '...', '...', '...')
-- 注释符使后续 SQL 失效，攻击者可插入任意数据

更严重: ', 'x'); DROP TABLE users; --
→ INSERT INTO users (...) VALUES ('', 'x'); DROP TABLE users; --', '...')
→ 直接删除整个 users 表
```

**修复代码（参数化查询 + 输入验证）：**
```python
# ✅ 使用 ? 占位符，SQL 结构与用户数据分离
username = (request.form.get("username") or "").strip()
password = request.form.get("password") or ""
email = (request.form.get("email") or "").strip()
phone = (request.form.get("phone") or "").strip()

# 输入验证
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
cur.execute(sql, (username, password, email, phone))
conn.commit()
```

**修复措施：**

| 措施 | 说明 |
|------|------|
| **参数化查询** | `VALUES (?, ?, ?, ?)` — 参数由 SQLite 驱动自动转义，单引号等特殊字符不影响 SQL 结构 |
| **空值检测** | 用户名和密码为空时直接返回错误 |
| **长度限制** | 用户名 2–50 字符、密码 6–128 字符 |
| **格式校验** | 邮箱正则 `xxx@yyy.zzz`、手机号正则 `+`可选 + 7–15 位数字 |
| **日志清理** | 移除 `logger.info(f"[REGISTER] 执行 SQL: {sql}")`，不再打印含用户输入的 SQL |

---

### 修复 2：搜索功能 SQL 注入

**涉及文件**：`app.py:202-235` — search 路由

**漏洞代码（f-string 拼接）：**
```python
# ❌ URL 参数直接拼入 LIKE 子句
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None
    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        cur = conn.cursor()
        sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SEARCH] SQL: {sql}")   # 控制台暴露完整 SQL
        cur.execute(sql)
```

**注入原理：**
```
?keyword=' OR 1=1 --
→ SELECT * FROM users WHERE username LIKE '%' OR 1=1 -- %'
→ WHERE 恒为真，返回全部用户数据

?keyword=' UNION SELECT 1,'admin','pwd','email','phone' --
→ 窃取其他表数据
```

**修复代码（参数化查询 + 登录校验）：**
```python
# ✅ 参数化查询，仅登录用户可用
@app.route("/search")
def search():
    username = session.get("username")
    if not username:                    # 要求登录
        return redirect("/login")

    user_info = get_safe_user_info(username)
    keyword = (request.args.get("keyword") or "").strip()

    if len(keyword) > 100:              # 长度限制
        keyword = keyword[:100]

    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        cur = conn.cursor()
        sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
        like_param = f"%{keyword}%"
        logger.info(f"[SEARCH] 搜索关键词: '{keyword}'")
        cur.execute(sql, (like_param, like_param))   # 参数自动转义
```

**修复措施：**

| 措施 | 说明 |
|------|------|
| **参数化查询** | `LIKE ?` — 通配符 `%` 作为参数值传入，不拼接到 SQL 模板 |
| **登录校验** | 未登录用户重定向到 `/login` |
| **长度限制** | 关键词最长 100 字符，超长截断 |
| **日志安全** | 移除 `print(f"[SEARCH] SQL: {sql}")`，改为记录安全的关键词文本 |

---

### 修复 3：输入验证

| 字段 | 验证规则 | 说明 |
|------|---------|------|
| 用户名 | 必填，2–50 字符 | 防止空值绕过长输入 |
| 密码 | 必填，6–128 字符 | 防止空密码和超长输入 |
| 邮箱 | 可选，正则 `xxx@yyy.zzz` | 防止构造恶意字符串 |
| 手机号 | 可选，正则 `+`可选 + 7–15 位数字 | 防止非数字字符 |
| 搜索关键词 | 最长 100 字符，超长截断 | 防止资源耗尽 |

---

### 修复 4：搜索接口登录认证

```python
# 新增：未登录用户不可搜索
username = session.get("username")
if not username:
    return redirect("/login")
```

---

## 四、修复验证

### UNION 注入测试
```
输入: keyword = ' UNION SELECT 1,'inj','inj@x.com','138'--
预期: 参数化查询将整个字符串作为普通文本进行模糊匹配，不执行 UNION 子查询
结果: 不会返回 "inj"，搜索无结果
```

### OR 注入测试
```
输入: keyword = ' OR '1'='1
预期: 单引号被自动转义，作为普通文本搜索
结果: 不会返回全部用户
```

### 注册注入测试
```
输入: username = "hacker', 'pass', 'h@x.com', '123')--"
预期: 整个字符串作为用户名处理
结果: INSERT 正常执行，单引号被正确转义存储
```

### 正常功能测试

| 测试场景 | 输入 | 预期结果 |
|---------|------|---------|
| 搜索 "admin" | `keyword=admin` | 返回 admin 用户信息 |
| 搜索 "alice" | `keyword=alice` | 返回 alice 用户信息 |
| 搜索空值 | `keyword=` | 不执行搜索 |
| 注册新用户 | 合法信息 | 成功注册并跳转登录页 |
| 注册重名 | 已存在用户名 | 提示"用户名已存在" |
| 未登录搜索 | 直接访问 `/search` | 重定向到 `/login` |

---

## 五、修复前后对比总结

| 维度 | 修复前（f-string 拼接） | 修复后（参数化查询） |
|------|------------------------|--------------------|
| **SQL 构建方式** | `f"SELECT ... '{keyword}'..."` | `SELECT ... ?` + 参数元组 |
| **特殊字符处理** | 直接嵌入 SQL，未转义 | SQLite 驱动自动转义 |
| **输入验证** | 无任何验证 | 所有字段均有格式/长度校验 |
| **搜索权限** | 任意用户（含未登录）可搜索 | 仅登录用户可搜索 |
| **错误处理** | 仅捕获 IntegrityError | 完整性 + 通用异常双捕获 |
| **SQL 日志** | `print()` 暴露完整 SQL | `logger.info()` 只记录安全文本 |

---

## 六、v3.0 与 v2.0 差异概要

| 对比项 | v2.0 | v3.0 |
|--------|------|------|
| 用户注册 | ❌ 无 | ✅ 新增 `/register`（参数化查询） |
| 用户搜索 | ❌ 无 | ✅ 新增 `/search`（参数化查询，需登录） |
| SQLite 数据库 | ❌ 无 | ✅ `data/users.db` |
| 登录功能 | USERS 字典 + bcrypt | **不变** |

> ⚠️ v3.0 保持原有登录功能不变，仍用内存字典 `USERS` 校验，新注册用户暂无法登录。

---

## 七、项目结构

```
3.0/
├── app.py                     # 主应用（SQL 注入已修复）
├── setup.sh                   # 环境配置脚本
├── requirements.txt           # pip 依赖清单
├── data/
│   └── users.db              # SQLite 数据库（自动生成）
├── templates/
│   ├── base.html              # 导航栏含"注册"链接
│   ├── index.html             # 首页含搜索框 + 结果表格
│   ├── login.html             # 登录页（含 CSRF token）
│   └── register.html          # 注册页
└── static/css/
    └── style.css
```

---

## 八、环境配置与运行

```bash
cd /opt/Class01/3.0
./setup.sh
python3 app.py
# 访问 http://127.0.0.1:5000
```

---

*本报告遵循 OWASP SQL Injection Prevention Cheat Sheet 最佳实践*
