# SQL 注入漏洞修复报告 — v3.0

| 项目 | 说明 |
|------|------|
| 报告编号 | SEC-20260720-001 |
| 项目名称 | Class01 用户管理系统 |
| 涉及版本 | v3.0 |
| 报告日期 | 2026-07-20 |
| 风险评级 | 严重（Critical） |
| 漏洞类型 | SQL Injection（SQL 注入） |

---

## 1. 背景说明

v3.0 基于 v2.0 构建，在保持原有登录功能不变的前提下，新增了 SQLite 数据库、用户注册接口（`/register`）和用户搜索接口（`/search`）。上线前的安全审计发现，新增代码中存在两处 SQL 注入漏洞，攻击者可利用这些漏洞遍历用户数据、篡改数据库内容甚至删除数据表。本文档记录漏洞详情及修复过程。

---

## 2. 漏洞详情

### 2.1 注册接口 SQL 注入（SEC-01）

**漏洞位置**：`app.py` — register 路由（第 161 行）

**漏洞描述**：
注册表单接收用户名、密码、邮箱、手机号四个字段后，使用 Python f-string 将用户输入直接拼接到 INSERT 语句中，未做任何转义或过滤处理。

**漏洞代码**：
```python
username = request.form.get("username", "")
password = request.form.get("password", "")
email = request.form.get("email", "")
phone = request.form.get("phone", "")

sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
cur.execute(sql)
```

**利用方式**：
攻击者在用户名字段输入 `x'), ('y', '123', 'y@x.com', '999')--`，实际拼接的 SQL 变为：

```sql
INSERT INTO users (...) VALUES ('x'), ('y', '123', 'y@x.com', '999')--', '...', '...', '...')
```

该语句一次性插入两条用户记录，`--` 注释符使后半句失效。若输入 `x'); DROP TABLE users; --`，则可直接删除 users 表。

**危害等级**：严重。可导致数据泄露、数据篡改、数据库表结构破坏。

---

### 2.2 搜索接口 SQL 注入（SEC-02）

**漏洞位置**：`app.py` — search 路由（第 192 行）

**漏洞描述**：
搜索接口从 URL 参数 `keyword` 获取用户输入，通过 f-string 拼接到 LIKE 子句中，并将完整 SQL 语句输出至控制台。

**漏洞代码**：
```python
keyword = request.args.get("keyword", "")

sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
print(f"[SEARCH] SQL: {sql}")
cur.execute(sql)
```

**利用方式**：
攻击者在浏览器地址栏输入 `?keyword=' OR 1=1 --`，实际执行的 SQL 为：

```sql
SELECT * FROM users WHERE username LIKE '%' OR 1=1 -- %'
```

`OR 1=1` 使 WHERE 条件恒为真，`--` 注释掉后续语句，返回 users 表的全部数据。进一步使用 `UNION SELECT` 构造可窃取其他数据库表信息。

**危害等级**：严重。可导致全量用户数据泄露，配合 UNION 注入可窃取任意表数据。

---

### 2.3 配套安全缺陷

| 编号 | 缺陷描述 | 危害等级 |
|------|---------|:--------:|
| SEC-03 | 注册字段及搜索关键词均无输入验证，空值、超长字符串、特殊字符均可通过 | 中危 |
| SEC-04 | 搜索接口未校验用户登录状态，未登录用户可直接调用查询 | 中危 |

---

## 3. 修复方案

### 3.1 修复 SEC-01：注册接口参数化改造

将 f-string 拼接替换为参数化查询，并在 SQL 执行前增加输入验证。

**修复代码**：
```python
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()

    # 输入验证：空值检测
    if not username or not password:
        return render_template("register.html", error="用户名和密码不能为空")

    # 输入验证：长度限制
    if len(username) > 50 or len(password) > 128:
        return render_template("register.html", error="用户名或密码过长")
    if len(username) < 2:
        return render_template("register.html", error="用户名至少 2 个字符")
    if len(password) < 6:
        return render_template("register.html", error="密码至少 6 个字符")

    # 输入验证：格式校验
    if email and not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return render_template("register.html", error="邮箱格式不正确")
    if phone and not re.match(r'^\+?\d{7,15}$', phone):
        return render_template("register.html", error="手机号格式不正确")

    conn = sqlite3.connect("data/users.db")
    cur = conn.cursor()
    # 参数化查询：使用 ? 占位符替代 f-string 拼接
    sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
    try:
        cur.execute(sql, (username, password, email, phone))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return render_template("register.html", error="用户名已存在，请换一个")
    conn.close()
    return redirect("/login?msg=注册成功，请登录")
```

**修复要点**：
- `VALUES (?, ?, ?, ?)` 参数化查询替代 f-string 拼接，用户数据由 SQLite 驱动自动转义
- 用户名、密码、邮箱、手机号逐一增加格式校验
- 移除日志中打印完整 SQL 的语句

---

### 3.2 修复 SEC-02：搜索接口参数化改造

将 LIKE 子句的 f-string 拼接替换为参数化查询，增加登录认证和长度限制。

**修复代码**：
```python
@app.route("/search")
def search():
    # 登录校验：未登录用户不可搜索
    username = session.get("username")
    if not username:
        return redirect("/login")

    user_info = get_safe_user_info(username)
    keyword = (request.args.get("keyword") or "").strip()

    # 长度限制：超 100 字符自动截断
    if len(keyword) > 100:
        keyword = keyword[:100]

    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # 参数化查询：LIKE ? 替代 f-string 拼接，通配符作为参数值传入
        sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
        like_param = f"%{keyword}%"
        try:
            cur.execute(sql, (like_param, like_param))
            rows = cur.fetchall()
            results = [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"[SEARCH] 查询异常: {e}")
        conn.close()

    return render_template("index.html", user=user_info, search_results=results, search_keyword=keyword)
```

**修复要点**：
- `LIKE ?` 参数化查询替代 f-string 拼接
- 通配符 `%keyword%` 作为参数值传入，不参与 SQL 结构
- 新增 session 登录校验
- 移除 `print(f"[SEARCH] SQL: {sql}")` 控制台输出
- 日志改为仅记录关键词文本

---

### 3.3 修复 SEC-03：输入验证（已在 3.1 中一并实施）

| 字段 | 验证规则 |
|------|---------|
| 用户名 | 必填，长度 2~50 字符 |
| 密码 | 必填，长度 6~128 字符 |
| 邮箱 | 选填，正则校验 `xxx@yyy.zzz` 格式 |
| 手机号 | 选填，7~15 位数字，允许前导 `+` |
| 搜索关键词 | 最长 100 字符，超长自动截断 |

### 3.4 修复 SEC-04：搜索接口登录认证（已在 3.2 中一并实施）

```python
username = session.get("username")
if not username:
    return redirect("/login")
```

---

## 4. 修复验证

### 4.1 注入攻击验证

使用修复前可成功利用的攻击载荷逐一测试：

| 测试用例 | 预期结果 | 验证结果 |
|---------|---------|:--------:|
| 搜索 `' OR 1=1 --` | 不应返回全部用户 | ✅ 通过 |
| 搜索 `' UNION SELECT 1,'a','b','c','d' --` | 不应执行 UNION 查询 | ✅ 通过 |
| 注册用户名 `x'); DROP TABLE users; --` | 不应删除数据表 | ✅ 通过 |
| 注册用户名 `admin', 'hacked')--` | 不应覆盖已有数据 | ✅ 通过 |

所有测试用例均通过。参数化查询将攻击载荷中的特殊字符作为普通文本处理，单引号、连字符、关键字均被安全转义，不改变 SQL 语义。

### 4.2 正常功能验证

| 测试场景 | 预期结果 | 验证结果 |
|---------|---------|:--------:|
| 搜索已存在的用户名 | 返回对应用户信息 | ✅ 通过 |
| 搜索不存在的关键词 | 显示"无搜索结果" | ✅ 通过 |
| 不输入关键词 | 页面正常加载，不执行查询 | ✅ 通过 |
| 合法信息注册 | 注册成功，跳转登录页 | ✅ 通过 |
| 注册已存在的用户名 | 提示"用户名已存在" | ✅ 通过 |
| 未登录访问 `/search` | 重定向至登录页 | ✅ 通过 |

---

## 5. 修复总结

### 5.1 变更统计

| 变更项 | 说明 |
|-------|------|
| 发现漏洞总数 | 4 项（2 严重 + 2 中危） |
| 已修复漏洞数 | 4 项 |
| 修复方式 | 参数化查询 + 输入验证 + 登录认证 |

### 5.2 版本变更概要

v3.0 在 v2.0（安全加固版）基础上新增：

| 变更项 | 说明 |
|-------|------|
| SQLite 数据库 | `data/users.db`，初始化 users 表 |
| 用户注册 | `/register` 路由及对应模板 |
| 用户搜索 | `/search` 路由，结果嵌入首页 |

登录验证逻辑保持不变，仍基于内存字典 `USERS` + bcrypt 密码哈希。通过注册功能写入 SQLite 的用户数据暂不参与登录校验。

---

## 6. 项目文件结构

```
3.0/
├── app.py                     # 主程序（SQL 注入已修复）
├── data/users.db              # SQLite 数据库
├── templates/
│   ├── base.html              # 导航栏新增"注册"入口
│   ├── index.html             # 首页集成搜索面板
│   ├── login.html
│   └── register.html          # 新增注册页面
├── static/css/style.css
├── setup.sh
└── requirements.txt
```

## 7. 启动方式

```bash
cd /opt/Class01/3.0
./setup.sh
python3 app.py
```

服务监听地址：`http://127.0.0.1:5000`，仅本机可访问。

---

*本报告由安全团队根据代码审计结果编写，修复方案遵循 OWASP SQL Injection Prevention 最佳实践。*
