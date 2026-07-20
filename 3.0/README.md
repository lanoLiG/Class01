# v3.0 代码安全审查记录

> **审查对象**：3.0/app.py（基于 v2.0 新增注册 + 搜索功能）  
> **审查日期**：2026-07-20  
> **审查结论**：发现 2 处严重 SQL 注入风险，已全部修复

---

## 背景

v3.0 在 v2.0 基础上新增了三个能力：SQLite 数据库持久化、用户注册、用户搜索。
功能构建完成后，对新增代码做了安全审查，发现 `app.py` 中两处新写的数据库操作存在安全隐患。

---

## 逐行审查记录

### 文件：app.py — register 路由（第 147~176 行）

```
审查到第 161 行时发现问题 ↓

  username = request.form.get("username", "")
  password = request.form.get("password", "")
  email = request.form.get("email", "")
  phone = request.form.get("phone", "")
                                    ← 4 个参数全部来自用户输入，未做任何检查
  sql = f"INSERT INTO users (...) VALUES ('{username}', '{password}', '{email}', '{phone}')"
                                    ← ⚠️ f-string 直接拼接，用户输入中的单引号会破坏 SQL 结构
  cur.execute(sql)
```

**风险演示**：假设用户在用户名字段输入 `x'), ('y', 'z', 'a', 'b')--`

实际拼接出的 SQL 变成：
```sql
INSERT INTO users (...) VALUES ('x'), ('y', 'z', 'a', 'b')--', '...', '...', '...')
```

等于一次插入了两条记录，`--` 把后半句注释掉了。

**如果输入** `x'); DROP TABLE users; --`
```sql
INSERT INTO users (...) VALUES ('x'); DROP TABLE users; --', '...')
```

**后果**：users 表被删除，系统崩溃。

**处理方案**：把这一段的 SQL 构建方式换掉，同时补上输入校验。

改动三处：
1. SQL 语句中的 `VALUES ('{username}', ...)` 改成 `VALUES (?, ?, ?, ?)`，参数单独传
2. 对每个字段加格式检查——用户名不能为空且 2~50 字、密码 6~128 字、邮箱符合 `xxx@yyy.zzz` 格式、手机号是纯数字
3. 删掉第 162 行 `logger.info(f"[REGISTER] 执行 SQL: {sql}")`，不在日志里打印用户输入

---

### 文件：app.py — search 路由（第 180~204 行）

```
审查到第 192 行时发现问题 ↓

  keyword = request.args.get("keyword", "")  ← URL 参数，攻击者可随意构造
                                   
  sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
                                    ← ⚠️ 同样的问题：keyword 拼到 LIKE 子句里
  print(f"[SEARCH] SQL: {sql}")    ← 还把完整 SQL 打到控制台
  cur.execute(sql)
```

**风险演示**：攻击者在搜索框输入 `' OR 1=1 --`

```sql
SELECT * FROM users WHERE username LIKE '%' OR 1=1 -- %'
```
`1=1` 永远为真，`--` 注释掉后面，**全表数据泄露**。

更进一步的攻击 `' UNION SELECT ... --` 还能窃取其他表数据。

**处理方案**：

1. SQL 中的 `LIKE '%{keyword}%'` 改成 `LIKE ?`，通配符 `%keyword%` 放在参数里传入
2. search 路由开头加一道登录检查——未登录用户直接跳到登录页
3. 删掉 `print(f"[SEARCH] SQL: {sql}")`
4. 关键词超 100 字符自动截断

---

### 文件：app.py — 全局（第 1~5 行）

修复过程中新增了一行 `import re`，用于表单字段的正则校验。这个包是 Python 自带的，不需要额外装第三方依赖。

---

## 修复改动清单

### register 路由

| 改动位置 | 改前 | 改后 |
|---------|------|------|
| SQL 构建 | `f"VALUES ('{username}', ...)"` | `VALUES (?, ?, ?, ?)` + 参数元组 |
| 输入处理 | `request.form.get("username", "")` | `(request.form.get("username") or "").strip()` |
| 用户名校验 | 无 | 必填、2~50 字符 |
| 密码校验 | 无 | 必填、6~128 字符 |
| 邮箱校验 | 无 | 正则匹配 `xxx@yyy.zzz` 格式 |
| 手机号校验 | 无 | 正则匹配数字，`+` 可选，7~15 位 |
| SQL 日志 | `logger.info(f"执行 SQL: {sql}")` | 移除（不再记录含用户输入的 SQL） |

### search 路由

| 改动位置 | 改前 | 改后 |
|---------|------|------|
| SQL 构建 | `f"LIKE '%{keyword}%'"` | `LIKE ?` + `f"%{keyword}%"` 参数 |
| 登录检查 | 无限制，未登录也能搜 | 检查 session，未登录跳转 `/login` |
| 关键词长度 | 无限制 | 超 100 字符自动截断 |
| 控制台输出 | `print(f"[SEARCH] SQL: {sql}")` | 移除 |
| 搜索日志 | `logger.info(f"执行 SQL: {sql}")` | `logger.info(f"搜索关键词: '{keyword}'")` |

---

## 修复效果验证

### 注入语句还能生效吗？

拿之前的攻击 payload 逐个试：

| 攻击输入 | 预期效果 | 实际效果 |
|---------|---------|---------|
| 搜索 `' OR 1=1 --` | 返回全部用户 | ❌ 不生效——整个字符串被当作文本去 LIKE 匹配，找不到匹配 `' OR 1=1 --` 的用户名，返回空 |
| 搜索 `' UNION SELECT ... --` | 窃取数据 | ❌ 不生效——UNION 关键字被当作文本，不是 SQL 指令 |
| 注册用户名 `x'); DROP TABLE users; --` | 删表 | ❌ 不生效——整个字符串作为用户名参数传入，单引号被转义正常存储 |
| 注册用户名 `admin', 'hacked')--` | 覆盖已有数据 | ❌ 不生效——作为普通用户名处理 |

### 正常功能受影响吗？

| 操作 | 结果 |
|------|------|
| 搜索 `admin` | ✅ 正常返回 admin 用户信息 |
| 搜索 `alice` | ✅ 正常返回 alice 用户信息 |
| 不输入关键词直接搜索 | ✅ 不执行查询 |
| 注册新用户（合法信息） | ✅ 成功，跳转登录页 |
| 注册已存在的用户名 | ✅ 提示"用户名已存在" |
| 未登录直接访问 `/search` | ✅ 重定向到登录页 |

---

## 附：v3.0 与 v2.0 的关系

v3.0 = v2.0（安全加固版）+ 三项新增 + SQL 注入修复

| 新增内容 | 说明 |
|---------|------|
| SQLite 数据库 | `data/users.db`，记录用户注册数据 |
| 用户注册 `/register` | 参数化查询，含输入校验 |
| 用户搜索 `/search` | 参数化查询，需登录 |

原有登录功能保持不变，仍使用 `USERS` 字典 + bcrypt 验证。
新注册用户写入 SQLite，但登录暂不查 SQLite 数据库。

---

## 项目文件结构

```
3.0/
├── app.py                     # 主程序（SQL 注入已修复）
├── setup.sh / requirements.txt
├── data/users.db              # 自动生成
├── templates/
│   ├── base.html              # 导航栏增加"注册"
│   ├── index.html             # 首页增加搜索框
│   ├── login.html
│   └── register.html          # 新增注册页面
└── static/css/style.css
```

## 运行方式

```bash
cd /opt/Class01/3.0
./setup.sh
python3 app.py
# http://127.0.0.1:5000
```
