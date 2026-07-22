# Class01/5.0 — 用户管理系统（越权业务逻辑漏洞修复版）

| 项目 | 说明 |
|------|------|
| 项目名称 | Class01 用户管理系统 |
| 版本 | v5.0（修复版） |
| 修复目标 | 个人中心（`/profile`）和充值（`/recharge`）中的越权与业务逻辑漏洞 |
| 修复日期 | 2026-07-22 |
| 审计方法 | 白盒代码审计 + 攻击向量推演 |

---

## 目录

1. [审计概述](#1-审计概述)
2. [漏洞发现汇总](#2-漏洞发现汇总)
3. [漏洞一：未认证访问 /profile](#3-漏洞一未认证访问-profile)
4. [漏洞二：水平越权查看任意用户资料（IDOR）](#4-漏洞二水平越权查看任意用户资料idor)
5. [漏洞三：未认证访问 /recharge](#5-漏洞三未认证访问-recharge)
6. [漏洞四：水平越权操作任意用户余额（IDOR）](#6-漏洞四水平越权操作任意用户余额idor)
7. [漏洞五：充值金额负数绕过（业务逻辑漏洞）](#7-漏洞五充值金额负数绕过业务逻辑漏洞)
8. [修复对照](#8-修复对照)
9. [复测验证](#9-复测验证)
10. [审计结论](#10-审计结论)

---

## 1. 审计概述

### 1.1 审计背景

v5.0 在 v4.0（登录 + 注册 + 搜索 + 头像上传）基础上新增了个人中心（`/profile`）和充值（`/recharge`）功能。本次审计针对这两个新增功能进行 **越权漏洞（IDOR）** 和 **业务逻辑漏洞** 的专项安全审查。

### 1.2 审计目标

- 识别 `/profile` 和 `/recharge` 中的越权访问漏洞
- 识别充值功能中的业务逻辑漏洞
- 评估各漏洞的风险等级和利用难度
- 提供可落地的修复方案
- 验证修复后的安全性

### 1.3 审计依据

| 标准 | 说明 |
|:----:|------|
| OWASP Top 10 2021 — A01:2021 | Broken Access Control（访问控制失效） |
| OWASP Top 10 2021 — A04:2021 | Insecure Design（不安全的设计） |
| CWE-862 | Missing Authorization（缺少授权） |
| CWE-285 | Improper Authorization（授权不当） |
| CWE-639 | Authorization Bypass Through User-Controlled Key（通过用户控制的键绕过授权） |

### 1.4 审计范围

| 审计项 | 说明 |
|--------|------|
| **目标应用** | Class01/5.0 用户管理系统 |
| **审计功能** | `/profile` 路由（GET）、`/recharge` 路由（POST） |
| **相关文件** | `app.py` — profile / recharge 路由 |
| **攻击者模型** | ① 未登录用户；② 已登录普通用户（alice）试图操作管理员（admin）的资源 |

### 1.5 修复前功能流程

```
┌─ 攻击面 1: /profile ──────────────────────────┐
│                                                │
│  GET /profile?user_id=1                        │
│       ↓                                       │
│  ┌─ 任何用户（含未登录）                     │
│  │  ❌ 无 session 认证检查                    │
│  │  ❌ 无权限校验                             │
│  │  ✅ 直接显示目标用户的资料                 │
│  └────────────────────────── 高风险           │
│                                                │
│  alice → /profile?user_id=1  → 看到admin资料  │
│  未登录 → /profile?user_id=2  → 看到alice资料 │
└────────────────────────────────────────────────┘

┌─ 攻击面 2: /recharge ─────────────────────────┐
│                                                │
│  POST /recharge                                │
│  user_id=1&amount=-99999                       │
│       ↓                                       │
│  ┌─ 任何用户（含未登录）                     │
│  │  ❌ 无 session 认证检查                    │
│  │  ❌ 无权限校验                             │
│  │  ❌ 无金额正负校验                         │
│  │  ✅ 直接修改余额：balance = balance - 99999 │
│  └────────────────────────── 高风险           │
│                                                │
│  alice → recharge admin(user_id=1, -99999)    │
│        → admin 余额从 99999 变为 0            │
└────────────────────────────────────────────────┘
```

---

## 2. 漏洞发现汇总

| 编号 | 漏洞名称 | 等级 | CWE | 利用难度 | 影响 |
|:----:|---------|:----:|:---:|:--------:|:----:|
| AUTH-001 | `/profile` 缺少登录认证 | 🔴 P1 | 862 | 低 | 未登录用户可查看任意用户资料 |
| AUTH-002 | `/profile` 水平越权（IDOR） | 🔴 P1 | 639 | 低 | 普通用户可查看管理员资料 |
| AUTH-003 | `/recharge` 缺少登录认证 | 🔴 P1 | 862 | 低 | 未登录用户可修改任意用户余额 |
| AUTH-004 | `/recharge` 水平越权（IDOR） | 🔴 P1 | 639 | 低 | 普通用户可操作管理员余额 |
| BL-001 | `/recharge` 金额负数绕过 | 🟠 P2 | 285 | 低 | 可恶意扣减他人（或自己）余额 |

### 2.1 风险评估标准

| 等级 | 代码 | 定义 |
|:----:|:----:|------|
| 🔴 **高危** | P1 | 可导致敏感数据泄露、资产损失、权限提升 |
| 🟠 **中危** | P2 | 可导致有限的数据破坏或非预期状态修改 |
| 🟢 **低危** | P3 | 用户体验问题或需结合其他漏洞利用 |

### 2.2 漏洞关联分析

```
                        ┌──────────────────┐
                        │  未认证（AUTH-001）│
                        │  未登录即可访问   │
                        └────────┬─────────┘
                                 │ 基础缺陷
                                 ▼
┌─────────────────────────────────────────────────────┐
│                   核心漏洞                            │
│           水平越权 IDOR（AUTH-002 / AUTH-004）       │
│                                                      │
│   user_id 完全由客户端控制，服务端无任何校验          │
│   ───  用户 → 服务端：我要看/操作 user_id=1 的资料   │
│   服务端：好的！（不检查你是谁）                     │
└──────────────────────┬──────────────────────────────┘
                       │ 叠加漏洞
                       ▼
               ┌──────────────────────┐
               │  金额负数(BL-001)     │
               │  充值-99999 = 扣款    │
               └──────────────────────┘
```

---

## 3. 漏洞一：未认证访问 /profile

| 属性 | 值 |
|------|-----|
| **漏洞编号** | AUTH-001 |
| **CWE 映射** | [CWE-862: Missing Authorization](https://cwe.mitre.org/data/definitions/862.html) |
| **风险等级** | 🔴 高危（P1） |
| **利用难度** | 低 |
| **影响范围** | 全部用户数据 |

### 3.1 漏洞描述

`/profile` 路由**未检查用户是否已登录**，未登录用户可以直接通过 URL 参数查看任意用户资料。

```python
# 漏洞代码（修复前）
@app.route("/profile")
def profile():
    # ← 缺少 session 登录检查
    user_id_str = request.args.get("user_id", "").strip()
    ...
```

### 3.2 攻击向量

| 攻击者状态 | 请求 | 结果 |
|:----------:|:----:|:----:|
| 未登录 | `GET /profile?user_id=1` | 看到 admin 的资料（邮箱、手机、余额） |
| 未登录 | `GET /profile?user_id=2` | 看到 alice 的资料 |

### 3.3 根因分析

1. 开发者未在路由入口处添加 `session.get("username")` 检查
2. 错误地认为"只有登录用户才会点击个人中心链接"——但攻击者可以直接构造 HTTP 请求

### 3.4 修复方案

```python
# 修复后
@app.route("/profile")
def profile():
    auth = require_auth()
    if not auth:
        return redirect("/login")  # 未登录 → 跳转登录页

    current_username, current_role, current_user_id = auth
    ...
```

新增 `require_auth()` 辅助函数：

```python
def require_auth():
    """检查用户是否已登录，返回 (username, role, user_id)"""
    username = session.get("username")
    if not username:
        return None
    user = USERS.get(username)
    if not user:
        return None
    user_id = get_user_id_from_username(username)
    return username, user.get("role", "user"), user_id
```

---

## 4. 漏洞二：水平越权查看任意用户资料（IDOR）

| 属性 | 值 |
|:----:|------|
| **漏洞编号** | AUTH-002 |
| **CWE 映射** | [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) |
| **攻击类型** | IDOR（Insecure Direct Object Reference） |
| **风险等级** | 🔴 高危（P1） |
| **利用难度** | 低 |
| **影响范围** | 全部用户敏感数据泄露 |

### 4.1 漏洞描述

`/profile` 的 `user_id` 完全由 URL 参数控制，服务端**未将该参数与当前登录用户进行绑定校验**。

```python
# 漏洞代码（修复前）
target_user_id = int(user_id_str)
# ← 直接查询，未检查 target_user_id 是否等于 current_user_id
```

### 4.2 攻击向量

| 攻击者 | 请求 | 结果 |
|:------:|:----:|:------|
| alice（普通用户，ID=2） | `GET /profile?user_id=1` | 🔴 看到 admin 的全部资料 |
| alice（普通用户，ID=2） | `GET /profile?user_id=2` | ✅ 正常查看自己 |
| admin | `GET /profile?user_id=2` | 允许（管理员应有全局查看权限） |

### 4.3 攻击示意图

```
┌────────┐     GET /profile?user_id=1     ┌──────────┐
│ alice  │ ─────────────────────────────→ │  Server  │
│ (id=2) │                                │          │
│        │ ← 响应：admin 的资料 ──────────│  ❌ 未检查 │
└────────┘    邮箱、手机、余额全泄露       │   user_id  │
                                           │   是否匹配  │
                                           │   当前用户  │
                                           └──────────┘
```

### 4.4 根因分析

1. `user_id` 作为资源直接引用（Direct Object Reference），但服务端未校验当前用户对该资源的访问权限
2. 缺少"当前用户身份 → 目标资源"的映射关系验证
3. 典型的 **IDOR（不安全的直接对象引用）** 漏洞

### 4.5 修复方案

```python
# 修复后 - 在查询前进行权限校验
@app.route("/profile")
def profile():
    ...
    target_user_id = int(user_id_str)

    # ── 权限校验 ───────────────────────────────────
    # 规则：管理员可以查看任意用户；普通用户只能查看自己的资料
    if current_role != "admin" and target_user_id != current_user_id:
        logger.warning(f"[AUTH] 越权操作拦截: 用户 {current_username} 尝试查看用户 ID={target_user_id} 的资料")
        return render_template("profile.html", error="无权查看其他用户的资料", user=None)
    ...
```

**权限矩阵：**

| 当前用户 | 目标 user_id | 结果 |
|:--------:|:------------:|:----:|
| alice (id=2, role=user) | 2（自己） | ✅ 允许 |
| alice (id=2, role=user) | 1（admin） | ❌ 拒绝 |
| admin (id=1, role=admin) | 1（自己） | ✅ 允许 |
| admin (id=1, role=admin) | 2（alice） | ✅ 允许 |

---

## 5. 漏洞三：未认证访问 /recharge

| 属性 | 值 |
|:----:|------|
| **漏洞编号** | AUTH-003 |
| **CWE 映射** | CWE-862: Missing Authorization |
| **风险等级** | 🔴 高危（P1） |
| **利用难度** | 低 |

### 5.1 漏洞描述

与 AUTH-001 相同，`/recharge` 路由也未检查用户登录状态。未登录用户可以通过 CSRF 保护的 POST 请求修改任意用户余额。

```python
# 漏洞代码（修复前）
@app.route("/recharge", methods=["POST"])
def recharge():
    # ← 缺少 session 登录检查
    user_id_str = (request.form.get("user_id") or "").strip()
    amount_str = (request.form.get("amount") or "").strip()
    ...
```

### 5.2 修复方案

```python
@app.route("/recharge", methods=["POST"])
def recharge():
    auth = require_auth()
    if not auth:
        return redirect("/login")
    ...
```

---

## 6. 漏洞四：水平越权操作任意用户余额（IDOR）

| 属性 | 值 |
|:----:|------|
| **漏洞编号** | AUTH-004 |
| **CWE 映射** | CWE-639: Authorization Bypass Through User-Controlled Key |
| **攻击类型** | IDOR（水平越权） |
| **风险等级** | 🔴 高危（P1） |
| **利用难度** | 低 |

### 6.1 漏洞描述

`/recharge` 的 `user_id` 来自表单隐藏字段，攻击者可修改该字段值，对任意用户执行充值（或扣款）操作。

### 6.2 攻击向量

| 攻击者 | 请求表单数据 | 结果 |
|:------:|:----------:|:----:|
| alice（普通用户） | `user_id=1&amount=-99999` | 🔴 admin 余额被扣为负数 |
| alice（普通用户） | `user_id=2&amount=100` | ✅ 给自己充值正常 |
| alice（普通用户） | `user_id=1&amount=100` | 🔴 给 admin 余额增加 |

### 6.3 攻击示意图

```
┌────────────┐        POST /recharge         ┌──────────┐
│  攻击者    │  user_id=1&amount=-99999      │  Server  │
│  (alice)   │ ────────────────────────────→ │          │
│            │                                │  ❌ 未验证 │
│            │ ← 302 → /profile?user_id=1 ──│  user_id  │
│            │                                │  ❌ 未检查 │
│            │  结果：admin 余额 99999→0      │  金额正负  │
└────────────┘                                └──────────┘
```

### 6.4 根因分析

1. 隐藏字段 `user_id` 在 HTML 中呈现在客户端，用户可随意修改
2. 服务端完全信任了客户端提交的 `user_id`，未与 session 中的当前用户比对
3. 无身份与操作的绑定关系

### 6.5 修复方案

```python
# 修复后
@app.route("/recharge", methods=["POST"])
def recharge():
    ...
    # ── 权限校验 ───────────────────────────────────
    # 规则：管理员可以给任意用户充值；普通用户只能给自己充值
    if current_role != "admin" and target_user_id != current_user_id:
        logger.warning(f"[AUTH] 越权操作拦截: 用户 {current_username} 尝试操作他人余额")
        return render_template("profile.html", error="无权操作其他用户的余额", user=None)
    ...
```

---

## 7. 漏洞五：充值金额负数绕过（业务逻辑漏洞）

| 属性 | 值 |
|:----:|------|
| **漏洞编号** | BL-001 |
| **CWE 映射** | [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) |
| **风险等级** | 🟠 中危（P2） |
| **利用难度** | 低 |

### 7.1 漏洞描述

`/recharge` 直接将表单提交的 `amount` 与余额相加，**未校验 `amount` 的值域范围**。负数可绕过"充值"意图，实现反向扣款。

```python
# 漏洞代码（修复前）
amount = float(amount_str)          # "充值 -99999" → amount = -99999
USERS[username]["balance"] += amount  # balance = 99999 + (-99999) = 0
```

### 7.2 攻击向量

| 攻击者 | amount 值 | 业务含义 | 实际效果 |
|:------:|:---------:|:--------:|:--------:|
| 攻击者（已越权） | `-99999` | 充值负数 | admin 余额清零 |
| 普通用户 | `-500` | 充值负数 | 自己余额减少（自残攻击） |
| 普通用户 | `0` | 零元充值 | 无意义，但可被日志污染 |

### 7.3 根因分析

1. 业务逻辑缺陷："充值"操作应隐含"金额必须为正数"的约束
2. 缺乏基本的输入校验 —— `float(amount_str)` 接受所有实数
3. 将"充值"接口实际上变成了"任意金额调整"接口

### 7.4 修复方案

```python
# 修复后
# ── 金额校验 ───────────────────────────────────
if amount <= 0:
    logger.warning(f"[RECHARGE] 用户 '{current_username}' 提交了无效金额: {amount}")
    return render_template("profile.html", error="充值金额必须大于0", user=None)
```

---

## 8. 修复对照

### 8.1 修复前后代码对比

#### /profile 路由

| 安全维度 | 修复前 | 修复后 |
|---------|--------|--------|
| 登录检查 | ❌ 无 | ✅ `require_auth()` 检查 session |
| 水平越权防护 | ❌ 无 | ✅ 普通用户只能看自己，管理员可看全部 |
| 越权日志记录 | ❌ 无 | ✅ `logger.warning()` 记录越权行为 |

#### /recharge 路由

| 安全维度 | 修复前 | 修复后 |
|---------|--------|--------|
| 登录检查 | ❌ 无 | ✅ `require_auth()` 检查 session |
| 水平越权防护 | ❌ 无 | ✅ 普通用户只能操作自己，管理员可操作全部 |
| 金额正负校验 | ❌ 无 | ✅ `amount > 0` 检查 |
| 日志详细程度 | 记录简单 | ✅ 记录操作人、目标用户、操作前后余额 |
| 金额显示精度 | 原始 float | ✅ 日志中使用 `{:.2f}` 格式化 |

### 8.2 修复函数：`require_auth()`

```python
def require_auth():
    """检查用户是否已登录，返回 (username, role, user_id)，未登录则返回 None"""
    username = session.get("username")
    if not username:
        return None
    user = USERS.get(username)
    if not user:
        return None
    user_id = get_user_id_from_username(username)
    return username, user.get("role", "user"), user_id
```

### 8.3 权限矩阵

| 角色 | 查看自己资料 | 查看他人资料 | 给自己充值 | 给他人充值 |
|:----:|:-----------:|:-----------:|:----------:|:----------:|
| **admin** | ✅ | ✅（任意用户） | ✅ | ✅（任意用户） |
| **user** | ✅ | ❌ 拦截 | ✅ | ❌ 拦截 |
| **未登录** | ❌ 跳转登录 | ❌ 跳转登录 | ❌ 跳转登录 | ❌ 跳转登录 |

### 8.4 修复涉及文件

| 文件 | 修改内容 |
|:----:|---------|
| `app.py` | 新增 `require_auth()`、`is_admin()` 辅助函数 |
| `app.py` | `/profile` 路由：添加认证 + 权限校验 |
| `app.py` | `/recharge` 路由：添加认证 + 权限校验 + 金额正负校验 |
| 其余文件 | 未改动 |

---

## 9. 复测验证

### 9.1 越权测试

| 测试用例 | 攻击类型 | 预期结果 | 结果 |
|---------|---------|---------|:----:|
| 未登录访问 `/profile?user_id=1` | 未认证访问 | 重定向到 `/login` | ✅ |
| alice 访问 `/profile?user_id=1`（admin） | 水平越权 | "无权查看其他用户的资料" | ✅ |
| alice 访问 `/profile?user_id=2`（自己） | 正常操作 | 显示 alice 资料 | ✅ |
| admin 访问 `/profile?user_id=2`（alice） | 管理员操作 | 显示 alice 资料 | ✅ |
| 未登录 POST `/recharge` | 未认证操作 | 重定向到 `/login` | ✅ |

### 9.2 充值金额测试

| 测试用例 | 预期结果 | 结果 |
|---------|---------|:----:|
| alice 给自己充值 100 | ✅ 余额增加 100 | ✅ |
| alice 给自己充值 -500（负数） | "充值金额必须大于0" | ✅ |
| alice 给自己充值 0（零元） | "充值金额必须大于0" | ✅ |
| alice 给 admin（user_id=1）充值 | "无权操作其他用户的余额" | ✅ |
| admin 给 alice（user_id=2）充值 500 | ✅ 管理员权限允许 | ✅ |
| 提交非数字金额 "abc" | "金额格式不正确" | ✅ |
| 提交空金额 | "请输入充值金额" | ✅ |

### 9.3 回归测试说明

| 功能 | 路由 | 是否修改 |
|:----:|:----:|:--------:|
| 首页 | `index` | ❌ |
| 登录 | `login` | ❌ |
| 注册 | `register` | ❌ |
| 搜索 | `search` | ❌ |
| 头像上传 | `upload` | ❌ |
| 登出 | `logout` | ❌ |
| 导航栏 | `base.html` | ❌ |
| 首页模板 | `index.html` | ❌ |
| 个人中心模板 | `profile.html` | ❌ |
| 样式 | `style.css` | ❌ |

---

## 10. 审计结论

### 10.1 修复统计

| 统计项 | 数值 |
|--------|:----:|
| 发现漏洞总数 | **5** |
| 已修复漏洞数 | **5** |
| 🔴 高危（P1） | 4 — 未认证访问（×2）、水平越权（×2） |
| 🟠 中危（P2） | 1 — 负数金额绕过 |
| 新增依赖 | 0（无额外依赖） |

### 10.2 纵深防御架构

修复后的个人中心和充值功能形成了 **4 层安全防线**：

```
Layer 1: 认证层
    require_auth() → session 检查 → 未登录跳转 /login
         ↓
Layer 2: 授权层（身份与角色的交叉校验）
    role == "admin" ? 可操作全部 : 只能操作自己
         ↓
Layer 3: 输入校验层
    user_id 必须为正整数、amount 必须大于 0
         ↓
Layer 4: 审计日志层
    logger.warning() 记录每次越权尝试
    logger.info() 记录每次正常操作（含操作人、目标、操作前后状态）
```

### 10.3 修复模式 —— 越权漏洞防护清单

```
                 ┌─────────────────────────────────────┐
                 │        越权漏洞防护 Checklist         │
                 ├─────────────────────────────────────┤
                 │                                     │
                 │  □ 1. 每个受保护路由有身份认证       │
                 │     □ session 检查                  │
                 │     □ 未登录 → redirect(/login)     │
                 │                                     │
                 │  □ 2. 水平越权防护                   │
                 │     □ 从 session 获取当前用户 ID    │
                 │     □ 比对 user_id 参数与 session ID│
                 │     □ user≠admin → 只能操作自己      │
                 │                                     │
                 │  □ 3. 垂直越权防护                   │
                 │     □ 区分 admin/user 角色           │
                 │     □ admin 拥有全局权限             │
                 │                                     │
                 │  □ 4. 输入校验                       │
                 │     □ 类型校验（isdigit、float）     │
                 │     □ 值域校验（amount > 0）         │
                 │     □ 边界校验（空值、特殊值）       │
                 │                                     │
                 │  □ 5. 审计日志                       │
                 │     □ 记录越权尝试（含操作人、目标）  │
                 │     □ 记录正常操作前后状态           │
                 └─────────────────────────────────────┘
```

### 10.4 后续改进建议

| 建议 | 优先级 | 说明 |
|:----:|:------:|------|
| 统一权限装饰器 | 🟠 高 | 将 `require_auth()` 和权限校验封装为 Flask 装饰器 `@login_required`、`@admin_required` |
| 金额使用 Decimal | 🟠 中 | `float` 存在浮点精度误差，建议改用 `decimal.Decimal` 处理金额 |
| 充值频率限制 | 🟢 中 | 为 `/recharge` 添加 `@limiter.limit("5 per minute")`，防止暴力调接口刷余额 |
| 余额上/下限 | 🟢 中 | 设置 `max_balance` 上限，防止余额溢出为负数或超大数 |

---

## 快速启动

```bash
cd /opt/Class01/5.0
bash setup.sh
python3 app.py
```

服务监听地址：`http://127.0.0.1:5000`

### 测试账号

| 用户名 | 密码 | 角色 | user_id |
|--------|:----:|:----:|:-------:|
| `admin` | `admin123` | admin（管理员） | 1 |
| `alice` | `alice2025` | user（普通用户） | 2 |

*报告生成日期：2026-07-22 | 审计方法：白盒代码审计 + 攻击向量推演*
