# Class01/7.0 — CSRF 漏洞审计与修复报告

## 📋 概述

| 项目 | 说明 |
|------|------|
| 新增功能 | 修改密码（`/change-password` 路由） |
| 引入的漏洞 | **跨站请求伪造（CSRF）** |
| CWE 编号 | [CWE-352](https://cwe.mitre.org/data/definitions/352.html): Cross-Site Request Forgery |
| CVSS 3.1 | **8.8 (HIGH)** — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| 利用条件 | 攻击者诱导已登录用户访问恶意页面，即可在用户不知情下执行任意敏感操作 |
| 修复方式 | 移除 `@csrf.exempt` 装饰器 + 表单添加 CSRF Token 隐藏字段 |
| 状态 | **已修复 ✅** |

---

## 🚨 漏洞描述

### CSRF 漏洞原理

跨站请求伪造（CSRF）是一种攻击方式，攻击者通过伪造请求，**诱骗已登录用户**在不知情的情况下执行非本意的操作。

典型攻击流程：

```
① 用户登录了目标站点（获得有效 Session Cookie）
                           │
② 用户访问了攻击者控制的恶意页面
                           │
③ 恶意页面自动提交表单/发起请求到目标站点
                           │
④ 浏览器自动附带目标站点的 Cookie（受害者身份）
                           │
⑤ 目标站点收到请求 → 以为是合法用户操作 → 执行攻击者指定的动作 ❌
```

### 漏洞成因

v7.0 新增的 `/change-password` 路由，由于使用了 `@csrf.exempt` 装饰器，**显式绕过了 Flask-WTF 的 CSRF 防护**。

在 v7.0 之前的版本中，所有 POST 路由均受 Flask-WTF 的 `CSRFProtect` 中间件保护（需要验证 `csrf_token`）。但 `/change-password` 路由被开发者手动豁免：

```python
# 漏洞代码（修复前）
@app.route("/change-password", methods=["POST"])
@csrf.exempt           # ← 显式跳过 CSRF 防护 —— 漏洞根源
def change_password():
    ...
```

同时，该路由的 HTML 表单**也没有**包含 CSRF Token 隐藏字段：

```html
<!-- 漏洞表单（修复前） -->
<form method="post" action="/change-password">
    {# 注意：本表单不使用 CSRF Token #}     <!-- ← 注释明确说不使用 -->
    <input type="hidden" name="username" value="{{ user.username }}">
    ...
</form>
```

### 风险叠加

该 CSRF 漏洞的风险被以下两个因素进一步放大：

| 风险因素 | 说明 |
|:--------:|------|
| **❌ 无原密码验证** | 修改密码时不需要验证旧密码，攻击者不需要知道当前密码即可重置 |
| **❌ 无身份校验** | 任意已登录用户可修改 **任何用户** 的密码（不存在 session 用户与目标用户的一致性检查） |

攻击者只需构造一个恶意页面，诱骗管理员 `admin` 访问，即可**静默**地将 `admin` 的密码修改为攻击者已知的值，随后登录管理员账号。

---

## 🎯 攻击场景复现

### 攻击向量

攻击者在恶意网站中嵌入以下 HTML 表单：

```html
<!-- evil.html — 攻击者架设的恶意页面 -->
<form action="http://目标站点:5000/change-password" method="POST" id="csrf-form">
    <input type="hidden" name="username" value="admin">
    <input type="hidden" name="new_password" value="hacker123">
</form>
<script>
    document.getElementById('csrf-form').submit();  // 自动提交
</script>
```

### 攻击流程

```
攻击者:  "admin你好，点这个链接看照片 → http://evil.com/cat.html"
                │
管理员 admin:   点击链接 → 浏览器打开恶意页面
                │
                ▼
恶意页面自动提交表单 → POST /change-password
  Cookie: session=admin的会话   ← 浏览器自动附带 Cookie
  Body:   username=admin&new_password=hacker123
                │
                ▼
服务端检查: session.get("username") = "admin"  → 已登录 ✅
            @csrf.exempt                        → 不检查 CSRF Token ✅
            不验证原密码                         → 直接修改 ✅
                │
                ▼
  USERS["admin"]["password"] = hash("hacker123")  ← 密码被静默篡改 ❌
                │
                ▼
攻击者: 用 hacker123 登录 admin 账号 → 完全控制管理员账户 🔴
```

### 影响范围

| 影响 | 说明 |
|:----:|------|
| **账号劫持** | 攻击者可修改任意用户的密码，实现账号接管 |
| **权限提升** | 普通用户被诱导访问恶意页面后，其账号密码可被攻击者控制 |
| **数据泄露** | 通过已劫持的管理员账号，可访问所有用户数据 |
| **业务篡改** | 可通过已劫持的账号执行充值、修改资料等操作 |

---

## 🔧 修复方案

### 修复思路

**核心原则：永远不要手动豁免 POST 敏感操作的 CSRF 保护。**

Flask-WTF 的 `CSRFProtect` 中间件为所有非 GET 请求自动启用了 CSRF Token 校验（生成一次性 Token 绑定到 Session，表单提交时校验 Token 是否匹配）。只需要：
1. **移除 `@csrf.exempt`** — 让 CSRF 中间件正常生效
2. **表单添加 CSRF Token** — 让合法请求能通过校验

### 修复①：移除 `@csrf.exempt`（app.py）

```python
# 修复前                                              # 修复后
@app.route("/change-password", methods=["POST"])     # @app.route("/change-password", methods=["POST"])
@csrf.exempt           # ← 漏洞：绕过 CSRF 防护        # def change_password():
def change_password():                                #     """修改密码 - 任意已登录用户可修改任意用户密码"""
                                                      #     # CSRF 保护由 Flask-WTF 全局生效（CSRFProtect）
```

**效果**：`CSRFProtect` 中间件会自动拦截所有没有携带有效 `csrf_token` 的 POST 请求，返回 HTTP 400。

### 修复②：表单添加 CSRF Token 隐藏字段（profile.html）

```html
<!-- 修复前 -->                                      <!-- 修复后 -->
<form method="post" action="/change-password">       # <form method="post" action="/change-password">
    {# 注意：本表单不使用 CSRF Token #}               #     <input type="hidden" name="csrf_token"
    <input type="hidden" name="username" ...>         #         value="{{ csrf_token() }}">
</form>                                               #     <input type="hidden" name="username" ...>
                                                      # </form>
```

**效果**：表单提交时携带有效的 CSRF Token，合法用户修改密码的请求正常通过。

### 修复后的请求流程对比

```
修复前（漏洞状态）                        修复后（安全状态）
─────────────────────                    ─────────────────────
POST /change-password                    POST /change-password
  ↓                                        ↓
@csrf.exempt 跳过检查                    CSRFProtect 拦截检查
  ↓                                        ↓
直接修改密码 ✅ 攻击成功                  csrf_token 存在且有效？
                                            ↓
                                         是 → 修改密码 ✅
                                         否 → HTTP 400 拒绝 ❌
```

---

## ✅ 修复验证

### 安全测试（三种攻击向量全部拦截）

```
测试①：无 CSRF Token（模拟攻击者伪造请求）
  POST /change-password
    Body: username=admin&new_password=hacker123
  → HTTP 400  ❌ 拒绝
  → 日志: "The CSRF token is missing."
  → 密码未被修改 ✅

测试②：伪造/过期 CSRF Token（模拟 Token 窃取攻击）
  POST /change-password
    Body: username=admin&new_password=hacker123&csrf_token=fake-token
  → HTTP 400  ❌ 拒绝
  → 日志: "The CSRF token is invalid."
  → 密码未被修改 ✅

测试③：携带正确 CSRF Token（模拟合法用户操作）
  POST /change-password
    Body: username=admin&new_password=newadmin456&csrf_token=<正确 Token>
  → HTTP 302  → 跳转到 /profile ✅
  → 密码成功更新 ✅
```

### 功能回归（v1.0~v7.0 全部正常）

```
[v1.0] 首页        ✅    [v2.0] 登录    ✅    [v2.0] 注册    ✅
[v2.0] 登出        ✅    [v3.0] 搜索    ✅    [v4.0] 上传    ✅
[v5.0] 个人中心    ✅    [v5.0] 充值    ✅    [v6.0] 动态页面 ✅
[v7.0] 修改密码    ✅（含 CSRF Token 校验）
```

---

## 🛡️ 纵深防御建议

| 方案 | 说明 | 当前状态 |
|:----:|------|:--------:|
| **✅ CSRF Token** | Flask-WTF 为每个 Session 生成唯一 Token | ✅ 已启用 |
| **➕ SameSite Cookie** | 设置 `SESSION_COOKIE_SAMESITE="Lax"` 已启用 | ✅ 已启用（v1.0 基础配置） |
| **➕ HttpOnly Cookie** | 防止 JavaScript 读取 Session Cookie | ✅ 已启用（v1.0 基础配置） |
| **➕ 原密码验证** | 修改密码时要求输入原密码（降低 CSRF 影响） | ❌ 未启用（业务需求豁免） |
| **➕ 操作确认** | 敏感操作二次确认（密码修改后邮件/短信通知） | ❌ 可选增强 |
| **➕ Referer/Origin 校验** | 验证请求来源是否为本站 | ❌ 可选增强（业务需求明确豁免） |

---

## 📁 项目文件结构

```
7.0/
├── app.py                    # 主程序（含 CSRF 修复后的 /change-password 路由）
├── data/
│   └── users.db              # SQLite 用户数据库
├── pages/
│   └── help.html             # 帮助中心页面
├── README.md                 # 本报告（CSRF 漏洞审计与修复）
├── requirements.txt          # 依赖清单
├── setup.sh                  # 安装脚本
├── static/
│   └── css/
│       └── style.css         # 样式表（含修改密码表单样式）
└── templates/
    ├── base.html             # 基础模板（导航栏）
    ├── index.html            # 首页
    ├── login.html            # 登录
    ├── register.html         # 注册
    ├── profile.html          # 个人中心（含充值 + 修改密码表单）
    └── upload.html           # 头像上传
```

---

## 🚀 快速启动

```bash
cd /opt/Class01/7.0
bash setup.sh       # 安装依赖
python3 app.py      # 启动服务 → http://127.0.0.1:5000
```

| 用户 | 密码 | 角色 |
|:----:|:----:|:----:|
| `admin` | `admin123` | 管理员 |
| `alice` | `alice2025` | 普通用户 |

### 修改密码操作路径

1. 登录后点击导航栏「个人中心」
2. 在「修改密码」区域输入新密码和确认密码
3. 点击「修改密码」按钮
4. 密码修改成功后自动跳转回个人中心

---

## 📊 附录：所有 POST 路由 CSRF 防护审计清单

| 路由 | 方法 | CSRF 防护 | 审计结论 |
|:----:|:----:|:---------:|:--------:|
| `/login` | POST | `csrf_token` 表单字段 + CSRFProtect | ✅ 安全 |
| `/register` | POST | `csrf_token` 表单字段 + CSRFProtect | ✅ 安全 |
| `/upload` | POST | `csrf_token` 表单字段 + CSRFProtect | ✅ 安全 |
| `/recharge` | POST | `csrf_token` 表单字段 + CSRFProtect | ✅ 安全 |
| **`/change-password`** | POST | ~~`@csrf.exempt` 绕过~~ → 已修复 ✅ | **🛠️ 已修复** |

---

*报告生成日期：2026-07-24 | 版本：v7.0 | 类型：安全漏洞修复报告（CSRF）*
