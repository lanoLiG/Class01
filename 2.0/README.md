# 用户信息管理平台（安全加固版）

> 本项目的功能与 [v1.0](../1.0) 完全一致，但在安全性上做了全面加固，修复了 v1.0 中的所有已知漏洞。

---

## Kali Linux 环境配置

> 不要直接执行 `pip install -r requirements.txt`，会报 PEP 668 错误。

### 方式一：setup.sh 自动配置（推荐）

```bash
cd /opt/Class01/2.0
./setup.sh
python3 app.py
```

### 方式二：手动安装

```bash
sudo apt install -y python3-flask python3-flaskext.wtf python3-flask-limiter
python3 app.py
```

### 方式三：虚拟环境

```bash
cd /opt/Class01/2.0
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
python3 app.py
```

服务仅监听 `http://127.0.0.1:5000`，仅本机可访问。

---

## 漏洞分析与修复对照

v1.0 包含以下 **12 个安全漏洞**，v2.0 逐一进行了修复：

---

### 🔴 P0 — 严重漏洞

#### 1. 密码明文存储

| 项目 | 说明 |
|------|------|
| **v1.0 漏洞** | `"password": "admin123"` 明文字符串 |
| **风险** | 服务器被入侵 → 所有密码完全暴露 |
| **v2.0 修复** | `generate_password_hash()` bcrypt 哈希存储 |

```python
# ❌ v1.0
USERS = {"admin": {"password": "admin123"}}

# ✅ v2.0
USERS = {"admin": {"password": generate_password_hash("admin123")}}
```

#### 2. 密码明文比对

| 项目 | 说明 |
|------|------|
| **v1.0 漏洞** | `==` 直接比对字符串 |
| **v2.0 修复** | `check_password_hash()` 安全哈希比对 |

#### 3. 密码明文展示在前端页面

| 项目 | 说明 |
|------|------|
| **v1.0 漏洞** | `{{ user.password }}` 展示在页面 |
| **v2.0 修复** | `get_safe_user_info()` 过滤 password 字段，页面不再显示密码 |

#### 4. Secret Key 硬编码

| 项目 | 说明 |
|------|------|
| **v1.0 漏洞** | `"dev-key-2025"` 公开已知字符串 |
| **风险** | 可伪造任意 session cookie |
| **v2.0 修复** | `secrets.token_hex(32)` 随机生成 |

```bash
# 攻击 v1.0：
flask-unsign --sign --cookie "{'username':'admin'}" --secret "dev-key-2025"
```

---

### 🟠 P1 — 高危漏洞

| # | 漏洞 | v1.0 | v2.0 修复 |
|:-:|------|------|-----------|
| 5 | Debug 模式 | `debug=True` → RCE 风险 | `debug=False` |
| 6 | 绑定地址 | `host="0.0.0.0"` 全网可达 | `host="127.0.0.1"` 仅本地 |
| 7 | 暴力破解 | 无限制 | `@limiter.limit("10 per minute")` |
| 8 | CSRF 防护 | 无 token 校验 | `CSRFProtect(app)` + 表单 token |

---

### 🟡 P2 — 中危漏洞

| # | 漏洞 | v1.0 | v2.0 修复 |
|:-:|------|------|-----------|
| 9 | HTML 注释泄密 | 泄露 `admin / admin123` | 已删除 |
| 10 | Session 过期 | 31 天永久有效 | 2 小时超时 |
| 11 | 日志审计 | 无 | 登录成功/失败/登出全记录 |
| 12 | 输入校验 | 无 | 空值 + 长度限制 |

---

### 🔵 其他加固

```python
SESSION_COOKIE_HTTPONLY=True   # 禁止 JS 读取 cookie
SESSION_COOKIE_SAMESITE="Lax"  # 限制跨站请求
```

登录失败统一提示 `"用户名或密码错误"`，防止用户枚举。

#### 防御层次总览

```
攻击者
  ├─ 伪造 cookie? → secrets.token_hex(32) → 无法伪造 ✗
  ├─ CSRF 攻击?   → CSRFProtect → HTTP 400 ✗
  ├─ 暴力破解?    → 10次/分钟限流 → HTTP 429 ✗
  ├─ 密码泄露?    → bcrypt 哈希 → 无法逆向 ✗
  └─ 信息泄露?    → 统一错误信息 + 无密码展示 → 无可利用信息 ✗
```

---

## 项目结构

```
2.0/
├── setup.sh                   # 环境配置脚本
├── app.py                     # Flask 主应用（安全加固版）
├── requirements.txt           # pip 依赖清单
├── templates/
│   ├── base.html              # 基础模板
│   ├── index.html             # 首页（无密码展示）
│   └── login.html             # 登录页（含 CSRF token）
└── static/css/
    └── style.css              # 样式文件
```

## 功能说明

- **首页 /** — 显示当前登录用户的信息（**不包含密码**）
- **登录 /login** — GET 显示表单，POST 安全验证
- **登出 /logout** — 清除 session 并跳转首页
