# Class01/6.0 — 文件包含漏洞修复报告

| 项目 | 说明 |
|------|------|
| 项目名称 | Class01 用户管理系统 |
| 版本 | v6.0（安全修复版） |
| 基于 | v5.0（登录 + 注册 + 搜索 + 头像上传 + 个人中心 + 充值） |
| 新增功能 | 动态页面加载（`/page`） |
| 修复漏洞 | 路径遍历 / 任意文件读取 (Path Traversal) |
| CWE 编号 | CWE-22 / CWE-73 |
| 报告日期 | 2026-07-23 |

---

## 目录

1. [快速启动](#快速启动)
2. [v6.0 新增功能](#v60-新增功能)
3. [漏洞描述](#漏洞描述)
4. [漏洞复现](#漏洞复现)
5. [漏洞根因分析](#漏洞根因分析)
6. [修复方案](#修复方案)
7. [修复前后对比](#修复前后对比)
8. [修复验证](#修复验证)
9. [安全建议](#安全建议)

---

## 快速启动

```bash
cd /opt/Class01/6.0
# 首次运行需安装依赖
bash setup.sh
# 启动服务
python3 app.py
```

服务监听地址：`http://127.0.0.1:5000`

### 测试账号

| 用户名 | 密码 | 角色 | user_id |
|--------|:----:|:----:|:-------:|
| `admin` | `admin123` | admin（管理员） | 1 |
| `alice` | `alice2025` | user（普通用户） | 2 |

---

## v6.0 新增功能

### 动态页面加载 `/page`

| 项目 | 说明 |
|:----:|------|
| 路由 | `GET /page` |
| 参数 | `name`（URL 查询参数，如 `/page?name=help`） |
| 功能 | 根据 name 动态读取 `pages/` 目录下的 HTML 文件并显示在首页 |

**实现逻辑：**

```
用户请求 /page?name=help
      ↓
os.path.realpath() 规范化路径，校验是否在 pages/ 目录内
      ↓
尝试读取 pages/help，失败则尝试 pages/help.html
      ↓
读取文件内容，渲染 index.html
      ↓
模板使用 {{ page_content | safe }} 渲染 HTML
```

### 帮助中心页面

`pages/help.html` 包含：系统简介、常用功能说明、常见问题 FAQ、联系管理员信息。

---

## 漏洞描述

### 漏洞概述

`/page` 路由在拼接文件路径时，**直接将用户输入的 `name` 参数拼接到文件路径中**，未对 `../` 或绝对路径做任何过滤或校验，导致存在**路径遍历（Path Traversal）漏洞**。攻击者可以通过精心构造的 `name` 参数读取服务器上的任意文件。

### 风险等级

| 项目 | 评级 |
|:----:|:----:|
| CVSS 3.1 评分 | **7.5 (HIGH)** |
| 攻击向量 | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| 利用难度 | 低（无需认证，无需交互，直接浏览器访问） |

### 影响范围

| 风险项 | 说明 |
|:------:|------|
| 🔴 **源代码泄露** | 可读取 `app.py`、模板文件等所有项目文件 |
| 🔴 **数据库泄露** | 可下载 `data/users.db`，获取所有用户数据（含密码哈希） |
| 🔴 **系统文件读取** | 可读取 `/etc/passwd` 等 Linux 系统文件 |
| 🟠 **配置信息泄露** | 可读取 `.env`、`config.py` 等敏感配置文件 |

---

## 漏洞复现

### 攻击向量

| Payload | 构造的路径 | 实际读取的文件 | 效果 |
|---------|:----------:|:--------------:|:----:|
| `help` | `pages/help` | `pages/help.html` | ✅ 正常功能 |
| `../app.py` | `pages/../app.py` | `app.py` | 🔴 读取应用源码 |
| `../data/users.db` | `pages/../data/users.db` | `data/users.db` | 🔴 读取用户数据库 |
| `../../etc/passwd` | `pages/../../etc/passwd` | `/etc/passwd` | 🔴 读取系统文件 |
| `../../.git/config` | `pages/../../.git/config` | `.git/config` | 🔴 读取 Git 配置 |

### 攻击流程

```
攻击者请求: GET /page?name=../app.py
      ↓
服务端: os.path.join("pages", "../app.py")
      ↓
路径: "pages/../app.py"  →  等效于 "app.py"
      ↓
open("app.py", "r")  →  读取源码
      ↓
{{ page_content | safe }}  渲染到浏览器
      ↓
攻击者获取完整应用源码 ❌
```

---

## 漏洞根因分析

### 漏洞代码（修复前）

```python
@app.route("/page")
def dynamic_page():
    page_name = request.args.get("name", "").strip()

    if not page_name:
        return render_template("index.html", page_content="<p class='no-results'>未指定页面名称</p>")

    # ── 漏洞：直接拼接用户输入到路径 ──────────────
    # 未检查 name 中是否包含 "../"
    # 未使用 os.path.abspath / os.path.realpath 规范化
    page_path = os.path.join("pages", page_name)

    try:
        with open(page_path, "r", encoding="utf-8") as f:
            content = f.read()
    ...
```

### 具体缺陷

| # | 缺陷 | 说明 |
|:-:|:----:|------|
| 1 | **用户输入直接拼路径** | `os.path.join("pages", page_name)` 未对 `page_name` 做任何过滤 |
| 2 | **缺少路径遍历防护** | 未检查 `name` 中是否包含 `../` 或绝对路径前缀 `/` |
| 3 | **缺少路径规范化校验** | 未使用 `os.path.realpath()` 将路径规范化后再校验前缀 |
| 4 | **文件内容直接回显** | `{{ page_content \| safe }}` 将文件内容直接渲染，攻击者可读到文件内容 |
| 5 | **无需认证即可利用** | `/page` 路由没有登录要求，未登录用户也可发起攻击 |

---

## 修复方案

### 方案：路径规范化校验（★ 已采用）

使用 `os.path.realpath()` 将用户请求的路径**规范化（解析所有 `..` 和符号链接）** 后，检查其是否仍在 `pages/` 目录范围内。

**修复原理：**

```
用户输入: ../app.py
      ↓
拼接: os.path.join(pages_dir, "../app.py") = "/opt/Class01/6.0/pages/../app.py"
      ↓
规范化: os.path.realpath() = "/opt/Class01/6.0/app.py"
      ↓
校验: startswith("/opt/Class01/6.0/pages/") ?
      ↓
结果: ❌ 不在 pages/ 目录内 → 拦截
```

**修复代码：**

```python
@app.route("/page")
def dynamic_page():
    page_name = request.args.get("name", "").strip()

    if not page_name:
        return render_template("index.html", page_content="<p class='no-results'>未指定页面名称</p>")

    # ── 安全修复：路径规范化校验 ────────────────────
    pages_dir = os.path.realpath(os.path.join(app.root_path, "pages"))
    requested_path = os.path.realpath(os.path.join(pages_dir, page_name))

    if not requested_path.startswith(pages_dir + os.sep):
        logger.warning(f"[PAGE] 路径遍历攻击被拦截: '{page_name}'")
        return render_template("index.html", page_content="<p class='no-results'>非法的页面名称</p>")

    try:
        with open(requested_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        # 尝试 .html 后缀
        try:
            page_path_html = requested_path + ".html"
            with open(page_path_html, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            content = f"<p class='no-results'>页面 '{page_name}' 不存在</p>"
        except Exception as e:
            content = f"<p class='no-results'>页面加载失败: {e}</p>"
    except Exception as e:
        content = f"<p class='no-results'>页面加载失败: {e}</p>"

    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None
    return render_template("index.html", user=user_info, page_content=content)
```

### 备选方案

如果希望更高的安全性，还可叠加以下措施：

| 方案 | 安全性 | 灵活性 | 说明 |
|:----:|:------:|:------:|------|
| **白名单校验** | ⭐⭐⭐ | ⭐ | 只允许 `{"help", "about", "faq"}` 等预定义页面 |
| **正则过滤** | ⭐⭐ | ⭐⭐ | 只允许字母、数字、连字符：`^[a-zA-Z0-9_-]+$` |
| **组合方案** | ⭐⭐⭐ | ⭐⭐ | 白名单 + 路径规范化 + 正则三层防护 |

---

## 修复前后对比

### 代码对比

```
                   修复前                                     修复后
             ┌─────────────────┐                     ┌──────────────────────┐
 page_path = os.path.join("pages", page_name)        pages_dir = os.path.realpath(
                                                     os.path.join(app.root_path, "pages"))
             with open(page_path, "r")                requested_path = os.path.realpath(
                                                     os.path.join(pages_dir, page_name))
                                                     if not requested_path.startswith(
                                                         pages_dir + os.sep):
                                                         return 拦截
                                                     with open(requested_path, "r")
```

### 行为对比

| 请求 | 修复前 | 修复后 |
|:----:|:------:|:------:|
| `?name=help` | ✅ 加载帮助中心 | ✅ 加载帮助中心 |
| `?name=../app.py` | 🔴 读取 `app.py` 源码 | ✅ 拦截，返回"非法的页面名称" |
| `?name=../../etc/passwd` | 🔴 读取系统文件 | ✅ 拦截，返回"非法的页面名称" |
| `?name=../data/users.db` | 🔴 读取用户数据库 | ✅ 拦截，返回"非法的页面名称" |

---

## 修复验证

### 测试结果

```
[OK] /page?name=help             → 帮助中心             ✅
[OK] /page?name=help.html        → 帮助中心（含后缀）    ✅
[OK] /page (无参数)              → 未指定页面名称        ✅
[OK] /page?name=nonexistent      → 页面不存在            ✅
[SEC] /page?name=../app.py       → 拦截路径遍历          ✅
[SEC] /page?name=../data/users.db → 拦截路径遍历          ✅
[SEC] /page?name=../../etc/passwd → 拦截路径遍历          ✅
[SEC] /page?name=../../.git/config → 拦截路径遍历          ✅
[SEC] /page?name=..%2Fapp.py     → 拦截 URL 编码绕过     ✅
```

### 功能回归测试

```
[v1.0] 首页               ✅  [v2.0] 登录       ✅
[v2.0] 注册               ✅  [v2.0] 登出       ✅
[v3.0] 搜索               ✅  [v4.0] 上传       ✅
[v5.0] 个人中心           ✅  [v5.0] 充值       ✅
[v6.0] 动态页面加载       ✅  [v6.0] 路径遍历防护 ✅
```

---

## 安全建议

1. **输入校验**：永远不要信任用户输入，所有外部输入必须经过校验
2. **最小权限**：Web 应用应以低权限用户运行，限制可读取的文件范围
3. **纵深防御**：不要依赖单一安全机制，建议多层防护叠加（白名单 + 路径校验 + 正则过滤）
4. **生产环境配置**：
   - 禁用 `DEBUG` 模式
   - 设置 `SESSION_COOKIE_HTTPONLY=True`
   - 设置 `SESSION_COOKIE_SAMESITE="Lax"`
5. **定期安全审计**：重点关注文件操作、SQL 查询、命令执行等高危功能

---

*报告生成日期：2026-07-23 | 版本：v6.0 | 报告类型：安全漏洞修复报告*
