# Class01/6.0 — 文件包含漏洞修复报告

## 📋 概述

| 项目 | 说明 |
|------|------|
| 新增功能 | 动态页面加载（`/page` 路由） |
| 引入的漏洞 | **文件包含漏洞（路径遍历 / 任意文件读取）** |
| CWE 编号 | [CWE-22](https://cwe.mitre.org/data/definitions/22.html): Path Traversal |
| CVSS 3.1 | **7.5 (HIGH)** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| 利用条件 | 无需认证，无需交互，浏览器直接访问 |
| 修复方式 | `os.path.realpath()` 路径规范化 + 目录边界校验 |
| 状态 | **已修复 ✅** |

---

## 🚨 漏洞描述

### 漏洞成因

`/page` 路由的功能是根据用户传入的 `name` 参数，动态读取 `pages/` 目录下的文件并渲染到首页。但由于**直接将用户输入拼接到文件路径中**，且未做任何安全检查，导致攻击者可以通过 `../` 实现路径遍历，读取服务器上的**任意文件**。

### 漏洞代码（修复前）

```python
@app.route("/page")
def dynamic_page():
    page_name = request.args.get("name", "").strip()
    page_path = os.path.join("pages", page_name)   # ← 直接拼接用户输入

    with open(page_path, "r", encoding="utf-8") as f:  # ← 可读取任意文件
        content = f.read()

    return render_template("index.html", page_content=content)
```

这段代码存在 4 个关键缺陷：

| # | 缺陷 | 风险 |
|:-:|------|------|
| 1 | `os.path.join("pages", page_name)` — 用户输入直接拼路径 | 攻击者可任意控制读取的文件 |
| 2 | 未检查 `name` 中是否包含 `../` | 路径遍历可穿越目录 |
| 3 | 未使用 `os.path.realpath()` 规范化路径 | `../app.py` → 等效于 `app.py` |
| 4 | `{{ page_content \| safe }}` 直接渲染文件内容 | 攻击者可看到文件原始内容 |

---

## 🎯 漏洞复现

### 攻击向量

只需在浏览器 URL 中构造 `name` 参数即可完成攻击：

```
正常请求:
  GET /page?name=help
  → pages/help → pages/help.html ✅  正常加载帮助中心

攻击请求①: 读取应用源码
  GET /page?name=../app.py
  → pages/../app.py → 等效于 app.py 🔴  泄露全部源代码

攻击请求②: 下载用户数据库
  GET /page?name=../data/users.db
  → pages/../data/users.db 🔴  获取所有用户密码哈希

攻击请求③: 读取系统文件
  GET /page?name=../../etc/passwd
  → pages/../../etc/passwd → /etc/passwd 🔴  系统用户列表泄露
```

### 攻击原理图解

```
攻击者:          GET /page?name=../app.py
                         │
服务端拼接路径:   os.path.join("pages", "../app.py")
                         │
                         ▼
                  "pages/../app.py"
                         │
操作系统解析路径:  .. 表示上一级目录
                         │
                         ▼
                  等效于 "app.py"  ← 穿越出了 pages/ 目录
                         │
                         ▼
                  open("app.py").read()  →  读取全部源代码
                         │
                         ▼
                  {{ page_content | safe }}  →  渲染到浏览器
                         │
                         ▼
                  攻击者获得完整应用源码 ❌
```

---

## 🔧 修复方案

### 修复思路

利用 `os.path.realpath()` 将用户请求的路径**解析为真实绝对路径**（消除所有 `..` 和符号链接），然后检查该路径是否**仍在 `pages/` 目录的范围内**。

### 修复后的安全逻辑

```
用户输入: ../app.py
     │
     ▼
拼接: os.path.join(pages_dir, "../app.py")
     = "/opt/Class01/6.0/pages/../app.py"
     │
     ▼
规范化: os.path.realpath() → "/opt/Class01/6.0/app.py"
     │
     ▼
校验: 是否以 "/opt/Class01/6.0/pages/" 开头？
     │
     ▼
结果: ❌ 不是 → 拒绝访问，记录日志
```

### 修复代码

```python
@app.route("/page")
def dynamic_page():
    page_name = request.args.get("name", "").strip()

    if not page_name:
        return render_template("index.html",
            page_content="<p class='no-results'>未指定页面名称</p>")

    # ── 安全修复：路径规范化 + 目录边界校验 ──────────
    pages_dir = os.path.realpath(os.path.join(app.root_path, "pages"))
    requested_path = os.path.realpath(os.path.join(pages_dir, page_name))

    if not requested_path.startswith(pages_dir + os.sep):
        logger.warning(f"[PAGE] 路径遍历攻击被拦截: '{page_name}' -> '{requested_path}'")
        return render_template("index.html",
            page_content="<p class='no-results'>非法的页面名称</p>")

    try:
        with open(requested_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        try:
            page_path_html = requested_path + ".html"
            with open(page_path_html, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            content = f"<p class='no-results'>页面 '{page_name}' 不存在</p>"
    except Exception as e:
        content = f"<p class='no-results'>页面加载失败: {e}</p>"

    username = session.get("username")
    user_info = get_safe_user_info(username) if username else None
    return render_template("index.html", user=user_info, page_content=content)
```

### 修复前后的代码对比

```
▼ 修复前                                              ▼ 修复后
                                                    
page_path =                                          pages_dir = os.path.realpath(
  os.path.join("pages", page_name)                      os.path.join(app.root_path, "pages"))
                                                      requested_path = os.path.realpath(
with open(page_path, "r") as f:                          os.path.join(pages_dir, page_name))
  content = f.read()
                                                      if not requested_path.startswith(
                                                          pages_dir + os.sep):
                                                          return 拦截
                                                      
                                                      with open(requested_path, "r") as f:
                                                        content = f.read()
```

核心变化：
1. **获取基准目录**：`os.path.realpath(app.root_path + "/pages")` 得到 `pages/` 的真实绝对路径
2. **规范化请求路径**：`os.path.realpath(pages_dir + page_name)` 将用户路径中的所有 `..` 解析掉
3. **前缀校验**：校验规范化后的路径是否以 `pages_dir` 开头——只要不在 `pages/` 目录内就拒绝

---

## ✅ 修复验证

### 安全测试（路径遍历被全部拦截）

```
[SEC] /page?name=../app.py              → 拦截 ✅  日志: "路径遍历攻击被拦截"
[SEC] /page?name=../data/users.db       → 拦截 ✅
[SEC] /page?name=../../etc/passwd       → 拦截 ✅
[SEC] /page?name=../../.git/config      → 拦截 ✅
[SEC] /page?name=..%2Fapp.py            → 拦截 ✅  URL 编码绕过也无效
```

日志输出示例：
```
WARNING [PAGE] 路径遍历攻击被拦截: '../app.py' -> '/opt/Class01/6.0/app.py' (不在 pages/ 目录内)
```

### 正常功能（完全不受影响）

```
[OK] /page?name=help                    → 帮助中心 ✅
[OK] /page?name=help.html               → 帮助中心（带后缀）✅
[OK] /page (无参数)                     → "未指定页面名称" ✅
[OK] /page?name=nonexistent             → "页面不存在" ✅
```

### 功能回归（v1.0~v5.0 全部正常）

```
[v1.0] 首页        ✅    [v2.0] 登录    ✅    [v2.0] 注册    ✅
[v2.0] 登出        ✅    [v3.0] 搜索    ✅    [v4.0] 上传    ✅
[v5.0] 个人中心    ✅    [v5.0] 充值    ✅
```

---

## 🛡️ 防御纵深建议

当前修复使用**路径规范化校验**，在此基础上可叠加以下措施形成纵深防御：

| 方案 | 说明 | 安全性 |
|:----:|------|:------:|
| **✅ 路径规范化**（已采用） | `os.path.realpath()` + `startswith()` 校验 | ⭐⭐⭐ |
| **➕ 白名单校验**（可选） | 只允许 `{"help", "about", "faq"}` 等预定义页面 | ⭐⭐⭐ |
| **➕ 正则过滤**（可选） | 只允许 `^[a-zA-Z0-9_-]+$`，拒绝含 `/` 或 `..` 的输入 | ⭐⭐ |

---

## 📁 项目文件结构

```
6.0/
├── app.py                    # 主程序（含漏洞修复后的 /page 路由）
├── pages/
│   └── help.html             # 帮助中心页面
├── README.md                 # 本报告
├── requirements.txt
├── setup.sh
├── static/css/style.css
└── templates/
    ├── base.html
    ├── index.html            # 含 page_content 显示区域 + 帮助中心入口
    ├── login.html
    ├── register.html
    ├── profile.html
    └── upload.html
```

---

## 🚀 快速启动

```bash
cd /opt/Class01/6.0
bash setup.sh       # 安装依赖
python3 app.py      # 启动服务 → http://127.0.0.1:5000
```

| 用户 | 密码 | 角色 |
|:----:|:----:|:----:|
| `admin` | `admin123` | 管理员 |
| `alice` | `alice2025` | 普通用户 |

---

*报告生成日期：2026-07-23 | 版本：v6.0 | 类型：安全漏洞修复报告*
