# Class01/4.0 — 用户管理系统（头像上传版）

| 项目 | 说明 |
|------|------|
| 项目名称 | Class01 用户管理系统 |
| 版本 | v4.0 |
| 基于 | v3.0（登录 + 注册 + 搜索） |
| 新增功能 | 用户头像上传（`/upload`） |
| 报告日期 | 2026-07-21 |

---

## 快速启动

```bash
cd /opt/Class01/4.0
# 首次运行安装依赖
bash setup.sh
# 启动
python3 app.py
```

服务监听地址：`http://127.0.0.1:5000`，仅本机可访问。

### 测试账号

| 用户名 | 密码 |
|--------|------|
| `admin` | `admin123` |
| `alice` | `alice2025` |

---

## v4.0 变更概览

### 新增功能

| 功能 | 路由 | 说明 |
|:----:|:----:|------|
| 用户头像上传 | `GET/POST /upload` | 登录用户可选择本地图片上传至服务器 |
| 图片预览 | 上传成功后页面内预览 | 显示图片 + 文件访问链接 |
| 自动目录创建 | `static/uploads/` | 首次上传时自动创建存储目录 |

### 新增/修改文件

```
4.0/
├── app.py                        # 新增 /upload 路由 + MAX_CONTENT_LENGTH=16MB
├── templates/upload.html         # 新增：上传页面（文件选择 + 预览 + 错误提示）
├── templates/base.html           # 修改：导航栏增加"上传头像"链接
├── templates/index.html          # 修改：首页增加"上传头像"快捷入口
└── static/uploads/               # 新增：上传文件存储目录
```

### 原有功能

登录、注册、搜索、登出功能完全保持不变。

---

## 文件上传漏洞审计与修复报告

> **审计目标：** v4.0 头像上传功能（`/upload` 路由）
> **审计日期：** 2026-07-21
> **审计方法：** 白盒代码审计 + 攻击向量推演

---

### 目录

1. [审计概述](#1-审计概述)
2. [审计方法](#2-审计方法)
3. [风险评估标准](#3-风险评估标准)
4. [审计发现](#4-审计发现)
5. [修复措施](#5-修复措施)
6. [修复后代码](#6-修复后代码)
7. [复测验证](#7-复测验证)
8. [审计结论](#8-审计结论)

---

### 1. 审计概述

#### 1.1 审计背景

v4.0 在 v3.0（登录 + 注册 + 搜索）基础上新增了用户头像上传功能，实现了 `/upload` 路由的 GET/POST 请求处理。该功能允许已登录用户将本地文件上传至服务器 `static/uploads/` 目录。本次审计针对该新增功能进行安全审查。

#### 1.2 审计目标

- 识别上传功能中存在的安全漏洞
- 评估各漏洞的风险等级和利用难度
- 提供可落地的修复方案
- 验证修复后的安全性

#### 1.3 审计依据

审计参考以下安全标准与最佳实践：
- OWASP File Upload Cheat Sheet
- OWASP Top 10 2021 — A04:2021 Insecure Design
- CWE-22: Path Traversal
- CWE-434: Unrestricted File Upload
- CWE-23: Relative Path Traversal

#### 1.4 审计范围

| 审计项 | 说明 |
|--------|------|
| **目标应用** | Class01/4.0 用户管理系统 |
| **审计功能** | `/upload` 路由（GET + POST） |
| **相关文件** | `app.py` upload 路由 |
| **审计约束** | 假设攻击者已登录（上传需认证）；`/static/` 公开可访问 |

#### 1.5 审计功能流程

```
┌─────────────┐     GET /upload     ┌──────────────┐
│  未登录用户  │ ──────────────────→ │  重定向 /login │
└─────────────┘                     └──────────────┘

┌─────────────┐     GET /upload     ┌──────────────┐
│  已登录用户  │ ──────────────────→ │  upload.html  │
└─────────────┘     POST /upload    │  (文件选择)    │
       │        ──────────────────→ └──────────────┘
       │                                   │
       │   文件接收                         │
       │   file = request.files.get("file")│
       │   filename = file.filename        │
       │                                   ↓
       │                          ┌──────────────────┐
       │                          │  保存到           │
       │                          │  static/uploads/  │
       │                          │   ← 原始文件名    │
       │                          └──────────────────┘
       │                                   │
       │                                   ↓
       │                          ┌──────────────────┐
       │                          │  返回 upload.html │
       │                          │  + 图片预览 + URL │
       └─────────────────────────→└──────────────────┘
```

---

### 2. 审计方法

本次审计采用 **白盒审计**（White-box Audit）方式，结合代码审查和攻击模拟进行。

#### 2.1 静态代码分析

| 检查点 | 审查项 |
|--------|--------|
| 文件路径处理 | 文件名是否经过安全过滤，是否存在路径穿越可能 |
| 文件类型校验 | 是否有类型限制，校验逻辑是否完整 |
| 文件内容验证 | 是否验证文件真实内容格式 |
| 文件名冲突处理 | 是否处理同名文件覆盖问题 |
| 大小限制 | 是否限制文件大小（`MAX_CONTENT_LENGTH`） |
| 错误处理 | 错误信息是否泄露敏感信息 |
| 认证检查 | 未登录用户是否可访问 |

#### 2.2 攻击向量推演

| 攻击向量 | 测试方法 | 预期后果 |
|---------|---------|---------|
| 路径遍历 | 上传 `../../app.py` | 覆盖应用源代码 |
| 任意文件上传 | 上传 `.html` 文件 | 存储型 XSS |
| 后缀伪造 | 修改后缀为 `.png` 上传非图片 | 绕过扩展名检查 |
| 同名覆盖 | 两次上传同名文件 | 覆盖已有文件 |
| 空文件名 | 不传文件或空文件名 | 异常错误 |

---

### 3. 风险评估标准

| 维度 | 高 | 中 | 低 |
|------|:--:|:--:|:--:|
| **利用难度** | 无需身份认证或简单绕过 | 需要认证但无额外限制 | 需要特殊条件或组合攻击 |
| **影响范围** | 影响全部用户或服务器安全 | 影响单个用户或部分功能 | 影响极小或无实际危害 |
| **修复紧急度** | 应立即修复 | 应在下次迭代修复 | 可选修复 |

**等级定义：**

| 等级 | 代码 | 定义 |
|:----:|:----:|------|
| 🔴 **高危** | P1 | 可导致远程代码执行、数据泄露、权限提升 |
| 🟠 **中危** | P2 | 可导致信息泄露、功能绕过、有限的数据破坏 |
| 🟢 **低危** | P3 | 用户体验问题，或需结合其他漏洞才能利用 |

---

### 4. 审计发现

#### 4.1 发现一：路径遍历漏洞

| 属性 | 值 |
|------|-----|
| **漏洞编号** | FU-001 |
| **CWE 映射** | [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html) |
| **风险等级** | 🔴 高危（P1） |
| **利用难度** | 低 |
| **影响范围** | 服务器文件系统 |

##### 漏洞描述

`/upload` 路由在接收用户上传文件后，直接将用户提供的 `file.filename` 拼接到文件保存路径中，未做任何安全过滤。

```python
# 漏洞代码
filename = file.filename          # 攻击者完全可控
file.save(os.path.join(upload_dir, filename))  # 路径拼接
```

`request.files.get("file").filename` 由客户端（HTTP 请求）提供，攻击者可构造包含路径分隔符和上级目录引用的恶意文件名。

##### 攻击向量

| Payload 文件名 | 实际保存路径 | 攻击后果 |
|---------------|-------------|---------|
| `../../app.py` | 穿越到应用根目录 | **覆盖应用源代码**，植入后门 |
| `../templates/index.html` | 模板目录 | **篡改首页**，植入钓鱼表单或 XSS |
| `../../etc/cron.d/malware` | 系统定时任务目录 | **植入定时任务**，持久化后门 |
| `../../venv/bin/python` | Python 解释器路径 | **替换可执行文件** |

##### 根因分析

1. 开发者已导入 `werkzeug.utils.secure_filename`，但未在 upload 路由中使用
2. 直接信任了 HTTP 请求中的 `file.filename` 字段
3. 未考虑操作系统路径解析中的 `..` 和 `/` 特殊含义

---

#### 4.2 发现二：任意文件上传漏洞

| 属性 | 值 |
|------|-----|
| **漏洞编号** | FU-002 |
| **CWE 映射** | [CWE-434: Unrestricted File Upload](https://cwe.mitre.org/data/definitions/434.html) |
| **风险等级** | 🔴 高危（P1） |
| **利用难度** | 低 |
| **影响范围** | 全部用户（XSS）/ 服务器（RCE） |

##### 漏洞描述

上传功能对文件类型**没有任何限制**，不检查后缀名、不检查 MIME 类型、不检查文件内容，任何文件都可上传并被公开访问。

```python
# 漏洞代码
# ← 无任何文件类型检查
filename = file.filename          # 任意扩展名
file.save(os.path.join(upload_dir, filename))
file_url = url_for("static", filename=f"uploads/{filename}")  # 公开可访问
```

##### 攻击向量

| 文件类型 | 攻击方式 |
|---------|---------|
| **`.html`** | 直接浏览器访问，HTML 中的 JS 在服务器源下执行 → **存储型 XSS** |
| **`.svg`** | SVG 嵌入 `<script>` 或 `onload` 事件，预览时触发 |
| **`.php`** | 若服务器配置 PHP 解析，直接获取 webshell |
| **`.exe`/`.dll`** | 可被其他用户下载，传播恶意软件 |

##### 根因分析

1. 代码注释明确写了"不做任何类型检查"——这是一个**有意识的**安全缺陷
2. 缺少扩展名白名单机制
3. 未识别 `.html`/`.svg` 在静态文件服务下的风险

---

#### 4.3 发现三：MIME 伪造绕过（魔数校验缺失）

| 属性 | 值 |
|------|-----|
| **漏洞编号** | FU-003 |
| **CWE 映射** | [CWE-180: Incorrect Behavior Order](https://cwe.mitre.org/data/definitions/180.html) |
| **风险等级** | 🟠 中危（P2） |
| **利用难度** | 低 |
| **影响范围** | 服务器（RCE） |

##### 漏洞描述

仅靠扩展名检查是不够的（即使假设有），攻击者可以将任意文件改名为合法后缀即可绕过。这称为 **MIME 伪造**（MIME Spoofing）。

```
cp /bin/bash shell.png   # 将 ELF 可执行文件改名为 shell.png
# 扩展名检查: .png → 通过（如果检查的话）
# 实际内容: ELF 可执行文件 → 危险
```

##### 根因分析

1. 未对文件内容进行魔数（Magic Bytes）验证
2. 信赖了客户端提供的 `file.filename` 中的扩展名
3. 缺乏"检查内容是否与扩展名一致"的纵深防御

---

#### 4.4 发现四：文件覆盖风险

| 属性 | 值 |
|------|-----|
| **漏洞编号** | FU-004 |
| **CWE 映射** | [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html) |
| **风险等级** | 🟢 低危（P3） |
| **利用难度** | 中 |
| **影响范围** | 单个用户 |

##### 漏洞描述

使用用户原始文件名直接保存，不同用户上传同名文件会互相覆盖。

```
09:00  alice 上传 avatar.png  → 保存为 static/uploads/avatar.png
09:05  bob   上传 avatar.png  → 覆盖为 bob 的文件 ❌
```

##### 根因分析

1. 直接使用用户提供的文件名，没有添加唯一化标识
2. 未考虑多用户场景下的文件名冲突

---

#### 4.5 发现五：客户端文件类型限制缺失

| 属性 | 值 |
|------|-----|
| **漏洞编号** | FU-005 |
| **CWE 映射** | [CWE-602: Client-Side Enforcement](https://cwe.mitre.org/data/definitions/602.html) |
| **风险等级** | 🟢 低危（P3） |

##### 漏洞描述

文件选择输入框没有 `accept` 属性，用户可选择任意类型文件。此问题本身不构成安全漏洞（服务端已加强校验后），属于用户体验优化项。

---

#### 4.6 审计发现汇总

| 编号 | 漏洞名称 | 等级 | CWE | 利用难度 | 影响 |
|:----:|---------|:----:|:---:|:--------:|:----:|
| FU-001 | 路径遍历 | 🔴 P1 | 22 | 低 | 覆盖应用源代码 |
| FU-002 | 任意文件上传 | 🔴 P1 | 434 | 低 | XSS / RCE |
| FU-003 | MIME 伪造绕过 | 🟠 P2 | 180 | 低 | 任意文件上传辅助 |
| FU-004 | 文件覆盖 | 🟢 P3 | 377 | 中 | 覆盖他人上传文件 |
| FU-005 | 客户端限制缺失 | 🟢 P3 | 602 | — | 用户体验优化 |

---

### 5. 修复措施

#### 5.1 修复优先级

```
                          影响范围
                  小             大
              ┌────────────┬────────────┐
         高   │  FU-004    │  FU-001    │
              │  (文件覆盖) │  (路径遍历) │
  利用        ├────────────┼────────────┤
  难度        │  FU-005    │  FU-002    │
         低   │  (客户端)   │  (任意文件) │
              │            │  FU-003    │
              │            │  (魔数验证) │
              └────────────┴────────────┘
    修复顺序: FU-001 → FU-002 → FU-003 → FU-004 → FU-005
```

#### 5.2 修复一：路径遍历 — `secure_filename()`

```python
from werkzeug.utils import secure_filename

# 修复前
filename = file.filename                           # "../../app.py"
file.save(os.path.join(upload_dir, filename))      # 穿越到父目录

# 修复后
safe_name = secure_filename(file.filename)          # "app.py"
file.save(os.path.join(upload_dir, safe_name))
```

**`secure_filename()` 行为对照表：**

| 输入 | 输出 | 说明 |
|------|------|------|
| `../../app.py` | `app.py` | 移除 `../` 路径遍历 |
| `foo/bar.png` | `bar.png` | 移除路径分隔符 |
| `a\b.txt` | `b.txt` | 移除 Windows 路径分隔符 |
| `<script>x</script>.png` | `script_x_script_.png` | 过滤 HTML 特殊字符 |

#### 5.3 修复二：任意文件上传 — 扩展名白名单

```python
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}

def allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

# 路由中调用
if not allowed_file(file.filename):
    return render_template("upload.html", error="仅允许上传图片文件")
```

> **为什么 SVG 不在白名单中？** SVG 是 XML 文档，支持嵌入 `<script>` 和事件处理器，即使通过 `<img>` 加载仍存在 XSS 风险，**不应纳入图片上传白名单**。

**白名单 vs 黑名单：**

| 方案 | 安全性 | 说明 |
|:----:|:------:|------|
| 白名单 | ✅ 高 | 明确允许的才通过，其余全部拒绝 |
| 黑名单 | ❌ 低 | 易绕过（`.phtml`、`.php5`、`.PhP`、`.php.jpg`） |

#### 5.4 修复三：MIME 伪造 — 魔数校验

```python
def is_actual_image(file_stream):
    """通过文件头部魔数验证是否为真实图片"""
    header = file_stream.read(12)
    file_stream.seek(0)  # 重要：重置指针，不影响后续保存

    if header[:3] == b'\xff\xd8\xff':        # JPEG
        return True
    if header[:8] == b'\x89PNG\r\n\x1a\n':   # PNG
        return True
    if header[:6] in (b'GIF87a', b'GIF89a'): # GIF
        return True
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP':  # WebP
        return True
    if header[:2] == b'BM':                  # BMP
        return True
    return False
```

**常见魔数对照表：**

| 文件格式 | 魔数（十六进制） | 魔数（文本） |
|---------|----------------|:-----------:|
| **JPEG** | `FF D8 FF` | 不可见 |
| **PNG** | `89 50 4E 47 0D 0A 1A 0A` | `.PNG....` |
| **GIF** | `47 49 46 38 37/39 61` | `GIF87a/89a` |
| **WebP** | `52 49 46 46 xx xx xx xx 57 45 42 50` | `RIFF....WEBP` |
| **BMP** | `42 4D` | `BM` |
| **ELF** | `7F 45 4C 46` | `.ELF` |
| **PE (exe)** | `4D 5A` | `MZ` |

#### 5.5 修复四：文件覆盖 — UUID 唯一化命名

```python
import uuid

unique_name = f"{uuid.uuid4().hex}_{safe_name}"
# 示例: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6_avatar.png
```

UUID v4 碰撞概率约 `1/2¹²²`，即使每秒生成 10 亿个，约 100 年才有 50% 碰撞概率。

#### 5.6 修复五：客户端限制

```html
<input type="file" id="file" name="file" class="file-input" accept="image/*">
```

> ⚠️ **安全提示：** `accept` 属性只是客户端用户体验优化，**不能替代服务端校验**。攻击者可通过 curl、Burp Suite 等工具直接构造 HTTP 请求绕过。

#### 5.7 修复中的未解决问题

| 事项 | 状态 | 说明 |
|------|:----:|------|
| 文件名字长度限制（>255） | ❌ 未处理 | 极端长文件名可能导致 `OSError` |
| 压缩炸弹 | ❌ 未处理 | 极小图片解压后极大，Flask 仅限制请求体大小 |
| EXIF 信息泄露 | ❌ 未处理 | 上传图片可能含 GPS 位置、设备信息 |

---

### 6. 修复后代码

```python
import uuid
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'}

def allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def is_actual_image(file_stream):
    header = file_stream.read(12)
    file_stream.seek(0)
    if header[:3] == b'\xff\xd8\xff':
        return True
    if header[:8] == b'\x89PNG\r\n\x1a\n':
        return True
    if header[:6] in (b'GIF87a', b'GIF89a'):
        return True
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
        return True
    if header[:2] == b'BM':
        return True
    return False

@app.route("/upload", methods=["GET", "POST"])
def upload():
    username = session.get("username")
    if not username:
        return redirect("/login")

    if request.method == "GET":
        return render_template("upload.html")

    file = request.files.get("file")
    if not file or file.filename == "":
        return render_template("upload.html", error="请选择要上传的文件")

    # ① 扩展名白名单检查
    if not allowed_file(file.filename):
        return render_template("upload.html", error="仅允许上传图片文件")

    # ② 魔数校验
    if not is_actual_image(file):
        return render_template("upload.html", error="文件内容不是有效的图片格式")

    upload_dir = os.path.join(app.root_path, "static", "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    # ③ secure_filename 防路径遍历
    original_filename = file.filename
    safe_name = secure_filename(original_filename)

    # ④ UUID 唯一化命名防覆盖
    unique_name = f"{uuid.uuid4().hex}_{safe_name}"
    file.save(os.path.join(upload_dir, unique_name))

    file_url = url_for("static", filename=f"uploads/{unique_name}")
    logger.info(f"[UPLOAD] '{original_filename}' -> '{unique_name}'")
    return render_template(
        "upload.html",
        success=True, file_url=file_url,
        filename=unique_name, original_filename=original_filename,
    )
```

**修复前后对照：**

| 安全维度 | 修复前 | 修复后 |
|---------|--------|--------|
| 文件名安全 | `file.filename` 直接拼接 | `secure_filename()` 过滤 |
| 文件类型检查 | 无 | 扩展名白名单（6 种图片格式） |
| 文件内容验证 | 无 | 魔数 Signature 校验（5 种格式） |
| 文件名唯一性 | 冲突时覆盖 | UUID v4 前缀唯一化 |
| 客户端限制 | 无 | `accept="image/*"` |
| 上传限制 | `MAX_CONTENT_LENGTH=16MB` | ✅ 保留不变 |

---

### 7. 复测验证

#### 7.1 安全测试

| 测试用例 | 攻击类型 | 预期结果 | 结果 |
|---------|---------|---------|:----:|
| 上传 `../../app.py` | 路径遍历 | 文件保存在 uploads/ 内 | ✅ |
| 上传 `test.html`（含 script） | 存储型 XSS | 返回"仅允许上传图片文件" | ✅ |
| 上传 `shell.exe` 改名为 `evil.png` | MIME 伪造 | 魔数校验拦截 | ✅ |
| 两次上传同名 `avatar.png` | 文件覆盖 | 不同 UUID 前缀，互不覆盖 | ✅ |
| 上传无扩展名文件 | 绕过检查 | 返回"仅允许上传图片文件" | ✅ |

#### 7.2 功能测试

| 测试场景 | 预期结果 | 结果 |
|---------|---------|:----:|
| 上传真实 PNG / JPEG / GIF / WebP 图片 | 正常显示预览和链接 | ✅ |
| 未登录访问 `/upload` | 重定向到 `/login` | ✅ |
| 登录后 GET `/upload` | 显示上传页面 | ✅ |
| 上传成功显示原始文件名 | 页面显示原始文件名 | ✅ |
| 原有登录 / 注册 / 搜索功能 | 完全不受影响 | ✅ |

#### 7.3 回归测试说明

v4.0 所有修复均基于 `/upload` 路由的修改，以下已有功能的相关代码**未做任何改动**：

| 功能 | 路由 | 是否修改 |
|:----:|:----:|:--------:|
| 首页 | `index` | ❌ |
| 登录 | `login` + `login.html` | ❌ |
| 注册 | `register` + `register.html` | ❌ |
| 搜索 | `search` | ❌ |
| 登出 | `logout` | ❌ |
| 导航栏 | `base.html` | ❌ |
| 样式 | `style.css` | ❌ |

---

### 8. 审计结论

#### 8.1 修复统计

| 统计项 | 数值 |
|--------|:----:|
| 发现漏洞总数 | **5** |
| 已修复漏洞数 | **5** |
| 🔴 高危（P1） | 2 — 路径遍历、任意文件上传 |
| 🟠 中危（P2） | 1 — MIME 伪造绕过（魔数校验缺失） |
| 🟢 低危（P3） | 2 — 文件覆盖、客户端限制缺失 |
| 新增依赖 | 0（使用内置 `uuid` + 已有 `werkzeug`） |

#### 8.2 纵深防御架构

修复后的上传功能形成了 **4 层安全防线**：

```
Layer 1: 认证层           session 检查 → 未登录跳转
Layer 2: 文件类型检查      扩展名白名单（6 种图片格式）
Layer 3: 文件内容验证      魔数 Magic Bytes 校验（5 种格式）
Layer 4: 文件存储安全      secure_filename + UUID + 大小限制
```

#### 8.3 后续改进建议

| 建议 | 优先级 | 说明 |
|:----:|:------:|------|
| Nginx 禁止执行脚本 | 🟠 高 | `static/uploads/` 目录配置 `deny all` 对 PHP/脚本的解析 |
| EXIF 元数据清理 | 🟢 中 | 使用 Pillow 清理图片中的 GPS、设备信息 |
| 上传频率限制 | 🟢 中 | 为 `/upload` 添加 `@limiter.limit("10 per minute")` |
| 图片重新压缩 | 🟢 低 | 上传时重新编码图片，消除压缩炸弹和嵌入的非图片数据 |

---

*报告生成日期：2026-07-21 | 审计方法：白盒代码审计 + 攻击向量推演*
