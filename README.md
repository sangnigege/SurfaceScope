# SurfaceScope

> 一个工具完成 Web 攻击面评估

> 目录发现 → JS/API 提取 → 指纹识别 → 403/401 复核 → Swagger 分析 → Packer 分析 → 统一报告

[![ci](https://github.com/sangnigege/SurfaceScope/actions/workflows/ci.yml/badge.svg)](https://github.com/sangnigege/SurfaceScope/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)

> ⚠️ 仅用于你拥有或已取得明确书面授权的目标。默认只做低风险发现，主动探测必须显式开启。


## 快速开始

### 安装

需要 Python 3.10 或更高版本。两种方式按用途选一个。

#### 方式一：uv / pipx（推荐，只运行不开发）

```bash
# uv：安装到独立工具环境，速度快
uv tool install "git+https://github.com/sangnigege/SurfaceScope.git@main"

# pipx：等价方案
pipx install "git+https://github.com/sangnigege/SurfaceScope.git@main"

surfacescope --version
```

两种方式都会把 `surfacescope`、`sscope`、`dsbp` 三个命令装进独立虚拟环境并放上 PATH，
不污染系统 Python。升级用 `uv tool upgrade surfacescope` 或 `pipx reinstall surfacescope`；
卸载用 `uv tool uninstall surfacescope` 或 `pipx uninstall surfacescope`。

> 尚未发布到 PyPI，暂时不能 `pipx install surfacescope`；请使用上面带 `git+https://` 的写法。
> 需要锁定版本时把 `@main` 换成具体 tag 或 commit hash。

#### 方式二：源码开发（可编辑安装）

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\surfacescope --version
```

Linux/WSL 用 `.venv/bin/python` 和 `.venv/bin/surfacescope`。

### 30 秒上手

```powershell
# 1. 先干跑，确认目标、组件和预算，不发任何扫描请求
surfacescope -u https://example.com/ --all --dry-run --no-env

# 2. 默认只跑低风险三件套：目录发现 + JS 提取 + 指纹
surfacescope -u https://example.com/

# 3. 确认授权后再开全部阶段（403 仍用 fast，写方法/SQLi/unsafe Packer 不会自动开）
surfacescope -u https://example.com/ --all
```

### 常用场景

| 我想做什么 | 命令 |
|---|---|
| 只看有哪些组件和资产 | `surfacescope --list-components` / `--list-assets` |
| 指定字典、扩展名和并发 | `surfacescope -u <url> --wordlist paths --extensions php,aspx,jsp --threads 25` |
| 复核某个目录的 403 | `surfacescope -u <url>/admin --components bypass403 --bypass --bypass-mode fast` |
| 一次拿到四种格式报告 | `surfacescope -u <url> --format json,markdown,html,csv --output reports` |
| 用配置文件跑 | `surfacescope -u <url> --config .\surfacescope.toml --no-env` |

## 能力

### 为什么用它

传统做法是把 dirsearch、JSFinder、指纹工具、403 绕过脚本、Swagger 扫描器各跑一遍，再手工拼报告。
SurfaceScope 把这些能力收口到一个包里，共享同一套请求执行器、请求画像、结果模型和报告出口：

| 痛点 | 传统做法 | SurfaceScope |
|---|---|---|
| 工具多、环境乱 | 每个工具一个 venv，还要装 ChromeDriver、EHole 等二进制 | 一个 `pip install`，纯 Python，无外部二进制 |
| 请求行为不一致 | 各工具 UA、超时、并发、认证头各管各的 | 统一 `RequestExecutor` + 统一请求画像 |
| 结果难合并 | 各工具输出格式不同，人工拼表 | 统一 `Finding` schema，一次输出 4 种格式 |
| 容易被误触发 | 装上就全量扫描，可能打到生产 | 主动阶段默认关闭，`--dry-run` 可预演 |

核心设计：**一个 HTTP 边界、一个结果存储、一个报告出口**。新增能力只能通过适配器接入，不能另开一套请求实现。

### 能力总览

```mermaid
flowchart LR
    T[目标 URL] --> D[目录发现]
    D --> J[JS/API 提取]
    J --> F[指纹识别]
    F --> B[403/401 复核]
    B --> S[Swagger 分析]
    S --> P[Packer 分析]
    P --> R[统一报告]
```

| 能力 | 说明 | 默认 |
|---|---|---|
| 目录发现 | dirsearch 0.4.3 兼容核心，支持字典扩展、递归、状态过滤、soft-404 和预算控制 | 开启 |
| JS/API 提取 | 从 script、相对/绝对 URL 和 source map 入口提取候选 | 开启 |
| 指纹识别 | Finger 规则快照、favicon、标题、Header 和 body 特征 | 开启 |
| 403/401 复核 | `quick` / `fast` / `balanced` / `full` 四种预算模式 | 关闭 |
| Swagger/OpenAPI | Swagger 2、OpenAPI 3.0/3.1、本地 `$ref` 和只读请求生成 | 关闭 |
| Packer/webpack | chunk、API、secret、upload surface、CORS 和匿名访问分析 | 关闭 |

### 403/401 复核

`fast` 是默认的低预算首轮，**不是"证明所有绕过都失败"的穷举模式**：

| 模式 | 候选硬上限 | 普通非根目标典型生成 | 说明 |
|---|---:|---:|---|
| `quick` | 2 | 2 | 最小验证 |
| `fast` | 72 | 65 | 默认；首轮 27 个，命中后再扩展 |
| `balanced` | 520 | 313 | 更广的 Header/路径组合 |
| `full` | 2600 | 1698 | 深度授权测试，必须显式选择 |

「候选上限」「生成候选」「首轮候选」和「网络请求数」是不同口径。多数统一拒绝场景下，
`fast` 约产生 29 次请求；只有真实 2xx/3xx 差异才触发扩展。真实目标的命中率和误报率仍应按目标单独验证。

## 使用与参考

### 报告

```powershell
surfacescope -u https://example.com/ --format json,markdown,html,csv --output reports
```

所有格式共用同一个 `Finding` schema 和原子写入逻辑：先写临时文件再替换，失败不会留下半份结果。
报告目录、中间产物和临时资产全部由命令行显式指定，不写入固定的 CWD 队列或数据库。

### 配置

默认配置在包内 `assets/config/defaults.toml`，可用 TOML 文件或环境变量覆盖：

```powershell
$env:SURFACESCOPE_THREADS = '25'
$env:SURFACESCOPE_TIMEOUT = '10'
surfacescope -u https://example.com/ --config .\surfacescope.toml --no-env
```

默认请求画像接近现代桌面 Chromium 的应用层语义：固定 UA/Client Hints、按用途设置 `Accept`、
自动生成 `Sec-Fetch-*`、跨域剥离认证 Header，且不随机化 Header。它**不宣称**等价于浏览器
TLS/HTTP2 指纹。完整参数见 [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md)，
配置项见 [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)。

### 项目结构

```text
src/surfacescope/
  cli.py pipeline.py models.py config.py   # 入口、编排、数据模型
  adapters/     # 能力边界与协议翻译
  components/   # 解析、匹配、候选生成、静态分析
  traffic/      # 唯一 HTTP 执行层与请求画像
  reporting/    # 唯一报告出口
  quality/      # soft-404 与响应差异判定
  assets/       # manifest、字典、指纹、请求画像、默认配置
tests/
  unit/ contract/ integration/ hygiene/
docs/           # 用户文档、开发文档、兼容性说明
```

### 兼容性

| 项 | 状态 |
|---|---|
| Python | `>= 3.10` |
| Windows | 本地验证 3.10–3.14 |
| Linux/WSL | 本地验证 3.10 / 3.14 |
| CI | Ubuntu + Python 3.12，每次推送跑测试、文档、资产与卫生门禁 |
| 打包 | 纯 Python wheel，无 C/Rust 扩展，无需编译 |
| 外部依赖 | 不需要 ChromeDriver、EHole、Selenium 或组件 venv |

完整说明见 [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md)。

## 参与

### 开发

```powershell
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python -m ruff check src tests scripts
.\.venv\Scripts\python scripts\check_docs.py
```

提交前请跑一遍 [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) 里的检查清单。网络测试只能用
loopback fixture，**不要在单元/契约/CI 里扫描真实目标**。贡献流程见
[`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md)，漏洞报告见
[`.github/SECURITY.md`](.github/SECURITY.md)。

### 文档

| 文档 | 内容 |
|---|---|
| [`docs/QUICKSTART.md`](docs/QUICKSTART.md) | 最短使用路径 |
| [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md) | 全部参数与示例 |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | TOML、环境变量、请求画像 |
| [`docs/COMPONENTS.md`](docs/COMPONENTS.md) | 六个组件的能力与边界 |
| [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) | Python、操作系统、依赖政策 |
| [`docs/DIRSEARCH_PARITY.md`](docs/DIRSEARCH_PARITY.md) | dirsearch 0.4.3 兼容子集与差异 |
| [`docs/QUALITY.md`](docs/QUALITY.md) | 覆盖率、请求预算、性能基线 |
| [`docs/ASSETS.md`](docs/ASSETS.md) | 字典、指纹与 manifest |
| [`docs/MIGRATION.md`](docs/MIGRATION.md) | 旧入口与旧参数迁移 |
| [`docs/NAMING.md`](docs/NAMING.md) | 品牌、包名、CLI 与环境变量 |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | 常见问题 |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | 开发与发布检查 |
| [`docs/PROJECT_STRUCTURE.md`](docs/PROJECT_STRUCTURE.md) | 目录与包结构说明 |
| [`CHANGELOG.md`](CHANGELOG.md) | 版本变更 |

### 致谢

第三方来源与致谢记录在 [`NOTICE.md`](NOTICE.md) 。
