# SurfaceScope

SurfaceScope 是一个统一的 Web 攻击面评估流水线，把目录发现、JS/API 提取、指纹识别、
403/401 复核、Swagger/OpenAPI 分析和 Packer/webpack 分析收口到同一个 Python 包。

当前公开版本：`0.2.0`。发行包和 import 名均为 `surfacescope`，主命令为
`surfacescope`，短别名为 `sscope`；`dsbp` 仅作为旧脚本迁移期的兼容别名。

> 仅用于你拥有或已取得明确授权的安全测试。默认行为是低风险发现，主动探测必须显式开启。

## 能力

| 能力 | 说明 | 默认 |
|---|---|---|
| 目录发现 | dirsearch 0.4.3 兼容核心，支持字典扩展、递归、状态过滤、soft-404 和预算控制 | 开启 |
| JS/API 提取 | 从 script、相对/绝对 URL 和 source map 入口提取候选 | 开启 |
| 指纹识别 | Finger 规则快照、favicon、标题、Header 和 body 特征 | 开启 |
| 403/401 复核 | `quick`/`fast`/`balanced`/`full` 四种预算模式，默认 `fast` | 关闭 |
| Swagger/OpenAPI | Swagger 2、OpenAPI 3.0/3.1、本地 `$ref` 和只读请求生成 | 关闭 |
| Packer/webpack | chunk、API、secret、upload surface、CORS 和匿名访问分析 | 关闭 |

所有网络请求共享一个 `RequestExecutor`、一个请求画像、一个结果存储和一个报告出口。
运行时不需要 ChromeDriver、EHole、组件 venv 或外部二进制。

## 安装

需要 Python 3.10 或更高版本。

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e .
.\.venv\Scripts\surfacescope --version
```

Linux/WSL 使用 `.venv/bin/python` 和 `.venv/bin/surfacescope`。推荐使用一个项目环境，
不要为每个组件创建独立 venv。

## 快速开始

```powershell
# 默认：目录发现 + JS 提取 + 指纹识别
surfacescope -u https://authorized.example/

# 启用全部阶段，但保持安全默认：
# 403 仍使用 fast；写方法、SQLi、unsafe Packer 和 source map 不自动开启
surfacescope -u https://authorized.example/ --all

# 指定字典、扩展名和并发
surfacescope -u https://authorized.example/ --wordlist paths --extensions php,aspx,jsp --threads 25

# 403/401 复核
surfacescope -u https://authorized.example/admin --components bypass403 --bypass --bypass-mode fast

# 查看可用组件、资产和配置
surfacescope --list-components
surfacescope --list-assets
```

先用 `--dry-run` 检查目标和组件组合，不会发起扫描请求：

```powershell
surfacescope -u https://authorized.example/ --all --dry-run --no-env
```

## 报告

报告支持 JSON、Markdown、HTML 和 CSV：

```powershell
surfacescope -u https://authorized.example/ --format json,markdown,html,csv --output reports
```

所有格式使用同一个 `Finding` schema 和原子写入逻辑。报告目录、中间文件和临时资产由
命令行显式指定，不会写入固定的工作目录队列或数据库。

## 403 模式

`fast` 是默认的低预算首轮，不是“证明所有绕过都失败”的穷举模式：

| 模式 | 候选硬上限 | 普通非根目标典型生成 | 说明 |
|---|---:|---:|---|
| `quick` | 2 | 2 | 最小验证 |
| `fast` | 72 | 65 | 默认；首轮 27 个，命中后再扩展 |
| `balanced` | 520 | 313 | 更广的 Header/路径组合 |
| `full` | 2600 | 1698 | 深度授权测试，必须显式选择 |

“候选上限”“生成候选”“首轮候选”和“网络请求数”是不同口径。多数统一拒绝场景下，
`fast` 约产生 29 次请求；只有真实 2xx/3xx 差异才触发扩展。真实目标的命中率和误报率
仍应按目标单独验证。

## 配置

默认配置位于包内 `assets/config/defaults.toml`，也可以用 TOML 文件或环境变量覆盖：

```powershell
$env:SURFACESCOPE_THREADS = '25'
$env:SURFACESCOPE_TIMEOUT = '10'
surfacescope -u https://authorized.example/ --config .\surfacescope.toml --no-env
```

环境变量和完整参数见 `docs/CONFIGURATION.md` 与 `docs/CLI_REFERENCE.md`。

默认请求画像接近现代桌面 Chromium 的应用层请求：固定 UA/Client Hints、按用途设置
`Accept`、自动生成 `Sec-Fetch-*`，并跨域剥离认证 Header。它不宣称等价于浏览器的
TLS/HTTP2 指纹。

## 项目结构

```text
src/surfacescope/
  cli.py pipeline.py models.py config.py
  adapters/        # 能力边界和协议翻译
  components/      # 解析、匹配、候选和静态分析
  traffic/         # 唯一 HTTP 执行层和请求画像
  reporting/       # 唯一报告出口
  quality/         # soft-404 和响应差异判定
  assets/          # manifest、字典、指纹、画像和配置
tests/
  unit/ contract/ integration/ hygiene/
docs/              # 用户文档、开发文档和兼容性说明
```

## 兼容性

- Python `>= 3.10`；本地已验证 Windows 3.10–3.14 与 Linux/WSL 3.10，CI 配置覆盖
  Windows/Linux × Python 3.10–3.14；
- 纯 Python wheel，不包含 Rust/C 扩展，不需要目标平台编译；
- Windows 和 Linux 使用 `pathlib`、显式 UTF-8、临时目录和 `sys.executable`；
- macOS 尚未完成原生验证，不宣称已支持；
- 不依赖 `pkg_resources`、`distutils`、Selenium、ChromeDriver、`docx2pdf` 或组件 venv。

完整说明见 `docs/COMPATIBILITY.md`。

## 开发

```powershell
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python -m ruff check src tests scripts
.\.venv\Scripts\python -W error -m compileall -q src scripts tests
.\.venv\Scripts\python scripts\check_docs.py
```

贡献流程、测试边界和发布检查见 `CONTRIBUTING.md` 与 `docs/DEVELOPMENT.md`。网络测试只能
使用 loopback fixture，不要在单元/契约/CI 中扫描真实目标。

## 文档

- `docs/QUICKSTART.md`：最短使用路径
- `docs/CLI_REFERENCE.md`：参数和示例
- `docs/CONFIGURATION.md`：TOML、环境变量和请求画像
- `docs/COMPONENTS.md`：六个组件的能力和边界
- `docs/COMPATIBILITY.md`：Python、操作系统、依赖和兼容政策
- `docs/DIRSEARCH_PARITY.md`：dirsearch 0.4.3 兼容子集和明确差异
- `docs/QUALITY.md`：覆盖率、请求预算和性能基线
- `docs/ASSETS.md`：字典、指纹和 manifest
- `docs/MIGRATION.md`：旧入口和旧参数迁移
- `docs/NAMING.md`：品牌、包名、CLI 和环境变量
- `docs/TROUBLESHOOTING.md`：常见问题
- `docs/DEVELOPMENT.md`：开发和发布检查
- `docs/SECURITY.md`：授权使用、默认安全和数据处理
- `CHANGELOG.md`：版本变更

## 来源与致谢

第三方来源、本地处理和资产来源记录在 `NOTICE.md`、`THIRD_PARTY_LICENSES.txt` 以及
`src/surfacescope/assets/manifest.json`。SurfaceScope 不依赖上游仓库的运行时目录或
组件 checkout。
