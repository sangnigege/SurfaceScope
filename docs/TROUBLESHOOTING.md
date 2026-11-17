# Troubleshooting

## `surfacescope: command not found`

使用：

```powershell
python -m surfacescope --help
```

或安装项目：

```powershell
python -m pip install -e .
```

## `No module named pytest`

安装开发依赖：

```powershell
python -m pip install -e ".[dev]"
```

如果只是运行源码，确保 `PYTHONPATH=src`。不要在仓库根创建组件 venv 或提交 `.venv`。

## pip 一直等待/下载失败

这是网络/镜像问题，不是项目运行时依赖问题。可临时使用环境可访问的镜像；不要把镜像 URL 写进项目配置。

## 系统 `HTTP_PROXY` 没有生效

这是设计行为。扫描器只使用显式 `--proxy` 或 target 文件中的 `proxy`。读取系统代理会
静默改写路径（例如把 `/admin;` 变成 `/admin`），影响 403 证据并可能把流量发往非预期出口。

## 旧的 `dirsearch.py` / `single_403pass.py` / `swagger.py` 入口已移除

这三个根脚本已在 0.2.x 移除，`python dirsearch.py ...` 会直接报找不到文件。请改用
`surfacescope`（或 `sscope`、`dsbp` 别名），参数映射见 `docs/MIGRATION.md`；
不要恢复旧参数解析器或组件私有 Session。

## 扫描没有发现 403 绕过

检查：

1. baseline 是否真的是 401/403；
2. `--bypass` 是否启用；
3. 是否命中预算 `--max-requests-per-host` / `--max-total-requests`；
4. 目标是否返回统一 WAF/软 404 页；
5. URL rewrite 变体是否与普通根页面相同（会被判定为误报）。

`fast` 不是全量；需要更多候选时用 `--bypass-mode balanced`，并自行承担请求量。

## Packer 没有做动态分析

当前版本没有 Deno/Node 动态拆包，`stats.dynamic_analysis` 为 `false`。核心静态分析仍工作。

## Packer secret 没出现

secret 扫描是被动默认开启，但只扫描已获取的页面/脚本；检查 `--packer` 是否启用、`max_assets` 是否太小、
目标是否把脚本放在跨域或未授权资源上。

## Swagger 只生成 GET

这是安全默认。确认 `include_unsafe`/`--swagger-unsafe` 是否显式开启，并确认文档声明了对应方法。

## 报告写到意外位置

默认是 `~/.surfacescope/reports`；用 `--output` 指定。中间产物默认临时目录；用 `--artifact-root` 固定。

## Windows 中文/路径问题

所有文本读写显式 UTF-8；不要从 GBK 终端直接粘贴未编码的路径。复杂路径用引号包裹。项目不使用 POSIX-only shell。

## 需要查看详细执行信息

```powershell
surfacescope -u URL --verbose
surfacescope --dry-run --no-env -u URL
```

`--dry-run` 不发起扫描，只打印解析后的配置和目标。

## 终端没有颜色或出现乱码

TTY 自动启用颜色；重定向/管道默认关闭。可用 `FORCE_COLOR=1` 强制颜色，或用
`NO_COLOR=1`、`--no-color` 禁用。Windows 重定向输出使用 UTF-8；若终端仍不支持，
先用 `chcp 65001` 或 Windows Terminal。每个已启用阶段都会打印独立 section，包括
Dirsearch、JSFinder、Packer、Swagger、403 和 Finger；没有 finding 时显示 `(no findings)`。

## 想一次启用全部阶段

使用 `--all`，它启用六个阶段但保持安全默认：403 仍为 `fast`，Swagger unsafe、
Packer active/SQLi/source-map 和主动写探测不会自动开启。若只需要部分能力，显式
`--components` 会覆盖 `--all`，`--no-bypass`/`--no-swagger`/`--no-packer` 可继续裁剪。

