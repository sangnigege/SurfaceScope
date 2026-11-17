# Migration from the old root scripts

旧入口 `dirsearch.py`、`single_403pass.py`、`swagger.py` 现在是统一 CLI 兼容入口：

- 只映射默认组件并调用 `surfacescope.cli:main`；
- 复用同一参数解析、pipeline、RequestExecutor、报告和退出码；
- `--help` 返回 `0`，`--dry-run` 和正常扫描可用；
- 不创建 venv；
- 不 clone 组件；
- 不写 CWD 文件；
- 不启动第二套扫描逻辑。

## From `dirsearch_bypass403` / `dsbp` to SurfaceScope

| 旧 | 新 | 兼容策略 |
|---|---|---|
| distribution / import `dirsearch_bypass403` | `surfacescope` | 不保留旧 import；嵌入方必须改 import |
| CLI `dsbp` | `surfacescope` | 保留 `dsbp` 和 `sscope` 别名，共享同一实现 |
| `DSBP_*` 环境变量 | `SURFACESCOPE_*` | 新变量优先，旧变量回退；计划 1.0 前移除 |
| `~/.dirsearch_bypass403/reports` | `~/.surfacescope/reports` | 不自动搬移；可用 `--output` 指向旧目录 |
| `python -m dirsearch_bypass403` | `python -m surfacescope` | 旧模块名立即失效 |

历史仓库名和旧 Git 提交可以继续保留；品牌迁移不要求改写 Git 历史。只有需要将
SurfaceScope 作为全新公开发行版时，才考虑独立新仓库或 orphan branch。

## Public contract changes

公共 API、CLI、JSON report、TOML config 和 environment 的兼容/弃用规则见
`docs/COMPATIBILITY.md`。本文件只记录用户可执行的迁移步骤；每个弃用项必须同时有：

- 首次弃用版本、最后支持版本和移除版本/触发条件；
- 旧写法、替代写法、默认行为变化和退出码变化；
- 一条旧入口负向测试和一条新入口正向等价测试；
- 适用于 JSON report 的 `schema_version` 变化及 fixture；
- 适用于配置/环境变量的优先级测试和 `--no-env` 行为。

`1.0` 前允许在一个 minor 版本内完成 breaking change，但仍必须经过 deprecation window
（至少一个 minor 周期或 90 天，取较长者）并保留迁移说明；`1.0` 后 breaking change
只进入 major。只有安全修复可以缩短窗口，且必须在 `CHANGELOG.md` 和迁移说明中
记录理由、影响、临时措施和移除计划。

## Command mapping

| Old | New |
|---|---|
| `python dirsearch.py -u URL` | `surfacescope -u URL` |
| `python dirsearch.py -u URL -b yes` | `surfacescope -u URL --bypass` |
| `python dirsearch.py -u URL -j yes` | `surfacescope -u URL --components dirsearch,jsfinder,finger` |
| `python dirsearch.py -u URL -z yes` | `surfacescope -u URL`（finger 默认启用） |
| `python dirsearch.py -u URL -b yes -j yes` | `surfacescope -u URL --bypass --components dirsearch,jsfinder,finger` |
| `python dirsearch.py -u URL --swagger yes` | `surfacescope -u URL --components dirsearch,swagger --swagger` |
| `python dirsearch.py -u URL -p yes` | `surfacescope -u URL --components dirsearch,packer --packer` |
| `python single_403pass.py -u URL -p /admin` | `surfacescope -u "URL/admin" --components bypass403 --bypass` |
| `python swagger.py -u URL` | `surfacescope -u URL --components dirsearch,swagger --swagger` |

## Option mapping

| Old family | New |
|---|---|
| `-u`, `-U` | 同名 |
| `-e`, `--extensions` | 同名 |
| `-w`, `--wordlist` | `--wordlist ASSET_ID`（不是任意路径） |
| `-t`, `--threads` | `--threads` |
| `--timeout` | `--timeout` |
| `--proxy` | `--proxy` |
| `--header` | `--header` |
| `--cookie` | `--cookie` |
| `-r`, `--recursive` | `--recursive` |
| `--max-time` | `--max-time` |
| `--exclude-status` | `--exclude-statuses` |
| 全局 `config.ini` / `options.ini` | `--config FILE` TOML |
| `403list.txt` / `bypass403_url.txt` | typed 403 handoff（无文件） |
| `output.txt` / `reports` 目录 | `--output DIR` + unified report |

## Behaviour changes

1. 旧 `-b yes`、`-j yes`、`-z yes` 这类“yes/no 字符串”不再使用；改用布尔开关、
   `--all` 或 `--components`。`--all` 只启用全部阶段，不自动开启 unsafe/active/SQLi。
2. 旧脚本的随机 UA、全局配置文件、组件 venv、运行时 clone 和 CWD 队列不会恢复。
3. Packer 默认只做被动分析；原来的主动上传、弱口令和时间盲注不在迁移范围。
4. 同一 URL 的多身份必须通过 `-T targets.json` 提供不同 `scope`，否则会按同一身份处理。
5. 旧 ChromeDriver/Chrome 浏览器路径不再需要；Swagger 是纯 Python 解析。

根入口本身可以直接运行，但只承载兼容默认值；需要新参数时应使用规范 `surfacescope`
命令。不要把旧组件重新放回项目根目录，也不要恢复组件 venv、运行时 clone 或 CWD 队列。

