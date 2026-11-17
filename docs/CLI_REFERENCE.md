# CLI reference

入口：

```powershell
surfacescope [targets ...] [options]
sscope [targets ...] [options]
dsbp [targets ...] [options]   # deprecated compatibility alias
python -m surfacescope [targets ...] [options]
```

所有入口共享同一 `surfacescope.cli:main`；argparse 的帮助标题规范化为
`surfacescope`。运行 `surfacescope --help` 查看当前安装版本的完整参数。

## Target input

| Option | Meaning |
|---|---|
| `URL` | positional target；可重复 |
| `-u, --url URL` | target；可重复 |
| `-U, --url-file FILE` | 每行一个 URL，空行和 `#` 注释跳过 |
| `-T, --target-file FILE` | JSON target objects（url/scope/headers/cookies/proxy） |

`-T` 顶层可以是数组，也可以是 `{"targets": [...]}`。每个对象必须有 `url`；
`scope` 用于分隔认证身份；`proxy` 只对对应 target 生效。

## Components and stages

| Option | Meaning |
|---|---|
| `--components LIST` | 逗号分隔；默认 `dirsearch,jsfinder,finger` |
| `-a, --all` | 启用 `dirsearch,jsfinder,finger,bypass403,swagger,packer`，但保持安全默认：403 仍为 `fast`，不自动开启 unsafe/active/SQLi/source-map |
| `--bypass` | 加入 403/401 复核 |
| `--swagger` | 加入 Swagger/OpenAPI 发现 |
| `--packer` | 加入 Packer/webpack 分析 |
| `--no-bypass` / `--no-swagger` / `--no-packer` | 从当前选择中移除对应阶段；可用于裁剪 `--all` |
| `--list-components` | 列出可运行组件 |
| `--list-profiles` | 列出请求画像 |
| `--list-assets` | 列出 manifest 资产 |

组件运行顺序固定为：`dirsearch → jsfinder → packer → swagger → bypass403 → finger`。
显式 `--components` 优先于 `--all`；`--bypass`/`--swagger`/`--packer` 是增量开关，
`--no-*` 最后应用。`--all` 不等于“全量发包”：403 仍使用 `fast`，主动能力继续 opt-in。

## Request and transport

| Option | Meaning |
|---|---|
| `--threads N` | 全局 worker 上限 |
| `--timeout SECONDS` | 单请求超时 |
| `--max-response-bytes N` | 响应截断上限 |
| `--proxy URL` | 全局 HTTP(S) 代理；target 级代理可覆盖 |
| `--header 'Name: value'` | 静态 Header；可重复。大小写不敏感同名、空名称、CR/LF 会失败；用户提供的 `Content-Length`/`Transfer-Encoding` 会在发包前失败 |
| `--cookie 'a=b; c=d'` | Cookie 字典 |
| `--insecure` | 关闭 TLS 证书校验；仅对明确授权的自签名/实验环境显式使用 |
| `--verify-tls` | 校验 TLS；默认开启，保留为脚本兼容参数 |
| `--follow-redirects` | 跟随重定向；默认关闭 |
| `--max-redirects N` | 重定向跳数上限；默认 10；只在跟随时生效，0 表示返回首个 3xx |
| `--profile ID` | 请求画像，默认 `chromium-desktop-stable` |

每个请求的 `Sec-Fetch-Site`、`Referer`、`Origin`、purpose 和跨域认证处理由执行器统一计算；
组件不得自行创建 Session 或随机化 Header。重定向由执行器逐跳处理；每一跳都会重新计算
`Sec-Fetch-*`/`Referer`、认证与 Cookie 边界、Session、预算和审计，而不是交给 `requests`
隐式重定向。

默认画像与 Chrome for Testing Stable `157.0.8103.78` 的 UA/Client Hints 对齐；`Sec-CH-UA*`
只在 HTTPS 目标发送，`Accept-Encoding` 会按本地 urllib3 实际可解码的 gzip/deflate/br/zstd
能力过滤。创建 Session 后会清除 `requests` 默认 Header，避免隐式 `python-requests` 风格；
组件显式攻击 Header 只存在于 403 variation catalog。
默认校验 TLS 证书，和现代浏览器一致；授权实验中的自签名目标使用 `--insecure`，
不要把它写进通用扫描配置。

`--header` 与 `--target-file` 中的 Header 使用同一校验：大小写不敏感的重复 Header、
空名称、CR/LF、用户提供的 `Content-Length`/`Transfer-Encoding` 都在发包前失败。
Raw absolute-URI 和 HTTP/1.0 不提供隐式表达；当前没有独立的 Raw/HTTP1.0 传输后端。

## Dirsearch

0.4.3 支持子集、明确差异和 fixture 见 `docs/DIRSEARCH_PARITY.md`。本节只列出当前
实际注册的选项；未列出的上游参数不会被静默模拟。

| Option | Meaning |
|---|---|
| `--wordlist ASSET_ID` | 路径字典资产 ID |
| `--target-profile NAME` | `grafana`、`spring-boot`、`actuator` 专用路径 |
| `-e, --extensions LIST` | 扩展名，不包含点 |
| `--force-extensions LIST` | 为无扩展名条目追加显式扩展名列表（不是上游布尔 `-f`） |
| `--exclude-extensions LIST` | 排除扩展名 |
| `--exclude-redirects REGEX` | 排除 Location |
| `--include-statuses LIST` | 接受的状态码；支持 `200-204` 范围 |
| `--exclude-statuses LIST` | 排除的状态码；支持 `400-410` 范围 |
| `--min-response-size N` / `--max-response-size N` | 响应长度边界 |
| `--max-candidates N` | 候选上限 |
| `--max-jobs N` | job 上限 |
| `--max-time SECONDS` | 阶段时间预算 |
| `--prefixes LIST` / `--suffixes LIST` | 路径前后缀 |
| `--recursive` / `--max-depth N` | 递归目录 |

## 403/401 review

| Option | Meaning |
|---|---|
| `--bypass-mode {quick,fast,balanced,full}` | 预算/候选策略；默认 `fast` |
| `--max-variants-per-url N` | 每 URL 最大候选；`0` 使用所选模式策略 |
| `--max-requests-per-host N` | 每 host 预算；`0` 使用所选模式策略 |
| `--max-total-requests N` | 阶段总预算；`0` 使用所选模式策略 |

模式硬上限为 `quick 2 / fast 72 / balanced 520 / full 2600`。典型非根目标 `/admin`
去重后生成 `quick 2 / fast 65 / balanced 313 / full 1698` 个候选；目标路径不同会下降。
`fast` 首轮发送 27 个高阶候选，确认 2xx/3xx 响应差异后才扩展；统一拒绝通常为 29 次网络请求。
`full` 必须显式选择。这些数字由 `MODE_POLICIES` 和当前候选目录共同决定；
修改 catalog 时需要同步更新本页和对应测试。

## Swagger/OpenAPI

| Option | Meaning |
|---|---|
| `--swagger-unsafe` | 允许声明的 POST/PUT/PATCH/DELETE |
| `--swagger-external` | 允许外部 `servers` / host |
| `--max-documents N` | 文档发现上限 |
| `--max-swagger-requests N` | 请求生成上限 |

解析支持 Swagger 2、OpenAPI 3.0/3.1 和本地 `$ref`；默认不执行写操作。

## Packer

| Option | Meaning |
|---|---|
| `--packer-probe` | 对方法明确的 GET API 做一次 GET 探测 |
| `--packer-context-probes` | 额外探测从邻近源码上下文推断出的 GET；默认关闭 |
| `--packer-active` | CORS 反射和认证/匿名访问对比；默认关闭 |
| `--packer-sqli` | 对 GET query 参数发送最小 SQL quote 探针；默认关闭 |
| `--packer-sourcemaps` | 获取并解析 source map 的 `sourcesContent` |
| `--max-assets N` / `--max-endpoints N` | 静态资产/端点上限 |

secret、upload marker、API surface 和 Finger 规则属于被动分析，不要求 `--packer-active`。
只有 `explicit` GET 会在 `--packer-probe` 下发包；`context` 需要
`--packer-context-probes`；`inferred` 永不主动发包。

## Config and output

| Option | Meaning |
|---|---|
| `--config FILE` | 用户 TOML |
| `--output DIR` | 报告目录；默认 `~/.surfacescope/reports` |
| `--artifact-root DIR` | 中间产物目录；默认临时目录 |
| `--format LIST` | `json,md,html,csv` |
| `--no-env` | 忽略 `SURFACESCOPE_*` 及回退的 `DSBP_*` 环境变量 |
| `--verbose` | 详细日志 |
| `--no-color` | 禁用 ANSI 颜色；TTY 默认自动检测，也支持 `NO_COLOR`/`FORCE_COLOR` |
| `--dry-run` | 只解析并打印计划，不发起扫描 |
| `--version` | 版本 |

扫描结束后的终端输出由 `surfacescope.console` 统一渲染：每个已启用阶段都有标题、
`OK/ERRORS` 状态、统计、finding、限制标记和错误；空结果输出 `(no findings)`。
`SUMMARY` 汇总 finding、错误、网络请求、缓存、403 预算和报告路径。终端渲染器是只读
展示层，不解析目标、不发包、不改变 `PipelineResult`。

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | 扫描完成且无组件错误 |
| `1` | 扫描完成但存在组件/请求错误 |
| `2` | 参数、配置、资产或运行时错误 |
| `130` | 用户中断 |

早期版本的根目录兼容入口 `dirsearch.py`、`single_403pass.py`、`swagger.py` 已移除；
等价能力由 `surfacescope`（或 `sscope`、`dsbp` 别名）提供，退出码同上表。

