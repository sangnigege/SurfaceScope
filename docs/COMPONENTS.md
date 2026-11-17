# Components

## Pipeline contract

所有适配器接收同一个 `ScanContext`，返回 `ComponentResult`：

- 不解析 CLI 参数；
- 不创建 `requests.Session`；
- 不写固定 CWD 文件；
- 不创建私有 worker pool 或预算；
- 不生成组件专属报告；
- 不伪造随机 User-Agent。

发现组件把候选写入 `ResultStore`；消费者只消费带 `source_target`/`auth_scope` 的候选，
避免把 A 账号的 403 结果拿去测 B 账号。

所有普通发现请求共享同一 `RequestExecutor` 和请求画像：默认 Chrome for Testing
Stable `157.0.8103.78` 的 reduced UA、语言、编码和 fetch metadata。Client Hints
只在 HTTPS 上发送；TLS 校验默认开启；Session 的 `requests` 默认 Header 被清空。
组件不得随机伪造 UA 或各自拼接一套“扫描器味道”的 Header。只有 bypass403 的显式
攻击变体可以替换为 catalog 中的 curl/Wget/旧浏览器等测试值，并必须保持
`auth_scope`、预算、审计和缓存约束。

## Dirsearch

- 项目内 0.4.3-compatible 实现：字典、扩展名、状态过滤、递归、软 404、响应长度。
- 支持 0.4.3 风格的主要参数，但不等于逐字节 vendored 上游 0.4.3。
- 支持子集、状态码范围和明确不支持项见 `docs/DIRSEARCH_PARITY.md`。
- 403 结果作为 typed handoff 进入 bypass，不依赖 `403list.txt`。
- 同一 target 的重复条目不会重复初始化 baseline。
- 代码约 483 行：`components/dirsearch/words.py` 负责纯字典展开，
  `adapters/dirsearch_adapter.py` 负责 baseline、并发探测、QC、递归和预算；没有
  复制上游 `lib/`，也没有私有 Session、CWD 队列或第二套报告器。
- 路径使用显式 base+path 组合，不使用会把 `::$DATA` 误判为 scheme 的 `urljoin`；
  该行为有 IIS ADS 回归测试。
- 本机完整字典 loopback 对照约 11611 次请求/11.429 秒，上游 0.4.3 约 11620 次/
  21.938 秒，约 `1.92x`；只代表本地调度和 HTTP 开销，不代表真实目标速度。
- 上游完整参数、deep/force recursion、crawl、session/resume 和上游报告格式仍是
  明确差异；默认产品边界是“兼容子集”，不能写成完整替代。

## JSFinder

- 静态 HTML/JS 提取，不执行 JavaScript。
- 处理 script src、相对 URL、绝对 URL、跨域过滤和重复候选。
- 所有请求经过 executor，403 候选可以进入后续 bypass。
- 去重后的截断使用显式列表切片，兼容 Python 3.12 对 dict view 不可切片的行为。
- 同一 endpoint 从多个 seed/页面出现时只产生一条 finding，`metadata.provenance`
  保留全部来源页面和出现次数；终端显示 `sources=N`，不丢证据。
- 默认只分析已取得页面和 script 资产；`--max-assets`/`--max-endpoints` 可限制
  被动面，不启动浏览器、Node 或独立子进程。

## Finger

- 替代 EHole 二进制，读取包内 Finger 规则快照。
- 支持 favicon hash、标题、Header、body 等规则组合。
- 只对已发现的、有意义的页面/端点运行；404、5xx、error 和零状态页面不进入匹配，
  统计写入 `skipped_unusable_pages`。
- 单 token Header 关键字使用边界匹配，避免 `eHTTP` 等规则误匹配 `SimpleHTTP/0.6`。
- URL-only 规则必须命中路径段边界；`/api`、`/api/v1` 等过泛路径不能单独触发
  `Kubernetes-Dashboard`。通用 Header 值（如 `PHP`）不能单独证明 `PHP-FPM`。
- 同一 `auth_scope + CMS` 的跨页面命中合并为一条 finding，同时保留 `sources` 和
  `occurrences`。
- 规则来源、版本和误报测试见 `docs/ASSETS.md`。
- 只消费已发现页面，不主动枚举全站；404/5xx/error/零状态页面跳过并写入统计。
- 没有运行时二进制、规则下载或组件 venv；规则更新通过包内 manifest 和资产测试完成。

## Bypass403

单一 403/401 引擎，`quick`/`fast`/`balanced`/`full` 四种预算：

- baseline 和随机 soft-404 校准；
- 包内 `sangnigege/bypass403@d465f2d3` 载荷快照，统一生成 path/Header/IP/host/
  method/method-override/Content-Type/Referer/Forwarded/protocol/POST/encoding 候选；
- 攻击变体的 UA 已更新到现代 Chrome/Firefox/Safari、curl 8.17、Wget 1.25 和
  python-requests 2.32；它们只用于 403 变体，不污染普通发现流量；
- `qc.bypass` 与软 404 双重判定；
- URL rewrite 必须与普通根页面不同；
- 非 rewrite 候选若归一化到站点根或普通首页，直接拒绝；
- 首个 accepted 结果立即停止；
- 只有 2xx/3xx 的真实差异才触发 fast 扩展；404/429/5xx 不作为扩展信号。
- `fast` 是默认低预算首轮，不是穷举证明；需要更深覆盖时显式选择 `balanced`/`full`。

模式规模：

| 模式 | 模式硬上限 | 首轮攻击数 | `/admin` 典型生成数 | 普通非根目标网络请求 |
|---|---:|---:|---:|---|
| `quick` | 2 | 2 | 2 | 约 4 |
| `fast` | 72 | 27 | 65 | 统一拒绝约 29；命中即短路 |
| `balanced` | 520 | 520 | 313 | 随短路、QC 和根校准变化 |
| `full` | 2600 | 2600 | 1698 | 随短路、QC 和根校准变化 |

模式硬上限来自 `MODE_POLICIES`；典型生成数是 `/admin` 经去重和基线等价过滤后的数量，
会随目标路径变化。修改候选目录时需要同步更新本页和对应测试。

终端中的 `generated` 表示模式生成、归一化和去重后的候选总数；`initial` 是首轮候选；
`tested` 和 `requests` 是实际测试数/网络请求数。三者不能混读，尤其不能把首轮 27
当成 fast 的全部候选。

27 场景回环基准中，`fast`、`balanced`、`full` 均为 24/27；套件总请求量分别为
462/1032/3802，这是合成场景总成本，不是单目标请求量或真实覆盖率。`fast` 默认已经覆盖
该基准中的全部 HTTP-compatible 类别。
未支持的能力是 HTTP/1.0 协议降级、绝对 URI Raw HTTP、重复 Header 和 CL/TE
desync；它们需要独立传输后端，不能用 `requests` 静默伪装。默认失败关闭：
CLI、target JSON 和 `RequestExecutor` 在发包前拒绝大小写不敏感重复 Header、空 Header
名、CR/LF，以及用户提供的 `Content-Length`/`Transfer-Encoding`；普通 GET/POST body
路径、预算、审计、认证 scope 和重定向保持不变。10 项边界测试见
`tests/contract/test_transport_boundaries.py`；独立复核归 `REV-01`。

路径编码候选经过执行器的受控 wire-path 模式，避免请求库提前解码 `%2e`/`%61`。
该模式仍使用统一 executor、Session、预算、审计、重定向和 QC，不是组件私有发包。

请求层由执行器自行逐跳跟随重定向；默认不跟随，每一跳重新计算 `Sec-Fetch-*`、
`Referer`、认证/Session、预算和审计，组件不得依赖 HTTP 库的隐式重定向行为。

## Swagger

- Swagger 2、OpenAPI 3.0/3.1；
- 本地 `$ref` 解析、servers/host 候选；
- 只生成声明的安全方法，默认禁止 POST/PUT/PATCH/DELETE；
- 无浏览器、UI、ChromeDriver、Excel；
- 参考 swagger-exp/swagger-hack 的发现和请求生成思路，不复制其 UI。
- 默认只生成声明的安全方法；`--swagger-unsafe` 和 `--swagger-external` 才扩大范围。
- 解析器是纯 Python，支持本地 `$ref`，资产和请求都由统一 executor 发送。

## Packer

当前实现为被动优先的 webpack/打包分析：

- 识别 webpack/Next/Gatsby/Vite 等 marker 和 script/chunk；
- 提取静态 API path，区分 explicit/context/inferred 方法；
- 默认扫描 secret（值脱敏）和 upload marker；
- 被动 surface：upload/authentication/sensitive；
- `--packer-probe` 只探测 method 明确的 GET；`--packer-context-probes` 才把上下文
  推断的 GET 纳入探测；inferred GET 始终不发包；
- `--packer-active` 才做 CORS 和认证/匿名对比；
- `--packer-sqli` 才发送保守 GET quote 探针；
- 所有 finding 带 target/auth_scope，避免跨账号去重。
- endpoint 和 surface 按语义键去重；多来源命中合并 `provenance`/`occurrences`，
  `stats.endpoints` 与 `stats.surface_candidates` 按最终唯一结果计数。
- 默认不执行 Deno/Node、不发送动态探测、不抓 source map；这些都需要显式 opt-in。
- 静态分析不依赖 Packer-Fuzzer 运行时目录或浏览器，只读取已发现的 HTML/JS 资产。

未实现：Deno/Node 动态执行、Word/PDF 富报告、弱口令爆破、完整 BAC、主动上传。
`stats` 明确报告 `dynamic_analysis: false` 和 `static_fallback: true`，不伪装动态能力。

## Capability degradation

| Capability | Missing dependency behavior |
|---|---|
| Packer 静态分析 | 始终可用 |
| Packer 动态分析 | 跳过并记录不可用 |
| Word/PDF 报告 | 不阻塞 JSON/Markdown/HTML |
| TLS 指纹增强 | 默认 requests 应用层语义，不声称浏览器等价 |
| Finger | 只依赖包内规则，无 EHole |

