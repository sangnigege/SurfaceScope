# Configuration

## Precedence

从低到高：

1. 包内 `assets/config/defaults.toml`；
2. `--config FILE` 用户 TOML；
3. `SURFACESCOPE_*` 环境变量；
4. CLI 显式参数。

CLI 未提供的列表参数不会用空列表覆盖 TOML 默认值；只有显式提供才覆盖。

机器可读的完整默认值见包内 `assets/config/defaults.toml`，schema 见
`assets/config/schema.json`。配置在扫描前校验，未知字段保留但不执行。

## Example TOML

```toml
[run]
threads = 25
timeout = 10.0
max_response_bytes = 8388608
profile = "chromium-desktop-stable"

[traffic]
verify_tls = true
follow_redirects = false
max_redirects = 10
cache_ttl = 300.0
cache_max_entries = 2048
max_total_requests = 0
max_requests_per_host = 0
rate_limit_per_second = 0.0

[dirsearch]
wordlist = "wordlist.paths.dicc"
target_profiles = []
extensions = []
include_statuses = [200, 204, 301, 302, 307, 308, 401, 403]
exclude_statuses = [400]

[bypass]
mode = "fast"
initial_variants_per_url = 0
max_variants_per_url = 0
max_requests_per_host = 0
max_total_requests = 0

[swagger]
active = false
allow_external = false
max_documents = 12
max_requests = 200
include_unsafe = false

[packer]
active = false
active_sqli = false
max_assets = 120
max_endpoints = 2000
max_active_checks = 60
max_secrets = 50
probe_endpoints = false
fetch_sourcemaps = false

[finger]
max_endpoints = 100
scan_discovered = true

[reports]
format = "json"
title = "surfacescope scan"
```

`[bypass]` 的四个数值 `0` 表示“使用所选模式的内置策略”，不是“无限”：

| 模式 | 模式硬上限 | 首轮攻击数 | `/admin` 典型生成数 | 每 host 预算 | 总预算 |
|---|---:|---:|---:|---:|---:|
| `quick` | 2 | 2 | 2 | 16 | 256 |
| `fast` | 72 | 27 | 65 | 600 | 12000 |
| `balanced` | 520 | 520 | 313 | 1200 | 40000 |
| `full` | 2600 | 2600 | 1698 | 6000 | 120000 |

显式设置正整数会覆盖模式预算。`initial_variants_per_url` 只会影响 `fast` 的首轮；
`max_variants_per_url` 同时限制所有模式的候选数。

“模式硬上限”是 `MODE_POLICIES` 中的候选数量上限；“典型生成数”是普通非根目标
`/admin` 经路径、去重和基线等价过滤后的数量。目标为 `/admin/` 或 `/` 时生成数会
下降（例如 `/` 为 fast 61 / balanced 268 / full 1587）。网络请求还包含 baseline、
随机 soft-404、根校准和扩展，不能把生成候选数直接当成发包数。这些数字由
`MODE_POLICIES` 和当前候选目录共同决定。

## Environment

| Variable | Section/key |
|---|---|
| `SURFACESCOPE_THREADS` | `run.threads` |
| `SURFACESCOPE_TIMEOUT` | `run.timeout` |
| `SURFACESCOPE_PROFILE` | `run.profile` |
| `SURFACESCOPE_VERIFY_TLS` | `traffic.verify_tls` |
| `SURFACESCOPE_FORMAT` | `reports.format` |

布尔值接受 `1/0`、`true/false`、`yes/no`、`on/off`。类型不合法会直接报错。
`SURFACESCOPE_*` 未设置时会回退读取对应的旧 `DSBP_*` 变量；新配置应只使用
`SURFACESCOPE_*`，旧前缀计划在 `1.0` 前移除。`--no-env` 同时禁用两套前缀。

`SURFACESCOPE_ALLOW_CWD_PARENT_TMP=1` 是受限环境的逃生口：只有当标准临时目录全部
不可写时，才允许把当前目录的父目录作为临时根。默认关闭，避免在项目父目录里积累
`surfacescope-*` 目录。
## Proxies

HTTP 出口只使用显式代理：全局 `--proxy` 或 target 文件中的 `proxy`。执行器不读取
`HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 或 `NO_PROXY`，避免系统代理静默改写请求路径、
改变 Host/认证边界或把授权目标流量发往非预期出口。需要代理时必须显式传入。

## Request profiles

当前默认画像是 `chromium-desktop-stable`，与 Chrome for Testing Stable `157.0.8103.78`
的 reduced UA/Client Hints 对齐，包含：

- User-Agent、Accept、Accept-Language、Accept-Encoding；
- `Sec-CH-UA*` Client Hints；仅 HTTPS 目标发送；
- `Sec-Fetch-Site/Mode/Dest/User`；
- navigation/xhr/asset/api 四种 purpose；
- 固定 Header 顺序。

请求执行器会根据目标 URL 和 initiator/Referer 计算 `same-origin`、`same-site`、
`cross-site` 或 `none`。跨域请求会剥离 Authorization/Cookie，不把一组凭据发到另一个 origin。
创建 Session 时会清除 `requests` 默认 Header，避免隐式工具标识；`Accept-Encoding` 会按
本地 urllib3 实际可解码能力过滤 `gzip/deflate/br/zstd`，不会声明无法解压的编码。
跟随重定向时由执行器逐跳处理，并在每一跳重新计算上述 Header、认证/Cookie 边界、
Session、请求预算和审计；`max_redirects` 控制跳数上限（默认 10）。跟随时设为 0
表示不再发送下一跳，直接返回首个 3xx，而不是让 HTTP 库隐式跟随。

这只是应用层浏览器化，不是 TLS/HTTP2 指纹等价。项目不提供伪造或随机 UA 的选项。

## Per-target settings

`-T/--target-file` 每个对象支持：

```json
{
  "url": "https://example.com/",
  "scope": "customer-a",
  "headers": {"Authorization": "Bearer A"},
  "cookies": {"session": "A"},
  "proxy": "http://127.0.0.1:8080"
}
```

- `scope` 必须区分不同认证身份；
- target 的 proxy 覆盖全局 `--proxy`；
- `headers`/`cookies` 与 CLI 的全局值合并，target 值优先。

