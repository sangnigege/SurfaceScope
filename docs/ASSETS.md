# Assets and wordlists

## Single source of truth

`src/surfacescope/assets/manifest.json` 是运行时资产的机器事实源。
每个 active 资产记录：

- stable `id` 和相对 `path`；
- `kind`、版本、来源、来源哈希；
- 规范字节的 `sha256`、大小、编码、行数和逻辑项数；
- `consumers`、`package`、`status`、复核日期；
- `source_refs` 和 merge policy。

`AssetManifest().validate()` 会检查路径、哈希、大小、LF、BOM、行数、逻辑项数、
consumer 可导入性和 canonical 关系。发布前还要在仓库外安装 wheel 后读取资产。

## Current asset set

当前共 11 条：

| ID | Consumer | Purpose |
|---|---|---|
| `config.defaults` | config | 默认 TOML |
| `config.schema` | config | 配置校验 |
| `profile.request.chromium_desktop` | traffic | 请求画像 |
| `wordlist.paths.dicc` | dirsearch | 通用路径字典 |
| `blacklist.status.codes` | dirsearch | 400/403/500 后缀噪声过滤 |
| `fingerprint.finger.rules` | finger | Finger 纯 Python 规则 |
| `wordlist.targets.grafana` | dirsearch | Grafana 专用路径 |
| `wordlist.targets.spring_boot_actuator` | dirsearch | Spring Boot/Actuator 专用路径 |
| `wordlist.credentials.username` | none | legacy；等待显式登录/弱口令设计 |
| `wordlist.credentials.password` | none | legacy；等待显式登录/弱口令设计 |
| `bypass.payloads.upstream` | bypass403 | `bypass403` 上游载荷快照 |

两条 credentials 资产是 `legacy`、无 consumer，不会在默认扫描中被使用。当前 wheel 仍会
包含它们，因为 `package` 是来源/生命周期分类，不是 package-data 的排除开关；发布时应把
“已打包”和“有消费者/默认启用”分开描述。不要把它们与通用路径字典合并。

## Dictionary policy

不是“字典越少越好”。以下语义不能合并：

- 通用路径候选；
- 产品或框架专用路径；
- HTTP 状态噪声后缀；
- 用户名/密码；
- 指纹规则；
- 模板/i18n/fixture。

只有同一判定器、同一消费者、同一生命周期和同一验证方式的数据才合并。当前状态过滤已合并为
`blacklist.status.codes`；Grafana 和 Spring Boot 保持独立目标字典。

`normalize_assets.py` 只对 `wordlist.*` 执行物理行去重（`strip-empty` /
`dedupe-preserve-case`）；JSON 资产按结构和逻辑值去重，不能做行级去重。目标字典和
通用路径字典都必须保持物理唯一，并由 `tests/unit/test_assets.py` 锁定。

## Sources

- 通用路径字典采用 `curated-union`：dirsearch 0.4.3 高价值路径、dirsearch v0.5.0
  相对 0.4.3 的高价值 delta（仅新增 `data.php`），以及 SurfaceScope 维护的现代入口（Swagger/OpenAPI、GraphQL、
  Next/Nuxt、actuator、`llms*.txt` 等）；经 LF、去空行、去完全重复和低价值噪声清理后
  为 9522 行、142230 bytes，SHA256
  `a3faa579ff1e8c9cf86c78f461711ff19d4b7d0d3863a2c6d7444ebfafdb002f`；
  已排除年份枚举和 traversal 噪声，不直接跟随 Rust 构建链或整包 vendoring；
- 指纹来自 Finger 规则快照，替代 EHole 二进制；
- 403 载荷目录来自 `sangnigege/bypass403@d465f2d3`，只导入载荷数据；
- 请求画像来自 Chrome for Testing Stable `157.0.8103.78` 的 reduced UA/Client Hints，
  作为项目维护资产；HTTPS-only Client Hints 由执行器控制；
- Packer-Fuzzer 的来源记录在 `NOTICE.md`。

旧根目录 `db/`、`ehole/` 已移出工作区；它们的规范副本已登记在 manifest 的 `source_refs`。
这不是删除来源证据，而是避免运行时出现两份可漂移的资产。

## Adding or changing an asset

1. 更新规范资产文件；
2. 更新 manifest 的 hash、size、行数、item_count、source_refs、consumer；
3. 运行：

```powershell
python scripts/validate_assets.py
python -m pytest -q tests/unit/test_assets.py
```

4. 构建 wheel 并确认 package data 中没有缺项或意外二进制；
5. 如果改变语义/消费者，更新本文件和对应组件测试。

