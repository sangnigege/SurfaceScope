# Security and authorized use

## Authorization

本项目只应用于你拥有或已取得明确书面授权的目标。扫描前确认：

- 目标范围；
- 测试时间窗；
- 允许的主动测试类型；
- 请求速率和预算；
- 报告/证据保存要求。

## Safe defaults

- 目录发现、JS、指纹默认启用；
- 403/401、Swagger、Packer 阶段默认关闭；
- Packer 默认只做静态分析；
- Swagger 默认不执行写方法；
- `--packer-active`、`--packer-sqli` 必须显式开启；
- 不实现自动弱口令爆破、主动上传或时间盲注。

## Request identity

默认请求画像接近现代桌面 Chromium 的应用层语义，而不是伪装成“无痕工具”：

- 固定 UA/Client Hints；
- 按 purpose 设置 Accept；
- 自动 `Sec-Fetch-*`；
- 跨域剥离 Authorization/Cookie；
- 不随机化 Header 或 User-Agent。

headers 仍不是浏览器 TLS/HTTP2 指纹等价；不要把它当作绕过所有反自动化系统的保证。

## Secret handling

Packer secret finding 只保存脱敏 preview，不把完整密钥写入报告/日志。仍建议：

- 限制报告目录权限；
- 不把报告上传到公共位置；
- 不在 issue/PR/聊天中粘贴 secret；
- 发现真实凭据后按授权方流程处置。

## Data and reports

- 报告写入显式输出目录；
- 多格式原子替换，失败不留下半份结果；
- 中间产物默认临时目录；
- 不创建固定 CWD 队列/数据库；
- 仓库 `.gitignore` 排除报告、SQLite、日志、agent scratch 和缓存。

## Dependency surface

运行时依赖较少，且不做运行时 pip install、组件 venv、动态 clone 或二进制下载。
这降低了供应链和跨平台风险，但不替代对依赖版本的审计。

