# Security policy

## 报告漏洞

SurfaceScope 自身的安全问题请通过仓库 **Security** 标签页的私密漏洞报告通道提交，
不要为 SurfaceScope 的漏洞开公开 issue。报告请包含：

- 受影响的版本或 commit；
- 操作系统与 Python 版本；
- 使用 loopback 或合成目标的最小复现；
- 影响面，以及是否涉及凭据、文件或第三方系统。

不要在报告中包含真实客户数据、访问令牌或第三方扫描结果。

## 授权使用

本项目只应用于你拥有或已取得明确书面授权的目标。扫描前确认：

- 目标范围；
- 测试时间窗；
- 允许的主动测试类型；
- 请求速率和预算；
- 报告/证据保存要求。

## 默认安全行为

- 目录发现、JS、指纹默认启用；
- 403/401、Swagger、Packer 阶段默认关闭；
- Packer 默认只做静态分析；
- Swagger 默认不执行写方法；
- `--packer-active`、`--packer-sqli` 必须显式开启；
- 不实现自动弱口令爆破、主动上传或时间盲注。

## 请求画像

默认请求画像接近现代桌面 Chromium 的应用层语义，而不是伪装成"无痕工具"：

- 固定 UA/Client Hints；
- 按 purpose 设置 Accept；
- 自动 `Sec-Fetch-*`；
- 跨域剥离 Authorization/Cookie；
- 不随机化 Header 或 User-Agent。

headers 仍不是浏览器 TLS/HTTP2 指纹等价；不要把它当作绕过所有反自动化系统的保证。

## 数据与报告

- 报告写入显式输出目录；
- 多格式原子替换，失败不留下半份结果；
- 中间产物默认临时目录；
- 不创建固定 CWD 队列/数据库；
- 仓库 `.gitignore` 排除报告、SQLite、日志、agent scratch 和缓存；
- 报告和日志可能包含目标 URL、Header 或截断的密钥预览，请存放在受控目录；
- 不要把报告上传到公开 issue、paste 站点或公开仓库；
- 按授权协议删除本地证据；
- Packer secret finding 只保存脱敏 preview，不写入完整凭据。

## 依赖与传输边界

运行时依赖较少，且不做运行时 pip install、组件 venv、动态 clone 或二进制下载；
所有请求统一走带预算与授权范围的共享执行器。这降低了供应链和跨平台风险，但不替代
对依赖版本的审计，也不表示对未授权目标扫描是安全的。