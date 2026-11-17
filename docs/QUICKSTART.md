# Quick start

## 1. Install

```powershell
python -m pip install -e .
surfacescope --version
surfacescope --list-components
surfacescope --list-assets
```

需要 Python 3.10 或更高版本。不要为组件创建单独 venv；所有扫描组件共享同一包和同一请求执行器。
`sscope` 是 `surfacescope` 的短别名；`dsbp` 仅用于过渡期兼容，新脚本应使用规范命令。

## 2. Safe first run

只在已获授权的目标上运行。下面的 loopback 示例不会访问公网：

```powershell
surfacescope --dry-run --no-env http://127.0.0.1:8000/
```

确认输出中的 components、profile、asset_count 和请求预算后，再运行真实目标：

```powershell
surfacescope -u "https://authorized.example/" -o reports --format json,md,html
```

默认组件是 `dirsearch,jsfinder,finger`。默认不做 403 绕过、Packer 主动探测或 Swagger 危险方法。
默认校验 TLS 证书；若授权目标使用自签名证书，显式添加 `--insecure`，不要全局关闭校验。

## 3. Enable a stage

```powershell
# 403/401 review
surfacescope -u "https://authorized.example/admin" --components bypass403 --bypass

# Swagger/OpenAPI
surfacescope -u "https://authorized.example/" --components dirsearch,swagger --swagger

# Packer passive analysis
surfacescope -u "https://authorized.example/" --components dirsearch,packer --packer

# Packer GET/API probe, explicit opt-in
surfacescope -u "https://authorized.example/" --components dirsearch,packer --packer --packer-probe
```

全部阶段的安全默认组合：

```powershell
surfacescope -u "https://authorized.example/" --all
```

`--all` 启用 `dirsearch,jsfinder,finger,bypass403,swagger,packer`，但不会把 403 切到
`balanced/full`，也不会自动开启 Swagger 写方法、Packer 主动探测、SQLi、source-map 或
主动利用。显式 `--components` 覆盖 `--all`；`--no-bypass`/`--no-swagger`/`--no-packer`
可在需要时裁剪。

## 4. Multiple identities

```json
{
  "targets": [
    {"url": "https://authorized.example/", "scope": "user-a", "headers": {"Authorization": "Bearer A"}},
    {"url": "https://authorized.example/", "scope": "user-b", "headers": {"Authorization": "Bearer B"}}
  ]
}
```

```powershell
surfacescope -T targets.json --components dirsearch,jsfinder,finger
```

不同身份必须使用不同 `scope`。同一 URL、同一 scope、不同凭据也会由 target identity 隔离；不要用相同 scope 手工串用两个账号。

## 5. Read the result

CLI 结束时会为每个已启用阶段打印标题、状态、统计、finding（无结果时显示
`(no findings)`）、限制标记和错误，最后打印 `SUMMARY`、403 预算和报告路径。JSON 是
机器事实源；Markdown/HTML 用于阅读；CSV 用于表格处理。报告写入 `--output` 指定目录，
不使用固定 CWD 文件。TTY 自动颜色，`NO_COLOR=1`/`--no-color` 关闭。

下一步：

- 参数：`docs/CLI_REFERENCE.md`
- 配置：`docs/CONFIGURATION.md`
- 组件边界：`docs/COMPONENTS.md`
- 旧脚本迁移：`docs/MIGRATION.md`

