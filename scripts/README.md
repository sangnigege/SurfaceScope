# scripts

仓库自检脚本。除标注「本地」外，CI 的 `ci` job 会跑带 ✅ 的那几个。

| 脚本 | 作用 | CI |
|---|---|:--:|
| `validate_assets.py` | 校验 `assets/manifest.json` 与实际资产文件一致（缺失/多余/哈希） | ✅ |
| `check_docs.py` | 校验公开文档树：必需文档齐全、Markdown 结构、表格列数、相对链接可达、README 版本标记与 `pyproject.toml` 一致、无私有路径泄漏 | ✅ |
| `check_release_hygiene.py` | 校验发布面：必需公开文件齐全，禁止 legacy 路径、二进制、内部文档进入索引 | ✅ |
| `check_worktree.py` | 计算源码快照 SHA256 摘要（`--json-out`），把证据绑定到具体工作树 | 本地 |
| `check_quality.py` | 覆盖率与质量基线对比（`--run-coverage --baseline docs/QUALITY_BASELINE.json`） | 本地 |
| `check_artifacts.py` | 校验 wheel/sdist 内容（必需资产、禁止文件） | 本地 |
| `check_install_matrix.py` | 验证不同安装方式（wheel/sdist/可编辑）在同一解释器下的行为 | 本地 |
| `normalize_assets.py` | 规范化字典/指纹等资产文件（换行、去重、排序） | 手动 |

## 约定

- 所有脚本只依赖标准库与安装后的 `surfacescope` 包，可直接 `python scripts/<name>.py` 运行；
- 失败时退出码为 `1` 并向 stderr 输出中文/英文错误明细，成功为 `0`；
- 不要在这些脚本里发起网络请求，网络类验证请放到 `tests/integration/`；
- 新增脚本必须同步登记到本文件与 `.github/workflows/ci.yml`（如果要在 CI 跑）。