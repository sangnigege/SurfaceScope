# tests

四层测试，全部只跑 loopback fixture，**不允许**访问真实或第三方目标。

| 目录 | 关注点 | 特点 |
|---|---|---|
| `unit/` | 单个组件/函数的行为与失败路径 | 最快，占大头 |
| `contract/` | 适配器与组件之间的协议契约（返回结构、错误语义） | 改接口时必跑 |
| `integration/` | 使用 loopback HTTP 服务跑完整流水线 | 慢，验证跨组件行为 |
| `hygiene/` | 仓库自身约束（目录布局、忽略规则、元数据一致性） | 与产品代码无关 |

## 约定

- 测试通过 `pyproject.toml` 的 `pythonpath = ["src"]` 导入源码，无需先安装；
- 网络测试统一用 `http.server`/loopback 夹具，端口从 0 动态分配，避免占用固定端口；
- 断言失败信息要能自解释，不要只写 `assert result`；
- 发现真实目标的凭据、报告或扫描结果**绝不能**作为 fixture 提交；
- 新增 hygiene 规则时，同时在 `scripts/check_*.py` 里实现并在本目录加回归测试。