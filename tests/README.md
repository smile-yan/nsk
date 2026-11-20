# NSK 测试体系（§16）

顶层目录只保留共享 fixtures；真正的测试位于各 crate 的 `tests/` 目录：

| 目录 / 文件 | 内容 | 运行环境 |
| --- | --- | --- |
| `fixtures/` | 安全测试用的攻击脚本（fork bomb、memory bomb、infinite loop、host-path probe、open-file bomb） | 任意 |
| `crates/nsk-core` / `nsk-policy` / `nsk-resource` / `nsk-workspace` 单元测试 | 类型、策略、路径安全、限额转换 | 任意 |
| `crates/nsk-supervisor/tests` | 进程监管器（spawn/输出/终止/rlimit） | Unix |
| `crates/nsk-runtime/tests/integration_lifecycle.rs` | 完整生命周期集成（§16.3） | 任意（mock provider） |
| `crates/nsk-runtime/tests/security_mock.rs` | supervisor 级安全测试（§16.4 子集） | Unix |
| `crates/nsk-runtime/tests/stress.rs` | 压力测试（§16.5，`#[ignore]`，用 `--ignored` 运行） | 任意 |
| `crates/nsk-runtime/tests/recovery.rs` | 恢复测试（§16.6） | 任意 |
| `crates/nsk-provider-linux/tests/isolation_linux.rs` | 真实 OS 隔离安全测试（§20.2） | Linux + bubblewrap |
| `crates/nsk-cli/tests` | CLI 端到端 | 任意 |

运行方式：

```sh
cargo test --workspace                                   # 常规测试
cargo test -p nsk-runtime --test stress -- --ignored     # 压力测试
NSK_STRESS_ITERS=1000 cargo test -p nsk-runtime --test stress -- --ignored
cargo test -p nsk-provider-linux --test isolation_linux  # Linux 隔离验收
```
