# NSK 测试体系（§16）

## 运行

```sh
cargo test --workspace                                   # 常规（约 260 项）
cargo test -p nsk-runtime --test stress -- --ignored     # 压力（§16.5）
NSK_STRESS_ITERS=1000 cargo test -p nsk-runtime --test stress -- --ignored
cargo test -p nsk-provider-linux --test isolation_linux  # Linux 隔离验收（§20.2）
cargo test -p nsk-provider-macos --test isolation_macos  # macOS Seatbelt 验收
cargo test -p nsk-provider-windows --test job_windows    # Windows Job Object 验收
cargo clippy --workspace --all-targets -- -D warnings    # lint
cargo fmt --all --check                                  # 格式
```

## 分层

| 层 | 位置 | 环境 |
| --- | --- | --- |
| Unit（§16.2） | 各 crate `#[cfg(test)]` | 任意 |
| Integration（§16.3） | `nsk-runtime/tests/integration_lifecycle.rs` | mock，任意 |
| Security（§16.4） | `nsk-runtime/tests/security_mock.rs`（supervisor 级）+ `nsk-provider-linux/tests/isolation_linux.rs`（Linux 隔离）+ `nsk-provider-macos/tests/isolation_macos.rs`（Seatbelt）+ `nsk-provider-windows/tests/job_windows.rs`（Job Objects） | 各平台 CI / 本机 |
| Stress（§16.5） | `nsk-runtime/tests/stress.rs`（`#[ignore]`） | 任意 |
| Recovery（§16.6） | `nsk-runtime/tests/recovery.rs` | 任意 |
| CLI E2E | `nsk-cli/tests` + `nsk-cli` 单元测试 | 任意 |
| Fixtures | `tests/fixtures/*.sh` | 任意 |

## 重要约定

- **共享 runtime**：所有涉及进程的测试共用一个多线程 tokio runtime
  （`block_on` helper）——SIGCHLD 处理器是进程全局的，每个测试独立 runtime
  会在并行负载下丢失子进程退出通知导致 `Child::wait()` 挂起。
- 安全测试 fixtures 位于 `tests/fixtures/`（fork bomb、memory bomb、
  infinite loop、host path probe、open file bomb）。
- **平台验收测试在无对应机制的主机上自动跳过**（probe 结果驱动），因此
  `cargo test --workspace` 在任何平台都能全绿。
- **跨目标编译检查**：Windows 路径在 macOS/Linux 开发机上以
  `cargo check --target x86_64-pc-windows-gnu --workspace --all-targets`
  验证编译与 lint；运行时验收由 windows CI 执行。
- CI（`.github/workflows/ci.yml`）：Linux 全量（含 bwrap）+ macOS 全量
  （含 Seatbelt 验收）+ Windows provider 测试 + fmt + clippy。
