# 使用示例（examples）

可运行、随 CI 编译检查的使用示例集（workspace 成员 `nsk-examples`）。每个
示例是单文件自包含入口，可直接运行、复制、修改：

```sh
cargo run -p nsk-examples --example hello_sandbox
```

> 示例命令基于 POSIX shell（`/bin/sh`）。Linux 上获得完整隔离（bubblewrap +
> namespaces + cgroups v2）；macOS 为 Seatbelt PoC；Windows Provider 无
> fs/network 隔离；mock Provider 无任何隔离（显式放宽后仅用于测试）。所有
> 平台降级都显式记录在结果 diagnostics 中，绝不静默。

## 示例目录

| 示例 | 场景 | CLI 等价命令 |
| --- | --- | --- |
| [hello_sandbox](hello_sandbox.rs) | 首次运行：探针 → strict profile → 按平台显式降级 → 执行 → 解读 diagnostics | `nsk run --profile strict --relax-unsupported -- /bin/sh -c 'echo hello; pwd'` |
| [resource_limits](resource_limits.rs) | 内存上限的强制与平台差异（cgroup 硬杀 / 看门狗反应式 / mock 兜底）与证据判定 | `nsk run --memory 32 -- /bin/sh -c 'x=a; while :; do x="$x$x"; done'` |
| [wall_time_timeout](wall_time_timeout.rs) | 墙钟超时终止（内核监督级，任何 Provider 都有效）+ 已产出输出的保留 | `nsk run --wall-time 2 -- /bin/sh -c 'while :; do echo tick; sleep 0.2; done'` |
| [lifecycle_events](lifecycle_events.rs) | 事件流全览（§14.4）+ 运行中取消与进程树终止 | （API-only：`subscribe` / `cancel`） |
| [batch_scheduler](batch_scheduler.rs) | 有界并发批量执行（FIFO + 全局并发预算）+ 调度统计 | （API-only：`nsk_scheduler::Scheduler`） |
| [cli_flow](cli_flow.rs) | 在 Rust 中走 CLI 同款代码路径：doctor 能力表 → run --json 结果文档 → inspect 复核 | `nsk doctor` · `nsk run --profile strict --relax-unsupported --json -- …` · `nsk inspect result.json` |

## 平台预期

示例刻意展示"机制阶梯 + 能力诚实上报"的行为差异：

- **Linux**：strict profile 原样接受；`resource_limits` 由 cgroup v2 硬杀，
  `oom_events` 给出确认证据，状态 `MemoryLimitExceeded`；
- **macOS**：mount namespace 不可用 → host-path 隐藏 / 根重映射被显式丢弃，
  文件系统隔离由 Seatbelt 承担；内存为看门狗反应式（有超调窗口，diagnostics
  明示），可能以 `MemoryLimitExceeded` 或兜底 `TimeLimitExceeded` 收场；
- **mock Provider**：无隔离、无强制 → 仅剩内核监督的 wall-time 兜底，示例
  会打印明确的降级说明。

## 约定

- 每个示例单文件自包含（不共享模块），复制一个 `.rs` 即可用；
- 降级永远显式（警告行 + diagnostics），绝不静默；
- 示例随 `cargo test --workspace` 编译、随
  `cargo clippy --workspace --all-targets -- -D warnings` 检查 —— API 演进
  时示例不会悄悄失效。

crate 级最小 API 示例（basic_execution / policy / monitoring）见
[crates/nsk-runtime/examples/](../crates/nsk-runtime/examples/)。
