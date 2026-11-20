# NSK macOS Provider（§12，Phase 16 交付：Seatbelt PoC）

当前状态：**Seatbelt PoC（已实测验证）**。macOS 没有 namespace / cgroups
机制，Provider 使用操作系统实际提供的能力，并如实上报（§9.3 六态）：

| 能力 | 状态 | 机制 |
| --- | --- | --- |
| 文件系统隔离 | ✅ Available（探针实测） | sandbox-exec 拒绝式 profile：仅 workspace + 可写清单可写 |
| 网络隔离 | ✅ Available（探针实测） | `(deny network*)` / LoopbackOnly 白名单 |
| no_new_privileges | ✅ Available（实测 sudo 被拒） | 拒绝式 profile 天然拒绝 setuid exec |
| rlimits（NOFILE/FSIZE/CPU） | ✅ Available | supervisor pre-exec setrlimit |
| 内存限制 | ⚠️ Available（reactive） | 看门狗（proc_pid_rusage 轮询 + 杀树；有超调窗口） |
| 进程数限制 | ⚠️ Available（reactive） | 组大小轮询 + 杀树（有超调窗口） |
| 进程树终止 | ✅ Available | 进程组 SIGTERM→SIGKILL |
| process/ipc/uts 隔离 | ❌ Unsupported | 无机制（策略请求即拒绝） |
| RLIMIT_AS / RLIMIT_NPROC | ❌ Unsupported | 实测 AS 返回 EINVAL；NPROC 是 per-user 语义 |
| seccomp / 权限丢弃 / 磁盘配额 | ❌ Unsupported | 无机制 |

## 机制细节（§12.2 验证结果）

- **sandbox-exec / Seatbelt**：Apple 标记废弃，但随 macOS 发行（macOS 26
  实测可用）。探针做功能验证（profile 下可执行 + 拒绝式写隔离生效）才报告
  Available；profile 为**拒绝式 allow-list**（无 `(allow default)`）：
  `file-read*` 全局允许（dyld/framework 不可避免）、`file-write*` 仅
  workspace（canonical 路径）+ `writable_paths` + `/dev/null`、
  `process-exec*/process-fork/sysctl-read` 允许、网络按策略。
- **诚实边界**：`filesystem.deny_host_paths` 与 `isolate_root` 无法被
  Seatbelt 满足 → prepare 直接拒绝（不会静默降级）。读路径无法按路径收敛
  （见上），这是 PoC 的明确限制。
- **资源控制**：RLIMIT_AS 在 macOS 上不可用（setrlimit 返回 EINVAL），
  RLIMIT_NPROC 是 per-user 语义（统计无关进程，不可用于单沙盒限制）。
  内存与进程数限制由 **supervisor watchdog**（`nsk-supervisor::watchdog`，
  §7.2）反应式执行：轮询组内进程的 physical footprint / 数量，超限即
  SIGTERM→SIGKILL 整组；击杀作为确定性证据写入 `oom_events` /
  `pids_limit_hits`（§7.4），状态机据此给出 `MemoryLimitExceeded` /
  `ProcessLimitExceeded`。
- **私有 API**：全部依赖公开 CLI（sandbox-exec）与 libc 公开调用
  （proc_pid_rusage / proc_listallpids），符合 §12.2「不依赖未经验证的
  私有 API」。

## CLI 用法

```sh
cargo run -p nsk-cli -- doctor --provider macos
cargo run -p nsk-cli -- run --provider macos --relax-unsupported -- /bin/echo hi
```

`--relax-unsupported` 按探针结果关闭平台无法提供的隔离域（process/ipc/uts
namespace 与 host-path 隐藏），所有降级都记录在结果 diagnostics 中。

## 验收测试

`crates/nsk-provider-macos/tests/isolation_macos.rs`（macOS 上运行，
macOS CI 覆盖）：隔离 echo、workspace 外写入被拒（EPERM）、setuid 拒绝、
网络禁用（errno 1）、LoopbackOnly、内存看门狗、进程看门狗、输出限制、
strict profile 拒绝。

## 后续方向

- Endpoint Security / App Sandbox 契约范围评估（若 Apple 移除
  sandbox-exec 需替代方案）；
- 读路径收敛（白名单化 file-read）需要维护完整系统路径清单，收益/成本
  待评估；
- 看门狗超调窗口收紧（更短轮询 / kqueue 事件）。
