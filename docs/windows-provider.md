# NSK Windows Provider（§11，Phase 15 交付：Job Objects MVP）

当前状态：**Job Objects MVP（Windows CI 实测）**。Windows 没有
namespace / cgroups / POSIX rlimits，按 §11 要求独立设计安全边界：

| 能力 | 状态 | 机制 |
| --- | --- | --- |
| 进程集合限制（资源） | ✅ Available | Job Object memory commit / active process / CPU rate |
| 整树终止 | ✅ Available | TerminateJobObject + KILL_ON_JOB_CLOSE 兜底 |
| 用量核算 | ✅ Available | Job accounting（CPU 时间、IO 计数、峰值内存、进程数） |
| 文件系统隔离 | ❌ Unsupported | Job Objects 不提供（§11.3）→ 策略请求即拒绝 |
| 网络隔离 | ❌ Unsupported | Job Objects 不提供（§11.3）→ 策略请求即拒绝 |
| rlimits | ❌ Unsupported | 无 POSIX rlimit 机制 |
| privilege_dropping | ⏳ NotConfigured | 令牌机制已实现并实测（DISABLE_MAX_PRIVILEGE 全禁权限），**尚未接入 spawn**，如实报告 |
| AppContainer | ❌ Unsupported | 仅 PoC 检测（TokenIsAppContainer/TokenElevation）；§11.5 要求实际安全验证后才可作为边界 |
| no_new_privileges / seccomp | ❌ Unsupported | 无对应机制 |

## 机制细节

- **无逃逸窗口的 spawn**（§11.3 进程集合管理）：子进程以
  `CREATE_SUSPENDED` 创建 → `AssignProcessToJobObject` → toolhelp 快照
  `ResumeThread`。作业分配发生在第一条指令之前，子进程无法抢先生成
  孤孙进程逃出作业。
- **限制翻译**（`limits.rs`，跨平台单测）：memory →
  `JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY`
  （commit-charge 语义，超限是子进程内分配失败）；max_processes →
  `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`；cpu_quota →
  `JobObjectCpuRateControlInformation`（硬限，粒度 1%）；
  另有 UI 限制（剪贴板 / 全局原子 / SYSTEMPARAMETERS / EXITWINDOWS /
  HANDLES）作为纵深防御。
- **确定性状态判定（§7.4）**：Job 内存超限不产生内核事件，子进程以
  非零码退出 → `NonZeroExit`（不臆断 OOM）。active process 超限表现为
  子进程创建失败，同理。
- **fail-closed**：文件系统/网络隔离请求在 Policy Engine 即被拒绝（能力
  快照如实上报 Unsupported）；Job Objects 探针失败时一切执行被拒绝
  （内存/进程限制无后备机制）。

## MVP 边界（诚实声明）

1. **受限令牌 spawn 未接线**：`token.rs` 完整实现并验证
   （DuplicateTokenEx → CreateRestrictedToken(DISABLE_MAX_PRIVILEGE) →
   实测 0 个 enabled privileges），但 `CreateProcessAsUserW` + 自管管道
   的 spawn 路径不在 MVP 中 → `privilege_dropping` 报告
   `NotConfigured`（子进程保留调用方权限），探针诊断明示。
2. **AppContainer 仅检测**：profile 创建机制需 §11.5 的实际安全验证，
   未通过前能力报告保持 Unsupported。
3. 文件系统/网络隔离依赖 AppContainer，随之同为后续项。

## CLI 用法（Windows 主机）

```sh
cargo run -p nsk-cli -- doctor --provider windows
cargo run -p nsk-cli -- run --provider windows --relax-unsupported -- cmd /C echo hi
```

（`--relax-unsupported` 关闭 Job Objects 无法提供的 fs/network 隔离域；
结果 diagnostics 记录全部降级。）

## 验收测试

- 跨平台单测：限制翻译、probe 诚实性（非 Windows 主机报告 Unsupported）。
- `crates/nsk-provider-windows/tests/job_windows.rs`（windows CI 运行）：
  作业内执行、整树终止、内存上限阻断大分配、active process 上限阻断
  子进程、用量核算、strict profile 拒绝。

## 后续方向

- Restricted-token spawn 接线（CreateProcessAsUserW + 管道）；
- AppContainer profile 创建 + 安全验证（§11.5）；
- JobObjectNotificationLimitInformation 事件（完成端口）驱动的限值判定。
