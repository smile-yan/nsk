# NSK 生命周期

**设计书 §4（核心执行模型）与 §8（Supervisor）的实施说明**

## 状态机

```
Created → Validating → Preparing → Ready → Starting → Running
    │            │            │                   │
    └────────────┴────────────┴→ Failed           ↓
                                                  Terminating
Running → Collecting → Cleaning → Completed
                                   ↑
Failed → Cleaning ─────────────────┘
```

- 合法转换表见 `nsk-core::state::SandboxState::can_transition_to`；
- 只有 Runtime Manager 能变更状态（§4.3）；
- `Failed` 仍可进入 `Cleaning`——内部错误不豁免清理；
- `Completed` 是唯一完全终态。

## Runtime 编排（Phase 9）

`create`（Created→Validating→Preparing→Ready）:
1. 规范化+校验+能力匹配（Policy Engine）；
2. Workspace 准备（创建/校验，kernel_created 标记）；
3. Provider `prepare`（隔离环境 + ExecutionPlan）。

`start`（Ready→Starting→Running）:
1. Provider `spawn`（supervisor 拉起进程，Linux 上 attach cgroup）；
2. 事件桥启动（SupervisorEvent → SandboxEvent）；
3. 驱动任务 `drive_to_completion` 启动。

`wait`：订阅 per-entry watch 通道，多消费者安全。

`cancel`：进程组 SIGTERM→(grace)→SIGKILL；cgroup.kill 优先。

`cleanup`：provider 资源（cgroup destroy）→ workspace（仅内核创建的）→ 标记完成。幂等，失败可重试。

## 结果推导（Collecting）

Supervisor outcome + provider 用量 → 依据可靠证据映射 SandboxStatus（详见
docs/security-model.md 的证据分级表）。

## Supervisor 终止矩阵（§8.4）

| 触发 | 行为 |
| --- | --- |
| 正常退出 | 退出码收集 + 进程组清扫（孤儿/守护进程） |
| wall-time 超时 | SIGTERM→grace→SIGKILL（组） |
| cancel | 同上，状态 Cancelled |
| 输出超限 | 同上，状态 OutputLimitExceeded |
| SIGXCPU/SIGXFSZ | 确定性映射 CpuLimitExceeded / DiskLimitExceeded |
| cgroup OOM / pids max | 确定性映射 Memory/ProcessLimitExceeded |

## 事件流（§14.4）

有界 broadcast（1024）。事件：Created/Preparing/Ready/Started/Stdout/Stderr/
ResourceUsage/LimitExceeded/Terminating/Exited/CleanupCompleted。
滞后订阅者收到 `Lagged`，绝不阻塞内核。
