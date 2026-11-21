# NSK 架构文档

**NSK · Native Sandbox Kernel — 模块化内核架构（设计书 §3）**

NSK 是一个使用 Rust 开发的独立、轻量、原生程序隔离执行内核。它不面向任何业务系统，职责只有一个：在宿主操作系统上为任意程序建立受策略约束的执行环境，管理其资源、进程、权限与生命周期，并在执行完成后可靠回收资源。

## 五层架构

```
┌────────────────────────────────────────────────────────┐
│ 5  System Layer      OS · syscall · 内核机制            │
├────────────────────────────────────────────────────────┤
│ 4  Platform Layer    Provider（Linux / macOS / Windows）│
├────────────────────────────────────────────────────────┤
│ 3  Runtime Layer     Supervisor · Output · Workspace   │
├────────────────────────────────────────────────────────┤
│ 2  Control Layer     Execution Manager · Policy Engine │
│                      Scheduler · Diagnostics            │
├────────────────────────────────────────────────────────┤
│ 1  Core Layer        Types · Policy · State · Result    │
│                      Errors · Capabilities              │
└────────────────────────────────────────────────────────┘
```

## Crate 依赖图（§13.2 规则）

```
nsk-core（纯类型，零平台依赖）
   ↑
nsk-policy（策略校验/规范化/能力匹配，无 OS 访问）
   ↑                 ↑
nsk-workspace      nsk-resource
（工作目录+路径安全）  （限额模型+用量核算）
   ↑                 ↑
nsk-supervisor（进程监管器：spawn/输出/终止）
   ↑                 ↑
nsk-provider（Trait + Mock）──────────────┐
   ↑                                      │
nsk-provider-linux / macos / windows ─────┤
   ↑                                      │
nsk-runtime（Runtime Manager + Provider 工厂装配）
   ↑
nsk-scheduler（FIFO + 并发预算）
   ↑
nsk-cli（诊断工具，非内核本体）
```

关键规则（均已由 crate 依赖关系强制）：

- `nsk-core` 不依赖任何 Provider；
- `nsk-policy` 不做 OS 访问；
- `nsk-provider` 只定义接口 + Mock，**不**依赖具体平台 Provider（避免循环依赖）；
- 平台 Provider 依赖接口与 Core；
- Runtime 负责组装各模块（Provider 工厂位于 `nsk-runtime::provider_factory`，符合「Runtime 负责组合各模块」规则）；
- CLI 不直接操作系统资源，只通过 Runtime API。

## 核心执行模型

基本单位是 **Sandbox Instance**（§4.1）：唯一 ID、命令、工作目录、环境、策略、进程集合、OS 隔离资源、监控状态、结果、清理状态。

生命周期（§4.2）：

```
Created → Validating → Preparing → Ready → Starting → Running
                                              ↓（超时/取消/超限）
                                        Terminating
Running → Collecting → Cleaning → Completed
（任意失败态 → Failed → Cleaning → Completed，Cleanup 幂等）
```

状态转换由 `nsk-core::state` 的状态机校验，只有 Runtime Manager 可以变更状态（§4.3）。

## 组件职责速查

| Crate | 职责 |
| --- | --- |
| `nsk-core` | SandboxId / Spec / Policy / State / Result / Error / Event / Capability |
| `nsk-policy` | 校验（结构/路径/资源/冲突）→ 规范化 → 能力匹配 → EffectivePolicy |
| `nsk-workspace` | 工作目录创建/清理（幂等、symlink 安全）、路径校验、MountPlan |
| `nsk-resource` | 限额编码（cgroup/rlimit）、用量核算、超限判定（纯逻辑） |
| `nsk-supervisor` | spawn、stdin/stdout/stderr 有界采集、wall-time、进程树终止、退出收集 |
| `nsk-provider` | SandboxProvider Trait、类型化生命周期句柄、supervisor 配置翻译、Mock |
| `nsk-provider-linux` | bubblewrap + namespaces + cgroups v2 + seccomp（参考实现，§10） |
| `nsk-provider-macos` | Seatbelt PoC：sandbox-exec 拒绝式 profile + 看门狗（§12） |
| `nsk-provider-windows` | Job Objects MVP：无逃逸窗口作业分配 + 硬限 + 整树终止（§11） |
| `nsk-runtime` | SandboxRuntime API、注册表、生命周期驱动、CleanupManager、事件流 |
| `nsk-scheduler` | FIFO 队列、全局并发预算、任务取消 |
| `nsk-cli` | doctor / capabilities / run / inspect / cleanup |

`nsk-examples`（workspace 成员 [examples/](../examples/)）不在内核分层内：
可运行、随 CI 编译检查的使用示例集，只依赖内核公共 API 与 CLI 库。

## 双重强制（Belt & Braces）

资源限制与进程终止由两层机制共同保证：

1. **Supervisor 层（跨平台）**：wall-time 定时器、输出限额（有界缓冲 + 触发终止）、rlimit（NOFILE/FSIZE/CPU/AS）、进程组 SIGTERM→SIGKILL 升级、退出后进程组清扫。
2. **Provider 层（平台）**：Linux 上为 cgroups v2（memory.max / cpu.max / pids.max / cgroup.kill）+ namespaces + seccomp；macOS 上为 Seatbelt 拒绝式 profile + supervisor 看门狗（反应式）；Windows 上为 Job Objects（内存/进程数/CPU rate 硬限 + TerminateJobObject）。

监控永远不能替代强制（§7.4）；cgroup 事件（memory.events 的 oom_kill、pids.events 的 max）是状态判定的**确定性证据**，而退出码本身永远不能单独证明 OOM。
