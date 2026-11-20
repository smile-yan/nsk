# NSK 安全模型

**设计书 §2（设计原则）与 §20.2（隔离验收）的实施说明**

## 威胁模型

NSK 的目标是限制**执行不受信任程序**的影响范围。防御对象包括：

- 无限循环 / 资源耗尽（CPU、内存、PID、文件描述符、输出、磁盘）；
- 文件系统越权（读取宿主机凭证、写入宿主机路径、symlink 逃逸、路径穿越）；
- 网络外联（数据外泄、攻击内网）；
- 进程逃逸（fork 炸弹、守护进程残留、进程组逃逸）；
- 权限提升（setuid、ptrace、内核接口滥用）。

**非目标**（第一阶段）：恶意内核级逃逸（如已知的 namespace/cgroup 漏洞利用）、侧信道防御、复杂网络代理与流量过滤。

## Fail-Closed（§2.4）

内核拒绝执行的三条防线：

1. **Policy Engine（创建时）**：`nsk-policy::effective::resolve` 将请求与 Provider 能力报告匹配。任何被请求但不可用的隔离域 → `CapabilityInsufficient` 错误。**Provider 能力报告必须诚实**（§2.6）：macOS/Windows Provider 与 Mock Provider 全部如实上报 `Unsupported`。
2. **Provider prepare（启动前）**：即使策略被误放行，`prepare` 在无法建立隔离时返回错误（如 Linux Provider 在 cgroup 被要求但不可用时拒绝）。
3. **Spawn 后 attach 失败即杀**：cgroup attach 失败立即终止刚启动的进程。

## 纵深防御（§2.3）

执行同时受以下机制约束（各层独立）：

| 防线 | 机制 | 层 |
| --- | --- | --- |
| 权限 | no_new_privileges、显式 uid 映射、最小 bind 集 | Provider |
| 进程 | PID namespace、进程组、cgroup pids.max | Provider + Supervisor |
| 文件系统 | Mount namespace、最小化 bind、tmpfs、workspace | Provider |
| 网络 | Network namespace（无接口） | Provider |
| 资源 | cgroups v2（memory/cpu/pids）+ rlimits + wall timer | Provider + Supervisor |
| 系统调用 | seccomp allowlist（可选，实验性） | Provider |
| 生命周期 | SIGTERM→SIGKILL 组升级、退出后组清扫、cgroup.kill | Supervisor + Provider |
| 输出 | 有界缓冲、字节上限、触发终止 | Supervisor |

## 路径安全（§6.3）

`nsk-workspace::path::PathValidator`：

- 全部基于 **canonical（完全解析 symlink）路径** 比较，绝不做字符串前缀比较；
- symlink 逃逸检测：解析后的真实位置必须仍在 root 内；
- `..` 组件直接拒绝；
- 清理（`remove_tree_safe`）把 symlink **作为链接删除**，绝不跟随——清理不可能越界删除宿主文件；
- 顶层路径（`/`、一级目录）删除直接拒绝（安全阀）。

## Workspace 所有权规则

- 内核创建的临时 workspace（`<base>/nsk-workspaces/nsk-ws-<id>`）由内核拥有，按 `cleanup_on_exit` 删除；
- **调用者提供的目录永远不被内核删除**（记录 `NSK7001` 诊断）——删除调用者的目录不是沙盒的决策；
- 崩溃恢复：`find_stale_workspaces` 只匹配内核前缀，`nsk cleanup` 可安全回收。

## 输出与资源无界增长的防线

- 输出流式读取（8 KiB chunk），每流保留缓冲有界（默认 ≤1 MiB），**总量精确**（即使保留被截断）；
- 组合限额触发可配置终止（`terminate_on_limit`）；
- 事件通道有界（broadcast 1024），滞后订阅者丢失事件而非阻塞内核（§14.4）；
- 事件桥、用量采样全部非阻塞。

## OOM 判定的证据分级（§7.4）

| 证据 | 结论 |
| --- | --- |
| cgroup `memory.events` oom_kill > 0 | **MemoryLimitExceeded（确定）** |
| SIGXCPU | **CpuLimitExceeded（确定，rlimit 语义）** |
| SIGXFSZ | **DiskLimitExceeded（确定，rlimit 语义）** |
| SIGKILL + 无 cgroup 证据 | **NonZeroExit + 诊断（绝不臆断 OOM）** |
| pids.events max > 0 | **ProcessLimitExceeded（确定）** |

## 已知边界（诚实声明）

1. **Mock Provider 没有任何隔离**——仅用于测试/开发，策略引擎默认拒绝它执行任何要求隔离的策略；CLI 中必须显式 `--provider mock --no-isolation` 并打印警告。
2. **Linux seccomp 允许列表为实验性**（§10.8），默认关闭；默认动作 EPERM，遗漏只影响兼容性不影响安全性（安全面由允许列表决定）。需在目标环境验证后才可启用。
3. **磁盘限额为咨询性**（扫描），无硬配额（cgroups 无目录配额机制）；诊断 `NSK4000` 明示。
4. **cgroup attach 存在竞态窗口**：spawn 后写 `cgroup.procs`，极短窗口内子进程 fork 的行为可能发生在 attach 前；缓解：bwrap 立即 unshare（新 cgroup 由父 cgroup 策略约束）+ fail-closed attach 失败即杀。
5. **TOCTOU**：路径校验与实际挂载之间存在理论窗口；Linux Provider 通过 mount namespace 内的挂载语义缓解（sandbox 内部视角的 root 由 bwrap 构建）。

## 安全测试矩阵（§16.4）

| 攻击 | 验收 | 测试位置 |
| --- | --- | --- |
| Infinite Loop | TimeLimitExceeded | `security_mock` / `isolation_linux` |
| Memory Bomb | MemoryLimitExceeded（cgroup OOM 证据） | `isolation_linux` |
| Fork Bomb | pids.max 生效 | `isolation_linux` |
| Output Bomb | OutputLimitExceeded + 有界内存 | `security_mock` |
| Host Path Access | /etc/shadow、/root/.ssh、docker.sock 不可达 | `isolation_linux` |
| Network Probe | 无宿主接口 | `isolation_linux` |
| Background Process | 组清扫、无进程残留 | `security_mock` |
| Open File Bomb | RLIMIT_NOFILE | `security_mock` |
| File Size Bomb | RLIMIT_FSIZE (SIGXFSZ) | `security_mock` |
| Env 泄漏 | 白名单之外变量不出现 | `security_mock` / `integration_lifecycle` |
| Cleanup Failure | 诊断完整、幂等重试 | `recovery` |
