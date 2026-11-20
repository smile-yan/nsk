# NSK 策略引擎

**设计书 §6（Policy Engine）与 §17（默认 Profile）的实施说明**

## 管线（§6.2）

```
SandboxSpec
  → 结构校验（executable/args/env/workspace 路径）
  → 规范化（去重 env/path、对齐 output 限额与 max_processes）
  → 资源校验（wall time / memory / cpu quota / pids / files / output 边界）
  → 安全校验（require_seccomp⇒use_seccomp、isolate_root⇒isolate_filesystem 等）
  → 能力匹配（逐项对照 PlatformCapabilities，fail-closed）
  → EffectivePolicy（记录 requested / applied / limitations）
```

入口：`nsk_policy::effective::resolve(&spec, &capabilities)`。

## 校验规则摘要（§6.3）

- executable 必须为绝对路径或裸程序名，禁止经 shell 解释；
- 参数与环境变量禁止 NUL、超长、非法键名、重复键；
- 边界：wall time 100ms–1h、memory 1MiB–64GiB、pids 1–65536、open files 3–2^20、output 1KiB–1GiB、cpu quota 0.05–1024 核；
- swap ≤ memory；
- `combined_limit ≥ max(stdout, stderr)`，`resources.max_output_bytes ≥ combined`；
- NetworkPolicy::Restricted / AllowAll 第一阶段直接拒绝（fail-closed）；
- 只读/可写路径必须绝对路径、禁止 `..`、禁止双角色（既只读又可写）。

## 能力匹配语义

| 请求 | 平台能力缺失时 |
| --- | --- |
| isolate_process/filesystem/network/ipc/uts | **拒绝执行**（CapabilityInsufficient） |
| no_new_privileges | **拒绝执行** |
| drop_privileges | 降级 + 警告（进程通常已非特权） |
| use_seccomp（含 require） | **拒绝执行** |
| require_user_namespace / require_cgroup | Provider 侧拒绝（prepare fail-closed） |
| memory（无 cgroup） | 降级到 rlimit AS + 警告 |
| cpu_quota（无 cgroup cpu 控制器） | 记录 Unsupported + 警告（不阻断） |
| max_processes（无 pids 控制器） | 降级到 rlimit NPROC（Linux 上按用户语义，诊断明示） |
| disk | 咨询性，记录 Unsupported |

## EffectivePolicy（§6.4）

`applied` 记录每个限额的实际机制与生效值；`limitations` 收集全部警告。
Runtime 将 `effective.limitations` 并入最终 `SandboxResult.diagnostics`，
调用者永远可以看到「实际生效的策略」而非「请求的策略」。

## Profile（§17）

`SandboxPolicy::minimal()` / `strict()` / `extended()` 与设计书 §17 表格逐值一致
（5s/256MiB/16pids、2s/128MiB/8pids、30s/1GiB/64pids；输出 8/4/32 MiB；
Network Disabled；Host Filesystem Restricted）。Profile 是开发参考初始值，
必须经 Policy Engine 校验后使用。
