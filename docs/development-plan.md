# NSK 开发计划与进度（§18）

## Phase 完成状态（2026-11-21）

| Phase | 内容 | 状态 | 交付物 |
| --- | --- | --- | --- |
| 0 | 工程基础（workspace/toolchain/lint/CI） | ✅ 完成 | Cargo workspace、rustfmt/clippy 配置、CI workflow |
| 1 | Core（§5） | ✅ 完成 | 全部核心类型 + 状态机 + 37 单元测试 |
| 2 | Policy Engine（§6） | ✅ 完成 | 校验/规范化/能力匹配（机制阶梯）/EffectivePolicy + 33 测试 |
| 3 | Provider 抽象（§9） | ✅ 完成 | Trait、类型化句柄、supervisor 配置翻译、Mock + 测试 |
| 4 | Workspace Manager（§ Phase 4） | ✅ 完成 | 路径安全、幂等清理、artifact、MountPlan + 24 测试 |
| 5 | Linux Capability Probe（§10.3） | ✅ 完成 | bwrap/namespace/cgroup v2/seccomp 实测探针 |
| 6 | Linux Isolation（§10.4-10.6） | ✅ 完成* | bwrap 参数生成、mount plan、env 隔离 |
| 7 | Resource Controller（§7, §10.7） | ✅ 完成* | cgroup manager（create/limits/metrics/kill/destroy）、用量核算 |
| 8 | Supervisor（§8） | ✅ 完成 | spawn/输出采集/终止/退出收集 + 23 测试 + macOS 看门狗 |
| 9 | Runtime Manager（§14） | ✅ 完成 | SandboxRuntime API、注册表、状态驱动、事件、CleanupManager |
| 10 | Linux MVP（§20 验收） | ✅ 完成* | 端到端隔离测试（Linux CI 验证） |
| 11 | Scheduler（§ Phase 11） | ✅ 完成 | FIFO + 并发预算 + 取消 + 6 测试 |
| 12 | Diagnostics（§15） | ✅ 完成 | 能力报告（CLI doctor/capabilities）、结构化诊断码、tracing 日志 |
| 13 | CLI（§ Phase 13） | ✅ 完成 | doctor/capabilities/run/inspect/cleanup + `--relax-unsupported` |
| 14 | Stability & Security（§16） | ✅ 完成* | 安全/压力/恢复测试矩阵、CI 矩阵 |
| 15 | Windows Provider（§11） | ✅ 完成 | **Job Objects MVP**：CREATE_SUSPENDED→作业分配→恢复、内存/进程数/CPU rate 硬限、UI 限制、整树终止、用量核算；受限令牌机制实现并实测（spawn 接线为后续项，如实报告）；AppContainer 仅检测（§11.5 安全验证前置）；windows CI 集成测试 |
| 16 | macOS Provider（§12） | ✅ 完成 | **Seatbelt PoC**：sandbox-exec 拒绝式 profile（workspace 写隔离 + 网络策略 + setuid 拒绝）、探针功能验证、supervisor 看门狗（内存/进程数反应式执行）、macOS 验收测试；macOS CI 覆盖 |

\* Linux 特定路径（bwrap/cgroups/seccomp 运行时行为）已在 macOS 开发环境
**编译验证 + 单元测试**，**运行时验收依赖 Linux CI**（`.github/workflows/ci.yml`
的 linux-tests job 安装 bubblewrap 执行 §20.2 隔离验收）。macOS 路径在本机
与 macOS CI **完整运行时验收**；Windows 路径在 windows CI 运行时验收。

## 里程碑（§19）

- M1 Core ✅ · M2 Policy ✅ · M3 Provider API ✅ · M4 Workspace ✅
- M5 Linux Isolation ✅* · M6 Resource Controller ✅* · M7 Supervisor ✅
- M8 Linux Kernel MVP ✅*（待 Linux CI 验收）
- M9 Scheduler ✅ · M10 Release Candidate ✅
- M11 Windows Provider MVP ✅（windows CI 验收）
- M12 macOS Provider PoC ✅（macOS 本机 + CI 验收）

## 已知差异与后续项

1. CLI `cancel` 子命令：单进程 CLI 中以 SIGINT→cancel 实现（`run` 期间
   Ctrl-C）；守护进程式远程 cancel 超出第一阶段范围。
2. `inspect` 读取 `run --json` 的结果文档（单进程 CLI 无跨进程注册表）。
3. seccomp allowlist：实验性、默认关闭，需按目标环境验证（§10.8）。
4. 磁盘硬配额：无机制，咨询性扫描（NSK4000 诊断）。
5. Windows：受限令牌 spawn 接线（机制已实现）与 AppContainer 完整实现
   （§11.5 安全验证前置）为后续项；fs/network 隔离在 Windows 上依赖
   AppContainer，当前 fail-closed。
6. macOS：sandbox-exec 已被 Apple 废弃（PoC 级边界，探针功能验证）；
   读路径无法按路径收敛（`deny_host_paths` fail-closed）；内存/进程数
   限制为看门狗反应式执行（有超调窗口，诊断明示）。
