# NSK 开发计划与进度（§18）

## Phase 完成状态（2026-11-21）

| Phase | 内容 | 状态 | 交付物 |
| --- | --- | --- | --- |
| 0 | 工程基础（workspace/toolchain/lint/CI） | ✅ 完成 | Cargo workspace、rustfmt/clippy 配置、CI workflow |
| 1 | Core（§5） | ✅ 完成 | 全部核心类型 + 状态机 + 37 单元测试 |
| 2 | Policy Engine（§6） | ✅ 完成 | 校验/规范化/能力匹配/EffectivePolicy + 23 测试 |
| 3 | Provider 抽象（§9） | ✅ 完成 | Trait、类型化句柄、supervisor 配置翻译、Mock + 测试 |
| 4 | Workspace Manager（§ Phase 4） | ✅ 完成 | 路径安全、幂等清理、artifact、MountPlan + 24 测试 |
| 5 | Linux Capability Probe（§10.3） | ✅ 完成 | bwrap/namespace/cgroup v2/seccomp 实测探针 |
| 6 | Linux Isolation（§10.4-10.6） | ✅ 完成* | bwrap 参数生成、mount plan、env 隔离 |
| 7 | Resource Controller（§7, §10.7） | ✅ 完成* | cgroup manager（create/limits/metrics/kill/destroy）、用量核算 |
| 8 | Supervisor（§8） | ✅ 完成 | spawn/输出采集/终止/退出收集 + 23 测试 |
| 9 | Runtime Manager（§14） | ✅ 完成 | SandboxRuntime API、注册表、状态驱动、事件、CleanupManager |
| 10 | Linux MVP（§20 验收） | ✅ 完成* | 端到端隔离测试（Linux CI 验证） |
| 11 | Scheduler（§ Phase 11） | ✅ 完成 | FIFO + 并发预算 + 取消 + 6 测试 |
| 12 | Diagnostics（§15） | ✅ 完成 | 能力报告（CLI doctor/capabilities）、结构化诊断码、tracing 日志 |
| 13 | CLI（§ Phase 13） | ✅ 完成 | doctor/capabilities/run/inspect/cleanup |
| 14 | Stability & Security（§16） | ✅ 完成* | 安全/压力/恢复测试矩阵、CI 矩阵 |
| 15 | Windows Provider（§11） | ⏳ 占位 | fail-closed stub |
| 16 | macOS Provider（§12） | ⏳ 占位 | fail-closed stub |

\* Linux 特定路径（bwrap/cgroups/seccomp 运行时行为）已在 macOS 开发环境
**编译验证 + 单元测试**，**运行时验收依赖 Linux CI**（`.github/workflows/ci.yml`
的 linux-tests job 安装 bubblewrap 执行 §20.2 隔离验收）。

## 里程碑（§19）

- M1 Core ✅ · M2 Policy ✅ · M3 Provider API ✅ · M4 Workspace ✅
- M5 Linux Isolation ✅* · M6 Resource Controller ✅* · M7 Supervisor ✅
- M8 Linux Kernel MVP ✅*（待 Linux CI 验收）
- M9 Scheduler ✅ · M10 Release Candidate ✅*（文档 + 回归就绪）

## 已知差异与后续项

1. CLI `cancel` 子命令：单进程 CLI 中以 SIGINT→cancel 实现（`run` 期间
   Ctrl-C）；守护进程式远程 cancel 超出第一阶段范围。
2. `inspect` 读取 `run --json` 的结果文档（单进程 CLI 无跨进程注册表）。
3. seccomp allowlist：实验性、默认关闭，需按目标环境验证（§10.8）。
4. 磁盘硬配额：无机制，咨询性扫描（NSK4000 诊断）。
