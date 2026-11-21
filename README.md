# NSK · Native Sandbox Kernel

**轻量、跨平台、操作系统原生的程序隔离执行内核（Rust）**

NSK 在宿主操作系统上为任意程序建立受策略约束的执行环境：隔离建立、资源限制、进程管理、监控、终止与资源回收。它不依赖任何业务系统——通过 Rust API 复用，附带一个开发诊断 CLI。

> 当前状态：**V0.2 · 三平台 Provider**。Linux 是参考平台（bubblewrap +
> namespaces + cgroups v2 + 可选 seccomp）；macOS Provider 为 Seatbelt
> PoC（sandbox-exec 拒绝式 profile + 看门狗，实测验收）；Windows Provider
> 为 Job Objects MVP（作业分配无逃逸窗口 + 硬限 + 整树终止）。详见
> [docs/development-plan.md](docs/development-plan.md)。

## 快速开始

```sh
# 构建与测试
cargo build --release
cargo test --workspace

# 环境诊断（能力探测，任何平台）
cargo run -p nsk-cli -- doctor

# 在 Linux 上执行隔离沙盒
cargo run -p nsk-cli -- run --profile strict -- /bin/sh -c 'echo hello; ls /'

# 在 macOS 上执行 Seatbelt 沙盒（workspace 写隔离 + 网络策略）
cargo run -p nsk-cli -- run --provider macos --relax-unsupported -- /bin/echo hi

# 在 Windows 上执行 Job Object 沙盒（资源硬限 + 整树终止）
cargo run -p nsk-cli -- run --provider windows --relax-unsupported -- cmd /C echo hi

# 在非隔离平台（无隔离，显式确认后用于测试）
cargo run -p nsk-cli -- run --provider mock --no-isolation -- /bin/echo hi

# JSON 结果 + 事后检查
cargo run -p nsk-cli -- run --provider mock --no-isolation --json -- /bin/echo hi > result.json
cargo run -p nsk-cli -- inspect result.json

# 回收崩溃残留的内核工作目录
cargo run -p nsk-cli -- cleanup --dry-run
cargo run -p nsk-cli -- cleanup --yes
```

`--relax-unsupported` 按探针结果关闭当前平台无法提供的隔离域（所有降级
记录在结果 diagnostics 中，绝不静默）。

Rust API（§14.3）：

```rust
let runtime = SandboxRuntimeBuilder::new()
    .with_provider(nsk_runtime::create_default_provider()?) // 平台真实 Provider
    .build().await?;

let result = runtime.execute(spec).await?; // create → start → wait (+cleanup)
println!("{:?} stdout={}", result.status, result.output.stdout.text());
```

完整示例：[examples/](examples/)（可运行场景集：隔离执行、资源限制、超时、
事件流、批量调度、CLI 代码路径，`cargo run -p nsk-examples --example <名>`）；
crate 级最小 API 示例：[crates/nsk-runtime/examples/](crates/nsk-runtime/examples/)（basic_execution / policy / monitoring）。

## 架构（简）

12 个内核 crate 的模块化内核（另有 [examples/](examples/) 可运行示例集，
不属于内核分层），五层结构，依赖关系由 Cargo 强制（Core 零平台依赖 → Policy 纯逻辑 → Workspace/Resource → Supervisor → Provider Trait → 平台 Provider → Runtime 装配 → Scheduler → CLI）：

```
nsk-core ─ nsk-policy ─ nsk-workspace ─ nsk-resource ─ nsk-supervisor
                                              ↓
        nsk-cli ← nsk-scheduler ← nsk-runtime ← nsk-provider(+linux/macos/windows)
```

详情：[docs/architecture.md](docs/architecture.md) ·
安全模型：[docs/security-model.md](docs/security-model.md) ·
Linux Provider：[docs/linux-provider.md](docs/linux-provider.md) ·
macOS Provider：[docs/macos-provider.md](docs/macos-provider.md) ·
Windows Provider：[docs/windows-provider.md](docs/windows-provider.md)。

## 平台能力矩阵

| 平台 | 文件系统隔离 | 网络隔离 | 内存限制 | 进程数限制 | CPU 限制 | 机制 |
| --- | --- | --- | --- | --- | --- | --- |
| Linux | ✅（mount ns） | ✅（net ns） | ✅ cgroup v2 | ✅ cgroup pids | ✅ cgroup cpu.max | bubblewrap + cgroups |
| macOS | ✅ 写隔离（Seatbelt） | ✅（Seatbelt） | ⚠️ 看门狗 | ⚠️ 看门狗 | ⚠️ 配额降级告警（cpu_time 经 rlimit） | sandbox-exec + supervisor 看门狗 |
| Windows | ❌ fail-closed | ❌ fail-closed | ✅ Job Object | ✅ Job Object | ✅ Job Object CPU rate 硬顶 | CREATE_SUSPENDED → 作业分配 |

⚠️ = 反应式执行（有超调窗口，诊断明示）；macOS CPU 配额无强制机制，降级为
告警并明示（cpu_time 经 rlimit 仍强制）；❌ = 策略请求时 fail-closed 拒绝。

## 安全特性

- **Fail-closed**：策略要求的隔离无法建立时拒绝执行（绝不静默降级为普通进程）；
- **能力诚实上报**：每个 Provider 明确声明 Available/Unsupported/PermissionDenied/NotConfigured/Failed/Unknown（非布尔）；
- **机制阶梯**：每个资源限制经阶梯解析（cgroup → Job Object → rlimit → 看门狗），applied policy 记录实际执行的机制；
- **纵深防御**：隔离机制 + rlimits + 有界输出 + 进程树终止同时生效；
- **确定性状态判定**：OOM/PID 超限仅由内核事件或 Provider 确认证据判定，退出码永不臆断；
- **路径安全**：canonical + symlink 逃逸检测 + 清理不跟随链接 + 用户目录永不删除。

## 测试

约 270 项测试：单元、集成、安全（攻击矩阵）、压力（`--ignored`）、恢复，
外加平台验收（Linux §20.2 隔离矩阵、macOS Seatbelt 验收、Windows Job
Object 验收）。所有涉及进程的测试共享单一 runtime 以避免 SIGCHLD 竞争。
详见 [docs/testing.md](docs/testing.md)。

## 文档

- [架构](docs/architecture.md)
- [安全模型](docs/security-model.md)
- [策略引擎](docs/policy.md)
- [生命周期](docs/lifecycle.md)
- [Linux Provider](docs/linux-provider.md)
- [macOS Provider](docs/macos-provider.md) / [Windows Provider](docs/windows-provider.md)
- [测试体系](docs/testing.md)
- [开发计划与进度](docs/development-plan.md)

## License

MIT — 见 [LICENSE](LICENSE)。
