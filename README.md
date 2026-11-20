# NSK · Native Sandbox Kernel

**轻量、跨平台、操作系统原生的程序隔离执行内核（Rust）**

NSK 在宿主操作系统上为任意程序建立受策略约束的执行环境：隔离建立、资源限制、进程管理、监控、终止与资源回收。它不依赖任何业务系统——通过 Rust API 复用，附带一个开发诊断 CLI。

> 当前状态：**V0.1 · Linux MVP（第一阶段）**。Linux 是参考平台（bubblewrap + namespaces + cgroups v2 + 可选 seccomp）；macOS / Windows Provider 为 fail-closed 占位。详见 [docs/development-plan.md](docs/development-plan.md)。

## 快速开始

```sh
# 构建与测试
cargo build --release
cargo test --workspace

# 环境诊断（能力探测，任何平台）
cargo run -p nsk-cli -- doctor

# 在 Linux 上执行隔离沙盒
cargo run -p nsk-cli -- run --profile strict -- /bin/sh -c 'echo hello; ls /'

# 在非 Linux 平台（无隔离，显式确认后用于测试）
cargo run -p nsk-cli -- run --provider mock --no-isolation -- /bin/echo hi

# JSON 结果 + 事后检查
cargo run -p nsk-cli -- run --provider mock --no-isolation --json -- /bin/echo hi > result.json
cargo run -p nsk-cli -- inspect result.json

# 回收崩溃残留的内核工作目录
cargo run -p nsk-cli -- cleanup --dry-run
cargo run -p nsk-cli -- cleanup --yes
```

Rust API（§14.3）：

```rust
let runtime = SandboxRuntimeBuilder::new()
    .with_provider(nsk_runtime::create_default_provider()?) // Linux 上为真实隔离
    .build().await?;

let result = runtime.execute(spec).await?; // create → start → wait (+cleanup)
println!("{:?} stdout={}", result.status, result.output.stdout.text());
```

完整示例：[examples](crates/nsk-runtime/examples/)（basic_execution / policy / monitoring）。

## 架构（简）

12 个 crate 的模块化内核，五层结构，依赖关系由 Cargo 强制（Core 零平台依赖 → Policy 纯逻辑 → Workspace/Resource → Supervisor → Provider Trait → 平台 Provider → Runtime 装配 → Scheduler → CLI）：

```
nsk-core ─ nsk-policy ─ nsk-workspace ─ nsk-resource ─ nsk-supervisor
                                              ↓
        nsk-cli ← nsk-scheduler ← nsk-runtime ← nsk-provider(+linux/macos/windows)
```

详情：[docs/architecture.md](docs/architecture.md) ·
安全模型：[docs/security-model.md](docs/security-model.md) ·
Linux Provider：[docs/linux-provider.md](docs/linux-provider.md)。

## 安全特性

- **Fail-closed**：策略要求的隔离无法建立时拒绝执行（绝不静默降级为普通进程）；
- **能力诚实上报**：每个 Provider 明确声明 Available/Unsupported/PermissionDenied/NotConfigured/Failed/Unknown（非布尔）；
- **纵深防御**：namespaces + cgroups v2 + rlimits + seccomp（可选）+ 有界输出 + 进程组终止同时生效；
- **确定性状态判定**：OOM/PID 超限仅由内核事件证据确认，退出码永不臆断；
- **路径安全**：canonical + symlink 逃逸检测 + 清理不跟随链接 + 用户目录永不删除。

## 测试

约 230 项测试：单元、集成、安全（攻击矩阵）、压力（`--ignored`）、恢复。所有涉及进程的测试共享单一 runtime 以避免 SIGCHLD 竞争。详见 [docs/testing.md](docs/testing.md)。

## 文档

- [架构](docs/architecture.md)
- [安全模型](docs/security-model.md)
- [策略引擎](docs/policy.md)
- [生命周期](docs/lifecycle.md)
- [Linux Provider](docs/linux-provider.md)
- [Windows Provider](docs/windows-provider.md) / [macOS Provider](docs/macos-provider.md)
- [测试体系](docs/testing.md)
- [开发计划与进度](docs/development-plan.md)

## License

MIT — 见 [LICENSE](LICENSE)。
