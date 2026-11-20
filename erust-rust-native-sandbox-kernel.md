# Rust Native Sandbox Kernel

**独立轻量原生沙盒内核开发设计书 · V1.0**

项目定位：独立的操作系统级受限程序执行内核

> ## 📌 开发进度（2026-11-21 更新）
>
> **Phase 0–14 已实现并通过 226 项自动化测试；Phase 15/16（Windows/macOS Provider）为 fail-closed 占位，按设计书排期属于后续阶段。**
>
> ### 交付总览
>
> | 维度 | 数据 |
> | --- | --- |
> | Cargo Workspace | 12 个 crate，~14,400 行 Rust（含测试） |
> | 自动化测试 | 226 项全部通过（单元 / 集成 / 安全 / 恢复；压力测试 `#[ignore]` 可选运行） |
> | 代码质量 | `cargo clippy --workspace --all-targets -- -D warnings` 零告警；`cargo fmt --check` 通过 |
> | CI | GitHub Actions：Linux 全量隔离验收（安装 bubblewrap）+ macOS + Windows 构建 + fmt + clippy |
> | 文档 | README + docs/（架构、安全模型、策略、生命周期、Linux/Windows/macOS Provider、测试、开发计划） |
>
> ### Phase 完成状态（§18.1 对照）
>
> | Phase | 内容 | 状态 |
> | --- | --- | --- |
> | 0 | 工程基础（workspace / toolchain / lint / CI） | ✅ 完成 |
> | 1 | Core（§5 全部核心类型 + 状态机） | ✅ 完成 |
> | 2 | Policy Engine（校验/规范化/能力匹配/EffectivePolicy） | ✅ 完成 |
> | 3 | Provider 抽象（Trait + 类型化句柄 + Mock） | ✅ 完成 |
> | 4 | Workspace Manager（路径安全 / 幂等清理 / artifact / MountPlan） | ✅ 完成 |
> | 5 | Linux Capability Probe（bwrap / namespace / cgroup v2 / seccomp 实测探针） | ✅ 完成 |
> | 6 | Linux Isolation（bwrap 参数生成 / mount plan / env 隔离） | ✅ 完成* |
> | 7 | Resource Controller（cgroup v2 管理 + 用量核算 + 强制决策） | ✅ 完成* |
> | 8 | Supervisor（spawn / 有界输出 / 进程树终止 / 退出收集） | ✅ 完成 |
> | 9 | Runtime Manager（SandboxRuntime API / 注册表 / 事件 / CleanupManager） | ✅ 完成 |
> | 10 | Linux MVP（§20 端到端验收测试） | ✅ 完成* |
> | 11 | Scheduler（FIFO + 全局并发预算 + 取消） | ✅ 完成 |
> | 12 | Diagnostics（能力报告 / 诊断码 / tracing） | ✅ 完成 |
> | 13 | CLI（doctor / capabilities / run / inspect / cleanup） | ✅ 完成 |
> | 14 | Stability & Security（安全 / 压力 / 恢复测试矩阵） | ✅ 完成* |
> | 15 | Windows Provider | ⏳ fail-closed 占位（§11，后续阶段） |
> | 16 | macOS Provider | ⏳ fail-closed 占位（§12，后续阶段） |
>
> \* Linux 特定运行时路径（bwrap / cgroups / seccomp）在本开发机（macOS arm64）上完成**编译验证 + 单元测试**；**运行时隔离验收由 Linux CI 执行**（CI 安装 bubblewrap 并运行 §20.2 隔离/资源/安全测试）。
>
> ### 与设计书的实现偏差（均为有意决策，详见 docs/development-plan.md）
>
> 1. **Provider 工厂位于 `nsk-runtime::provider_factory`** 而非 `nsk-provider/factory.rs`：具体平台 Provider 依赖 Provider Trait（§13.2），若 Trait crate 反向依赖具体 Provider 会形成循环依赖；符合「Runtime 负责组合各模块」规则。
> 2. **`ProcessSpec::working_directory` 语义明确化**：空路径 = workspace root（runtime 解析）。
> 3. **Workspace 所有权规则强化**：用户提供的 workspace 目录**永不**被内核删除（即使 `cleanup_on_exit`），记录 `NSK7001` 诊断——删除调用者目录不是沙盒的决策。
> 4. **正常退出路径增加进程组清扫**（§8.4 进程残留）：主进程退出后对进程组残留成员 SIGKILL（守护进程/孤儿清除），已由安全测试验证。
> 5. **seccomp allowlist 为实验性且默认关闭**（§10.8 谨慎原则）：BPF 生成器已实现并有结构测试，默认动作 EPERM（遗漏只影响兼容性不影响安全面），需在目标环境验证后启用。
> 6. **CLI cancel**：单进程 CLI 中以 `run` 期间 SIGINT→cancel 实现；守护进程式远程 cancel 超出第一阶段。`inspect` 读取 `run --json` 结果文档。
> 7. **Supervisor 配置翻译集中在 `nsk_provider::traits::supervisor_config`**：wall-time / 输出限额 / terminate_on_limit 由 EffectivePolicy 统一推导，各 Provider 强制语义一致。
>
> ### 已知边界（诚实声明）
>
> - Mock Provider 无任何隔离（测试/开发专用），策略引擎默认拒绝其执行任何要求隔离的策略；CLI 需显式 `--provider mock --no-isolation` 并打印警告。
> - 磁盘限额为咨询性扫描（cgroups 无目录配额机制），诊断 `NSK4000` 明示。
> - cgroup attach 存在极短竞态窗口（spawn 后写 `cgroup.procs`），attach 失败即杀（fail-closed）。
> - 多 tokio runtime 进程内并发使用 `tokio::process` 会竞争进程全局 SIGCHLD 处理器——内核自身单 runtime 使用；测试已按共享 runtime 模式编写。
>
> ### 运行方式
>
> ```sh
> cargo test --workspace                                   # 226 项测试
> cargo test -p nsk-runtime --test stress -- --ignored     # 压力测试
> cargo test -p nsk-provider-linux --test isolation_linux  # Linux 隔离验收（§20.2）
> cargo run -p nsk-cli -- doctor                           # 环境诊断
> cargo run -p nsk-cli -- run --profile strict -- /bin/sh -c 'echo hello'
> ```
>
> 里程碑对照（§19）：M1–M10 全部达成（M5/M6/M8/M10 的运行时验收依赖 Linux CI）。

---

本设计书将彻底移除桌面应用、UI、Tauri、算法学习平台、题库、编译器管理以及应用集成等相关内容。

**本项目只开发 Sandbox Kernel 本身。**

我们将把它视为一个独立的系统软件项目，目标是使用 Rust 构建一套轻量、可复用、可测试、具备实际操作系统隔离能力的程序执行内核。

它不依赖任何具体应用，也不面向某个业务系统。它的职责只有一个：

> 在宿主操作系统上，为任意指定的程序建立一个受策略约束的执行环境，管理其资源、进程、权限、生命周期，并在执行完成后可靠地回收执行资源。

# **一、项目定义**

## **1.1 项目名称**

暂定项目名称：

# **Native Sandbox Kernel**

**NSK · Rust Native Sandbox Kernel**

轻量、跨平台、操作系统原生程序隔离执行内核

## **1.2 项目目标**

使用 Rust 开发独立的原生沙盒内核，实现受控程序执行的基础能力。

| 目标       | 说明                     |
| -------- | ---------------------- |
| **独立性**  | 内核不依赖任何具体业务应用          |
| **轻量化**  | 不使用完整虚拟机，不引入庞大的容器运行时   |
| **安全性**  | 利用操作系统机制建立实际隔离         |
| **资源控制** | 限制执行时间、CPU、内存、进程、文件和输出 |
| **可回收**  | 统一管理进程及执行资源生命周期        |
| **可扩展**  | 通过 Provider 适配不同操作系统   |
| **可测试**  | 提供独立测试、验证、诊断及压力测试能力    |
| **可复用**  | 通过 Rust API 提供执行能力     |

## **1.3 非目标**

本项目不开发：

- 桌面应用。
- GUI。
- Web UI。
- 题库。
- 判题系统。
- 算法平台。
- 编译器下载管理。
- 语言包管理。
- 用户账户。
- 在线服务。
- 应用级通信协议。
- 业务级任务调度。
- IDE。
- 代码编辑器。
- 完整容器管理系统。
- 虚拟机管理系统。

本项目允许使用 CLI 作为内核的开发、诊断和验证工具，但 CLI 不是内核主体。

# **二、设计原则**

## **2.1 Minimal Kernel**

内核只保留程序执行安全所需的核心能力。

不引入业务逻辑，不实现不必要的服务，不将内核设计成完整容器运行时。

## **2.2 OS Native Isolation**

优先利用宿主操作系统原生安全机制。

- Linux：Namespaces、cgroups、seccomp、rlimits。
- Windows：Job Objects、Restricted Token、AppContainer 等。
- macOS：经过验证的系统隔离机制。

内核负责协调这些机制，而不是重新实现操作系统。

## **2.3 Defense in Depth**

不能依赖单一隔离机制。

程序执行应同时受到：

- 权限限制。
- 进程隔离。
- 文件系统隔离。
- 网络隔离。
- 资源限制。
- 系统调用限制。
- 生命周期管理。

## **2.4 Fail-Closed**

如果执行策略要求的隔离机制无法建立，内核应拒绝安全执行。

不能静默地退化为普通宿主机进程。

## **2.5 Platform Independent Core**

核心数据模型、策略、状态机、生命周期逻辑及执行结果尽可能不依赖平台。

操作系统特定机制放入 Provider。

## **2.6 Explicit Capabilities**

内核必须明确声明当前环境能够提供什么隔离能力。

不能因为 API 相同，就假设各操作系统具备相同的安全边界。

## **2.7 Least Privilege**

内核、执行程序、启动器及辅助进程都应尽可能使用最低必要权限。

避免依赖高权限服务或常驻管理员权限。

## **2.8 Reproducibility**

同一执行策略、同一环境配置和相同程序输入，应尽可能获得一致的执行行为。

内核应明确记录实际应用的策略和能力，而不是仅记录用户请求的策略。

# **三、内核总体架构**

## **3.1 架构总览**

采用模块化内核架构（Modular Kernel Architecture）。

核心分为五层：

1. Core Layer：基础类型、状态、错误、策略及结果。
2. Control Layer：执行生命周期、调度、管理、监控。
3. Runtime Layer：进程、输出、资源、Workspace。
4. Platform Layer：OS 原生隔离实现。
5. System Layer：操作系统、系统调用及内核机制。

# **NSK Core**

Types · Policy · State · Result · Errors · Capabilities

**Execution Manager**

生命周期及状态管理

**Policy Engine**

策略验证及规范化

**Supervisor**

进程执行及终止

**Resource Controller**

资源限制及监控

**Workspace Manager**

文件及执行目录

**Output Collector**

输出采集及限流

**Platform Abstraction Layer**

Provider · Isolation · Process · Resource · Filesystem

**Linux Provider**

Namespaces / cgroups / seccomp

**Windows Provider**

Job / Token / AppContainer

**macOS Provider**

Validated OS isolation mechanisms

**Operating System**

Kernel · Filesystem · Process · Memory · Network

## **3.2 模块职责**

| 模块                  | 职责               |
| ------------------- | ---------------- |
| Core                | 基础类型、错误、状态、能力    |
| Policy Engine       | 策略校验、规范化、能力匹配    |
| Execution Manager   | 创建、启动、停止及状态管理    |
| Supervisor          | 进程管理、监控、终止       |
| Resource Controller | CPU、内存、PID 等资源控制 |
| Workspace Manager   | 文件系统及工作目录隔离      |
| Output Collector    | 输出采集、缓冲、限流       |
| Scheduler           | 内核级并发控制与资源预算     |
| Provider            | 平台原生隔离机制适配       |
| Diagnostics         | 环境检测、诊断及能力报告     |
| Cleanup Manager     | 资源回收与异常恢复        |

# **四、核心执行模型**

## **4.1 Sandbox Execution Unit**

内核的基本执行单位是 Sandbox Instance。

一个 Sandbox Instance 代表一次受策略控制的执行环境，包含：

- 唯一 ID。
- 执行命令。
- 参数。
- 工作目录。
- 环境变量。
- 执行策略。
- 进程或进程集合。
- OS 隔离资源。
- 资源监控状态。
- 执行结果。
- 清理状态。

每个 Sandbox Instance 必须独立管理。

**Sandbox Instance**

Identity

Sandbox ID · Created At · State

Execution

Executable · Args · Stdin · Environment

Isolation

Namespaces · Filesystem · Network · Security

Resources

CPU · Memory · PID · Output · Disk · Time

Runtime

Process · Monitor · Events · Cancellation

Result

Exit · Status · Usage · Output · Diagnostics

## **4.2 执行生命周期**

\#chatgpt-mermaid-\_r_9t9\_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;fill:rgb(13, 13, 13);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-\_r_9t9\_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_9t9\_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_9t9\_ .error-icon{fill:rgb(243, 243, 243);}#chatgpt-mermaid-\_r_9t9\_ .error-text{fill:rgb(13, 13, 13);stroke:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_9t9\_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-\_r_9t9\_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-\_r_9t9\_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-\_r_9t9\_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-\_r_9t9\_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-\_r_9t9\_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-\_r_9t9\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_9t9\_ .marker.cross{stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_9t9\_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;}#chatgpt-mermaid-\_r_9t9\_ p{margin:0;}#chatgpt-mermaid-\_r_9t9\_ defs [id$="-barbEnd"]{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_9t9\_ g.stateGroup text{fill:rgb(83, 154, 248);stroke:none;font-size:10px;}#chatgpt-mermaid-\_r_9t9\_ g.stateGroup text{fill:rgb(13, 13, 13);stroke:none;font-size:10px;}#chatgpt-mermaid-\_r_9t9\_ g.stateGroup .state-title{font-weight:bolder;fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_9t9\_ g.stateGroup rect{fill:rgb(222, 234, 251);stroke:rgb(83, 154, 248);}#chatgpt-mermaid-\_r_9t9\_ g.stateGroup line{stroke:rgb(143, 143, 143);stroke-width:1;}#chatgpt-mermaid-\_r_9t9\_ .transition{stroke:rgb(143, 143, 143);stroke-width:1;fill:none;}#chatgpt-mermaid-\_r_9t9\_ .stateGroup .composit{fill:transparent;border-bottom:1px;}#chatgpt-mermaid-\_r_9t9\_ .stateGroup .alt-composit{fill:#e0e0e0;border-bottom:1px;}#chatgpt-mermaid-\_r_9t9\_ .state-note{stroke:rgb(107, 198, 127);fill:rgb(243, 243, 243);}#chatgpt-mermaid-\_r_9t9\_ .state-note text{fill:rgb(13, 13, 13);stroke:none;font-size:10px;}#chatgpt-mermaid-\_r_9t9\_ .stateLabel .box{stroke:none;stroke-width:0;fill:rgb(222, 234, 251);opacity:0.5;}#chatgpt-mermaid-\_r_9t9\_ .edgeLabel .label rect{fill:rgb(222, 234, 251);opacity:0.5;}#chatgpt-mermaid-\_r_9t9\_ .edgeLabel{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_9t9\_ .edgeLabel p{background-color:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_9t9\_ .edgeLabel rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_9t9\_ .edgeLabel .label text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_9t9\_ .label div .edgeLabel{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_9t9\_ .stateLabel text{fill:rgb(13, 13, 13);font-size:10px;font-weight:bold;}#chatgpt-mermaid-\_r_9t9\_ .node circle.state-start{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_9t9\_ .node .fork-join{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_9t9\_ .node circle.state-end{fill:rgb(83, 154, 248);stroke:transparent;stroke-width:1.5;}#chatgpt-mermaid-\_r_9t9\_ .end-state-inner{fill:transparent;stroke-width:1.5;}#chatgpt-mermaid-\_r_9t9\_ .node rect{fill:rgb(222, 234, 251);stroke:rgb(83, 154, 248);stroke-width:1px;}#chatgpt-mermaid-\_r_9t9\_ .node polygon{fill:rgb(222, 234, 251);stroke:rgb(83, 154, 248);stroke-width:1px;}#chatgpt-mermaid-\_r_9t9\_ [id$="-barbEnd"]{fill:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_9t9\_ .statediagram-cluster rect{fill:rgb(222, 234, 251);stroke:rgb(83, 154, 248);stroke-width:1px;}#chatgpt-mermaid-\_r_9t9\_ .cluster-label,#chatgpt-mermaid-\_r_9t9\_ .nodeLabel{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_9t9\_ .statediagram-cluster rect.outer{rx:5px;ry:5px;}#chatgpt-mermaid-\_r_9t9\_ .statediagram-state .divider{stroke:rgb(83, 154, 248);}#chatgpt-mermaid-\_r_9t9\_ .statediagram-state .title-state{rx:5px;ry:5px;}#chatgpt-mermaid-\_r_9t9\_ .statediagram-cluster.statediagram-cluster .inner{fill:transparent;}#chatgpt-mermaid-\_r_9t9\_ .statediagram-cluster.statediagram-cluster-alt .inner{fill:rgb(243, 243, 243);}#chatgpt-mermaid-\_r_9t9\_ .statediagram-cluster .inner{rx:0;ry:0;}#chatgpt-mermaid-\_r_9t9\_ .statediagram-state rect.basic{rx:5px;ry:5px;}#chatgpt-mermaid-\_r_9t9\_ .statediagram-state rect.divider{stroke-dasharray:10,10;fill:rgb(243, 243, 243);}#chatgpt-mermaid-\_r_9t9\_ .note-edge{stroke-dasharray:5;}#chatgpt-mermaid-\_r_9t9\_ .statediagram-note rect{fill:rgb(243, 243, 243);stroke:rgb(107, 198, 127);stroke-width:1px;rx:0;ry:0;}#chatgpt-mermaid-\_r_9t9\_ .statediagram-note rect{fill:rgb(243, 243, 243);stroke:rgb(107, 198, 127);stroke-width:1px;rx:0;ry:0;}#chatgpt-mermaid-\_r_9t9\_ .statediagram-note text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_9t9\_ .statediagram-note .nodeLabel{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_9t9\_ .statediagram .edgeLabel{color:red;}#chatgpt-mermaid-\_r_9t9\_ [id$="-dependencyStart"],#chatgpt-mermaid-\_r_9t9\_ [id$="-dependencyEnd"]{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);stroke-width:1;}#chatgpt-mermaid-\_r_9t9\_ .statediagramTitleText{text-anchor:middle;font-size:18px;fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].statediagram-cluster rect{fill:rgb(222, 234, 251);stroke:url(#chatgpt-mermaid-\_r_9t9\_-gradient);stroke-width:1;}#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].statediagram-cluster rect.outer{rx:5px;ry:5px;filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_9t9\_ .node .neo-node{stroke:rgb(83, 154, 248);}#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].node rect,#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].cluster rect,#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-\_r_9t9\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-\_r_9t9\_-gradient);stroke-width:1px;}#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].node .neo-line path{stroke:rgb(83, 154, 248);filter:none;}#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-\_r_9t9\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-\_r_9t9\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_9t9\_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-\_r_9t9\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_9t9\_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";}CreatedValidatingPreparingReadyStartingRunningCollectingTerminatingCleaningCompletedFailedProcess exitsCancel / Limit / Timeout

### **状态说明**

| 状态          | 含义         |
| ----------- | ---------- |
| Created     | 已创建执行实例    |
| Validating  | 校验执行参数及策略  |
| Preparing   | 创建隔离环境及资源  |
| Ready       | 环境准备完成     |
| Starting    | 正在启动       |
| Running     | 程序执行中      |
| Terminating | 正在终止       |
| Collecting  | 收集执行结果     |
| Cleaning    | 清理资源       |
| Completed   | 完成         |
| Failed      | 执行过程中的内核错误 |

## **4.3 生命周期管理规则**

- 一个 Sandbox 只能由 Manager 管理状态。
- Provider 不允许直接修改全局状态。
- 每个 Sandbox 必须有明确的终止路径。
- 终止路径必须能够处理进程、资源和 Workspace。
- 状态转换必须经过验证。
- Cleanup 必须具有幂等性。
- Cleanup 失败必须记录并保留可诊断信息。
- Sandbox 不允许未经管理的后台资源遗留。
- 执行结果收集应与清理协调，避免资源回收失败导致结果丢失。

# **五、核心 Rust 类型设计**

## **5.1 Sandbox ID**

```
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SandboxId(Uuid);

impl SandboxId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}
```

## **5.2 Sandbox Specification**

```
pub struct SandboxSpec {
    pub id: SandboxId,

    pub command: CommandSpec,

    pub workspace: WorkspaceSpec,

    pub environment: EnvironmentSpec,

    pub policy: SandboxPolicy,
}
```

## **5.3 CommandSpec**

```
use std::ffi::OsString;
use std::path::PathBuf;

pub struct CommandSpec {
    pub executable: PathBuf,

    pub args: Vec<OsString>,

    pub working_directory: PathBuf,

    pub stdin: StdinSpec,
}
```

执行命令必须采用程序路径与参数分离的方式。

不应默认使用 Shell 执行用户提供的命令字符串。

```
pub enum StdinSpec {
    Closed,

    Bytes(Vec<u8>),
}
```

第一阶段不实现交互式终端（PTY）。

## **5.4 EnvironmentSpec**

```
pub struct EnvironmentSpec {
    pub variables: Vec<EnvironmentVariable>,
}

pub struct EnvironmentVariable {
    pub key: String,

    pub value: String,
}
```

环境变量默认采用显式白名单。

不继承宿主机完整环境。

## **5.5 WorkspaceSpec**

```
pub struct WorkspaceSpec {
    pub root: PathBuf,

    pub writable_paths: Vec<PathBuf>,

    pub readonly_paths: Vec<PathBuf>,

    pub cleanup_on_exit: bool,
}
```

## **5.6 SandboxPolicy**

```
pub struct SandboxPolicy {
    pub isolation: IsolationPolicy,

    pub resources: ResourceLimits,

    pub filesystem: FilesystemPolicy,

    pub network: NetworkPolicy,

    pub security: SecurityPolicy,

    pub process: ProcessPolicy,

    pub output: OutputPolicy,
}
```

### **IsolationPolicy**

```
pub struct IsolationPolicy {
    pub isolate_process: bool,

    pub isolate_filesystem: bool,

    pub isolate_network: bool,

    pub isolate_ipc: bool,

    pub isolate_uts: bool,
}
```

### **FilesystemPolicy**

```
pub struct FilesystemPolicy {
    pub readonly_paths: Vec<PathBuf>,

    pub writable_paths: Vec<PathBuf>,

    pub deny_host_paths: bool,

    pub isolate_root: bool,
}
```

### **NetworkPolicy**

```
pub enum NetworkPolicy {
    Disabled,

    LoopbackOnly,

    Restricted,

    AllowAll,
}
```

### **SecurityPolicy**

```
pub struct SecurityPolicy {
    pub drop_privileges: bool,

    pub no_new_privileges: bool,

    pub use_seccomp: bool,

    pub require_seccomp: bool,

    pub require_user_namespace: bool,

    pub require_cgroup: bool,
}
```

### **ProcessPolicy**

```
pub struct ProcessPolicy {
    pub max_processes: u32,

    pub kill_process_tree: bool,

    pub allow_daemonize: bool,
}
```

### **OutputPolicy**

```
pub struct OutputPolicy {
    pub max_stdout_bytes: u64,

    pub max_stderr_bytes: u64,

    pub combined_limit_bytes: u64,

    pub terminate_on_limit: bool,
}
```

## **5.7 ResourceLimits**

```
use std::time::Duration;

pub struct ResourceLimits {
    pub wall_time: Duration,

    pub cpu_time: Option<Duration>,

    pub cpu_quota: Option<CpuQuota>,

    pub memory_bytes: u64,

    pub swap_bytes: Option<u64>,

    pub max_processes: u32,

    pub max_open_files: u64,

    pub max_file_size_bytes: u64,

    pub max_disk_bytes: u64,

    pub max_output_bytes: u64,
}

pub struct CpuQuota {
    pub cores: f64,
}
```

不同 OS Provider 可能无法实现完全一致的限制语义，因此资源限制必须支持：

- Requested Limits。
- Effective Limits。
- Unsupported Limits。
- Failed Limits。
- Observed Usage。

## **5.8 SandboxResult**

```
pub struct SandboxResult {
    pub id: SandboxId,

    pub status: SandboxStatus,

    pub exit_info: Option<ExitInfo>,

    pub resource_usage: ResourceUsage,

    pub output: OutputResult,

    pub diagnostics: Vec<Diagnostic>,
}
```

## **5.9 SandboxStatus**

```
pub enum SandboxStatus {
    Success,

    NonZeroExit,

    TimeLimitExceeded,

    CpuLimitExceeded,

    MemoryLimitExceeded,

    ProcessLimitExceeded,

    OutputLimitExceeded,

    DiskLimitExceeded,

    Cancelled,

    SpawnFailed,

    IsolationFailed,

    ResourceLimitUnavailable,

    InternalError,
}
```

# **六、Policy Engine**

## **6.1 职责**

Policy Engine 是内核安全配置的入口。

负责：

- Policy Validation。
- Policy Normalization。
- 安全默认值。
- Policy Capability Matching。
- Policy Conflict Detection。
- Policy Limit Validation。
- Policy Effective Configuration。
- Policy Diagnostics。

## **6.2 Policy Pipeline**

\#chatgpt-mermaid-\_r_a00\_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;fill:rgb(13, 13, 13);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-\_r_a00\_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_a00\_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_a00\_ .error-icon{fill:rgb(243, 243, 243);}#chatgpt-mermaid-\_r_a00\_ .error-text{fill:rgb(13, 13, 13);stroke:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a00\_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-\_r_a00\_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-\_r_a00\_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-\_r_a00\_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-\_r_a00\_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-\_r_a00\_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-\_r_a00\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a00\_ .marker.cross{stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a00\_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;}#chatgpt-mermaid-\_r_a00\_ p{margin:0;}#chatgpt-mermaid-\_r_a00\_ .label{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a00\_ .cluster-label text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a00\_ .cluster-label span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a00\_ .cluster-label span p{background-color:transparent;}#chatgpt-mermaid-\_r_a00\_ .label text,#chatgpt-mermaid-\_r_a00\_ span{fill:rgb(13, 13, 13);color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a00\_ .node rect,#chatgpt-mermaid-\_r_a00\_ .node circle,#chatgpt-mermaid-\_r_a00\_ .node ellipse,#chatgpt-mermaid-\_r_a00\_ .node polygon,#chatgpt-mermaid-\_r_a00\_ .node path{fill:rgb(222, 234, 251);stroke:rgb(83, 154, 248);stroke-width:1px;}#chatgpt-mermaid-\_r_a00\_ .rough-node .label text,#chatgpt-mermaid-\_r_a00\_ .node .label text,#chatgpt-mermaid-\_r_a00\_ .image-shape .label,#chatgpt-mermaid-\_r_a00\_ .icon-shape .label{text-anchor:middle;}#chatgpt-mermaid-\_r_a00\_ .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#chatgpt-mermaid-\_r_a00\_ .rough-node .label,#chatgpt-mermaid-\_r_a00\_ .node .label,#chatgpt-mermaid-\_r_a00\_ .image-shape .label,#chatgpt-mermaid-\_r_a00\_ .icon-shape .label{text-align:center;}#chatgpt-mermaid-\_r_a00\_ .node.clickable{cursor:pointer;}#chatgpt-mermaid-\_r_a00\_ .root .anchor path{fill:rgb(143, 143, 143)!important;stroke-width:0;stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a00\_ .arrowheadPath{fill:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a00\_ .edgePath .path{stroke:rgb(143, 143, 143);stroke-width:1px;}#chatgpt-mermaid-\_r_a00\_ .flowchart-link{stroke:rgb(143, 143, 143);fill:none;}#chatgpt-mermaid-\_r_a00\_ .edgeLabel{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_a00\_ .edgeLabel p{background-color:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a00\_ .edgeLabel rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a00\_ .labelBkg{background-color:rgba(252, 252, 252, 0.5);}#chatgpt-mermaid-\_r_a00\_ .cluster rect{fill:rgb(243, 243, 243);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_a00\_ .cluster text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a00\_ .cluster span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a00\_ div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:12px;background:rgb(243, 243, 243);border:1px solid rgba(0, 0, 0, 0.1);border-radius:2px;pointer-events:none;z-index:100;}#chatgpt-mermaid-\_r_a00\_ .flowchartTitleText{text-anchor:middle;font-size:18px;fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a00\_ rect.text{fill:none;stroke-width:0;}#chatgpt-mermaid-\_r_a00\_ .icon-shape,#chatgpt-mermaid-\_r_a00\_ .image-shape{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_a00\_ .icon-shape p,#chatgpt-mermaid-\_r_a00\_ .image-shape p{background-color:rgb(252, 252, 252);padding:2px;}#chatgpt-mermaid-\_r_a00\_ .icon-shape .label rect,#chatgpt-mermaid-\_r_a00\_ .image-shape .label rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a00\_ .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#chatgpt-mermaid-\_r_a00\_ .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#chatgpt-mermaid-\_r_a00\_ .node .neo-node{stroke:rgb(83, 154, 248);}#chatgpt-mermaid-\_r_a00\_ [data-look="neo"].node rect,#chatgpt-mermaid-\_r_a00\_ [data-look="neo"].cluster rect,#chatgpt-mermaid-\_r_a00\_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-\_r_a00\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a00\_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-\_r_a00\_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-\_r_a00\_-gradient);stroke-width:1px;}#chatgpt-mermaid-\_r_a00\_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a00\_ [data-look="neo"].node .neo-line path{stroke:rgb(83, 154, 248);filter:none;}#chatgpt-mermaid-\_r_a00\_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-\_r_a00\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a00\_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-\_r_a00\_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-\_r_a00\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a00\_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-\_r_a00\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a00\_ .node text{font-size:14px;font-weight:600;letter-spacing:normal;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_a00\_ .edgeLabels text{font-size:13px;font-weight:600;letter-spacing:-0.08px;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_a00\_ .node tspan[font-weight="normal"],#chatgpt-mermaid-\_r_a00\_ .edgeLabels tspan[font-weight="normal"]{font-weight:600;}#chatgpt-mermaid-\_r_a00\_ .edgeLabel .label rect{opacity:1;rx:13px;ry:13px;fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-width:1px;}#chatgpt-mermaid-\_r_a00\_ .node rect,#chatgpt-mermaid-\_r_a00\_ .node circle,#chatgpt-mermaid-\_r_a00\_ .node ellipse,#chatgpt-mermaid-\_r_a00\_ .node polygon,#chatgpt-mermaid-\_r_a00\_ .node path{fill:rgb(229, 243, 255);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_a00\_ .node rect{rx:16px;ry:16px;}#chatgpt-mermaid-\_r_a00\_ .mermaid-decision .label-container{fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-dasharray:2,2;}#chatgpt-mermaid-\_r_a00\_ .edgePaths .flowchart-link{stroke:rgb(143, 143, 143);stroke-width:1px;stroke-linecap:round;stroke-linejoin:round;}#chatgpt-mermaid-\_r_a00\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a00\_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";}SandboxSpecStructural ValidationSecurity ValidationPath ValidationResource ValidationCapability MatchingPolicy NormalizationEffective PolicyProvider Preparation

## **6.3 Policy 校验规则**

### **基础规则**

- Executable 必须合法。
- 参数不得非法转换为 Shell 命令。
- Workspace 必须符合安全边界。
- 环境变量必须经过校验。
- 资源限制必须合法。
- 输出限制必须合法。
- 网络策略必须明确。
- 不允许无效的资源配置。

### **路径规则**

- 不接受未验证的路径。
- 不允许路径越界。
- 不允许通过 Symlink 绕过策略。
- 不允许任意宿主机路径。
- 不允许挂载敏感文件。
- 路径访问规则必须基于实际路径和文件系统语义验证，而非简单字符串比较。

### **能力规则**

如果 Policy 要求：

```
Memory Limit = 256 MiB
Network Isolation = Required
Filesystem Isolation = Required
PID Isolation = Required
```

但当前 Provider 无法实现其中某项，则必须返回能力不足。

不能默默忽略。

## **6.4 Effective Policy**

内核应该记录实际应用的策略：

```
pub struct EffectivePolicy {
    pub requested: SandboxPolicy,

    pub applied: AppliedPolicy,

    pub capabilities: PlatformCapabilities,

    pub limitations: Vec<Diagnostic>,
}
```

这样可以避免将用户请求的限制误认为已实际生效的限制。

# **七、Resource Controller**

## **7.1 资源管理目标**

Resource Controller 的职责是控制和监控 Sandbox 所消耗的系统资源。

| 资源         | 控制目标        |
| ---------- | ----------- |
| Wall Time  | 控制执行持续时间    |
| CPU Time   | 控制 CPU 使用时间 |
| CPU Quota  | 限制 CPU 使用率  |
| Memory     | 限制内存        |
| Swap       | 限制交换空间使用    |
| PID        | 限制进程及线程资源   |
| Open Files | 限制文件描述符     |
| File Size  | 限制文件大小      |
| Disk       | 限制执行目录空间    |
| stdout     | 限制输出        |
| stderr     | 限制输出        |
| I/O        | 可选控制 I/O    |
| Network    | 控制网络访问能力    |

## **7.2 Resource Monitor**

```
pub struct ResourceUsage {
    pub wall_time: Duration,

    pub cpu_time: Option<Duration>,

    pub memory_current_bytes: Option<u64>,

    pub memory_peak_bytes: Option<u64>,

    pub process_count: Option<u32>,

    pub stdout_bytes: u64,

    pub stderr_bytes: u64,

    pub disk_usage_bytes: Option<u64>,
}
```

## **7.3 Resource Controller 模块**

```
Resource Controller
├── Limit Manager
├── CPU Monitor
├── Memory Monitor
├── PID Monitor
├── Disk Monitor
├── Output Monitor
├── Usage Accounting
└── Limit Enforcement
```

## **7.4 资源限制策略**

内核必须区分：

- 限制是否成功应用。
- 当前使用量。
- 峰值使用量。
- 超限事件。
- 资源回收情况。

资源监控不能代替资源强制限制。

例如：

- 目录大小扫描不是硬磁盘限额。
- Wall Time 不是 CPU Time。
- CPU Quota 不是 CPU Time。
- `Child::kill()` 不是进程树终止。
- 进程退出码不能单独证明是否发生 OOM。

# **八、Supervisor**

## **8.1 Supervisor 定位**

Supervisor 是 Sandbox Execution Unit 的运行时控制组件。

它负责：

- 进程启动。
- 进程监控。
- Stdin。
- Stdout。
- Stderr。
- Wall Time。
- Cancellation。
- Resource Monitoring。
- Limit Enforcement。
- Process Termination。
- Exit Collection。

## **8.2 Supervisor 模块**

```
Supervisor
├── Process Manager
├── Process Monitor
├── Output Collector
├── Stdin Controller
├── Timer
├── Cancellation
├── Resource Monitor
├── Termination Controller
└── Exit Collector
```

## **8.3 进程生命周期**

\#chatgpt-mermaid-\_r_a0t\_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;fill:rgb(13, 13, 13);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-\_r_a0t\_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_a0t\_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_a0t\_ .error-icon{fill:rgb(243, 243, 243);}#chatgpt-mermaid-\_r_a0t\_ .error-text{fill:rgb(13, 13, 13);stroke:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a0t\_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-\_r_a0t\_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-\_r_a0t\_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-\_r_a0t\_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-\_r_a0t\_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-\_r_a0t\_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-\_r_a0t\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a0t\_ .marker.cross{stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a0t\_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;}#chatgpt-mermaid-\_r_a0t\_ p{margin:0;}#chatgpt-mermaid-\_r_a0t\_ .label{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a0t\_ .cluster-label text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a0t\_ .cluster-label span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a0t\_ .cluster-label span p{background-color:transparent;}#chatgpt-mermaid-\_r_a0t\_ .label text,#chatgpt-mermaid-\_r_a0t\_ span{fill:rgb(13, 13, 13);color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a0t\_ .node rect,#chatgpt-mermaid-\_r_a0t\_ .node circle,#chatgpt-mermaid-\_r_a0t\_ .node ellipse,#chatgpt-mermaid-\_r_a0t\_ .node polygon,#chatgpt-mermaid-\_r_a0t\_ .node path{fill:rgb(222, 234, 251);stroke:rgb(83, 154, 248);stroke-width:1px;}#chatgpt-mermaid-\_r_a0t\_ .rough-node .label text,#chatgpt-mermaid-\_r_a0t\_ .node .label text,#chatgpt-mermaid-\_r_a0t\_ .image-shape .label,#chatgpt-mermaid-\_r_a0t\_ .icon-shape .label{text-anchor:middle;}#chatgpt-mermaid-\_r_a0t\_ .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#chatgpt-mermaid-\_r_a0t\_ .rough-node .label,#chatgpt-mermaid-\_r_a0t\_ .node .label,#chatgpt-mermaid-\_r_a0t\_ .image-shape .label,#chatgpt-mermaid-\_r_a0t\_ .icon-shape .label{text-align:center;}#chatgpt-mermaid-\_r_a0t\_ .node.clickable{cursor:pointer;}#chatgpt-mermaid-\_r_a0t\_ .root .anchor path{fill:rgb(143, 143, 143)!important;stroke-width:0;stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a0t\_ .arrowheadPath{fill:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a0t\_ .edgePath .path{stroke:rgb(143, 143, 143);stroke-width:1px;}#chatgpt-mermaid-\_r_a0t\_ .flowchart-link{stroke:rgb(143, 143, 143);fill:none;}#chatgpt-mermaid-\_r_a0t\_ .edgeLabel{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_a0t\_ .edgeLabel p{background-color:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a0t\_ .edgeLabel rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a0t\_ .labelBkg{background-color:rgba(252, 252, 252, 0.5);}#chatgpt-mermaid-\_r_a0t\_ .cluster rect{fill:rgb(243, 243, 243);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_a0t\_ .cluster text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a0t\_ .cluster span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a0t\_ div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:12px;background:rgb(243, 243, 243);border:1px solid rgba(0, 0, 0, 0.1);border-radius:2px;pointer-events:none;z-index:100;}#chatgpt-mermaid-\_r_a0t\_ .flowchartTitleText{text-anchor:middle;font-size:18px;fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a0t\_ rect.text{fill:none;stroke-width:0;}#chatgpt-mermaid-\_r_a0t\_ .icon-shape,#chatgpt-mermaid-\_r_a0t\_ .image-shape{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_a0t\_ .icon-shape p,#chatgpt-mermaid-\_r_a0t\_ .image-shape p{background-color:rgb(252, 252, 252);padding:2px;}#chatgpt-mermaid-\_r_a0t\_ .icon-shape .label rect,#chatgpt-mermaid-\_r_a0t\_ .image-shape .label rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a0t\_ .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#chatgpt-mermaid-\_r_a0t\_ .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#chatgpt-mermaid-\_r_a0t\_ .node .neo-node{stroke:rgb(83, 154, 248);}#chatgpt-mermaid-\_r_a0t\_ [data-look="neo"].node rect,#chatgpt-mermaid-\_r_a0t\_ [data-look="neo"].cluster rect,#chatgpt-mermaid-\_r_a0t\_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-\_r_a0t\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a0t\_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-\_r_a0t\_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-\_r_a0t\_-gradient);stroke-width:1px;}#chatgpt-mermaid-\_r_a0t\_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a0t\_ [data-look="neo"].node .neo-line path{stroke:rgb(83, 154, 248);filter:none;}#chatgpt-mermaid-\_r_a0t\_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-\_r_a0t\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a0t\_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-\_r_a0t\_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-\_r_a0t\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a0t\_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-\_r_a0t\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a0t\_ .node text{font-size:14px;font-weight:600;letter-spacing:normal;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_a0t\_ .edgeLabels text{font-size:13px;font-weight:600;letter-spacing:-0.08px;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_a0t\_ .node tspan[font-weight="normal"],#chatgpt-mermaid-\_r_a0t\_ .edgeLabels tspan[font-weight="normal"]{font-weight:600;}#chatgpt-mermaid-\_r_a0t\_ .edgeLabel .label rect{opacity:1;rx:13px;ry:13px;fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-width:1px;}#chatgpt-mermaid-\_r_a0t\_ .node rect,#chatgpt-mermaid-\_r_a0t\_ .node circle,#chatgpt-mermaid-\_r_a0t\_ .node ellipse,#chatgpt-mermaid-\_r_a0t\_ .node polygon,#chatgpt-mermaid-\_r_a0t\_ .node path{fill:rgb(229, 243, 255);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_a0t\_ .node rect{rx:16px;ry:16px;}#chatgpt-mermaid-\_r_a0t\_ .mermaid-decision .label-container{fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-dasharray:2,2;}#chatgpt-mermaid-\_r_a0t\_ .edgePaths .flowchart-link{stroke:rgb(143, 143, 143);stroke-width:1px;stroke-linecap:round;stroke-linejoin:round;}#chatgpt-mermaid-\_r_a0t\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a0t\_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";}Prepare ProcessAttach Isolation ResourcesSpawnMonitorTermination ConditionCollect ExitTerminate SandboxConfirm Process CleanupCollect UsageCleanupNormal ExitTimeoutResource LimitCancel

## **8.4 终止机制**

Supervisor 应能够：

- 终止整个 Sandbox。
- 终止所有相关进程。
- 处理正常退出。
- 处理异常退出。
- 处理超时。
- 处理取消。
- 处理资源超限。
- 处理进程残留。
- 处理 Cleanup Failure。

Linux 应以 cgroup 作为主要进程集合管理机制，Process Group 作为辅助机制。

Windows 应以 Job Object 为主要进程集合管理机制。

macOS 应根据实际验证过的机制实现进程集合管理。

## **8.5 输出采集**

```
Process stdout/stderr
        ↓
Async Reader
        ↓
Bounded Output Collector
        ↓
Byte Counter
        ↓
Policy Enforcement
        ↓
Buffer / Event
```

要求：

- 流式读取。
- 有界缓冲。
- 不允许无限内存增长。
- 超限可终止。
- 支持截断。
- 支持独立 stdout/stderr。
- 支持 combined limit。
- 监控输出速率。
- 避免事件队列无限增长。

# **九、Platform Provider**

## **9.1 Provider 架构**

Platform Provider 是内核与操作系统安全机制之间的适配层。

它不应承担业务逻辑，也不应直接决定执行策略。

它负责将 Effective Policy 转换成 OS-specific execution plan。

\#chatgpt-mermaid-\_r_a18\_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;fill:rgb(13, 13, 13);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-\_r_a18\_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_a18\_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_a18\_ .error-icon{fill:rgb(243, 243, 243);}#chatgpt-mermaid-\_r_a18\_ .error-text{fill:rgb(13, 13, 13);stroke:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a18\_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-\_r_a18\_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-\_r_a18\_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-\_r_a18\_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-\_r_a18\_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-\_r_a18\_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-\_r_a18\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a18\_ .marker.cross{stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a18\_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;}#chatgpt-mermaid-\_r_a18\_ p{margin:0;}#chatgpt-mermaid-\_r_a18\_ .label{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a18\_ .cluster-label text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a18\_ .cluster-label span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a18\_ .cluster-label span p{background-color:transparent;}#chatgpt-mermaid-\_r_a18\_ .label text,#chatgpt-mermaid-\_r_a18\_ span{fill:rgb(13, 13, 13);color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a18\_ .node rect,#chatgpt-mermaid-\_r_a18\_ .node circle,#chatgpt-mermaid-\_r_a18\_ .node ellipse,#chatgpt-mermaid-\_r_a18\_ .node polygon,#chatgpt-mermaid-\_r_a18\_ .node path{fill:rgb(222, 234, 251);stroke:rgb(83, 154, 248);stroke-width:1px;}#chatgpt-mermaid-\_r_a18\_ .rough-node .label text,#chatgpt-mermaid-\_r_a18\_ .node .label text,#chatgpt-mermaid-\_r_a18\_ .image-shape .label,#chatgpt-mermaid-\_r_a18\_ .icon-shape .label{text-anchor:middle;}#chatgpt-mermaid-\_r_a18\_ .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#chatgpt-mermaid-\_r_a18\_ .rough-node .label,#chatgpt-mermaid-\_r_a18\_ .node .label,#chatgpt-mermaid-\_r_a18\_ .image-shape .label,#chatgpt-mermaid-\_r_a18\_ .icon-shape .label{text-align:center;}#chatgpt-mermaid-\_r_a18\_ .node.clickable{cursor:pointer;}#chatgpt-mermaid-\_r_a18\_ .root .anchor path{fill:rgb(143, 143, 143)!important;stroke-width:0;stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a18\_ .arrowheadPath{fill:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a18\_ .edgePath .path{stroke:rgb(143, 143, 143);stroke-width:1px;}#chatgpt-mermaid-\_r_a18\_ .flowchart-link{stroke:rgb(143, 143, 143);fill:none;}#chatgpt-mermaid-\_r_a18\_ .edgeLabel{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_a18\_ .edgeLabel p{background-color:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a18\_ .edgeLabel rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a18\_ .labelBkg{background-color:rgba(252, 252, 252, 0.5);}#chatgpt-mermaid-\_r_a18\_ .cluster rect{fill:rgb(243, 243, 243);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_a18\_ .cluster text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a18\_ .cluster span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a18\_ div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:12px;background:rgb(243, 243, 243);border:1px solid rgba(0, 0, 0, 0.1);border-radius:2px;pointer-events:none;z-index:100;}#chatgpt-mermaid-\_r_a18\_ .flowchartTitleText{text-anchor:middle;font-size:18px;fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a18\_ rect.text{fill:none;stroke-width:0;}#chatgpt-mermaid-\_r_a18\_ .icon-shape,#chatgpt-mermaid-\_r_a18\_ .image-shape{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_a18\_ .icon-shape p,#chatgpt-mermaid-\_r_a18\_ .image-shape p{background-color:rgb(252, 252, 252);padding:2px;}#chatgpt-mermaid-\_r_a18\_ .icon-shape .label rect,#chatgpt-mermaid-\_r_a18\_ .image-shape .label rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a18\_ .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#chatgpt-mermaid-\_r_a18\_ .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#chatgpt-mermaid-\_r_a18\_ .node .neo-node{stroke:rgb(83, 154, 248);}#chatgpt-mermaid-\_r_a18\_ [data-look="neo"].node rect,#chatgpt-mermaid-\_r_a18\_ [data-look="neo"].cluster rect,#chatgpt-mermaid-\_r_a18\_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-\_r_a18\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a18\_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-\_r_a18\_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-\_r_a18\_-gradient);stroke-width:1px;}#chatgpt-mermaid-\_r_a18\_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a18\_ [data-look="neo"].node .neo-line path{stroke:rgb(83, 154, 248);filter:none;}#chatgpt-mermaid-\_r_a18\_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-\_r_a18\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a18\_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-\_r_a18\_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-\_r_a18\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a18\_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-\_r_a18\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a18\_ .node text{font-size:14px;font-weight:600;letter-spacing:normal;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_a18\_ .edgeLabels text{font-size:13px;font-weight:600;letter-spacing:-0.08px;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_a18\_ .node tspan[font-weight="normal"],#chatgpt-mermaid-\_r_a18\_ .edgeLabels tspan[font-weight="normal"]{font-weight:600;}#chatgpt-mermaid-\_r_a18\_ .edgeLabel .label rect{opacity:1;rx:13px;ry:13px;fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-width:1px;}#chatgpt-mermaid-\_r_a18\_ .node rect,#chatgpt-mermaid-\_r_a18\_ .node circle,#chatgpt-mermaid-\_r_a18\_ .node ellipse,#chatgpt-mermaid-\_r_a18\_ .node polygon,#chatgpt-mermaid-\_r_a18\_ .node path{fill:rgb(229, 243, 255);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_a18\_ .node rect{rx:16px;ry:16px;}#chatgpt-mermaid-\_r_a18\_ .mermaid-decision .label-container{fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-dasharray:2,2;}#chatgpt-mermaid-\_r_a18\_ .edgePaths .flowchart-link{stroke:rgb(143, 143, 143);stroke-width:1px;stroke-linecap:round;stroke-linejoin:round;}#chatgpt-mermaid-\_r_a18\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a18\_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";}Effective PolicyProvider FactoryPlatform ProviderIsolation PlanResource PlanProcess PlanOS Execution

## **9.2 Provider Trait**

```
#[async_trait::async_trait]
pub trait SandboxProvider: Send + Sync {
    async fn probe(
        &self,
    ) -> Result<PlatformCapabilities, SandboxError>;

    async fn prepare(
        &self,
        spec: &SandboxSpec,
        policy: &EffectivePolicy,
    ) -> Result<PreparedSandbox, SandboxError>;

    async fn spawn(
        &self,
        prepared: PreparedSandbox,
    ) -> Result<RunningSandbox, SandboxError>;

    async fn terminate(
        &self,
        sandbox: &RunningSandbox,
    ) -> Result<(), SandboxError>;

    async fn collect(
        &self,
        sandbox: RunningSandbox,
    ) -> Result<SandboxResult, SandboxError>;

    async fn cleanup(
        &self,
        handle: SandboxHandle,
    ) -> Result<(), SandboxError>;
}
```

**Provider Trait 不应把所有操作简单地包装成几个方法。**

正式实现应把资源生命周期拆分成明确的对象，防止资源句柄丢失、跨实例误操作及清理顺序错误。

建议引入：

- `PreparedSandbox`：准备完成的隔离环境。
- `RunningSandbox`：运行中的实例。
- `SandboxHandle`：资源句柄。
- `ProviderSession`：Provider 资源生命周期上下文。

这些类型应通过 Rust 类型系统限制非法状态操作。

## **9.3 PlatformCapabilities**

```
pub struct PlatformCapabilities {
    pub platform: Platform,

    pub isolation: IsolationCapabilities,

    pub resources: ResourceCapabilities,

    pub security: SecurityCapabilities,

    pub diagnostics: Vec<Diagnostic>,
}
```

能力检测应区分：

- Available。
- Unsupported。
- PermissionDenied。
- NotConfigured。
- Failed。
- Unknown。

不要使用简单的 `bool` 表示所有能力。

例如：

```
pub enum CapabilityStatus {
    Available,

    Unsupported,

    PermissionDenied,

    NotConfigured,

    Failed,

    Unknown,
}
```

# **十、Linux Provider 设计**

**第一阶段唯一重点平台：Linux**

Linux Provider 是第一阶段的完整实现目标，其他平台暂不进入正式开发。

## **10.1 Linux 技术方案**

| 机制                   | 技术                | 职责             |
| -------------------- | ----------------- | -------------- |
| User Isolation       | User Namespace    | 用户身份隔离         |
| Process Isolation    | PID Namespace     | 进程隔离           |
| Filesystem Isolation | Mount Namespace   | 文件系统隔离         |
| Network Isolation    | Network Namespace | 网络隔离           |
| IPC Isolation        | IPC Namespace     | IPC 隔离         |
| UTS Isolation        | UTS Namespace     | 主机名隔离          |
| Resource Control     | cgroups v2        | CPU、Memory、PID |
| Syscall Filtering    | seccomp           | 系统调用过滤         |
| Privilege            | No New Privileges | 降低权限提升风险       |
| Process Management   | Linux Process     | 进程执行           |
| Process Group        | Process Group     | 辅助终止机制         |
| Filesystem           | Mount / tmpfs     | 文件系统构建         |
| Startup              | bubblewrap        | 隔离启动           |

## **10.2 Linux Provider 架构**

```
Linux Provider
├── Capability Probe
├── Isolation Planner
├── Bwrap Executor
├── Namespace Manager
├── Mount Manager
├── Network Isolation
├── Cgroup Manager
├── Seccomp Manager
├── Process Manager
├── Resource Monitor
└── Cleanup Manager
```

## **10.3 Capability Probe**

启动或初始化时检测：

- Linux Kernel Version。
- bubblewrap Availability。
- bubblewrap Version。
- User Namespace。
- Mount Namespace。
- PID Namespace。
- Network Namespace。
- IPC Namespace。
- UTS Namespace。
- cgroups v2。
- CPU Controller。
- Memory Controller。
- PID Controller。
- seccomp。
- No New Privileges。
- 当前用户权限。
- cgroup 委托状态。
- 实际可执行的隔离机制。

检测应尽量使用实际能力测试，而不是仅检查系统文件或版本号。

## **10.4 bubblewrap**

第一阶段推荐使用 bubblewrap 作为 Linux 隔离启动器。

Rust 内核负责：

- 生成结构化隔离配置。
- 验证路径。
- 验证策略。
- 生成参数。
- 启动 bwrap。
- 管理生命周期。
- 收集结果。
- 处理错误。
- 清理资源。

bubblewrap 参数只能由内核根据结构化 Policy 生成。

禁止让用户直接传入任意 bwrap 参数。

## **10.5 文件系统隔离**

目标文件系统结构：

```
Sandbox Root
├── /usr        Read-only
├── /bin        Read-only
├── /lib        Read-only
├── /lib64      Read-only
├── /etc        Minimal Read-only
├── /dev        Restricted
├── /proc       Isolated
├── /tmp        Writable
└── /workspace  Writable
```

实际构建必须根据系统发行版、运行环境及所需工具链进行调整。

需要防止：

- 宿主机 Home 暴露。
- 凭证暴露。
- 任意 Host Path。
- Symlink 越界。
- Path Traversal。
- Mount Traversal。
- Host Device 暴露。
- Docker Socket 暴露。
- SSH 文件暴露。
- 任意宿主机用户目录访问。

## **10.6 网络隔离**

默认：

**NetworkPolicy::Disabled**

目标：

- 不允许外部网络访问。
- 不允许宿主机网络访问。
- 不允许局域网访问。
- 不允许外部 DNS。
- 不允许任意网络接口访问。

第一阶段不实现复杂网络代理、流量过滤或动态网络白名单。

## **10.7 cgroups v2**

独立 cgroup：

```
sandbox-cgroups/
└── <sandbox-id>/
    ├── memory.max
    ├── memory.current
    ├── memory.events
    ├── cpu.max
    ├── cpu.stat
    ├── pids.max
    ├── pids.current
    └── cgroup.kill
```

实际可用文件取决于内核、控制器启用状态和配置。

### **Cgroup Manager**

```
pub struct CgroupManager {
    root: PathBuf,
}
```

负责：

- Probe。
- Create。
- Apply Limits。
- Attach。
- Read Metrics。
- Kill。
- Cleanup。

### **内存**

使用：

- `memory.max`
- `memory.current`
- `memory.events`

实现：

- 内存限制。
- 当前内存监控。
- OOM 诊断。
- 峰值使用量记录。

### **CPU**

使用：

- `cpu.max`
- `cpu.stat`

实现：

- CPU Quota。
- CPU 使用量监控。
- CPU 使用时间统计。

### **PID**

使用：

- `pids.max`
- `pids.current`

实现：

- PID 限制。
- 进程数量监控。
- Fork Bomb 防护。

### **Cgroup 安全与权限**

cgroups v2 的可用性不等于用户具有创建和管理 cgroup 的权限。

必须检测：

- Controller 是否启用。
- Controller 是否委托。
- 当前用户是否具有写入权限。
- 是否存在 cgroup 父级限制。
- 是否可应用所要求的限制。
- 是否能够可靠终止 cgroup 中的进程。

如果当前环境不允许应用必须的限制，不能假装资源限制已经生效。

## **10.8 seccomp**

第一阶段：

- 使用经过验证的 seccomp 配置方案。
- 不从零设计复杂通用系统调用允许列表。
- 不接受用户直接输入 seccomp 规则。
- 根据运行环境验证规则兼容性。
- 记录实际应用规则。
- 必要规则失败时拒绝启动。

后续可以按运行环境提供经过测试的 Profile。

## **10.9 Linux 执行流程**

\#chatgpt-mermaid-\_r_a2f\_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;fill:rgb(13, 13, 13);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-\_r_a2f\_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_a2f\_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_a2f\_ .error-icon{fill:rgb(243, 243, 243);}#chatgpt-mermaid-\_r_a2f\_ .error-text{fill:rgb(13, 13, 13);stroke:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a2f\_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-\_r_a2f\_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-\_r_a2f\_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-\_r_a2f\_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-\_r_a2f\_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-\_r_a2f\_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-\_r_a2f\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a2f\_ .marker.cross{stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a2f\_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;}#chatgpt-mermaid-\_r_a2f\_ p{margin:0;}#chatgpt-mermaid-\_r_a2f\_ .label{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a2f\_ .cluster-label text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a2f\_ .cluster-label span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a2f\_ .cluster-label span p{background-color:transparent;}#chatgpt-mermaid-\_r_a2f\_ .label text,#chatgpt-mermaid-\_r_a2f\_ span{fill:rgb(13, 13, 13);color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a2f\_ .node rect,#chatgpt-mermaid-\_r_a2f\_ .node circle,#chatgpt-mermaid-\_r_a2f\_ .node ellipse,#chatgpt-mermaid-\_r_a2f\_ .node polygon,#chatgpt-mermaid-\_r_a2f\_ .node path{fill:rgb(222, 234, 251);stroke:rgb(83, 154, 248);stroke-width:1px;}#chatgpt-mermaid-\_r_a2f\_ .rough-node .label text,#chatgpt-mermaid-\_r_a2f\_ .node .label text,#chatgpt-mermaid-\_r_a2f\_ .image-shape .label,#chatgpt-mermaid-\_r_a2f\_ .icon-shape .label{text-anchor:middle;}#chatgpt-mermaid-\_r_a2f\_ .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#chatgpt-mermaid-\_r_a2f\_ .rough-node .label,#chatgpt-mermaid-\_r_a2f\_ .node .label,#chatgpt-mermaid-\_r_a2f\_ .image-shape .label,#chatgpt-mermaid-\_r_a2f\_ .icon-shape .label{text-align:center;}#chatgpt-mermaid-\_r_a2f\_ .node.clickable{cursor:pointer;}#chatgpt-mermaid-\_r_a2f\_ .root .anchor path{fill:rgb(143, 143, 143)!important;stroke-width:0;stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a2f\_ .arrowheadPath{fill:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a2f\_ .edgePath .path{stroke:rgb(143, 143, 143);stroke-width:1px;}#chatgpt-mermaid-\_r_a2f\_ .flowchart-link{stroke:rgb(143, 143, 143);fill:none;}#chatgpt-mermaid-\_r_a2f\_ .edgeLabel{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_a2f\_ .edgeLabel p{background-color:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a2f\_ .edgeLabel rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a2f\_ .labelBkg{background-color:rgba(252, 252, 252, 0.5);}#chatgpt-mermaid-\_r_a2f\_ .cluster rect{fill:rgb(243, 243, 243);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_a2f\_ .cluster text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a2f\_ .cluster span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a2f\_ div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:12px;background:rgb(243, 243, 243);border:1px solid rgba(0, 0, 0, 0.1);border-radius:2px;pointer-events:none;z-index:100;}#chatgpt-mermaid-\_r_a2f\_ .flowchartTitleText{text-anchor:middle;font-size:18px;fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a2f\_ rect.text{fill:none;stroke-width:0;}#chatgpt-mermaid-\_r_a2f\_ .icon-shape,#chatgpt-mermaid-\_r_a2f\_ .image-shape{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_a2f\_ .icon-shape p,#chatgpt-mermaid-\_r_a2f\_ .image-shape p{background-color:rgb(252, 252, 252);padding:2px;}#chatgpt-mermaid-\_r_a2f\_ .icon-shape .label rect,#chatgpt-mermaid-\_r_a2f\_ .image-shape .label rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a2f\_ .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#chatgpt-mermaid-\_r_a2f\_ .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#chatgpt-mermaid-\_r_a2f\_ .node .neo-node{stroke:rgb(83, 154, 248);}#chatgpt-mermaid-\_r_a2f\_ [data-look="neo"].node rect,#chatgpt-mermaid-\_r_a2f\_ [data-look="neo"].cluster rect,#chatgpt-mermaid-\_r_a2f\_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-\_r_a2f\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a2f\_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-\_r_a2f\_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-\_r_a2f\_-gradient);stroke-width:1px;}#chatgpt-mermaid-\_r_a2f\_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a2f\_ [data-look="neo"].node .neo-line path{stroke:rgb(83, 154, 248);filter:none;}#chatgpt-mermaid-\_r_a2f\_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-\_r_a2f\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a2f\_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-\_r_a2f\_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-\_r_a2f\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a2f\_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-\_r_a2f\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a2f\_ .node text{font-size:14px;font-weight:600;letter-spacing:normal;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_a2f\_ .edgeLabels text{font-size:13px;font-weight:600;letter-spacing:-0.08px;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_a2f\_ .node tspan[font-weight="normal"],#chatgpt-mermaid-\_r_a2f\_ .edgeLabels tspan[font-weight="normal"]{font-weight:600;}#chatgpt-mermaid-\_r_a2f\_ .edgeLabel .label rect{opacity:1;rx:13px;ry:13px;fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-width:1px;}#chatgpt-mermaid-\_r_a2f\_ .node rect,#chatgpt-mermaid-\_r_a2f\_ .node circle,#chatgpt-mermaid-\_r_a2f\_ .node ellipse,#chatgpt-mermaid-\_r_a2f\_ .node polygon,#chatgpt-mermaid-\_r_a2f\_ .node path{fill:rgb(229, 243, 255);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_a2f\_ .node rect{rx:16px;ry:16px;}#chatgpt-mermaid-\_r_a2f\_ .mermaid-decision .label-container{fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-dasharray:2,2;}#chatgpt-mermaid-\_r_a2f\_ .edgePaths .flowchart-link{stroke:rgb(143, 143, 143);stroke-width:1px;stroke-linecap:round;stroke-linejoin:round;}#chatgpt-mermaid-\_r_a2f\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a2f\_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";}Validate SpecValidate PolicyProbe CapabilitiesPrepare WorkspaceCreate CgroupApply Resource LimitsBuild Bwrap ConfigPrepare IsolationSpawn ProcessMonitorExit / Timeout / Limit / CancelTerminateCollect UsageCollect OutputCleanup CgroupCleanup WorkspaceComplete

# **十一、Windows Provider 设计**

**Windows Provider 暂不进入第一阶段正式开发。**

Windows Provider 需要独立设计安全边界，而不是照搬 Linux Namespace。

## **11.1 技术机制**

| 技术               | 职责           |
| ---------------- | ------------ |
| Job Objects      | 进程集合、资源限制及终止 |
| Restricted Token | 降低权限         |
| ACL              | 文件访问控制       |
| AppContainer     | 应用权限隔离       |
| Process Creation | 受控进程创建       |
| Named Pipes      | 可选通信         |

## **11.2 Provider 模块**

```
Windows Provider
├── Capability Probe
├── Process Manager
├── Job Manager
├── Restricted Token Manager
├── AppContainer Manager
├── Filesystem Policy
├── Network Policy
├── Resource Controller
└── Cleanup Manager
```

## **11.3 Job Objects**

负责：

- 进程集合管理。
- 进程树生命周期管理。
- CPU 限制。
- 内存限制。
- 进程数量限制。
- 整体终止。

Job Objects 不提供完整的文件系统和网络隔离。

## **11.4 Restricted Token**

目标：

- 降低执行权限。
- 限制用户权限。
- 禁用不必要的特权。
- 受控进程创建。

## **11.5 AppContainer**

进一步验证：

- 文件访问。
- 网络访问。
- 权限访问。
- 系统资源访问。

必须通过实际安全测试确认隔离边界。

# **十二、macOS Provider 设计**

**macOS Provider 暂不进入第一阶段正式开发。**

## **12.1 设计目标**

- 独立进程。
- 文件系统隔离。
- 网络隔离。
- 权限限制。
- 生命周期管理。
- 资源控制。
- 能力检测。

## **12.2 技术验证方向**

需要评估：

- 系统支持的 Sandbox 机制。
- 公开 API 与非公开 API 的边界。
- 文件访问限制。
- 网络限制。
- 进程管理。
- 资源控制。
- 系统版本兼容性。

不应依赖未经验证的私有 API 作为正式安全边界。

## **12.3 Provider 目标**

```
macOS Provider
├── Capability Probe
├── Process Manager
├── Sandbox Mechanism
├── Filesystem Isolation
├── Network Isolation
├── Resource Monitor
└── Cleanup Manager
```

macOS Provider 的能力必须根据实际验证结果声明，不能假设与 Linux 一致。

# **十三、Rust 工程结构**

## **13.1 项目目录**

```
nsk/
├── Cargo.toml
├── rust-toolchain.toml
├── README.md
├── LICENSE
├── docs/
│   ├── architecture.md
│   ├── security-model.md
│   ├── policy.md
│   ├── lifecycle.md
│   ├── linux-provider.md
│   ├── windows-provider.md
│   ├── macos-provider.md
│   ├── testing.md
│   └── development-plan.md
│
├── crates/
│   ├── nsk-core/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── id.rs
│   │       ├── spec.rs
│   │       ├── policy.rs
│   │       ├── state.rs
│   │       ├── result.rs
│   │       ├── error.rs
│   │       ├── event.rs
│   │       ├── capability.rs
│   │       └── validation.rs
│   │
│   ├── nsk-policy/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── validate.rs
│   │       ├── normalize.rs
│   │       ├── effective.rs
│   │       └── diagnostics.rs
│   │
│   ├── nsk-runtime/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── runtime.rs
│   │       ├── manager.rs
│   │       ├── registry.rs
│   │       ├── lifecycle.rs
│   │       ├── cancellation.rs
│   │       └── cleanup.rs
│   │
│   ├── nsk-supervisor/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── process.rs
│   │       ├── monitor.rs
│   │       ├── terminate.rs
│   │       ├── output.rs
│   │       ├── stdin.rs
│   │       └── timer.rs
│   │
│   ├── nsk-resource/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── limits.rs
│   │       ├── monitor.rs
│   │       ├── usage.rs
│   │       ├── accounting.rs
│   │       └── enforcement.rs
│   │
│   ├── nsk-workspace/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── manager.rs
│   │       ├── path.rs
│   │       ├── mount.rs
│   │       ├── cleanup.rs
│   │       └── artifact.rs
│   │
│   ├── nsk-provider/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── traits.rs
│   │       ├── factory.rs
│   │       ├── capability.rs
│   │       └── handle.rs
│   │
│   ├── nsk-provider-linux/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── provider.rs
│   │       ├── probe.rs
│   │       ├── bwrap.rs
│   │       ├── namespace.rs
│   │       ├── mount.rs
│   │       ├── network.rs
│   │       ├── cgroup.rs
│   │       ├── seccomp.rs
│   │       ├── process.rs
│   │       └── cleanup.rs
│   │
│   ├── nsk-provider-windows/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── provider.rs
│   │       ├── probe.rs
│   │       ├── job.rs
│   │       ├── token.rs
│   │       └── appcontainer.rs
│   │
│   ├── nsk-provider-macos/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── provider.rs
│   │       ├── probe.rs
│   │       └── isolation.rs
│   │
│   ├── nsk-scheduler/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── queue.rs
│   │       ├── concurrency.rs
│   │       └── budget.rs
│   │
│   └── nsk-cli/
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── run.rs
│           ├── inspect.rs
│           ├── doctor.rs
│           ├── capabilities.rs
│           └── cleanup.rs
│
├── tests/
│   ├── integration/
│   ├── security/
│   ├── stress/
│   ├── recovery/
│   └── fixtures/
│
└── examples/
    ├── basic_execution.rs
    ├── policy.rs
    └── monitoring.rs
```

## **13.2 Workspace 依赖规则**

\#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).green :is(rect,circle,ellipse,polygon,path):where(:not(.label \*)) {fill:#daf4e4;stroke:#9dd8a5}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).green [fill="none"]:where(:not(.label \*)) {fill:none}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).green [stroke="none"]:where(:not(.label \*)) {stroke:none}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).green :where(text,.label,.nodeLabel) {fill:#2c6732;color:#2c6732}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).blue :is(rect,circle,ellipse,polygon,path):where(:not(.label \*)) {fill:#deefff;stroke:#9cc4fc}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).blue [fill="none"]:where(:not(.label \*)) {fill:none}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).blue [stroke="none"]:where(:not(.label \*)) {stroke:none}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).blue :where(text,.label,.nodeLabel) {fill:#2c67c5;color:#2c67c5}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).orange :is(rect,circle,ellipse,polygon,path):where(:not(.label \*)) {fill:#fee7db;stroke:#f6b48d}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).orange [fill="none"]:where(:not(.label \*)) {fill:none}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).orange [stroke="none"]:where(:not(.label \*)) {stroke:none}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).orange :where(text,.label,.nodeLabel) {fill:#87401d;color:#87401d}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).purple :is(rect,circle,ellipse,polygon,path):where(:not(.label \*)) {fill:#efe5fe;stroke:#c1a3f7}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).purple [fill="none"]:where(:not(.label \*)) {fill:none}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).purple [stroke="none"]:where(:not(.label \*)) {stroke:none}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).purple :where(text,.label,.nodeLabel) {fill:#4e2f88;color:#4e2f88}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).gray :is(rect,circle,ellipse,polygon,path):where(:not(.label \*)) {fill:#ededed;stroke:#cdcdcd}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).gray [fill="none"]:where(:not(.label \*)) {fill:none}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).gray [stroke="none"]:where(:not(.label \*)) {stroke:none}#chatgpt-mermaid-\_r_a32\_ :is(.node,.pele-node).gray :where(text,.label,.nodeLabel) {fill:#303030;color:#303030}#chatgpt-mermaid-\_r_a32\_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;fill:rgb(13, 13, 13);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-\_r_a32\_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_a32\_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_a32\_ .error-icon{fill:rgb(243, 243, 243);}#chatgpt-mermaid-\_r_a32\_ .error-text{fill:rgb(13, 13, 13);stroke:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a32\_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-\_r_a32\_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-\_r_a32\_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-\_r_a32\_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-\_r_a32\_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-\_r_a32\_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-\_r_a32\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a32\_ .marker.cross{stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a32\_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;}#chatgpt-mermaid-\_r_a32\_ p{margin:0;}#chatgpt-mermaid-\_r_a32\_ .label{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a32\_ .cluster-label text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a32\_ .cluster-label span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a32\_ .cluster-label span p{background-color:transparent;}#chatgpt-mermaid-\_r_a32\_ .label text,#chatgpt-mermaid-\_r_a32\_ span{fill:rgb(13, 13, 13);color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a32\_ .node rect,#chatgpt-mermaid-\_r_a32\_ .node circle,#chatgpt-mermaid-\_r_a32\_ .node ellipse,#chatgpt-mermaid-\_r_a32\_ .node polygon,#chatgpt-mermaid-\_r_a32\_ .node path{fill:rgb(222, 234, 251);stroke:rgb(83, 154, 248);stroke-width:1px;}#chatgpt-mermaid-\_r_a32\_ .rough-node .label text,#chatgpt-mermaid-\_r_a32\_ .node .label text,#chatgpt-mermaid-\_r_a32\_ .image-shape .label,#chatgpt-mermaid-\_r_a32\_ .icon-shape .label{text-anchor:middle;}#chatgpt-mermaid-\_r_a32\_ .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#chatgpt-mermaid-\_r_a32\_ .rough-node .label,#chatgpt-mermaid-\_r_a32\_ .node .label,#chatgpt-mermaid-\_r_a32\_ .image-shape .label,#chatgpt-mermaid-\_r_a32\_ .icon-shape .label{text-align:center;}#chatgpt-mermaid-\_r_a32\_ .node.clickable{cursor:pointer;}#chatgpt-mermaid-\_r_a32\_ .root .anchor path{fill:rgb(143, 143, 143)!important;stroke-width:0;stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a32\_ .arrowheadPath{fill:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a32\_ .edgePath .path{stroke:rgb(143, 143, 143);stroke-width:1px;}#chatgpt-mermaid-\_r_a32\_ .flowchart-link{stroke:rgb(143, 143, 143);fill:none;}#chatgpt-mermaid-\_r_a32\_ .edgeLabel{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_a32\_ .edgeLabel p{background-color:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a32\_ .edgeLabel rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a32\_ .labelBkg{background-color:rgba(252, 252, 252, 0.5);}#chatgpt-mermaid-\_r_a32\_ .cluster rect{fill:rgb(243, 243, 243);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_a32\_ .cluster text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a32\_ .cluster span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a32\_ div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:12px;background:rgb(243, 243, 243);border:1px solid rgba(0, 0, 0, 0.1);border-radius:2px;pointer-events:none;z-index:100;}#chatgpt-mermaid-\_r_a32\_ .flowchartTitleText{text-anchor:middle;font-size:18px;fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_a32\_ rect.text{fill:none;stroke-width:0;}#chatgpt-mermaid-\_r_a32\_ .icon-shape,#chatgpt-mermaid-\_r_a32\_ .image-shape{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_a32\_ .icon-shape p,#chatgpt-mermaid-\_r_a32\_ .image-shape p{background-color:rgb(252, 252, 252);padding:2px;}#chatgpt-mermaid-\_r_a32\_ .icon-shape .label rect,#chatgpt-mermaid-\_r_a32\_ .image-shape .label rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_a32\_ .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#chatgpt-mermaid-\_r_a32\_ .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#chatgpt-mermaid-\_r_a32\_ .node .neo-node{stroke:rgb(83, 154, 248);}#chatgpt-mermaid-\_r_a32\_ [data-look="neo"].node rect,#chatgpt-mermaid-\_r_a32\_ [data-look="neo"].cluster rect,#chatgpt-mermaid-\_r_a32\_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-\_r_a32\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a32\_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-\_r_a32\_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-\_r_a32\_-gradient);stroke-width:1px;}#chatgpt-mermaid-\_r_a32\_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a32\_ [data-look="neo"].node .neo-line path{stroke:rgb(83, 154, 248);filter:none;}#chatgpt-mermaid-\_r_a32\_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-\_r_a32\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a32\_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-\_r_a32\_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-\_r_a32\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a32\_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-\_r_a32\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_a32\_ .node text{font-size:14px;font-weight:600;letter-spacing:normal;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_a32\_ .edgeLabels text{font-size:13px;font-weight:600;letter-spacing:-0.08px;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_a32\_ .node tspan[font-weight="normal"],#chatgpt-mermaid-\_r_a32\_ .edgeLabels tspan[font-weight="normal"]{font-weight:600;}#chatgpt-mermaid-\_r_a32\_ .edgeLabel .label rect{opacity:1;rx:13px;ry:13px;fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-width:1px;}#chatgpt-mermaid-\_r_a32\_ .node rect,#chatgpt-mermaid-\_r_a32\_ .node circle,#chatgpt-mermaid-\_r_a32\_ .node ellipse,#chatgpt-mermaid-\_r_a32\_ .node polygon,#chatgpt-mermaid-\_r_a32\_ .node path{fill:rgb(229, 243, 255);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_a32\_ .node rect{rx:16px;ry:16px;}#chatgpt-mermaid-\_r_a32\_ .mermaid-decision .label-container{fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-dasharray:2,2;}#chatgpt-mermaid-\_r_a32\_ .edgePaths .flowchart-link{stroke:rgb(143, 143, 143);stroke-width:1px;stroke-linecap:round;stroke-linejoin:round;}#chatgpt-mermaid-\_r_a32\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_a32\_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";}#chatgpt-mermaid-\_r_a32\_ .green rect{fill:rgb(220, 252, 231)!important;color:rgb(20, 83, 45)!important;}#chatgpt-mermaid-\_r_a32\_ .green polygon{fill:rgb(220, 252, 231)!important;color:rgb(20, 83, 45)!important;}#chatgpt-mermaid-\_r_a32\_ .green ellipse{fill:rgb(220, 252, 231)!important;color:rgb(20, 83, 45)!important;}#chatgpt-mermaid-\_r_a32\_ .green circle{fill:rgb(220, 252, 231)!important;color:rgb(20, 83, 45)!important;}#chatgpt-mermaid-\_r_a32\_ .green path{fill:rgb(220, 252, 231)!important;color:rgb(20, 83, 45)!important;}#chatgpt-mermaid-\_r_a32\_ .green tspan{fill:rgb(20, 83, 45)!important;}#chatgpt-mermaid-\_r_a32\_ .blue rect{fill:rgb(219, 234, 254)!important;color:rgb(30, 58, 138)!important;}#chatgpt-mermaid-\_r_a32\_ .blue polygon{fill:rgb(219, 234, 254)!important;color:rgb(30, 58, 138)!important;}#chatgpt-mermaid-\_r_a32\_ .blue ellipse{fill:rgb(219, 234, 254)!important;color:rgb(30, 58, 138)!important;}#chatgpt-mermaid-\_r_a32\_ .blue circle{fill:rgb(219, 234, 254)!important;color:rgb(30, 58, 138)!important;}#chatgpt-mermaid-\_r_a32\_ .blue path{fill:rgb(219, 234, 254)!important;color:rgb(30, 58, 138)!important;}#chatgpt-mermaid-\_r_a32\_ .blue tspan{fill:rgb(30, 58, 138)!important;}#chatgpt-mermaid-\_r_a32\_ .orange rect{fill:rgb(255, 237, 213)!important;color:rgb(154, 52, 18)!important;}#chatgpt-mermaid-\_r_a32\_ .orange polygon{fill:rgb(255, 237, 213)!important;color:rgb(154, 52, 18)!important;}#chatgpt-mermaid-\_r_a32\_ .orange ellipse{fill:rgb(255, 237, 213)!important;color:rgb(154, 52, 18)!important;}#chatgpt-mermaid-\_r_a32\_ .orange circle{fill:rgb(255, 237, 213)!important;color:rgb(154, 52, 18)!important;}#chatgpt-mermaid-\_r_a32\_ .orange path{fill:rgb(255, 237, 213)!important;color:rgb(154, 52, 18)!important;}#chatgpt-mermaid-\_r_a32\_ .orange tspan{fill:rgb(154, 52, 18)!important;}#chatgpt-mermaid-\_r_a32\_ .purple rect{fill:rgb(243, 232, 255)!important;color:rgb(107, 33, 168)!important;}#chatgpt-mermaid-\_r_a32\_ .purple polygon{fill:rgb(243, 232, 255)!important;color:rgb(107, 33, 168)!important;}#chatgpt-mermaid-\_r_a32\_ .purple ellipse{fill:rgb(243, 232, 255)!important;color:rgb(107, 33, 168)!important;}#chatgpt-mermaid-\_r_a32\_ .purple circle{fill:rgb(243, 232, 255)!important;color:rgb(107, 33, 168)!important;}#chatgpt-mermaid-\_r_a32\_ .purple path{fill:rgb(243, 232, 255)!important;color:rgb(107, 33, 168)!important;}#chatgpt-mermaid-\_r_a32\_ .purple tspan{fill:rgb(107, 33, 168)!important;}#chatgpt-mermaid-\_r_a32\_ .gray rect{fill:rgb(229, 231, 235)!important;color:rgb(17, 24, 39)!important;}#chatgpt-mermaid-\_r_a32\_ .gray polygon{fill:rgb(229, 231, 235)!important;color:rgb(17, 24, 39)!important;}#chatgpt-mermaid-\_r_a32\_ .gray ellipse{fill:rgb(229, 231, 235)!important;color:rgb(17, 24, 39)!important;}#chatgpt-mermaid-\_r_a32\_ .gray circle{fill:rgb(229, 231, 235)!important;color:rgb(17, 24, 39)!important;}#chatgpt-mermaid-\_r_a32\_ .gray path{fill:rgb(229, 231, 235)!important;color:rgb(17, 24, 39)!important;}#chatgpt-mermaid-\_r_a32\_ .gray tspan{fill:rgb(17, 24, 39)!important;}nsk-corensk-policynsk-providernsk-workspacensk-resourcensk-supervisornsk-provider-linuxnsk-runtimensk-schedulernsk-cli

### **依赖规则**

- `nsk-core` 不依赖任何 Provider。
- `nsk-policy` 不依赖 OS。
- `nsk-provider` 只定义接口。
- Linux Provider 依赖接口与 Core。
- Runtime 负责组合各模块。
- Supervisor 不负责 Policy。
- Policy Engine 不负责执行。
- CLI 不直接操作系统资源。
- Scheduler 不直接操作 OS。
- Provider 不处理业务级执行逻辑。

## **13.3 Cargo Workspace 配置**

根目录：

```
[workspace]
resolver = "2"

members = [
    "crates/nsk-core",
    "crates/nsk-policy",
    "crates/nsk-runtime",
    "crates/nsk-supervisor",
    "crates/nsk-resource",
    "crates/nsk-workspace",
    "crates/nsk-provider",
    "crates/nsk-provider-linux",
    "crates/nsk-provider-windows",
    "crates/nsk-provider-macos",
    "crates/nsk-scheduler",
    "crates/nsk-cli",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT"
rust-version = "1.85"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "2"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
uuid = { version = "1", features = ["v4", "serde"] }

tokio = { version = "1", features = [
    "rt",
    "rt-multi-thread",
    "sync",
    "process",
    "time",
    "macros",
    "io-util",
] }

tokio-util = { version = "0.7", features = ["rt"] }
```

正式工程应固定 Rust Toolchain，维护依赖锁文件，避免开发和 CI 之间出现版本差异。

# **十四、内核内部 API**

## **14.1 Runtime API**

建议对外提供简洁的 Rust API。

```
#[async_trait::async_trait]
pub trait SandboxRuntime: Send + Sync {
    async fn create(
        &self,
        spec: SandboxSpec,
    ) -> Result<SandboxId, SandboxError>;

    async fn start(
        &self,
        id: SandboxId,
    ) -> Result<(), SandboxError>;

    async fn wait(
        &self,
        id: SandboxId,
    ) -> Result<SandboxResult, SandboxError>;

    async fn cancel(
        &self,
        id: SandboxId,
    ) -> Result<(), SandboxError>;

    async fn inspect(
        &self,
        id: SandboxId,
    ) -> Result<SandboxState, SandboxError>;

    async fn cleanup(
        &self,
        id: SandboxId,
    ) -> Result<(), SandboxError>;
}
```

## **14.2 Builder**

```
pub struct SandboxRuntimeBuilder {
    provider: Option<Arc<dyn SandboxProvider>>,
}
```

```
impl SandboxRuntimeBuilder {
    pub fn new() -> Self {
        Self {
            provider: None,
        }
    }

    pub fn with_provider(
        mut self,
        provider: Arc<dyn SandboxProvider>,
    ) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn build(
        self,
    ) -> Result<Runtime, SandboxError> {
        // Validate and assemble runtime.
        todo!()
    }
}
```

## **14.3 执行 API**

```
let runtime = SandboxRuntimeBuilder::new()
    .with_provider(provider)
    .build()?;

let id = runtime.create(spec).await?;

runtime.start(id).await?;

let result = runtime.wait(id).await?;

runtime.cleanup(id).await?;
```

## **14.4 Event API**

```
pub enum SandboxEvent {
    Created,

    Preparing,

    Ready,

    Started,

    Stdout(Vec<u8>),

    Stderr(Vec<u8>),

    ResourceUsage(ResourceUsage),

    LimitExceeded(LimitType),

    Terminating,

    Exited(ExitInfo),

    CleanupCompleted,
}
```

Event Stream 设计：

- 有界队列。
- 可取消。
- 支持多个监控事件。
- 输出事件支持流式读取。
- 不允许事件生产者无限等待。
- 不允许输出事件无限积累。
- Resource Usage 事件可按频率采样。
- 不允许监控事件阻塞进程终止。

# **十五、内核诊断与观测系统**

## **15.1 Diagnostics**

Diagnostics 是内核的独立模块。

负责：

- 环境检测。
- Provider 能力检测。
- Isolation Validation。
- Resource Validation。
- Runtime Validation。
- Cleanup Diagnostics。

## **15.2 Diagnostic 模型**

```
pub struct Diagnostic {
    pub code: String,

    pub severity: DiagnosticSeverity,

    pub message: String,

    pub details: Option<String>,
}
```

```
pub enum DiagnosticSeverity {
    Info,

    Warning,

    Error,
}
```

## **15.3 诊断分类**

```
Diagnostics
├── Host Environment
├── OS Capabilities
├── Isolation Capabilities
├── Resource Capabilities
├── Security Capabilities
├── Policy Validation
├── Execution Diagnostics
└── Cleanup Diagnostics
```

## **15.4 日志**

采用 tracing。

建议日志级别：

| Level | 内容             |
| ----- | -------------- |
| ERROR | 内核错误、隔离失败、清理失败 |
| WARN  | 能力不足、资源限制异常    |
| INFO  | Sandbox 生命周期   |
| DEBUG | Provider 细节    |
| TRACE | 调试级执行流程        |

日志不应记录：

- 用户程序完整输出。
- 用户文件内容。
- 不必要的敏感路径。
- 凭证。
- 密码。
- 敏感环境变量。

日志应允许用户选择诊断级别，但不能因为关闭日志而关闭安全监控。

# **十六、测试体系**

## **16.1 测试架构**

```
Test System
├── Unit Tests
├── Integration Tests
├── Provider Tests
├── Security Tests
├── Stress Tests
├── Lifecycle Tests
├── Recovery Tests
└── Capability Tests
```

## **16.2 Unit Tests**

| 模块         | 测试               |
| ---------- | ---------------- |
| Core       | 类型、ID、状态         |
| Policy     | Policy 校验        |
| Policy     | Policy Normalize |
| Workspace  | 路径验证             |
| Resource   | 限制转换             |
| Supervisor | 状态和监控            |
| Output     | Output Limit     |
| Runtime    | 生命周期             |
| Scheduler  | 并发与预算            |

## **16.3 Integration Tests**

- 正常程序执行。
- Exit Code 0。
- Non-zero Exit。
- Stdin。
- stdout。
- stderr。
- Wall Time。
- Cancel。
- Workspace。
- Environment。
- Process。
- Cleanup。

## **16.4 Security Tests**

| 攻击                            | 验收目标           |
| ----------------------------- | -------------- |
| Infinite Loop                 | Wall Time 超限终止 |
| Memory Bomb                   | Memory 限制生效    |
| Fork Bomb                     | PID 限制生效       |
| Output Bomb                   | 输出限制生效         |
| Host Path Access              | 宿主机受保护文件不可访问   |
| Network Probe                 | 网络隔离生效         |
| Background Process            | 生命周期受控         |
| Symlink Escape                | 路径策略不被绕过       |
| Path Traversal                | 访问边界有效         |
| Privilege Escalation Attempts | 权限限制有效         |
| File Creation                 | 文件策略有效         |
| Open File Bomb                | 文件描述符限制有效      |
| Cgroup Escape Attempts        | 进程集合管理及回收验证    |
| Cleanup Failure               | 失败可诊断          |

测试应在独立、可恢复的测试环境中执行。攻击测试不应在未经隔离的生产主机上运行。

## **16.5 Stress Tests**

- 1000 次连续执行。
- 100 次并发执行。
- 多次同时取消。
- 多次同时超时。
- 大量 stdout。
- 大量 stderr。
- 大量短进程。
- 长时间执行。
- 频繁 Cleanup。
- Workspace 压力。
- Cgroup 压力。

实际压力测试数量应依据测试环境能力调整。

## **16.6 Recovery Tests**

- Sandbox 正常退出。
- Sandbox 异常退出。
- Runtime 异常退出。
- 系统重启。
- Cgroup 残留。
- Workspace 残留。
- Cleanup 失败。
- Process 残留。
- Registry 状态不一致。

内核应具备可诊断的残留资源识别机制，并通过安全校验决定是否清理。

# **十七、内核默认执行策略**

内核应提供基础 Profile，方便开发者定义安全执行环境。Profile 仅用于初始化策略，不是内核执行的硬编码限制。

## **17.1 Minimal Profile**

用于普通程序的基础受限执行。

| 限制              | 初始值        |
| --------------- | ---------- |
| Wall Time       | 5 秒        |
| CPU Quota       | 1 CPU      |
| Memory          | 256 MiB    |
| Max PID         | 16         |
| Max Open Files  | 64         |
| Max File Size   | 16 MiB     |
| Combined Output | 8 MiB      |
| Network         | Disabled   |
| Workspace       | Writable   |
| Host Filesystem | Restricted |

## **17.2 Strict Profile**

用于更严格的执行环境。

| 限制              | 初始值        |
| --------------- | ---------- |
| Wall Time       | 2 秒        |
| CPU Quota       | 1 CPU      |
| Memory          | 128 MiB    |
| Max PID         | 8          |
| Max Open Files  | 32         |
| Max File Size   | 8 MiB      |
| Combined Output | 4 MiB      |
| Network         | Disabled   |
| Workspace       | Writable   |
| Host Filesystem | Restricted |

## **17.3 Extended Profile**

用于较复杂的程序。

| 限制              | 初始值        |
| --------------- | ---------- |
| Wall Time       | 30 秒       |
| CPU Quota       | 2 CPU      |
| Memory          | 1 GiB      |
| Max PID         | 64         |
| Max Open Files  | 128        |
| Max File Size   | 64 MiB     |
| Combined Output | 32 MiB     |
| Network         | Disabled   |
| Workspace       | Writable   |
| Host Filesystem | Restricted |

**这些值是开发阶段参考配置，不是安全保证或通用最佳参数。**

最终值需要通过测试、目标系统能力、执行环境及实际资源预算确定。每个 Profile 必须经过 Policy Engine 验证。

# **十八、开发计划书**

**开发目标：从零构建独立 Rust Sandbox Kernel，先实现可验证的 Linux MVP。**

## **18.1 开发阶段**

### **Phase 0 — Engineering Foundation**

预计 2～3 个工作日

- 初始化 Cargo Workspace。
- 固定 Rust Toolchain。
- 配置 CI。
- 配置 Clippy。
- 配置 Rustfmt。
- 建立错误体系。
- 建立日志系统。
- 建立测试体系。
- 建立开发文档。

**交付：可编译的 Rust 工程基础。**

### **Phase 1 — Core**

预计 3～5 个工作日

- Sandbox ID。
- SandboxSpec。
- CommandSpec。
- WorkspaceSpec。
- SandboxPolicy。
- ResourceLimits。
- SandboxState。
- SandboxResult。
- SandboxError。
- SandboxEvent。
- PlatformCapabilities。
- Unit Tests。

**交付：纯 Rust Core。**

### **Phase 2 — Policy Engine**

预计 3～5 个工作日

- Policy Validation。
- Policy Normalize。
- Policy Conflict Detection。
- Resource Validation。
- Path Validation。
- Security Validation。
- Capability Matching。
- Effective Policy。
- Policy Tests。

**交付：策略验证引擎。**

### **Phase 3 — Provider Abstraction**

预计 3～5 个工作日

- Provider Trait。
- Provider Factory。
- Platform Capability Model。
- Prepared Sandbox。
- Running Sandbox。
- Sandbox Handle。
- Provider Lifecycle。
- Mock Provider。
- Provider Tests。

**交付：平台抽象层。**

### **Phase 4 — Workspace Manager**

预计 3～5 个工作日

- Workspace 创建。
- Workspace 隔离。
- Path Validation。
- Path Normalization。
- Symlink 检查。
- 临时目录。
- Cleanup。
- Artifact Collection。
- Workspace Tests。

**交付：Workspace Manager。**

### **Phase 5 — Linux Capability Probe**

预计 3～5 个工作日

- Linux Probe。
- bubblewrap Probe。
- Namespace Probe。
- User Namespace Probe。
- cgroups v2 Probe。
- Controller Probe。
- seccomp Probe。
- No New Privileges Probe。
- 实际执行能力验证。
- Capability Report。

**交付：Linux Capability Detection。**

### **Phase 6 — Linux Isolation**

预计 5～8 个工作日

- Bwrap Config Builder。
- Mount Policy。
- PID Isolation。
- Network Isolation。
- IPC Isolation。
- UTS Isolation。
- User Namespace。
- Filesystem Isolation。
- Environment Isolation。
- Isolation Tests。

**交付：Linux Isolation Provider。**

### **Phase 7 — Resource Controller**

预计 5～8 个工作日

- Cgroup Manager。
- Cgroup Creation。
- Memory Limits。
- CPU Limits。
- PID Limits。
- Memory Monitoring。
- CPU Monitoring。
- PID Monitoring。
- Cgroup Kill。
- Cgroup Cleanup。
- Resource Tests。

**交付：Linux Resource Controller。**

### **Phase 8 — Supervisor**

预计 5～7 个工作日

- Process Spawn。
- Stdin。
- Stdout。
- Stderr。
- Output Collector。
- Wall Time。
- Process Monitoring。
- Cancellation。
- Termination。
- Exit Collection。
- Process Tree Cleanup。
- Supervisor Tests。

**交付：Supervisor。**

### **Phase 9 — Runtime Manager**

预计 3～5 个工作日

- Runtime API。
- Sandbox Registry。
- State Machine。
- Lifecycle。
- Provider Integration。
- Workspace Integration。
- Resource Integration。
- Supervisor Integration。
- Cleanup Manager。
- Integration Tests。

**交付：完整 Runtime Manager。**

### **Phase 10 — Linux MVP**

预计 3～5 个工作日

- Linux Provider Integration。
- Runtime Integration。
- Isolation Tests。
- Resource Tests。
- Cleanup Tests。
- Security Tests。
- Stress Tests。
- Linux MVP Validation。

**交付：可实际执行程序的 Linux Sandbox Kernel。**

### **Phase 11 — Scheduler**

预计 3～5 个工作日

- FIFO Queue。
- Max Concurrency。
- Global Resource Budget。
- Task Cancellation。
- Scheduler Tests。

**交付：基础执行调度系统。**

### **Phase 12 — Diagnostics**

预计 3～5 个工作日

- Capability Report。
- Policy Report。
- Resource Report。
- Cleanup Diagnostics。
- Execution Diagnostics。
- Structured Logging。
- Diagnostics Tests。

**交付：内核诊断系统。**

### **Phase 13 — CLI**

预计 3～5 个工作日

- `nsk doctor`。
- `nsk capabilities`。
- `nsk run`。
- `nsk inspect`。
- `nsk cancel`。
- `nsk cleanup`。
- CLI Tests。

**交付：独立内核测试工具。**

### **Phase 14 — Stability & Security**

预计 5～8 个工作日

- Stress Tests。
- Security Regression。
- Resource Leak Tests。
- Cleanup Recovery。
- Crash Recovery。
- Concurrent Execution。
- Performance Tests。
- Security Documentation。
- Release Checklist。

**交付：Linux Kernel V0.1 Release Candidate。**

### **Phase 15 — Windows Provider**

预计 8～12 个工作日，初步估算

- Capability Probe。
- Job Objects。
- Restricted Token。
- Process Management。
- Resource Control。
- Filesystem ACL。
- AppContainer PoC。
- Network Isolation PoC。
- Integration Tests。
- Security Tests。

**交付：Windows Provider PoC / MVP，取决于安全机制验证结果。**

### **Phase 16 — macOS Provider**

预计 5～10 个工作日，初步估算

- Capability Probe。
- Process Management。
- Filesystem Isolation PoC。
- Network Isolation PoC。
- Resource Management PoC。
- Sandbox Mechanism Validation。
- Integration Tests。
- Security Tests。

**交付：macOS Provider PoC，取决于可用系统机制。**

## **18.2 Sprint 规划**

| Sprint     | 重点                      | 交付                      |
| ---------- | ----------------------- | ----------------------- |
| Sprint 1   | Core                    | Rust Core               |
| Sprint 2   | Policy + Provider API   | 策略引擎 + Provider 接口      |
| Sprint 3   | Workspace + Probe       | Workspace + Linux Probe |
| Sprint 4   | Linux Isolation         | Linux Provider          |
| Sprint 5   | Resource Controller     | cgroups v2              |
| Sprint 6   | Supervisor              | 进程控制与输出                 |
| Sprint 7   | Runtime Manager         | 完整生命周期                  |
| Sprint 8   | Linux MVP               | 可验证沙盒                   |
| Sprint 9   | Scheduler + Diagnostics | 调度与诊断                   |
| Sprint 10  | CLI + Security          | 测试工具及安全验证               |
| Sprint 11  | Stability               | 稳定性及回归测试                |
| Sprint 12+ | Windows                 | Windows Provider        |
| Sprint 13+ | macOS                   | macOS Provider          |

以上 Sprint 是规划参考，并不意味着所有阶段能在固定周期内完成。安全验证、平台权限及资源控制实现可能显著影响排期。

# **十九、里程碑**

**M1 — Core**

纯 Rust Core、基础类型、状态机、错误体系和测试完成。

**M2 — Policy**

Policy Engine、规范化及能力匹配完成。

**M3 — Provider API**

Provider 抽象层及生命周期 API 完成。

**M4 — Workspace**

独立工作目录和文件管理完成。

**M5 — Linux Isolation**

Linux 文件、进程及网络隔离机制完成并验证。

**M6 — Resource Controller**

cgroups v2 资源控制及监控完成。

**M7 — Supervisor**

进程执行、监控、输出、终止及回收完成。

**M8 — Linux Kernel MVP**

独立 Sandbox Runtime 可实际运行程序并通过安全测试。

**M9 — Scheduler**

执行队列、并发控制及全局资源预算完成。

**M10 — Release Candidate**

稳定性、诊断、回归测试和发布文档完成。

# **二十、Linux MVP 验收标准**

## **20.1 功能验收**

- 创建 Sandbox。
- 启动程序。
- 参数传递。
- Stdin。
- stdout。
- stderr。
- Exit Code。
- Cancel。
- Inspect。
- Cleanup。
- Resource Usage。
- State Management。

## **20.2 隔离验收**

- PID 隔离。
- 文件系统隔离。
- 网络隔离。
- IPC 隔离。
- 用户权限隔离（在声明支持的环境中）。
- Workspace 隔离。
- 宿主机 Home 不可访问。
- 宿主机凭证文件不可访问。
- 受保护文件不可访问。
- 隔离失败时拒绝安全执行。

## **20.3 资源验收**

- Wall Time。
- Memory。
- CPU Quota。
- PID。
- Open Files。
- File Size。
- stdout Limit。
- stderr Limit。
- Combined Output Limit。
- Resource Usage Monitoring。
- Resource Limit Failure Diagnostics。

## **20.4 生命周期验收**

- 正常退出。
- 超时。
- 取消。
- OOM。
- PID 超限。
- Output 超限。
- Process Tree Termination。
- Cgroup Cleanup。
- Workspace Cleanup。
- Cleanup Failure Diagnostics。
- Crash Recovery。

## **20.5 稳定性验收**

- 1000 次连续执行。
- 并发执行。
- 高频输出。
- 多进程。
- 取消竞态。
- 超时竞态。
- Cleanup。
- Resource Leak。
- Security Regression。

# **二十一、最终交付物**

**NSK · Native Sandbox Kernel V0.1**

- &#x20;Rust Core
- &#x20;Policy Engine
- &#x20;Provider Abstraction
- &#x20;Linux Provider
- &#x20;bubblewrap Isolation
- &#x20;Namespace Isolation
- &#x20;cgroups v2
- &#x20;Resource Controller
- &#x20;Supervisor
- &#x20;Workspace Manager
- &#x20;Output Collector
- &#x20;Sandbox Lifecycle
- &#x20;Scheduler
- &#x20;Diagnostics
- &#x20;CLI
- &#x20;Unit Tests
- &#x20;Integration Tests
- &#x20;Security Tests
- &#x20;Stress Tests
- &#x20;Recovery Tests
- &#x20;Architecture Documentation
- &#x20;Security Documentation

# **二十二、项目最终架构**

\#chatgpt-mermaid-\_r_abk\_{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;fill:rgb(13, 13, 13);}@keyframes edge-animation-frame{from{stroke-dashoffset:0;}}@keyframes dash{to{stroke-dashoffset:0;}}#chatgpt-mermaid-\_r_abk\_ .edge-animation-slow{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 50s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_abk\_ .edge-animation-fast{stroke-dasharray:9,5!important;stroke-dashoffset:900;animation:dash 20s linear infinite;stroke-linecap:round;}#chatgpt-mermaid-\_r_abk\_ .error-icon{fill:rgb(243, 243, 243);}#chatgpt-mermaid-\_r_abk\_ .error-text{fill:rgb(13, 13, 13);stroke:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_abk\_ .edge-thickness-normal{stroke-width:1px;}#chatgpt-mermaid-\_r_abk\_ .edge-thickness-thick{stroke-width:3.5px;}#chatgpt-mermaid-\_r_abk\_ .edge-pattern-solid{stroke-dasharray:0;}#chatgpt-mermaid-\_r_abk\_ .edge-thickness-invisible{stroke-width:0;fill:none;}#chatgpt-mermaid-\_r_abk\_ .edge-pattern-dashed{stroke-dasharray:3;}#chatgpt-mermaid-\_r_abk\_ .edge-pattern-dotted{stroke-dasharray:2;}#chatgpt-mermaid-\_r_abk\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_abk\_ .marker.cross{stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_abk\_ svg{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:16px;}#chatgpt-mermaid-\_r_abk\_ p{margin:0;}#chatgpt-mermaid-\_r_abk\_ .label{font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_abk\_ .cluster-label text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_abk\_ .cluster-label span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_abk\_ .cluster-label span p{background-color:transparent;}#chatgpt-mermaid-\_r_abk\_ .label text,#chatgpt-mermaid-\_r_abk\_ span{fill:rgb(13, 13, 13);color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_abk\_ .node rect,#chatgpt-mermaid-\_r_abk\_ .node circle,#chatgpt-mermaid-\_r_abk\_ .node ellipse,#chatgpt-mermaid-\_r_abk\_ .node polygon,#chatgpt-mermaid-\_r_abk\_ .node path{fill:rgb(222, 234, 251);stroke:rgb(83, 154, 248);stroke-width:1px;}#chatgpt-mermaid-\_r_abk\_ .rough-node .label text,#chatgpt-mermaid-\_r_abk\_ .node .label text,#chatgpt-mermaid-\_r_abk\_ .image-shape .label,#chatgpt-mermaid-\_r_abk\_ .icon-shape .label{text-anchor:middle;}#chatgpt-mermaid-\_r_abk\_ .node .katex path{fill:#000;stroke:#000;stroke-width:1px;}#chatgpt-mermaid-\_r_abk\_ .rough-node .label,#chatgpt-mermaid-\_r_abk\_ .node .label,#chatgpt-mermaid-\_r_abk\_ .image-shape .label,#chatgpt-mermaid-\_r_abk\_ .icon-shape .label{text-align:center;}#chatgpt-mermaid-\_r_abk\_ .node.clickable{cursor:pointer;}#chatgpt-mermaid-\_r_abk\_ .root .anchor path{fill:rgb(143, 143, 143)!important;stroke-width:0;stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_abk\_ .arrowheadPath{fill:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_abk\_ .edgePath .path{stroke:rgb(143, 143, 143);stroke-width:1px;}#chatgpt-mermaid-\_r_abk\_ .flowchart-link{stroke:rgb(143, 143, 143);fill:none;}#chatgpt-mermaid-\_r_abk\_ .edgeLabel{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_abk\_ .edgeLabel p{background-color:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_abk\_ .edgeLabel rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_abk\_ .labelBkg{background-color:rgba(252, 252, 252, 0.5);}#chatgpt-mermaid-\_r_abk\_ .cluster rect{fill:rgb(243, 243, 243);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_abk\_ .cluster text{fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_abk\_ .cluster span{color:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_abk\_ div.mermaidTooltip{position:absolute;text-align:center;max-width:200px;padding:2px;font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";font-size:12px;background:rgb(243, 243, 243);border:1px solid rgba(0, 0, 0, 0.1);border-radius:2px;pointer-events:none;z-index:100;}#chatgpt-mermaid-\_r_abk\_ .flowchartTitleText{text-anchor:middle;font-size:18px;fill:rgb(13, 13, 13);}#chatgpt-mermaid-\_r_abk\_ rect.text{fill:none;stroke-width:0;}#chatgpt-mermaid-\_r_abk\_ .icon-shape,#chatgpt-mermaid-\_r_abk\_ .image-shape{background-color:rgb(252, 252, 252);text-align:center;}#chatgpt-mermaid-\_r_abk\_ .icon-shape p,#chatgpt-mermaid-\_r_abk\_ .image-shape p{background-color:rgb(252, 252, 252);padding:2px;}#chatgpt-mermaid-\_r_abk\_ .icon-shape .label rect,#chatgpt-mermaid-\_r_abk\_ .image-shape .label rect{opacity:0.5;background-color:rgb(252, 252, 252);fill:rgb(252, 252, 252);}#chatgpt-mermaid-\_r_abk\_ .label-icon{display:inline-block;height:1em;overflow:visible;vertical-align:-0.125em;}#chatgpt-mermaid-\_r_abk\_ .node .label-icon path{fill:currentColor;stroke:revert;stroke-width:revert;}#chatgpt-mermaid-\_r_abk\_ .node .neo-node{stroke:rgb(83, 154, 248);}#chatgpt-mermaid-\_r_abk\_ [data-look="neo"].node rect,#chatgpt-mermaid-\_r_abk\_ [data-look="neo"].cluster rect,#chatgpt-mermaid-\_r_abk\_ [data-look="neo"].node polygon{stroke:url(#chatgpt-mermaid-\_r_abk\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_abk\_ [data-look="neo"].swimlane.cluster rect{filter:none;}#chatgpt-mermaid-\_r_abk\_ [data-look="neo"].node path{stroke:url(#chatgpt-mermaid-\_r_abk\_-gradient);stroke-width:1px;}#chatgpt-mermaid-\_r_abk\_ [data-look="neo"].node .outer-path{filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_abk\_ [data-look="neo"].node .neo-line path{stroke:rgb(83, 154, 248);filter:none;}#chatgpt-mermaid-\_r_abk\_ [data-look="neo"].node circle{stroke:url(#chatgpt-mermaid-\_r_abk\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_abk\_ [data-look="neo"].node circle .state-start{fill:#000000;}#chatgpt-mermaid-\_r_abk\_ [data-look="neo"].icon-shape .icon{fill:url(#chatgpt-mermaid-\_r_abk\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_abk\_ [data-look="neo"].icon-shape .icon-neo path{stroke:url(#chatgpt-mermaid-\_r_abk\_-gradient);filter:drop-shadow( 1px 2px 2px rgba(185,185,185,1));}#chatgpt-mermaid-\_r_abk\_ .node text{font-size:14px;font-weight:600;letter-spacing:normal;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_abk\_ .edgeLabels text{font-size:13px;font-weight:600;letter-spacing:-0.08px;fill:rgb(0, 79, 153);}#chatgpt-mermaid-\_r_abk\_ .node tspan[font-weight="normal"],#chatgpt-mermaid-\_r_abk\_ .edgeLabels tspan[font-weight="normal"]{font-weight:600;}#chatgpt-mermaid-\_r_abk\_ .edgeLabel .label rect{opacity:1;rx:13px;ry:13px;fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-width:1px;}#chatgpt-mermaid-\_r_abk\_ .node rect,#chatgpt-mermaid-\_r_abk\_ .node circle,#chatgpt-mermaid-\_r_abk\_ .node ellipse,#chatgpt-mermaid-\_r_abk\_ .node polygon,#chatgpt-mermaid-\_r_abk\_ .node path{fill:rgb(229, 243, 255);stroke:rgba(0, 0, 0, 0.1);stroke-width:1px;}#chatgpt-mermaid-\_r_abk\_ .node rect{rx:16px;ry:16px;}#chatgpt-mermaid-\_r_abk\_ .mermaid-decision .label-container{fill:rgb(245, 250, 255);stroke:rgb(206, 219, 229);stroke-dasharray:2,2;}#chatgpt-mermaid-\_r_abk\_ .edgePaths .flowchart-link{stroke:rgb(143, 143, 143);stroke-width:1px;stroke-linecap:round;stroke-linejoin:round;}#chatgpt-mermaid-\_r_abk\_ .marker{fill:rgb(143, 143, 143);stroke:rgb(143, 143, 143);}#chatgpt-mermaid-\_r_abk\_ :root{--mermaid-font-family:-apple-system-body,ui-sans-serif,-apple-system,system-ui,"Segoe UI",Helvetica,"Apple Color Emoji",Arial,sans-serif,"Segoe UI Emoji","Segoe UI Symbol";}NSK Runtime APIExecution ManagerPolicy EngineSupervisorResource ControllerWorkspace ManagerSchedulerEffective PolicyPlatform ProviderLinux ProviderWindows ProvidermacOS ProviderLinux OSWindows OSmacOS OS

## **最终技术决策**

| 维度                     | 决策                           |
| ---------------------- | ---------------------------- |
| 项目名称                   | NSK / Native Sandbox Kernel  |
| 开发语言                   | Rust                         |
| Rust Edition           | 2024                         |
| 架构                     | Modular Kernel               |
| 内核形态                   | Independent Runtime Library  |
| 项目组织                   | Cargo Workspace              |
| 异步模型                   | Tokio                        |
| Core                   | Platform Independent         |
| Provider               | OS-specific                  |
| 第一阶段平台                 | Linux                        |
| Linux Isolation        | bubblewrap                   |
| Linux Resource Control | cgroups v2                   |
| Syscall Isolation      | seccomp                      |
| Process Control        | Supervisor                   |
| Filesystem             | Workspace Manager            |
| Output                 | Bounded Output Collector     |
| Policy                 | Policy Engine                |
| Lifecycle              | Runtime Manager              |
| Scheduler              | Basic FIFO                   |
| CLI                    | Kernel Diagnostics & Testing |
| Windows                | 后续 Provider                  |
| macOS                  | 后续 Provider                  |
| 第一阶段目标                 | Linux Kernel MVP             |

# **项目核心定义**

**NSK 是一个使用 Rust 开发的独立、轻量、跨平台原生沙盒内核。它利用操作系统安全机制，为程序提供受策略约束的执行环境，并负责隔离建立、资源限制、进程管理、监控、终止和资源回收。**

**推荐正式开发顺序：Core → Policy Engine → Provider API → Workspace → Linux Probe → Linux Isolation → Resource Controller → Supervisor → Runtime Manager → Linux MVP → Scheduler → Diagnostics → CLI → Security & Stability。**
