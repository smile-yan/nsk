# NSK macOS Provider（§12，第一阶段未开发）

当前状态：**fail-closed 占位**。`probe` 如实上报（无 namespace 机制、无
隔离启动器；rlimits 可用、进程组终止可用），`prepare` 永远拒绝。

## 技术验证方向（后续）

- Seatbelt（sandbox-exec）：Apple 已标记废弃，未验证为安全边界前不采用（§12.2
  「不依赖未经验证的私有 API」）；
- Endpoint Security / App Sandbox 契约范围评估；
- 进程资源控制（如 task policy）的公开 API 边界。

在验证完成前，macOS 上唯一可用的执行路径是显式 mock provider（无隔离，
仅测试用途）。
