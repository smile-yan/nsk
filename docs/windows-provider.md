# NSK Windows Provider（§11，第一阶段未开发）

当前状态：**fail-closed 占位**。`probe` 报告如实（rlimits 不支持、Job Object
机制 OS 层面可行但未实现），`prepare`/`spawn` 永远返回
`CapabilityInsufficient`——绝不以普通宿主进程执行要求隔离的策略。

## 目标技术栈（后续实现）

| 机制 | 职责 |
| --- | --- |
| Job Objects | 进程集合、内存/CPU/PID 限制、整体终止（KILL_ON_JOB_CLOSE） |
| Restricted Token | 降权、去除特权、受限 SID |
| AppContainer | 文件/网络/资源访问隔离（需实际安全验证） |
| ACL | 文件访问控制 |
| Named Pipes | 可选通信 |

注意：Job Objects **不提供**文件系统与网络隔离——必须与 Restricted Token /
AppContainer 组合，不能照搬 Linux namespace 语义（§11）。
