# NSK Linux Provider

**设计书 §10（第一阶段参考实现）的实施说明**

## 隔离栈

| 机制 | 实现 |
| --- | --- |
| 全部 namespaces | bwrap `--unshare-all`（user/pid/net/mount/ipc/uts/cgroup） |
| 文件系统 | 最小 bind：`/usr`（+ merged-usr symlink `/bin` 等）、`/etc/ld.so.cache`、tmpfs `/etc` `/tmp`、proc `/proc`、dev `/dev`、workspace `/workspace` |
| 网络 | netns 无接口（Disabled） |
| 资源 | cgroups v2：memory.max / memory.swap.max / cpu.max / pids.max |
| 终止 | cgroup.kill（≥5.14）→ 组 SIGKILL 兜底 |
| seccomp | 可选 allowlist BPF（`--seccomp-fd` 经 pre-exec dup 注入），默认关闭 |
| 启动 | bubblewrap 参数完全由内核从结构化策略生成（§10.4 禁止透传用户参数） |

## 能力探测（§10.3）

`probe_with_config` 用**实际功能测试**而非版本号：

- bwrap：执行真实沙盒 `bwrap --ro-bind / / --dev /dev --proc /proc /bin/true`；
- cgroup v2：创建探针组 + 写 pids.max + 读回（委托验证），区分
  PermissionDenied / NotConfigured / Available；
- 控制器从 `cgroup.controllers` / `cgroup.subtree_control` 读取；
- 探针组用后即删。

## 执行流程（§10.9）

Validate → Probe → Prepare Workspace → Create Cgroup → Apply Limits →
Build Bwrap Config → Spawn → **Attach cgroup（失败即杀，fail-closed）** →
Monitor → Collect（cgroup 指标合并）→ Cleanup（cgroup destroy 幂等）。

## 沙盒内文件系统视图

```
/            空根（无宿主根）
/usr         ro-bind（宿主）
/bin,/lib…   usr symlink 或 ro-bind
/etc         tmpfs + ld.so.cache ro-bind
/dev         bwrap 最小 dev
/proc        新 procfs
/tmp         新 tmpfs
/workspace   宿主 workspace（可写，cwd）
```

/home、/root、/var、socket、设备与一切未列出路径**永不挂载**（§10.5）。

## 已知边界

- cgroup 委托是硬前提：无委托时 `require_cgroup` 拒绝，未要求时降级 rlimit 并记录诊断；
- 磁盘配额咨询性（§7.4）；
- seccomp 允许列表需在目标环境验证（默认关闭，见 docs/security-model.md）。
