//! Effective Policy & capability matching (design document §6.4, §9.3).
//!
//! The resolver combines a normalized, validated policy with the
//! [`PlatformCapabilities`] reported by a provider and decides:
//! * which isolation domains can be honored (fail closed otherwise),
//! * how each resource limit is enforced and by which mechanism,
//! * what must be recorded as degraded / unsupported.
//!
//! The result distinguishes *requested* from *applied* policy so callers can
//! never mistake a request for an actually enforced limit (§6.4).

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use nsk_core::capability::{CapabilityStatus, PlatformCapabilities, ResourceCapabilities};
use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::error::SandboxError;
#[allow(unused_imports)]
use nsk_core::policy::{IsolationPolicy, ProcessPolicy};
use nsk_core::policy::{
    NetworkPolicy, OutputPolicy, ResourceLimits, SandboxPolicy, SecurityPolicy,
};
use nsk_core::spec::SandboxSpec;
use nsk_core::validation as bounds;

use crate::normalize::normalize_spec;
use crate::validate::diagnose_spec;

/// How one requested limit is actually enforced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedLimit {
    pub kind: LimitKind,
    /// Requested value, rendered for reporting (e.g. "256 MiB").
    pub requested: String,
    /// Value actually applied, when available.
    pub effective: Option<String>,
    pub status: CapabilityStatus,
    /// Enforcement mechanism, e.g. "cgroup v2 memory.max" or "rlimit AS".
    pub mechanism: Option<String>,
    pub detail: Option<String>,
}

/// Kinds of enforceable limits (§5.7 / §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    WallTime,
    CpuTime,
    CpuQuota,
    Memory,
    Swap,
    Processes,
    OpenFiles,
    FileSize,
    Disk,
    Output,
}

impl fmt::Display for LimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LimitKind::WallTime => "wall_time",
            LimitKind::CpuTime => "cpu_time",
            LimitKind::CpuQuota => "cpu_quota",
            LimitKind::Memory => "memory",
            LimitKind::Swap => "swap",
            LimitKind::Processes => "processes",
            LimitKind::OpenFiles => "open_files",
            LimitKind::FileSize => "file_size",
            LimitKind::Disk => "disk",
            LimitKind::Output => "output",
        };
        f.write_str(s)
    }
}

/// Isolation domains actually applied (§5.6 IsolationPolicy).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedIsolation {
    pub process: CapabilityStatus,
    pub filesystem: CapabilityStatus,
    pub network: CapabilityStatus,
    pub ipc: CapabilityStatus,
    pub uts: CapabilityStatus,
    pub user: CapabilityStatus,
}

/// Filesystem policy as applied (§5.6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedFilesystem {
    pub root_isolation: CapabilityStatus,
    pub readonly_paths: Vec<String>,
    pub writable_paths: Vec<String>,
    pub deny_host_paths: bool,
}

/// Network policy as applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedNetwork {
    pub policy: NetworkPolicy,
    /// Mechanism, e.g. "network namespace (no interfaces)".
    pub enforced_by: String,
}

/// Security hardening as applied.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedSecurity {
    pub no_new_privileges: CapabilityStatus,
    pub drop_privileges: CapabilityStatus,
    pub seccomp: CapabilityStatus,
}

/// Process policy as applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedProcess {
    pub max_processes: u32,
    pub kill_process_tree: bool,
    /// Mechanism, e.g. "cgroup pids.max" or "rlimit NPROC".
    pub enforced_by: String,
}

/// The policy as it will actually be executed (§6.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppliedPolicy {
    pub isolation: AppliedIsolation,
    pub filesystem: AppliedFilesystem,
    pub network: AppliedNetwork,
    pub security: AppliedSecurity,
    pub process: AppliedProcess,
    pub output: OutputPolicy,
    pub resources: Vec<AppliedLimit>,
}

/// Resolved execution policy (§6.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivePolicy {
    pub requested: SandboxPolicy,
    pub applied: AppliedPolicy,
    pub capabilities: PlatformCapabilities,
    pub limitations: Vec<Diagnostic>,
}

/// Resolve a request into an [`EffectivePolicy`].
///
/// Pipeline (§6.2): structural validation → security validation → resource
/// validation → capability matching → normalization → effective policy.
///
/// # Errors
/// * [`SandboxError::PolicyValidation`] — request violates validation rules.
/// * [`SandboxError::CapabilityInsufficient`] — a *required* capability is
///   missing on this platform (fail-closed, §2.4).
pub fn resolve(
    spec: &SandboxSpec,
    capabilities: &PlatformCapabilities,
) -> Result<EffectivePolicy, SandboxError> {
    // 1) Normalize first so validation sees canonical values.
    let (normalized, mut limitations) = normalize_spec(spec);

    // 2) Validate (errors block; warnings join the limitations record).
    let diags = diagnose_spec(&normalized);
    let has_errors = diags
        .iter()
        .any(|d| d.severity == nsk_core::diagnostic::DiagnosticSeverity::Error);
    limitations.extend(diags);
    if has_errors {
        return Err(SandboxError::PolicyValidation(limitations));
    }

    // 3) Capability matching (fail-closed for mandatory requirements).
    let applied = match_policy(&normalized.policy, capabilities, &mut limitations)?;

    Ok(EffectivePolicy {
        requested: spec.policy.clone(),
        applied,
        capabilities: capabilities.clone(),
        limitations,
    })
}

/// Format byte sizes for reports.
pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Format a duration for reports.
pub fn format_duration(d: Duration) -> String {
    if d.as_secs() >= 1 {
        format!("{:.3}s", d.as_secs_f64())
    } else {
        format!("{}ms", d.as_millis())
    }
}

fn unavailable(code: &str, what: &str, status: CapabilityStatus) -> SandboxError {
    SandboxError::CapabilityInsufficient {
        code: code.to_string(),
        message: format!("required capability '{what}' is {status:?} on this platform"),
    }
}

/// Describe the network-isolation mechanism from the capability snapshot.
fn network_enforced_by(caps: &PlatformCapabilities) -> String {
    if caps.isolation.network_namespace.is_available() {
        "network namespace (no interfaces)".to_string()
    } else {
        "platform network-isolation mechanism (all socket operations denied)".to_string()
    }
}

/// Describe the loopback-only mechanism from the capability snapshot.
fn loopback_enforced_by(caps: &PlatformCapabilities) -> String {
    if caps.isolation.network_namespace.is_available() {
        "network namespace (loopback only)".to_string()
    } else {
        "platform network-isolation mechanism (loopback only)".to_string()
    }
}

/// Capability matching (§6.3 capability rules, §2.4 fail-closed).
fn match_policy(
    policy: &SandboxPolicy,
    caps: &PlatformCapabilities,
    limitations: &mut Vec<Diagnostic>,
) -> Result<AppliedPolicy, SandboxError> {
    let iso = &caps.isolation;
    let res = &caps.resources;
    let sec = &caps.security;
    let req_iso = &policy.isolation;

    // --- isolation domains -------------------------------------------------
    let check_domain = |requested: bool,
                        name: &str,
                        status: CapabilityStatus,
                        limitations: &mut Vec<Diagnostic>|
     -> Result<CapabilityStatus, SandboxError> {
        if !requested {
            return Ok(CapabilityStatus::NotConfigured);
        }
        if status.is_available() {
            Ok(CapabilityStatus::Available)
        } else {
            limitations.push(Diagnostic::error(
                codes::ISOLATION_FAILED,
                format!("isolation domain '{name}' requested but {status:?}"),
            ));
            Err(unavailable(
                codes::ISOLATION_FAILED,
                &format!("isolation.{name}"),
                status,
            ))
        }
    };

    let process = check_domain(
        req_iso.isolate_process,
        "process",
        iso.pid_namespace,
        limitations,
    )?;
    // Filesystem/network isolation is matched against the domain-level
    // mechanism fields: providers can satisfy these domains with mechanisms
    // other than namespaces (Seatbelt on macOS, AppContainer on Windows).
    let filesystem = check_domain(
        req_iso.isolate_filesystem,
        "filesystem",
        iso.filesystem_isolation,
        limitations,
    )?;
    let network = check_domain(
        req_iso.isolate_network,
        "network",
        iso.network_isolation,
        limitations,
    )?;
    let ipc = check_domain(req_iso.isolate_ipc, "ipc", iso.ipc_namespace, limitations)?;
    let uts = check_domain(req_iso.isolate_uts, "uts", iso.uts_namespace, limitations)?;

    // User namespace is requested implicitly by security requirements and by
    // the Linux provider; match it when either side needs it.
    let user = if policy.security.require_user_namespace {
        check_domain(true, "user", iso.user_namespace, limitations)?
    } else if iso.user_namespace.is_available() {
        CapabilityStatus::Available
    } else {
        CapabilityStatus::NotConfigured
    };

    // --- filesystem --------------------------------------------------------
    let root_isolation = if policy.filesystem.isolate_root {
        filesystem
    } else {
        CapabilityStatus::NotConfigured
    };
    let applied_fs = AppliedFilesystem {
        root_isolation,
        readonly_paths: policy
            .filesystem
            .readonly_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        writable_paths: policy
            .filesystem
            .writable_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        deny_host_paths: policy.filesystem.deny_host_paths,
    };

    // --- network -----------------------------------------------------------
    let applied_net = match policy.network {
        NetworkPolicy::Disabled => {
            if network.is_available() {
                AppliedNetwork {
                    policy: NetworkPolicy::Disabled,
                    enforced_by: network_enforced_by(caps),
                }
            } else {
                // Unreachable in practice: check_domain already failed when
                // isolate_network && net ns unavailable. Handle defensive case.
                AppliedNetwork {
                    policy: NetworkPolicy::Disabled,
                    enforced_by: "unavailable (no mechanism)".into(),
                }
            }
        }
        NetworkPolicy::LoopbackOnly => AppliedNetwork {
            policy: NetworkPolicy::LoopbackOnly,
            enforced_by: loopback_enforced_by(caps),
        },
        NetworkPolicy::Restricted | NetworkPolicy::AllowAll => {
            // Rejected by validation; defensive record only.
            limitations.push(Diagnostic::warning(
                codes::ISOLATION_NOT_APPLIED,
                format!(
                    "network policy {:?} has no phase-1 mechanism",
                    policy.network
                ),
            ));
            AppliedNetwork {
                policy: policy.network,
                enforced_by: "not enforced (phase 1)".into(),
            }
        }
    };

    // --- security ----------------------------------------------------------
    let nnp = match_nnp(&policy.security, sec, limitations)?;
    let drop = match_drop_privileges(&policy.security, sec, limitations)?;
    let seccomp_status = match_seccomp(&policy.security, sec, limitations)?;

    // --- resources ---------------------------------------------------------
    let resources = match_limits(&policy.resources, res, limitations)?;

    // --- process -----------------------------------------------------------
    // Process-limit mechanism ladder (§6.4): preventive per-sandbox limits
    // rank before degraded per-user rlimits, reactive watchdogs last.
    let enforced_by = if res.cgroup_v2.is_available() && res.controllers.pids.is_available() {
        "cgroup pids.max".to_string()
    } else if res.job_objects.is_available() {
        "Job Object active process limit (Windows)".to_string()
    } else if res.rlimit_processes.is_available() {
        "rlimit NPROC (per-user semantics; degraded)".to_string()
    } else if res.process_watchdog.is_available() {
        limitations.push(Diagnostic::warning(
            codes::RESOURCE_LIMIT_DEGRADED,
            "max_processes degraded to process-group watchdog (reactive; overshoot possible)",
        ));
        "process watchdog (group-size polling + kill; reactive)".to_string()
    } else {
        limitations.push(Diagnostic::error(
            codes::RESOURCE_LIMIT_UNAVAILABLE,
            "no mechanism to enforce max_processes",
        ));
        return Err(SandboxError::ResourceLimit(
            "max_processes cannot be enforced: no per-sandbox mechanism, no usable rlimit NPROC and no watchdog"
                .into(),
        ));
    };

    Ok(AppliedPolicy {
        isolation: AppliedIsolation {
            process,
            filesystem,
            network,
            ipc,
            uts,
            user,
        },
        filesystem: applied_fs,
        network: applied_net,
        security: AppliedSecurity {
            no_new_privileges: nnp,
            drop_privileges: drop,
            seccomp: seccomp_status,
        },
        process: AppliedProcess {
            max_processes: policy.process.max_processes,
            kill_process_tree: policy.process.kill_process_tree,
            enforced_by,
        },
        output: policy.output.clone(),
        resources,
    })
}

fn match_nnp(
    security: &SecurityPolicy,
    sec: &nsk_core::capability::SecurityCapabilities,
    limitations: &mut Vec<Diagnostic>,
) -> Result<CapabilityStatus, SandboxError> {
    if !security.no_new_privileges {
        return Ok(CapabilityStatus::NotConfigured);
    }
    if sec.no_new_privileges.is_available() {
        Ok(CapabilityStatus::Available)
    } else {
        limitations.push(Diagnostic::error(
            codes::ISOLATION_FAILED,
            "no_new_privileges requested but unavailable",
        ));
        Err(unavailable(
            codes::ISOLATION_FAILED,
            "security.no_new_privileges",
            sec.no_new_privileges,
        ))
    }
}

fn match_drop_privileges(
    security: &SecurityPolicy,
    sec: &nsk_core::capability::SecurityCapabilities,
    limitations: &mut Vec<Diagnostic>,
) -> Result<CapabilityStatus, SandboxError> {
    if !security.drop_privileges {
        return Ok(CapabilityStatus::NotConfigured);
    }
    if sec.privilege_dropping.is_available() {
        Ok(CapabilityStatus::Available)
    } else {
        // Dropping privileges is best-effort hardening; degrade with warning
        // instead of failing closed (the process is already unprivileged in
        // the typical kernel deployment).
        limitations.push(Diagnostic::warning(
            codes::ISOLATION_DEGRADED,
            format!(
                "privilege dropping unavailable ({:?}); continuing unprivileged",
                sec.privilege_dropping
            ),
        ));
        Ok(sec.privilege_dropping)
    }
}

fn match_seccomp(
    security: &SecurityPolicy,
    sec: &nsk_core::capability::SecurityCapabilities,
    limitations: &mut Vec<Diagnostic>,
) -> Result<CapabilityStatus, SandboxError> {
    if !security.use_seccomp {
        return Ok(CapabilityStatus::NotConfigured);
    }
    if sec.seccomp.is_available() {
        Ok(CapabilityStatus::Available)
    } else {
        limitations.push(Diagnostic::error(
            codes::ISOLATION_FAILED,
            format!("seccomp requested but {security:?} reports unavailable"),
        ));
        Err(unavailable(
            codes::ISOLATION_FAILED,
            "security.seccomp",
            sec.seccomp,
        ))
    }
}

/// Match resource limits to mechanisms and record per-limit application.
///
/// Each limit is resolved through a mechanism ladder (§6.4). Preventive
/// per-sandbox mechanisms rank before degraded per-process mechanisms, and
/// reactive watchdogs last: the ladder order encodes enforcement quality, and
/// the applied record names the exact rung actually used.
fn match_limits(
    limits: &ResourceLimits,
    res: &ResourceCapabilities,
    limitations: &mut Vec<Diagnostic>,
) -> Result<Vec<AppliedLimit>, SandboxError> {
    let mut out = Vec::new();

    // Wall time — supervisor-enforced, always available.
    out.push(AppliedLimit {
        kind: LimitKind::WallTime,
        requested: format_duration(limits.wall_time),
        effective: Some(format_duration(limits.wall_time)),
        status: CapabilityStatus::Available,
        mechanism: Some("supervisor wall-clock timer".into()),
        detail: None,
    });

    let cgroup_ok = res.cgroup_v2.is_available();
    let cgroup_memory = cgroup_ok && res.controllers.memory.is_available();
    let job_memory = res.job_objects.is_available();

    // Memory: cgroup memory.max → Job Object memory limit → rlimit AS
    // (degraded) → watchdog (reactive) → fail.
    out.push(if cgroup_memory {
        AppliedLimit {
            kind: LimitKind::Memory,
            requested: format_bytes(limits.memory_bytes),
            effective: Some(format_bytes(limits.memory_bytes)),
            status: CapabilityStatus::Available,
            mechanism: Some("cgroup v2 memory.max".into()),
            detail: None,
        }
    } else if job_memory {
        AppliedLimit {
            kind: LimitKind::Memory,
            requested: format_bytes(limits.memory_bytes),
            effective: Some(format_bytes(limits.memory_bytes)),
            status: CapabilityStatus::Available,
            mechanism: Some("Job Object process/job memory limit (Windows)".into()),
            detail: Some("commit-charge based; allocation beyond the limit fails in the child".into()),
        }
    } else if res.rlimit_address_space.is_available() {
        limitations.push(Diagnostic::warning(
            codes::RESOURCE_LIMIT_DEGRADED,
            "memory limit degraded to rlimit AS (virtual memory; coarse)",
        ));
        AppliedLimit {
            kind: LimitKind::Memory,
            requested: format_bytes(limits.memory_bytes),
            effective: Some(format_bytes(limits.memory_bytes)),
            status: CapabilityStatus::Available,
            mechanism: Some("rlimit AS (address space; degraded vs cgroup)".into()),
            detail: Some("virtual-memory based; shared mappings may distort semantics".into()),
        }
    } else if res.memory_watchdog.is_available() {
        limitations.push(Diagnostic::warning(
            codes::RESOURCE_LIMIT_DEGRADED,
            "memory limit degraded to monitor-and-kill watchdog (reactive; enforcement window ~100-300ms)",
        ));
        AppliedLimit {
            kind: LimitKind::Memory,
            requested: format_bytes(limits.memory_bytes),
            effective: Some(format_bytes(limits.memory_bytes)),
            status: CapabilityStatus::Available,
            mechanism: Some("memory watchdog (RSS polling + kill; reactive)".into()),
            detail: Some(
                "no preventive mechanism on this platform; usage is polled and the tree is killed on exceed (overshoot possible)"
                    .into(),
            ),
        }
    } else {
        limitations.push(Diagnostic::error(
            codes::RESOURCE_LIMIT_UNAVAILABLE,
            "memory limit cannot be enforced: no preventive mechanism and no watchdog",
        ));
        return Err(SandboxError::ResourceLimit(
            "memory_bytes cannot be enforced on this platform".into(),
        ));
    });

    // Swap.
    out.push(AppliedLimit {
        kind: LimitKind::Swap,
        requested: limits
            .swap_bytes
            .map(format_bytes)
            .unwrap_or_else(|| "0 (no swap)".into()),
        effective: if cgroup_memory {
            Some(format_bytes(limits.swap_bytes.unwrap_or(0)))
        } else {
            None
        },
        status: if cgroup_memory {
            CapabilityStatus::Available
        } else {
            CapabilityStatus::Unsupported
        },
        mechanism: if cgroup_memory {
            Some("cgroup v2 memory.swap.max".into())
        } else {
            None
        },
        detail: None,
    });

    // CPU quota — cgroup cpu.max → Job Object CPU rate control → degrade
    // (record, don't fail).
    out.push(if cgroup_ok && res.controllers.cpu.is_available() {
        AppliedLimit {
            kind: LimitKind::CpuQuota,
            requested: limits
                .cpu_quota
                .map(|q| format!("{:.2} cores", q.cores))
                .unwrap_or_else(|| "unlimited".into()),
            effective: limits
                .cpu_quota
                .map(|q| format!("{:.2} cores", q.cores)),
            status: CapabilityStatus::Available,
            mechanism: Some("cgroup v2 cpu.max".into()),
            detail: None,
        }
    } else if job_memory {
        let effective = limits
            .cpu_quota
            .map(|q| format!("{:.2} cores", q.cores));
        AppliedLimit {
            kind: LimitKind::CpuQuota,
            requested: limits
                .cpu_quota
                .map(|q| format!("{:.2} cores", q.cores))
                .unwrap_or_else(|| "unlimited".into()),
            status: if limits.cpu_quota.is_some() {
                CapabilityStatus::Available
            } else {
                CapabilityStatus::NotConfigured
            },
            mechanism: if limits.cpu_quota.is_some() {
                Some("Job Object CPU rate control (Windows; hard limit)".into())
            } else {
                None
            },
            effective,
            detail: Some("1% granularity (CpuRate is percent × 100)".into()),
        }
    } else {
        if limits.cpu_quota.is_some() {
            limitations.push(Diagnostic::warning(
                codes::RESOURCE_LIMIT_DEGRADED,
                "cpu_quota unsupported without a CPU rate mechanism; running unlimited (wall/cpu-time limits still enforced)",
            ));
        }
        AppliedLimit {
            kind: LimitKind::CpuQuota,
            requested: limits
                .cpu_quota
                .map(|q| format!("{:.2} cores", q.cores))
                .unwrap_or_else(|| "unlimited".into()),
            effective: None,
            status: CapabilityStatus::Unsupported,
            mechanism: None,
            detail: Some("requires cgroups v2 cpu controller or Job Object CPU rate control".into()),
        }
    });

    // CPU time — rlimit.
    out.push(AppliedLimit {
        kind: LimitKind::CpuTime,
        requested: limits
            .cpu_time
            .map(format_duration)
            .unwrap_or_else(|| "unlimited".into()),
        effective: limits.cpu_time.map(format_duration),
        status: if res.rlimits.is_available() && limits.cpu_time.is_some() {
            CapabilityStatus::Available
        } else if limits.cpu_time.is_none() {
            CapabilityStatus::NotConfigured
        } else {
            CapabilityStatus::Unsupported
        },
        mechanism: if limits.cpu_time.is_some() {
            Some("rlimit CPU".into())
        } else {
            None
        },
        detail: None,
    });

    // Open files — rlimit.
    out.push(AppliedLimit {
        kind: LimitKind::OpenFiles,
        requested: limits.max_open_files.to_string(),
        effective: if res.rlimits.is_available() {
            Some(limits.max_open_files.to_string())
        } else {
            None
        },
        status: if res.rlimits.is_available() {
            CapabilityStatus::Available
        } else {
            CapabilityStatus::Unsupported
        },
        mechanism: if res.rlimits.is_available() {
            Some("rlimit NOFILE".into())
        } else {
            None
        },
        detail: None,
    });

    // File size — rlimit FSIZE.
    out.push(AppliedLimit {
        kind: LimitKind::FileSize,
        requested: format_bytes(limits.max_file_size_bytes),
        effective: if res.rlimits.is_available() {
            Some(format_bytes(limits.max_file_size_bytes))
        } else {
            None
        },
        status: if res.rlimits.is_available() {
            CapabilityStatus::Available
        } else {
            CapabilityStatus::Unsupported
        },
        mechanism: if res.rlimits.is_available() {
            Some("rlimit FSIZE".into())
        } else {
            None
        },
        detail: None,
    });

    // Disk — advisory without a real quota mechanism.
    out.push(AppliedLimit {
        kind: LimitKind::Disk,
        requested: format_bytes(limits.max_disk_bytes),
        effective: None,
        status: CapabilityStatus::Unsupported,
        mechanism: None,
        detail: Some("phase 1: advisory only (workspace scan); no hard directory quota".into()),
    });

    // Output — supervisor-enforced, always available.
    out.push(AppliedLimit {
        kind: LimitKind::Output,
        requested: format_bytes(limits.max_output_bytes),
        effective: Some(format_bytes(limits.max_output_bytes)),
        status: CapabilityStatus::Available,
        mechanism: Some("bounded output collector".into()),
        detail: None,
    });

    // Sanity: wall time must satisfy bounds (defense in depth; validation
    // should already have caught violations).
    bounds::check_wall_time(limits.wall_time).map_err(|e| {
        SandboxError::ResourceLimit(format!("wall_time invalid after normalize: {e}"))
    })?;

    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use nsk_core::capability::{
        CgroupControllers, IsolationCapabilities, ResourceCapabilities, SecurityCapabilities,
        ToolInfo,
    };
    use nsk_core::spec::{CommandSpec, WorkspaceSpec};

    fn full_caps() -> PlatformCapabilities {
        let a = CapabilityStatus::Available;
        PlatformCapabilities {
            platform: nsk_core::capability::Platform::Linux,
            isolation: IsolationCapabilities {
                user_namespace: a,
                mount_namespace: a,
                pid_namespace: a,
                network_namespace: a,
                ipc_namespace: a,
                uts_namespace: a,
                filesystem_isolation: a,
                network_isolation: a,
                launcher: ToolInfo {
                    name: "bwrap".into(),
                    path: Some("/usr/bin/bwrap".into()),
                    version: Some("0.10".into()),
                    status: a,
                },
            },
            resources: ResourceCapabilities {
                cgroup_v2: a,
                controllers: CgroupControllers {
                    cpu: a,
                    memory: a,
                    pids: a,
                },
                rlimits: a,
                rlimit_address_space: a,
                rlimit_processes: a,
                job_objects: CapabilityStatus::Unsupported,
                memory_watchdog: CapabilityStatus::Unsupported,
                process_watchdog: CapabilityStatus::Unsupported,
                process_tree_kill: a,
                disk_quota: CapabilityStatus::Unsupported,
            },
            security: SecurityCapabilities {
                seccomp: a,
                no_new_privileges: a,
                privilege_dropping: a,
            },
            diagnostics: vec![],
        }
    }

    fn no_isolation_caps() -> PlatformCapabilities {
        let mut caps = full_caps();
        caps.isolation = IsolationCapabilities::unsupported();
        caps.resources.cgroup_v2 = CapabilityStatus::Unsupported;
        caps.resources.controllers = CgroupControllers::unsupported();
        caps.security.seccomp = CapabilityStatus::Unsupported;
        caps.security.no_new_privileges = CapabilityStatus::Unsupported;
        caps
    }

    /// Absolute executable that satisfies §6.3 validation on every platform
    /// ("/bin/echo" is not `is_absolute()` on Windows and fails NSK2000).
    fn any_absolute_exe() -> &'static str {
        if cfg!(windows) {
            "C:\\Windows\\System32\\cmd.exe"
        } else {
            "/bin/echo"
        }
    }

    fn spec(policy: SandboxPolicy) -> SandboxSpec {
        let mut s = SandboxSpec::new(CommandSpec::new(any_absolute_exe()));
        s.workspace = WorkspaceSpec::ephemeral();
        s.policy = policy;
        s
    }

    #[test]
    fn full_platform_satisfies_minimal_policy() {
        let eff = resolve(&spec(SandboxPolicy::minimal()), &full_caps()).expect("resolve");
        assert_eq!(eff.applied.isolation.network, CapabilityStatus::Available);
        let mem = eff
            .applied
            .resources
            .iter()
            .find(|l| l.kind == LimitKind::Memory)
            .expect("memory limit");
        assert_eq!(mem.status, CapabilityStatus::Available);
        assert_eq!(mem.mechanism.as_deref(), Some("cgroup v2 memory.max"));
        assert!(eff.limitations.is_empty());
    }

    #[test]
    fn missing_isolation_fails_closed() {
        let err = resolve(&spec(SandboxPolicy::minimal()), &no_isolation_caps())
            .expect_err("must refuse");
        assert!(matches!(err, SandboxError::CapabilityInsufficient { .. }));
    }

    #[test]
    fn relaxed_policy_runs_on_plain_host() {
        // No isolation requested → mock/host provider compatible policy.
        let mut policy = SandboxPolicy::minimal();
        policy.isolation = IsolationPolicy {
            isolate_process: false,
            isolate_filesystem: false,
            isolate_network: false,
            isolate_ipc: false,
            isolate_uts: false,
        };
        policy.filesystem.isolate_root = false;
        policy.filesystem.deny_host_paths = false;
        policy.security.no_new_privileges = false;
        policy.security.drop_privileges = false;

        let eff = resolve(&spec(policy), &no_isolation_caps()).expect("resolve");
        assert_eq!(
            eff.applied.isolation.network,
            CapabilityStatus::NotConfigured
        );
        // Memory degrades to rlimit AS with a warning.
        let mem = eff
            .applied
            .resources
            .iter()
            .find(|l| l.kind == LimitKind::Memory)
            .expect("memory limit");
        assert_eq!(
            mem.mechanism.as_deref(),
            Some("rlimit AS (address space; degraded vs cgroup)")
        );
        assert!(
            eff.limitations
                .iter()
                .any(|d| d.code == codes::RESOURCE_LIMIT_DEGRADED)
        );
    }

    #[test]
    fn cpu_quota_degrades_with_warning_not_error() {
        let mut caps = full_caps();
        caps.resources.cgroup_v2 = CapabilityStatus::Unsupported;
        caps.resources.controllers = CgroupControllers::unsupported();
        let eff = resolve(&spec(SandboxPolicy::minimal()), &caps).expect("resolve");
        let quota = eff
            .applied
            .resources
            .iter()
            .find(|l| l.kind == LimitKind::CpuQuota)
            .expect("quota limit");
        assert_eq!(quota.status, CapabilityStatus::Unsupported);
        assert!(
            eff.limitations
                .iter()
                .any(|d| d.message.contains("cpu_quota unsupported"))
        );
    }

    #[test]
    fn required_cgroup_missing_fails_when_required() {
        // require_cgroup is enforced by the provider layer at prepare time
        // (it owns cgroup creation); resolver records user-namespace and
        // seccomp requirements. Verify seccomp requirement fails closed.
        let mut policy = SandboxPolicy::minimal();
        policy.security.use_seccomp = true;
        policy.security.require_seccomp = true;
        let mut caps = full_caps();
        caps.security.seccomp = CapabilityStatus::NotConfigured;
        let err = resolve(&spec(policy), &caps).expect_err("must refuse");
        assert!(matches!(err, SandboxError::CapabilityInsufficient { .. }));
    }

    #[test]
    fn requested_policy_is_preserved_verbatim() {
        let policy = SandboxPolicy::strict();
        let eff = resolve(&spec(policy.clone()), &full_caps()).expect("resolve");
        assert_eq!(eff.requested, policy);
        assert_eq!(eff.applied.process.max_processes, 8);
    }

    #[test]
    fn formatting_helpers() {
        assert_eq!(format_bytes(256 * 1024 * 1024), "256.0 MiB");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_duration(Duration::from_millis(1500)), "1.500s");
        assert_eq!(format_duration(Duration::from_millis(150)), "150ms");
    }

    #[test]
    fn disk_limit_is_advisory() {
        let eff = resolve(&spec(SandboxPolicy::minimal()), &full_caps()).expect("resolve");
        let disk = eff
            .applied
            .resources
            .iter()
            .find(|l| l.kind == LimitKind::Disk)
            .expect("disk limit");
        assert_eq!(disk.status, CapabilityStatus::Unsupported);
        assert!(disk.detail.as_deref().unwrap().contains("advisory"));
    }

    /// Windows-style capability snapshot: Job Objects, no namespaces, no
    /// rlimits, no cgroups.
    fn windows_caps() -> PlatformCapabilities {
        let mut caps = full_caps();
        caps.platform = nsk_core::capability::Platform::Windows;
        caps.isolation = IsolationCapabilities::unsupported();
        caps.resources.cgroup_v2 = CapabilityStatus::Unsupported;
        caps.resources.controllers = CgroupControllers::unsupported();
        caps.resources.rlimits = CapabilityStatus::Unsupported;
        caps.resources.rlimit_address_space = CapabilityStatus::Unsupported;
        caps.resources.rlimit_processes = CapabilityStatus::Unsupported;
        caps.resources.job_objects = CapabilityStatus::Available;
        caps.resources.process_tree_kill = CapabilityStatus::Available;
        caps.security = SecurityCapabilities::unsupported();
        caps.security.privilege_dropping = CapabilityStatus::NotConfigured;
        caps
    }

    /// macOS-style capability snapshot: Seatbelt filesystem/network
    /// isolation, usable rlimits, reactive watchdogs, no namespaces/cgroups.
    fn macos_caps() -> PlatformCapabilities {
        let mut caps = full_caps();
        caps.platform = nsk_core::capability::Platform::MacOS;
        caps.isolation = IsolationCapabilities::unsupported();
        caps.isolation.filesystem_isolation = CapabilityStatus::Available;
        caps.isolation.network_isolation = CapabilityStatus::Available;
        caps.resources.cgroup_v2 = CapabilityStatus::Unsupported;
        caps.resources.controllers = CgroupControllers::unsupported();
        caps.resources.rlimit_address_space = CapabilityStatus::Unsupported;
        caps.resources.rlimit_processes = CapabilityStatus::Unsupported;
        caps.resources.job_objects = CapabilityStatus::Unsupported;
        caps.resources.memory_watchdog = CapabilityStatus::Available;
        caps.resources.process_watchdog = CapabilityStatus::Available;
        caps.resources.process_tree_kill = CapabilityStatus::Available;
        caps.security.seccomp = CapabilityStatus::Unsupported;
        caps.security.privilege_dropping = CapabilityStatus::Unsupported;
        caps
    }

    /// A policy compatible with providers that lack namespace-style process/
    /// ipc/uts isolation (Windows, macOS): filesystem+network isolation
    /// requested, the other domains off.
    fn domain_policy() -> SandboxPolicy {
        let mut policy = SandboxPolicy::minimal();
        policy.isolation = IsolationPolicy {
            isolate_process: false,
            isolate_filesystem: true,
            isolate_network: true,
            isolate_ipc: false,
            isolate_uts: false,
        };
        policy
    }

    /// Domain-isolation-free policy with limits intact (Windows-compatible).
    fn windows_policy() -> SandboxPolicy {
        let mut policy = SandboxPolicy::minimal();
        policy.isolation = IsolationPolicy {
            isolate_process: false,
            isolate_filesystem: false,
            isolate_network: false,
            isolate_ipc: false,
            isolate_uts: false,
        };
        policy.filesystem.isolate_root = false;
        policy.filesystem.deny_host_paths = false;
        policy.security.no_new_privileges = false;
        policy
    }

    #[test]
    fn windows_job_objects_enforce_memory_and_processes() {
        let eff = resolve(&spec(windows_policy()), &windows_caps()).expect("resolve");
        let mem = eff
            .applied
            .resources
            .iter()
            .find(|l| l.kind == LimitKind::Memory)
            .expect("memory limit");
        assert_eq!(
            mem.mechanism.as_deref(),
            Some("Job Object process/job memory limit (Windows)")
        );
        assert_eq!(
            eff.applied.process.enforced_by,
            "Job Object active process limit (Windows)"
        );
        let quota = eff
            .applied
            .resources
            .iter()
            .find(|l| l.kind == LimitKind::CpuQuota)
            .expect("quota limit");
        assert_eq!(quota.status, CapabilityStatus::Available);
        assert!(quota.mechanism.as_deref().unwrap().contains("Job Object"));
    }

    #[test]
    fn windows_still_fails_closed_on_fs_network_isolation() {
        // Job Objects provide no filesystem/network isolation (§11.3).
        let err = resolve(&spec(domain_policy()), &windows_caps()).expect_err("must refuse");
        assert!(matches!(err, SandboxError::CapabilityInsufficient { .. }));
    }

    #[test]
    fn macos_watchdog_ladder_is_used() {
        let eff = resolve(&spec(domain_policy()), &macos_caps()).expect("resolve");
        let mem = eff
            .applied
            .resources
            .iter()
            .find(|l| l.kind == LimitKind::Memory)
            .expect("memory limit");
        assert_eq!(
            mem.mechanism.as_deref(),
            Some("memory watchdog (RSS polling + kill; reactive)")
        );
        assert!(eff.applied.process.enforced_by.contains("process watchdog"));
        // Filesystem and network domains resolve via the domain-level fields.
        assert_eq!(
            eff.applied.isolation.filesystem,
            CapabilityStatus::Available
        );
        assert_eq!(eff.applied.isolation.network, CapabilityStatus::Available);
        // Degrade warnings are recorded.
        assert!(
            eff.limitations
                .iter()
                .any(|d| d.code == codes::RESOURCE_LIMIT_DEGRADED)
        );
    }

    #[test]
    fn macos_still_fails_closed_on_process_ipc_uts_domains() {
        // Seatbelt provides no process/ipc/uts isolation.
        let err = resolve(&spec(SandboxPolicy::minimal()), &macos_caps()).expect_err("must refuse");
        assert!(matches!(err, SandboxError::CapabilityInsufficient { .. }));
    }

    #[test]
    fn no_mechanism_at_all_fails_closed() {
        let mut caps = macos_caps();
        caps.resources.memory_watchdog = CapabilityStatus::Unsupported;
        caps.resources.process_watchdog = CapabilityStatus::Unsupported;
        let err = resolve(&spec(domain_policy()), &caps).expect_err("must refuse");
        assert!(matches!(err, SandboxError::ResourceLimit(_)));
    }
}
