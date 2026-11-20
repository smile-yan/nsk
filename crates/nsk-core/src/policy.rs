//! Execution policy model (design document §5.6, §5.7, §17).
//!
//! The policy describes **what the caller asks for**. The Policy Engine
//! (`nsk-policy`) validates, normalizes and capability-matches it into an
//! `EffectivePolicy` describing what is **actually applied**.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Isolation domains requested for a sandbox (§5.6 IsolationPolicy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolationPolicy {
    pub isolate_process: bool,
    pub isolate_filesystem: bool,
    pub isolate_network: bool,
    pub isolate_ipc: bool,
    pub isolate_uts: bool,
}

/// Filesystem-level access policy (§5.6 FilesystemPolicy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    /// Host paths mounted read-only into the sandbox.
    pub readonly_paths: Vec<PathBuf>,
    /// Paths writable from inside the sandbox (plus the workspace root).
    pub writable_paths: Vec<PathBuf>,
    /// Refuse execution when unlisted host paths would be reachable.
    pub deny_host_paths: bool,
    /// Require a container-style root instead of the host root.
    pub isolate_root: bool,
}

impl Default for FilesystemPolicy {
    /// Secure defaults: deny unlisted host paths and require an isolated root.
    fn default() -> Self {
        Self {
            readonly_paths: Vec::new(),
            writable_paths: Vec::new(),
            deny_host_paths: true,
            isolate_root: true,
        }
    }
}

/// Network access policy (§5.6 NetworkPolicy).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// No network access at all. This is the secure default.
    #[default]
    Disabled,
    /// Only loopback interfaces inside an isolated network namespace.
    LoopbackOnly,
    /// Restricted: only explicitly allowed endpoints (not implemented in Phase 1).
    Restricted,
    /// Full host network. Refused unless the provider explicitly supports it.
    AllowAll,
}

/// Security hardening switches (§5.6 SecurityPolicy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub drop_privileges: bool,
    pub no_new_privileges: bool,
    /// Opt-in seccomp allowlist profile (experimental, see §10.8).
    pub use_seccomp: bool,
    /// Fail closed when seccomp cannot be applied.
    pub require_seccomp: bool,
    /// Fail closed when user namespaces are unavailable.
    pub require_user_namespace: bool,
    /// Fail closed when cgroups v2 (and required controllers) are unavailable.
    pub require_cgroup: bool,
}

/// Process-related policy (§5.6 ProcessPolicy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessPolicy {
    pub max_processes: u32,
    pub kill_process_tree: bool,
    pub allow_daemonize: bool,
}

/// Output limits (§5.6 OutputPolicy).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputPolicy {
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub combined_limit_bytes: u64,
    pub terminate_on_limit: bool,
}

/// Resource limits (§5.7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Hard wall-clock deadline for the whole execution.
    pub wall_time: Duration,
    /// Optional CPU-time budget (enforced via rlimit where supported).
    pub cpu_time: Option<Duration>,
    /// Optional CPU rate quota (enforced via cgroups where supported).
    pub cpu_quota: Option<CpuQuota>,
    pub memory_bytes: u64,
    /// Swap allowance; `None` means provider default (usually "no extra swap").
    pub swap_bytes: Option<u64>,
    pub max_processes: u32,
    pub max_open_files: u64,
    /// Per-file size cap (RLIMIT_FSIZE where supported).
    pub max_file_size_bytes: u64,
    /// Workspace disk budget (advisory where no hard quota exists).
    pub max_disk_bytes: u64,
    /// Global output ceiling; must be >= `OutputPolicy::combined_limit_bytes`.
    pub max_output_bytes: u64,
}

/// CPU rate quota in cores (§5.7).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CpuQuota {
    pub cores: f64,
}

impl CpuQuota {
    pub const fn new(cores: f64) -> Self {
        Self { cores }
    }
}

/// The full requested sandbox policy (§5.6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    pub isolation: IsolationPolicy,
    pub resources: ResourceLimits,
    pub filesystem: FilesystemPolicy,
    pub network: NetworkPolicy,
    pub security: SecurityPolicy,
    pub process: ProcessPolicy,
    pub output: OutputPolicy,
}

impl SandboxPolicy {
    /// Minimal profile (§17.1): baseline restricted execution for ordinary
    /// programs. These values are development reference defaults, not
    /// security guarantees (§17 preamble).
    pub fn minimal() -> Self {
        Self {
            isolation: IsolationPolicy::default(),
            resources: ResourceLimits {
                wall_time: Duration::from_secs(5),
                cpu_time: None,
                cpu_quota: Some(CpuQuota::new(1.0)),
                memory_bytes: 256 * 1024 * 1024,
                swap_bytes: None,
                max_processes: 16,
                max_open_files: 64,
                max_file_size_bytes: 16 * 1024 * 1024,
                max_disk_bytes: 64 * 1024 * 1024,
                max_output_bytes: 8 * 1024 * 1024,
            },
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::Disabled,
            security: SecurityPolicy::default(),
            process: ProcessPolicy {
                max_processes: 16,
                kill_process_tree: true,
                allow_daemonize: false,
            },
            output: OutputPolicy {
                max_stdout_bytes: 8 * 1024 * 1024,
                max_stderr_bytes: 8 * 1024 * 1024,
                combined_limit_bytes: 8 * 1024 * 1024,
                terminate_on_limit: true,
            },
        }
    }

    /// Strict profile (§17.2).
    pub fn strict() -> Self {
        let mut p = Self::minimal();
        p.resources = ResourceLimits {
            wall_time: Duration::from_secs(2),
            cpu_time: None,
            cpu_quota: Some(CpuQuota::new(1.0)),
            memory_bytes: 128 * 1024 * 1024,
            swap_bytes: None,
            max_processes: 8,
            max_open_files: 32,
            max_file_size_bytes: 8 * 1024 * 1024,
            max_disk_bytes: 32 * 1024 * 1024,
            max_output_bytes: 4 * 1024 * 1024,
        };
        p.process.max_processes = 8;
        p.output = OutputPolicy {
            max_stdout_bytes: 4 * 1024 * 1024,
            max_stderr_bytes: 4 * 1024 * 1024,
            combined_limit_bytes: 4 * 1024 * 1024,
            terminate_on_limit: true,
        };
        p.security.require_user_namespace = true;
        p.security.require_cgroup = true;
        p
    }

    /// Extended profile (§17.3).
    pub fn extended() -> Self {
        let mut p = Self::minimal();
        p.resources = ResourceLimits {
            wall_time: Duration::from_secs(30),
            cpu_time: None,
            cpu_quota: Some(CpuQuota::new(2.0)),
            memory_bytes: 1024 * 1024 * 1024,
            swap_bytes: None,
            max_processes: 64,
            max_open_files: 128,
            max_file_size_bytes: 64 * 1024 * 1024,
            max_disk_bytes: 256 * 1024 * 1024,
            max_output_bytes: 32 * 1024 * 1024,
        };
        p.process.max_processes = 64;
        p.output = OutputPolicy {
            max_stdout_bytes: 32 * 1024 * 1024,
            max_stderr_bytes: 32 * 1024 * 1024,
            combined_limit_bytes: 32 * 1024 * 1024,
            terminate_on_limit: true,
        };
        p
    }
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self::minimal()
    }
}

impl Default for IsolationPolicy {
    /// Secure defaults: request every isolation domain (fail-closed posture,
    /// §2.4). The Policy Engine will refuse execution when the platform
    /// cannot provide a requested domain.
    fn default() -> Self {
        Self {
            isolate_process: true,
            isolate_filesystem: true,
            isolate_network: true,
            isolate_ipc: true,
            isolate_uts: true,
        }
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            drop_privileges: true,
            no_new_privileges: true,
            use_seccomp: false,
            require_seccomp: false,
            require_user_namespace: false,
            require_cgroup: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation;

    #[test]
    fn profiles_match_reference_values() {
        let m = SandboxPolicy::minimal();
        assert_eq!(m.resources.wall_time, Duration::from_secs(5));
        assert_eq!(m.resources.memory_bytes, 256 * 1024 * 1024);
        assert_eq!(m.process.max_processes, 16);
        assert_eq!(m.network, NetworkPolicy::Disabled);
        assert!(m.filesystem.deny_host_paths);

        let s = SandboxPolicy::strict();
        assert_eq!(s.resources.wall_time, Duration::from_secs(2));
        assert_eq!(s.resources.memory_bytes, 128 * 1024 * 1024);
        assert_eq!(s.output.combined_limit_bytes, 4 * 1024 * 1024);

        let e = SandboxPolicy::extended();
        assert_eq!(e.resources.wall_time, Duration::from_secs(30));
        assert_eq!(e.resources.memory_bytes, 1024 * 1024 * 1024);
        assert_eq!(e.output.combined_limit_bytes, 32 * 1024 * 1024);
    }

    #[test]
    fn secure_defaults_request_isolation() {
        let p = SandboxPolicy::default();
        assert!(p.isolation.isolate_network);
        assert!(p.isolation.isolate_filesystem);
        assert!(p.security.no_new_privileges);
        assert!(p.output.terminate_on_limit);
    }

    #[test]
    fn serde_roundtrip() {
        let p = SandboxPolicy::strict();
        let json = serde_json::to_string(&p).unwrap();
        let back: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn bounds_are_consistent_with_profiles() {
        for (name, p) in [
            ("minimal", SandboxPolicy::minimal()),
            ("strict", SandboxPolicy::strict()),
            ("extended", SandboxPolicy::extended()),
        ] {
            validation::check_wall_time(p.resources.wall_time)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            validation::check_memory(p.resources.memory_bytes)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(p.output.combined_limit_bytes <= p.resources.max_output_bytes);
        }
    }
}
