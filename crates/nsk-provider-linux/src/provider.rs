//! LinuxProvider assembly (§10.2 architecture, §10.9 execution flow).
//!
//! Flow (§10.9): validate spec → resolve policy → probe capabilities →
//! prepare workspace (runtime) → create cgroup → apply limits → build bwrap
//! config → spawn → attach cgroup → monitor (supervisor) → collect →
//! cleanup.
//!
//! Fail-closed rules (§2.4):
//! * launcher unavailable + filesystem/process/network isolation requested
//!   → refused by the Policy Engine before we get here;
//! * `require_cgroup` and the cgroup controller is missing → refused here;
//! * cgroup attach fails after spawn → the process is killed immediately.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use nsk_core::capability::PlatformCapabilities;
use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::error::SandboxError;
use nsk_core::id::SandboxId;
use nsk_core::policy::NetworkPolicy;
use nsk_core::result::ResourceUsage;
use nsk_provider::traits::{
    ExecutionPlan, PrepareContext, PreparedSandbox, ProviderResources, RunningSandbox,
    SandboxProvider, SpawnContext,
};
use nsk_resource::limits::{CgroupLimitFiles, RlimitSpec};

use crate::bwrap::{BwrapOptions, build_bwrap_args};
use crate::cgroup::CgroupManager;
use crate::cleanup::{CleanupTarget, cleanup_sandbox};
use crate::mount::{SystemMountSet, build_default_mount_plan, path_mapper};
use crate::probe::probe_with_config;
use crate::seccomp::{SECCOMP_AUX_FD, SeccompArch, SeccompDefaultAction, SeccompProfile};

/// seccomp profile selection (§10.8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompChoice {
    /// No seccomp filter (phase-1 default; profile is experimental).
    #[default]
    Off,
    /// Default action EPERM — compatibility profile.
    Compatible,
    /// Default action KILL_THREAD — strict profile.
    Strict,
}

/// Linux provider configuration.
#[derive(Debug, Clone)]
pub struct LinuxProviderConfig {
    /// Explicit bwrap path (default: PATH lookup).
    pub bwrap_path: Option<PathBuf>,
    /// cgroup v2 root (default `/sys/fs/cgroup`).
    pub cgroup_root: PathBuf,
    /// System mount set (default minimal set for the host).
    pub system_mounts: SystemMountSet,
    /// seccomp profile choice (default off).
    pub seccomp_profile: SeccompChoice,
}

impl Default for LinuxProviderConfig {
    fn default() -> Self {
        Self {
            bwrap_path: None,
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            system_mounts: SystemMountSet::default_for_host(),
            seccomp_profile: SeccompChoice::Off,
        }
    }
}

/// Resources owned by a running Linux sandbox.
#[derive(Debug)]
pub struct LinuxResources {
    pub cgroup: Option<CgroupManager>,
    pub owned_files: Vec<PathBuf>,
    /// seccomp profile passed to bwrap via `--seccomp-fd`.
    pub seccomp_file: Option<PathBuf>,
    pub id: SandboxId,
}

impl ProviderResources for LinuxResources {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn kill_all(&self) -> Result<(), SandboxError> {
        if let Some(cg) = &self.cgroup {
            cg.kill_all()?;
        }
        Ok(())
    }

    fn observe_usage(&self) -> Result<ResourceUsage, SandboxError> {
        Ok(self
            .cgroup
            .as_ref()
            .map(|cg| cg.observe_usage())
            .unwrap_or_default())
    }

    fn cleanup(&self) -> Result<Vec<Diagnostic>, SandboxError> {
        cleanup_sandbox(&CleanupTarget {
            id: self.id,
            cgroup: self.cgroup.clone(),
            owned_files: self.owned_files.clone(),
        })
    }
}

/// The phase-1 Linux isolation provider.
#[derive(Debug, Clone)]
pub struct LinuxProvider {
    config: LinuxProviderConfig,
    probe_cache: Arc<tokio::sync::OnceCell<PlatformCapabilities>>,
}

impl LinuxProvider {
    pub fn new(config: LinuxProviderConfig) -> Self {
        Self {
            config,
            probe_cache: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Capabilities, probed once per provider instance.
    pub async fn capabilities(&self) -> Result<PlatformCapabilities, SandboxError> {
        let config = self.config.clone();
        Ok(self
            .probe_cache
            .get_or_init(|| async move { probe_with_config(&config).await })
            .await
            .clone())
    }

    /// Build the bwrap plan for one sandbox (unit-testable).
    fn build_execution_plan(
        &self,
        ctx: &PrepareContext,
        caps: &PlatformCapabilities,
        seccomp_file: Option<PathBuf>,
    ) -> Result<ExecutionPlan, SandboxError> {
        let spec = &ctx.spec;
        let policy = &ctx.policy;

        let mapper = path_mapper(
            &ctx.workspace.root,
            &policy.requested.filesystem,
            &self.config.system_mounts,
        );

        // Map executable + working dir to sandbox paths (fail closed on
        // unmapped paths — §6.3 path rules).
        let exe_sandbox = mapper
            .to_sandbox_path(&spec.command.executable)
            .ok_or_else(|| SandboxError::Isolation(format!(
                "executable {} is not reachable inside the sandbox (add it to filesystem.readonly_paths or place it in the workspace)",
                spec.command.executable.display()
            )))?;
        let cwd_host = spec.working_directory(&ctx.workspace.root);
        let cwd_sandbox = mapper.to_sandbox_path(cwd_host).ok_or_else(|| {
            SandboxError::Isolation(format!(
                "working directory {} is not reachable inside the sandbox",
                cwd_host.display()
            ))
        })?;

        let plan_mounts = build_default_mount_plan(
            &ctx.workspace.root,
            &policy.requested.filesystem,
            &policy.requested.isolation,
            &self.config.system_mounts,
        );

        // Environment: sandbox defaults + explicit whitelist (never the host
        // environment, §5.4).
        let mut env: Vec<(String, String)> = vec![
            (
                "PATH".into(),
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
            ),
            ("HOME".into(), "/workspace".into()),
            ("TMPDIR".into(), "/tmp".into()),
            ("LANG".into(), "C.UTF-8".into()),
        ];
        for var in &spec.environment.variables {
            // Whitelist entries override defaults deliberately.
            env.retain(|(k, _)| k != &var.key);
            env.push((var.key.clone(), var.value.clone()));
        }

        let seccomp_fd = seccomp_file.map(|_| SECCOMP_AUX_FD);
        let options = BwrapOptions {
            unshare_all: true,
            session_hygiene: true,
            seccomp_fd,
            env,
            chdir: cwd_sandbox,
        };

        let mut argv = vec![
            self.config
                .bwrap_path
                .clone()
                .or_else(|| crate::probe::find_in_path("bwrap"))
                .ok_or_else(|| SandboxError::Isolation("bwrap not found".into()))?
                .display()
                .to_string(),
        ];
        argv.extend(build_bwrap_args(&plan_mounts, &options));
        argv.push(exe_sandbox.display().to_string());
        for a in &spec.command.args {
            argv.push(a.to_string_lossy().to_string());
        }

        let _ = caps; // capability snapshot already enforced by resolve()
        let mut rlimits = vec![
            RlimitSpec::OpenFiles(spec.policy.resources.max_open_files),
            RlimitSpec::FileSize(spec.policy.resources.max_file_size_bytes),
        ];
        if let Some(cpu_time) = spec.policy.resources.cpu_time {
            rlimits.push(RlimitSpec::CpuTime(cpu_time.as_secs().max(1)));
        }
        if !caps.resources.cgroup_v2.is_available() {
            // No cgroups: degrade memory enforcement to rlimit AS, matching
            // the resolver's recorded decision.
            rlimits.push(RlimitSpec::AddressSpace(spec.policy.resources.memory_bytes));
        }

        Ok(ExecutionPlan {
            argv,
            cwd: Some(ctx.workspace.root.clone()),
            env: Vec::new(), // environment is passed via bwrap --setenv
            stdin: spec.command.stdin.clone(),
            process_group: true,
            rlimits,
        })
    }

    /// Create + configure the cgroup when required/possible.
    async fn setup_cgroup(
        &self,
        ctx: &PrepareContext,
        caps: &PlatformCapabilities,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> Result<Option<CgroupManager>, SandboxError> {
        let policy = &ctx.policy;
        let security = &policy.requested.security;
        let require_cgroup = security.require_cgroup;
        let needs_cgroup = caps.resources.cgroup_v2.is_available();

        if !needs_cgroup {
            if require_cgroup {
                return Err(SandboxError::ResourceLimit(
                    "security.require_cgroup set but cgroups v2 unavailable on this host".into(),
                ));
            }
            diagnostics.push(Diagnostic::warning(
                codes::RESOURCE_LIMIT_UNAVAILABLE,
                "cgroups v2 unavailable; memory degrades to rlimit AS, pids to rlimit NPROC",
            ));
            return Ok(None);
        }

        let manager = CgroupManager::create(&self.config.cgroup_root, &format!("nsk-{}", ctx.id))
            .map_err(|e| {
                if require_cgroup {
                    e
                } else {
                    SandboxError::ResourceLimit(format!(
                        "cgroup creation failed: {e}; continuing without cgroup limits (require_cgroup not set)"
                    ))
                }
            })?;

        if !manager.group.exists() {
            return Ok(None);
        }

        // Apply limits per controller availability (§10.7).
        let r = &policy.requested.resources;
        let mut applied = Vec::new();

        if let Ok(true) = manager.write_limit_if_controller(
            "memory",
            CgroupLimitFiles::MEMORY_MAX,
            &r.memory_bytes.to_string(),
        ) {
            applied.push("memory.max");
            let swap = r.swap_bytes.unwrap_or(0).to_string();
            let _ = manager.write_limit_if_controller(
                "memory",
                CgroupLimitFiles::MEMORY_SWAP_MAX,
                &swap,
            );
        } else if require_cgroup {
            return Err(SandboxError::ResourceLimit(
                "memory controller not delegated; require_cgroup set".into(),
            ));
        } else {
            diagnostics.push(Diagnostic::warning(
                codes::RESOURCE_LIMIT_DEGRADED,
                "memory controller unavailable; memory limit will use rlimit AS",
            ));
        }

        if let Some(quota) = &r.cpu_quota {
            let cpu_max = nsk_resource::limits::cpu_quota_to_cgroup_max(quota.cores, 100_000);
            if let Ok(true) =
                manager.write_limit_if_controller("cpu", CgroupLimitFiles::CPU_MAX, &cpu_max)
            {
                applied.push("cpu.max");
            } else {
                diagnostics.push(Diagnostic::warning(
                    codes::RESOURCE_LIMIT_DEGRADED,
                    "cpu controller unavailable; cpu_quota not enforced",
                ));
            }
        }

        let pids_max = r.max_processes.to_string();
        if let Ok(true) =
            manager.write_limit_if_controller("pids", CgroupLimitFiles::PIDS_MAX, &pids_max)
        {
            applied.push("pids.max");
        } else {
            diagnostics.push(Diagnostic::warning(
                codes::RESOURCE_LIMIT_DEGRADED,
                "pids controller unavailable; process limit degrades to rlimit NPROC",
            ));
        }

        debug!(cgroup = %manager.group.display(), applied = ?applied, "cgroup limits applied");
        Ok(Some(manager))
    }
}

#[async_trait]
impl SandboxProvider for LinuxProvider {
    fn name(&self) -> &'static str {
        "linux"
    }

    async fn probe(&self) -> Result<PlatformCapabilities, SandboxError> {
        self.capabilities().await
    }

    async fn prepare(&self, ctx: PrepareContext) -> Result<PreparedSandbox, SandboxError> {
        let caps = self.capabilities().await?;
        let mut diagnostics: Vec<Diagnostic> = Vec::new();

        // seccomp profile (§10.8): generated by the kernel only.
        let seccomp_file = match self.config.seccomp_profile {
            SeccompChoice::Off => None,
            choice => {
                if !caps.security.seccomp.is_available() {
                    if ctx.policy.requested.security.require_seccomp {
                        return Err(SandboxError::Isolation(
                            "seccomp required but unavailable".into(),
                        ));
                    }
                    diagnostics.push(Diagnostic::warning(
                        codes::ISOLATION_NOT_APPLIED,
                        "seccomp profile requested but not verified available; skipped",
                    ));
                    None
                } else {
                    let arch = SeccompArch::current().ok_or_else(|| {
                        SandboxError::Isolation("unsupported architecture for seccomp".into())
                    })?;
                    let action = match choice {
                        SeccompChoice::Strict => SeccompDefaultAction::KillThread,
                        _ => SeccompDefaultAction::ErrnoPerm,
                    };
                    let profile = SeccompProfile::validated_default(arch, action);
                    let dir = tempfile_dir()?;
                    let path = crate::seccomp::write_profile_file(&profile, &dir).map_err(|e| {
                        SandboxError::Isolation(format!("write seccomp profile: {e}"))
                    })?;
                    info!(path = %path.display(), profile = %crate::seccomp::describe(&profile), "seccomp profile prepared");
                    diagnostics.push(Diagnostic::info(
                        codes::CAPABILITY_UNVERIFIED,
                        format!(
                            "experimental seccomp profile applied: {}",
                            crate::seccomp::describe(&profile)
                        ),
                    ));
                    Some(path)
                }
            }
        };

        // Network policy is enforced by the namespace (--unshare-all).
        if ctx.policy.requested.network == NetworkPolicy::Disabled {
            debug!("network disabled via network namespace");
        }

        let cgroup = self.setup_cgroup(&ctx, &caps, &mut diagnostics).await?;
        let plan = self.build_execution_plan(&ctx, &caps, seccomp_file.clone())?;

        let owned_files: Vec<PathBuf> = seccomp_file.iter().cloned().collect();

        Ok(PreparedSandbox {
            id: ctx.id,
            provider_name: self.name(),
            plan,
            resources: Some(Arc::new(LinuxResources {
                cgroup,
                owned_files,
                seccomp_file,
                id: ctx.id,
            })),
        })
    }

    async fn spawn(
        &self,
        prepared: PreparedSandbox,
        ctx: SpawnContext,
    ) -> Result<RunningSandbox, SandboxError> {
        let mut process_spec = prepared.plan.clone().into_process_spec();

        // Hand the seccomp profile to bwrap via a fixed aux fd (§10.8):
        // the supervisor opens the file pre-exec and dups it onto the fd
        // referenced by the `--seccomp-fd` argument.
        if prepared.plan.argv.iter().any(|a| a == "--seccomp-fd") {
            if let Some(res) = &prepared.resources {
                if let Some(seccomp_path) = seccomp_path_of(res.as_ref()) {
                    process_spec = process_spec.pre_open(seccomp_path, SECCOMP_AUX_FD);
                }
            }
        }

        let process = nsk_supervisor::monitor::spawn(
            process_spec,
            nsk_provider::traits::supervisor_config(&ctx.policy, ctx.events),
        )?;

        let pid = process.pid();
        if let Some(res) = &prepared.resources {
            if let Err(e) = res.attach(pid) {
                // Fail closed: kill the process immediately (§2.4).
                warn!(pid, error = %e, "cgroup attach failed; killing process");
                let _ = res.kill_all();
                process.cancel();
                return Err(e);
            }
        }

        Ok(RunningSandbox {
            id: prepared.id,
            provider_name: prepared.provider_name,
            process: Arc::new(process),
            resources: prepared.resources,
            started_at: std::time::Instant::now(),
        })
    }

    async fn terminate(&self, running: &RunningSandbox) -> Result<(), SandboxError> {
        // cgroup kill first (strongest), supervisor escalation as backup.
        if let Some(res) = &running.resources {
            let _ = res.kill_all();
        }
        running
            .process
            .terminate(nsk_supervisor::terminate::TerminateKind::External);
        Ok(())
    }

    async fn collect_usage(&self, running: &RunningSandbox) -> Result<ResourceUsage, SandboxError> {
        if let Some(res) = &running.resources {
            res.observe_usage()
        } else {
            Ok(ResourceUsage::default())
        }
    }

    async fn cleanup(
        &self,
        resources: Option<Arc<dyn ProviderResources>>,
    ) -> Result<Vec<Diagnostic>, SandboxError> {
        match resources {
            Some(res) => res.cleanup(),
            None => Ok(Vec::new()),
        }
    }
}

/// Recover the seccomp profile path from provider resources via downcast.
fn seccomp_path_of(res: &dyn ProviderResources) -> Option<PathBuf> {
    res.as_any()
        .downcast_ref::<LinuxResources>()
        .and_then(|r| r.seccomp_file.clone())
}

fn tempfile_dir() -> Result<PathBuf, SandboxError> {
    let dir = std::env::temp_dir().join(format!("nsk-provider-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(SandboxError::Io)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_are_safe() {
        let config = LinuxProviderConfig::default();
        assert_eq!(config.seccomp_profile, SeccompChoice::Off);
        assert_eq!(config.cgroup_root, PathBuf::from("/sys/fs/cgroup"));
    }

    #[test]
    fn cpu_quota_conversion_matches_resource_crate() {
        assert_eq!(
            nsk_resource::limits::cpu_quota_to_cgroup_max(1.0, 100_000),
            "100000 100000"
        );
    }

    #[tokio::test]
    async fn probe_is_cached() {
        let provider = LinuxProvider::new(LinuxProviderConfig::default());
        let a = provider.probe().await.unwrap();
        let b = provider.probe().await.unwrap();
        assert_eq!(a, b);
    }
}
