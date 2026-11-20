//! # nsk-provider-macos
//!
//! macOS provider — **Seatbelt PoC** (design document §12, phase 16).
//!
//! macOS has no namespace machinery and no cgroups. The provider instead
//! uses the mechanisms the OS *does* offer, functionally verified by the
//! capability probe ([`probe`]):
//!
//! * **Sandbox mechanism** — `/usr/bin/sandbox-exec` with generated
//!   deny-by-default SBPL profiles ([`seatbelt`]): workspace-only file
//!   writes, policy-driven network restrictions, and a default-deny posture
//!   that refuses setuid exec (which makes `no_new_privileges` satisfiable).
//!   Apple has deprecated `sandbox-exec`; the boundary is therefore
//!   PoC-grade and reported as such (§12.2: never rely on unverified or
//!   private APIs).
//! * **Resource control** — reliable rlimits (`NOFILE` / `FSIZE` / `CPU`)
//!   via the supervisor pre-exec hook, plus **reactive watchdogs**
//!   ([`watchdog`]) for memory and process-count limits (macOS has no
//!   preventive per-tree mechanism for those).
//! * **Lifecycle** — supervisor-managed process groups with escalating
//!   tree termination.
//!
//! Fail-closed rules (§2.4):
//! * `sandbox-exec` missing or broken + isolation requested → refused by
//!   the Policy Engine (domain fields report the probe result);
//! * `filesystem.deny_host_paths` → refused by `prepare` (reads cannot be
//!   path-restricted with a maintainable SBPL profile);
//! * `filesystem.isolate_root` → refused by `prepare` (no root remap);
//! * isolation-requesting policies whose domains the platform cannot
//!   provide (process/ipc/uts namespaces) → refused by the Policy Engine.
//!
//! Runtime acceptance (§20-style, macOS scope) lives in
//! `tests/isolation_macos.rs` and runs on every macOS host/CI runner.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod probe;
pub mod seatbelt;

/// Watchdog machinery (lives in the supervisor — §7.2/§8 — and is shared
/// with the mock provider); re-exported for the macOS public API.
#[cfg(target_os = "macos")]
pub use nsk_supervisor::watchdog;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use tracing::debug;

use nsk_core::capability::PlatformCapabilities;
use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::error::SandboxError;
use nsk_core::result::ResourceUsage;
use nsk_provider::traits::{
    ExecutionPlan, PrepareContext, PreparedSandbox, ProviderResources, RunningSandbox,
    SandboxProvider, SpawnContext,
};
use nsk_resource::limits::RlimitSpec;

use crate::probe::{find_sandbox_exec, probe_capabilities};
#[cfg(target_os = "macos")]
use crate::watchdog::{WatchdogConfig, WatchdogEvidence, WatchdogLimits, spawn_watchdog};

/// macOS provider configuration.
#[derive(Debug, Clone)]
pub struct MacOSProviderConfig {
    /// Explicit `sandbox-exec` path (default: PATH + `/usr/bin` lookup).
    pub sandbox_exec: Option<PathBuf>,
    /// Watchdog poll interval / lifetime caps (macOS mechanism).
    #[cfg(target_os = "macos")]
    pub watchdog: WatchdogConfig,
    /// Create `<workspace>/tmp` and point `TMPDIR` at it (keeps temp writes
    /// inside the workspace write-allow-list).
    pub tmpdir_in_workspace: bool,
}

impl Default for MacOSProviderConfig {
    fn default() -> Self {
        Self {
            sandbox_exec: None,
            #[cfg(target_os = "macos")]
            watchdog: WatchdogConfig::default(),
            tmpdir_in_workspace: true,
        }
    }
}

/// Resources owned by a running macOS sandbox.
#[derive(Debug)]
pub struct MacOSResources {
    pub id: nsk_core::id::SandboxId,
    /// Watchdog evidence (confirmed limit kills, peak memory).
    ///
    /// `None` on non-macos builds (watchdogs are a macOS mechanism).
    #[cfg(target_os = "macos")]
    pub evidence: Arc<WatchdogEvidence>,
}

impl ProviderResources for MacOSResources {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn observe_usage(&self) -> Result<ResourceUsage, SandboxError> {
        #[cfg(target_os = "macos")]
        let usage = {
            let (oom, pids, peak) = self.evidence.snapshot();
            Ok(ResourceUsage {
                oom_events: oom,
                pids_limit_hits: pids,
                memory_peak_bytes: peak,
                ..Default::default()
            })
        };
        #[cfg(not(target_os = "macos"))]
        let usage = Ok(ResourceUsage::default());
        usage
    }
}

/// The phase-16 macOS isolation provider (Seatbelt PoC).
#[derive(Debug, Clone)]
pub struct MacOSProvider {
    config: MacOSProviderConfig,
    probe_cache: Arc<tokio::sync::OnceCell<PlatformCapabilities>>,
}

impl MacOSProvider {
    pub fn new() -> Self {
        Self::with_config(MacOSProviderConfig::default())
    }

    pub fn with_config(config: MacOSProviderConfig) -> Self {
        Self {
            config,
            probe_cache: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Capabilities, probed once per provider instance.
    pub async fn capabilities(&self) -> Result<PlatformCapabilities, SandboxError> {
        Ok(self
            .probe_cache
            .get_or_init(|| async move { probe_capabilities().await })
            .await
            .clone())
    }

    /// Resolve the launcher path (explicit config, PATH, `/usr/bin`).
    fn launcher(&self) -> Result<PathBuf, SandboxError> {
        self.config.sandbox_exec.clone().map(Ok).unwrap_or_else(|| {
            find_sandbox_exec().ok_or_else(|| {
                SandboxError::Isolation("sandbox-exec not found on this host".into())
            })
        })
    }

    /// Build the execution plan (unit-testable core of `prepare`).
    fn build_execution_plan(
        &self,
        ctx: &PrepareContext,
        launcher: &Path,
    ) -> Result<ExecutionPlan, SandboxError> {
        let spec = &ctx.spec;
        let policy = &ctx.policy;

        // macOS cannot honor these FilesystemPolicy requirements (§12);
        // fail closed with precise diagnostics instead of degrading.
        if policy.requested.filesystem.deny_host_paths {
            return Err(SandboxError::Isolation(
                "filesystem.deny_host_paths cannot be honored on macOS: Seatbelt profiles \
                 cannot hide host paths while allowing dynamic-loader/framework reads \
                 (set it to false; workspace writes are still the only writes allowed)"
                    .into(),
            ));
        }
        if policy.requested.filesystem.isolate_root {
            return Err(SandboxError::Isolation(
                "filesystem.isolate_root cannot be honored on macOS: no root-remap mechanism \
                 (set it to false; the sandbox still runs from the workspace)"
                    .into(),
            ));
        }

        // Canonicalize every write-allowed path: SBPL matches on resolved
        // paths (`/tmp` is a symlink to `/private/tmp` on macOS).
        let workspace_root = canonicalize_or(&ctx.workspace.root, "workspace root")?;
        let mut writable: Vec<PathBuf> = Vec::new();
        for p in &policy.requested.filesystem.writable_paths {
            writable.push(canonicalize_or(p, "filesystem.writable_paths entry")?);
        }
        for p in &spec.workspace.writable_paths {
            writable.push(canonicalize_or(p, "workspace.writable_paths entry")?);
        }

        let profile = seatbelt::build_profile(&workspace_root, &writable, policy.requested.network);
        debug!(
            sandbox = %ctx.id,
            writes = ?profile.write_allowlist,
            network = ?policy.requested.network,
            "seatbelt profile generated"
        );

        let cwd_host = spec.working_directory(&ctx.workspace.root).to_path_buf();

        // Environment: explicit whitelist (never the host env, §5.4).
        let mut env: Vec<(String, String)> = vec![
            (
                "PATH".into(),
                "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into(),
            ),
            ("HOME".into(), workspace_root.display().to_string()),
            ("LANG".into(), "C".into()),
        ];
        if self.config.tmpdir_in_workspace {
            let tmp = workspace_root.join("tmp");
            if let Err(e) = std::fs::create_dir_all(&tmp) {
                debug!(error = %e, "workspace tmpdir creation failed; TMPDIR falls back to the workspace root");
                env.push(("TMPDIR".into(), workspace_root.display().to_string()));
            } else {
                env.push(("TMPDIR".into(), tmp.display().to_string()));
            }
        }
        for var in &spec.environment.variables {
            env.retain(|(k, _)| k != &var.key);
            env.push((var.key.clone(), var.value.clone()));
        }

        let mut argv = vec![launcher.display().to_string(), "-p".into(), profile.source];
        argv.push(spec.command.executable.display().to_string());
        for a in &spec.command.args {
            argv.push(a.to_string_lossy().to_string());
        }

        // Reliable rlimits only (NOFILE/FSIZE/CPU); memory/process limits
        // are enforced by the watchdogs (see caps report + resolver).
        let r = &policy.requested.resources;
        let mut rlimits = vec![
            RlimitSpec::OpenFiles(r.max_open_files),
            RlimitSpec::FileSize(r.max_file_size_bytes),
        ];
        if let Some(cpu_time) = r.cpu_time {
            rlimits.push(RlimitSpec::CpuTime(cpu_time.as_secs().max(1)));
        }

        Ok(ExecutionPlan {
            argv,
            cwd: Some(cwd_host),
            env,
            stdin: spec.command.stdin.clone(),
            process_group: true,
            rlimits,
        })
    }

    /// Arm the watchdogs for a spawned sandbox (macOS mechanism).
    #[cfg(target_os = "macos")]
    fn watchdog_limits(policy: &nsk_policy::EffectivePolicy) -> WatchdogLimits {
        let r = &policy.requested.resources;
        let memory = (policy.applied.resources.iter().any(|l| {
            l.kind == nsk_policy::effective::LimitKind::Memory
                && l.status.is_available()
                && l.mechanism
                    .as_deref()
                    .is_some_and(|m| m.contains("watchdog"))
        }))
        .then_some(r.memory_bytes);
        let processes = (policy.applied.process.enforced_by.contains("watchdog"))
            .then_some(policy.requested.process.max_processes.max(1));
        WatchdogLimits {
            memory_bytes: memory,
            max_processes: processes,
        }
    }
}

fn canonicalize_or(path: &Path, what: &str) -> Result<PathBuf, SandboxError> {
    match path.canonicalize() {
        Ok(p) => Ok(p),
        Err(e) => Err(SandboxError::Isolation(format!(
            "cannot canonicalize {what} {}: {e}",
            path.display()
        ))),
    }
}

impl Default for MacOSProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SandboxProvider for MacOSProvider {
    fn name(&self) -> &'static str {
        "macos"
    }

    async fn probe(&self) -> Result<PlatformCapabilities, SandboxError> {
        self.capabilities().await
    }

    async fn prepare(&self, ctx: PrepareContext) -> Result<PreparedSandbox, SandboxError> {
        let caps = self.capabilities().await?;
        let mut diagnostics: Vec<Diagnostic> = Vec::new();

        let launcher = self.launcher()?;
        let plan = self.build_execution_plan(&ctx, &launcher)?;

        // Record what the applied policy actually relies on (§6.4).
        if !ctx.policy.requested.isolation.isolate_filesystem {
            diagnostics.push(Diagnostic::info(
                codes::ISOLATION_NOT_APPLIED,
                "no filesystem isolation requested; the Seatbelt profile still restricts \
                 writes to the workspace (deny-by-default posture, stricter than requested)",
            ));
        }
        if ctx.policy.applied.security.drop_privileges
            != nsk_core::capability::CapabilityStatus::NotConfigured
        {
            diagnostics.push(Diagnostic::warning(
                codes::ISOLATION_DEGRADED,
                "privilege dropping unavailable on macOS; the process keeps the caller's uid \
                 (isolation is profile-based, not uid-based)",
            ));
        }
        for l in &ctx.policy.applied.resources {
            if l.status.is_available()
                && l.detail.as_deref().is_some_and(|d| d.contains("reactive"))
            {
                diagnostics.push(Diagnostic::warning(
                    codes::RESOURCE_LIMIT_DEGRADED,
                    format!("{}: {}", l.kind, l.detail.as_deref().unwrap_or_default()),
                ));
            }
        }
        if !caps.isolation.filesystem_isolation.is_available() {
            // Defense in depth: the resolver should already have refused.
            return Err(SandboxError::CapabilityInsufficient {
                code: codes::ISOLATION_FAILED.to_string(),
                message: "Seatbelt launcher not verified functional; refusing to spawn \
                          (see probe diagnostics)"
                    .into(),
            });
        }

        debug!(
            sandbox = %ctx.id,
            launcher = %launcher.display(),
            "macOS sandbox prepared (Seatbelt profile)"
        );
        Ok(PreparedSandbox {
            id: ctx.id,
            provider_name: self.name(),
            plan,
            resources: Some(Arc::new(MacOSResources {
                id: ctx.id,
                #[cfg(target_os = "macos")]
                evidence: Arc::new(WatchdogEvidence::default()),
            })),
        })
    }

    async fn spawn(
        &self,
        prepared: PreparedSandbox,
        ctx: SpawnContext,
    ) -> Result<RunningSandbox, SandboxError> {
        let process = nsk_supervisor::monitor::spawn(
            prepared.plan.clone().into_process_spec(),
            nsk_provider::traits::supervisor_config(&ctx.policy, ctx.events),
        )?;

        // Arm reactive enforcement (watchdogs self-terminate with the
        // process; their evidence flows into collect_usage).
        #[cfg(target_os = "macos")]
        if let Some(res) = &prepared.resources {
            if let Some(macos_res) = res.as_ref().as_any().downcast_ref::<MacOSResources>() {
                let limits = Self::watchdog_limits(&ctx.policy);
                if limits.is_armed() {
                    debug!(sandbox = %prepared.id, ?limits, "arming watchdogs");
                    spawn_watchdog(
                        process.pid(),
                        process.clone(),
                        limits,
                        macos_res.evidence.clone(),
                        self.config.watchdog,
                    );
                }
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
        // Process-group escalation is the strongest macOS mechanism; the
        // watchdogs have already recorded evidence for their own kills.
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
        _resources: Option<Arc<dyn ProviderResources>>,
    ) -> Result<Vec<Diagnostic>, SandboxError> {
        // The workspace (runtime CleanupManager) and process group
        // (supervisor) own every resource; watchdogs exit with the process.
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use nsk_core::capability::CapabilityStatus;
    use nsk_core::policy::IsolationPolicy;
    use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};

    fn provider() -> MacOSProvider {
        MacOSProvider::new()
    }

    fn spec_with(policy: nsk_core::policy::SandboxPolicy) -> SandboxSpec {
        let mut s = SandboxSpec::new(CommandSpec::new("/bin/echo"));
        s.workspace = WorkspaceSpec::ephemeral();
        s.policy = policy;
        s
    }

    /// macOS-compatible minimal policy (domains Seatbelt cannot provide are
    /// off; see resolver tests).
    fn macos_policy() -> nsk_core::policy::SandboxPolicy {
        let mut p = nsk_core::policy::SandboxPolicy::minimal();
        p.isolation = IsolationPolicy {
            isolate_process: false,
            isolate_filesystem: true,
            isolate_network: true,
            isolate_ipc: false,
            isolate_uts: false,
        };
        p.filesystem.deny_host_paths = false;
        p.filesystem.isolate_root = false;
        p
    }

    #[tokio::test]
    async fn probe_is_cached() {
        let p = provider();
        let a = p.probe().await.unwrap();
        let b = p.probe().await.unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn probe_reports_honest_capabilities() {
        let caps = provider().probe().await.unwrap();
        assert_eq!(caps.platform, nsk_core::capability::Platform::MacOS);
        assert_eq!(
            caps.isolation.filesystem_isolation,
            CapabilityStatus::Available
        );
        assert_eq!(caps.isolation.pid_namespace, CapabilityStatus::Unsupported);
        assert_eq!(
            caps.resources.rlimit_address_space,
            CapabilityStatus::Unsupported
        );
        assert_eq!(caps.resources.memory_watchdog, CapabilityStatus::Available);
    }

    #[tokio::test]
    async fn isolation_requesting_policy_is_refused_before_prepare() {
        // A full strict policy must fail closed in the resolver (defense in
        // depth before the provider is even reached).
        let caps = provider().probe().await.unwrap();
        let err = nsk_policy::effective::resolve(
            &spec_with(nsk_core::policy::SandboxPolicy::strict()),
            &caps,
        )
        .expect_err("strict must be refused on macOS");
        assert!(matches!(err, SandboxError::CapabilityInsufficient { .. }));
    }

    #[tokio::test]
    async fn prepare_refuses_deny_host_paths() {
        let caps = provider().probe().await.unwrap();
        let mut spec = spec_with(macos_policy());
        spec.policy.filesystem.deny_host_paths = true;
        let eff = nsk_policy::effective::resolve(&spec, &caps).unwrap();
        let ws = nsk_workspace::manager::WorkspaceManager::with_defaults()
            .prepare(&spec.workspace, &spec.id)
            .unwrap();
        let err = provider()
            .prepare(PrepareContext {
                id: spec.id,
                spec,
                policy: Arc::new(eff),
                workspace: Arc::new(ws),
            })
            .await
            .expect_err("deny_host_paths must be refused");
        assert!(err.to_string().contains("deny_host_paths"));
    }

    #[tokio::test]
    async fn prepare_refuses_isolate_root() {
        let caps = provider().probe().await.unwrap();
        let mut spec = spec_with(macos_policy());
        spec.policy.filesystem.isolate_root = true;
        let eff = nsk_policy::effective::resolve(&spec, &caps).unwrap();
        let ws = nsk_workspace::manager::WorkspaceManager::with_defaults()
            .prepare(&spec.workspace, &spec.id)
            .unwrap();
        let err = provider()
            .prepare(PrepareContext {
                id: spec.id,
                spec,
                policy: Arc::new(eff),
                workspace: Arc::new(ws),
            })
            .await
            .expect_err("isolate_root must be refused");
        assert!(err.to_string().contains("isolate_root"));
    }

    #[tokio::test]
    async fn prepare_builds_seatbelt_plan() {
        let caps = provider().probe().await.unwrap();
        let spec = spec_with(macos_policy());
        let eff = nsk_policy::effective::resolve(&spec, &caps).unwrap();
        let ws = nsk_workspace::manager::WorkspaceManager::with_defaults()
            .prepare(&spec.workspace, &spec.id)
            .unwrap();
        let prepared = provider()
            .prepare(PrepareContext {
                id: spec.id,
                spec,
                policy: Arc::new(eff),
                workspace: Arc::new(ws),
            })
            .await
            .expect("prepare must succeed");

        assert_eq!(prepared.provider_name, "macos");
        assert!(prepared.plan.argv[0].ends_with("sandbox-exec"));
        assert_eq!(prepared.plan.argv[1], "-p");
        let profile = &prepared.plan.argv[2];
        assert!(profile.starts_with("(version 1)"));
        assert!(profile.contains("(deny network*)"));
        assert!(prepared.plan.process_group);
        assert!(prepared.plan.rlimits.len() >= 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn watchdog_limits_follow_applied_policy() {
        let caps = futures_block_on(probe_capabilities());
        let spec = spec_with(macos_policy());
        let eff = nsk_policy::effective::resolve(&spec, &caps).unwrap();
        let limits = MacOSProvider::watchdog_limits(&eff);
        // Memory: resolver picks the watchdog rung on macOS → armed.
        assert_eq!(limits.memory_bytes, Some(256 * 1024 * 1024));
        // Processes: resolver picks the watchdog rung on macOS → armed.
        assert_eq!(limits.max_processes, Some(16));
    }

    /// Minimal synchronous helper for building a capability snapshot in
    /// tests (probe uses tokio internally).
    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    fn futures_block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }
}
