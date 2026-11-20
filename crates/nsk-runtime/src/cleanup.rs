//! Idempotent Cleanup Manager (§4.3, §7.3, Phase 9).
//!
//! Cleanup order (§10.2): provider resources (cgroup kill first) →
//! workspace. Failures become diagnostics; cleanup is retryable until every
//! step reports success.

use std::sync::Arc;

use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::error::SandboxError;
#[allow(unused_imports)]
use nsk_core::id::SandboxId;
use tracing::{debug, info, warn};

use crate::registry::SandboxEntry;

/// Runs the cleanup sequence for a sandbox entry.
#[derive(Debug, Clone)]
pub struct CleanupManager {
    provider_name: String,
}

impl CleanupManager {
    pub fn new(provider_name: impl Into<String>) -> Self {
        Self {
            provider_name: provider_name.into(),
        }
    }

    /// Execute cleanup for `entry`; returns all diagnostics.
    ///
    /// Idempotent (§4.3): repeated calls after success are no-ops.
    pub async fn cleanup(
        &self,
        entry: &Arc<SandboxEntry>,
        provider: &Arc<dyn nsk_provider::traits::SandboxProvider>,
    ) -> Result<Vec<Diagnostic>, SandboxError> {
        if entry.cleanup_done.load(std::sync::atomic::Ordering::SeqCst) {
            debug!(id = %entry.id, "cleanup already done");
            return Ok(Vec::new());
        }

        let mut diags = Vec::new();

        // 1. Ensure the process is gone (idempotent on the supervisor side).
        // Scope the guard so it drops before any await (MutexGuard is !Send).
        let running = {
            let guard = entry.running.lock().unwrap_or_else(|p| p.into_inner());
            guard.clone()
        };
        if let Some(running) = running {
            if !running.process.is_finished() {
                debug!(id = %entry.id, pid = running.process.pid(), "ensuring process terminated");
                running.process.cancel();
                // Give the escalation a bounded window; the monitor still
                // owns the child and will report the outcome.
                tokio::time::timeout(std::time::Duration::from_secs(10), running.process.wait())
                    .await
                    .ok();
            }
        }

        // 2. Provider resources (cgroup kill → destroy, owned files).
        let prepared_resources = entry
            .prepared
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|p| p.resources.clone());
        match provider.cleanup(prepared_resources.flatten()).await {
            Ok(mut d) => diags.append(&mut d),
            Err(e) => {
                warn!(id = %entry.id, provider = %self.provider_name, error = %e, "provider cleanup failed");
                diags.push(Diagnostic::error(
                    codes::CLEANUP_FAILED,
                    format!("provider cleanup failed: {e}"),
                ));
            }
        }

        // 3. Workspace (only kernel-created, only when policy allows).
        let workspace = entry
            .workspace
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(ws) = workspace {
            if ws.kernel_created && ws.cleanup_on_exit {
                // Workspace removal is blocking fs work; run it off the
                // async executor.
                let ws2 = ws.clone();
                let result = tokio::task::spawn_blocking(move || {
                    nsk_workspace::WorkspaceManager::with_defaults().cleanup(&ws2)
                })
                .await
                .map_err(|e| SandboxError::Internal(format!("workspace cleanup task: {e}")))?;
                match result {
                    Ok(mut d) => diags.append(&mut d),
                    Err(e) => {
                        diags.push(Diagnostic::error(
                            codes::FS_WORKSPACE_NOT_REMOVED,
                            format!("workspace cleanup failed: {e}"),
                        ));
                    }
                }
            }
        }

        // Decide the outcome.
        let has_errors = diags
            .iter()
            .any(|d| d.severity == nsk_core::diagnostic::DiagnosticSeverity::Error);
        entry.push_diagnostics(diags.clone());
        if has_errors {
            entry
                .cleanup_done
                .store(false, std::sync::atomic::Ordering::SeqCst);
            Err(SandboxError::Cleanup(diags))
        } else {
            entry
                .cleanup_done
                .store(true, std::sync::atomic::Ordering::SeqCst);
            info!(id = %entry.id, "cleanup complete");
            entry.emit(nsk_core::event::SandboxEvent::CleanupCompleted);
            Ok(diags)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cleanup_is_idempotent() {
        use crate::registry::SandboxEntry;
        let entry = Arc::new(SandboxEntry::new(SandboxId::new()));
        let manager = CleanupManager::new("mock");
        let provider = nsk_provider::create_mock_provider();

        let d1 = manager
            .cleanup(&entry, &provider)
            .await
            .expect("first cleanup");
        let d2 = manager
            .cleanup(&entry, &provider)
            .await
            .expect("second cleanup");
        assert!(d1.is_empty());
        assert!(d2.is_empty());
        assert!(entry.cleanup_done.load(std::sync::atomic::Ordering::SeqCst));
    }
}
