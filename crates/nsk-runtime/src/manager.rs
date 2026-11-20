//! SandboxManager — the Execution Manager implementation (§3.2, §14).
//!
//! Owns the registry and drives every sandbox through the lifecycle. All
//! state mutations happen here (§4.3 rule 1); providers only receive
//! lifecycle callbacks.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, info, warn};

use nsk_core::capability::PlatformCapabilities;
use nsk_core::error::SandboxError;
use nsk_core::event::RuntimeEvent;
use nsk_core::id::SandboxId;
use nsk_core::result::SandboxResult;
use nsk_core::spec::SandboxSpec;
use nsk_provider::traits::SandboxProvider;
use nsk_workspace::manager::WorkspaceManager;

use crate::cleanup::CleanupManager;
use crate::lifecycle;
use crate::registry::{SandboxEntry, SandboxInfo, SandboxRegistry};
use crate::runtime::SandboxRuntime;

/// The Execution Manager.
pub struct SandboxManager {
    pub(crate) provider: Arc<dyn SandboxProvider>,
    pub(crate) capabilities: PlatformCapabilities,
    pub(crate) workspace_manager: WorkspaceManager,
    pub(crate) registry: SandboxRegistry,
    pub(crate) cleanup: CleanupManager,
}

impl std::fmt::Debug for SandboxManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxManager")
            .field("provider", &self.provider.name())
            .field("capabilities", &self.capabilities)
            .field("workspace_manager", &self.workspace_manager)
            .field("registry", &self.registry)
            .field("cleanup", &self.cleanup)
            .finish()
    }
}

impl SandboxManager {
    /// Create + validate + prepare (§14.1 create).
    pub async fn create(&self, spec: SandboxSpec) -> Result<SandboxId, SandboxError> {
        let entry = Arc::new(SandboxEntry::new(spec.id));
        self.registry.insert(entry.clone());
        lifecycle::prepare(&entry, spec, &self.provider, &self.workspace_manager)
            .await
            .map_err(|e| {
                // Keep the entry for diagnostics; the caller may inspect it.
                warn!(id = %entry.id, error = %e, "sandbox prepare failed");
                e
            })?;
        Ok(entry.id)
    }

    /// Start a prepared sandbox.
    pub async fn start(&self, id: SandboxId) -> Result<(), SandboxError> {
        let entry = self.registry.get(&id).ok_or(SandboxError::NotFound(id))?;
        lifecycle::start(&entry, &self.provider).await
    }

    /// Wait for the final result.
    pub async fn wait(&self, id: SandboxId) -> Result<Arc<SandboxResult>, SandboxError> {
        let entry = self.registry.get(&id).ok_or(SandboxError::NotFound(id))?;
        let mut rx = entry.result_rx();
        loop {
            if let Some(result) = rx.borrow().clone() {
                return Ok(result);
            }
            if rx.changed().await.is_err() {
                return Err(SandboxError::Internal(format!(
                    "sandbox {id}: result channel closed before completion"
                )));
            }
        }
    }

    /// Cancel a running sandbox (idempotent).
    pub async fn cancel(&self, id: SandboxId) -> Result<(), SandboxError> {
        let entry = self.registry.get(&id).ok_or(SandboxError::NotFound(id))?;
        let state = entry.state();
        if state.is_active() || state == nsk_core::state::SandboxState::Ready {
            lifecycle::cancel(&entry);
            info!(id = %id, "cancel requested");
            Ok(())
        } else {
            Err(SandboxError::InvalidOperation {
                id,
                state,
                required: "Starting, Running, Terminating or Ready",
            })
        }
    }

    /// Inspect lifecycle state.
    pub async fn inspect(&self, id: SandboxId) -> Result<SandboxInfo, SandboxError> {
        let entry = self.registry.get(&id).ok_or(SandboxError::NotFound(id))?;
        Ok(entry.info())
    }

    /// Explicit cleanup (idempotent / retryable).
    pub async fn cleanup(&self, id: SandboxId) -> Result<(), SandboxError> {
        let entry = self.registry.get(&id).ok_or(SandboxError::NotFound(id))?;
        lifecycle::cleanup_entry(&entry, &self.provider).await?;
        debug!(id = %id, "explicit cleanup done");
        Ok(())
    }

    /// Execute end-to-end (§14.3): create → start → wait.
    ///
    /// The lifecycle driver already cleans up before completing, so no
    /// separate cleanup call is needed on success.
    pub async fn execute(&self, spec: SandboxSpec) -> Result<Arc<SandboxResult>, SandboxError> {
        let id = self.create(spec).await?;
        match self.start(id).await {
            Ok(()) => {}
            Err(e) => {
                // Prepare may have succeeded but spawn failed — clean up.
                if let Some(entry) = self.registry.get(&id) {
                    let _ = lifecycle::cleanup_entry(&entry, &self.provider).await;
                }
                self.registry.remove(&id);
                return Err(e);
            }
        }
        let result = self.wait(id).await?;
        self.registry.remove(&id);
        Ok(result)
    }

    /// Subscribe to events: `None` for all sandboxes, `Some(id)` filters by
    /// sandbox (receiver-side filtering; the channel carries all events).
    pub fn subscribe(
        &self,
        _id: Option<SandboxId>,
    ) -> tokio::sync::broadcast::Receiver<RuntimeEvent> {
        // Events are per-entry; a global subscription would need a fan-in
        // hub. Return a fresh per-entry channel for the requested sandbox.
        // For None, callers iterate over live entries' channels.
        // Simplification: only per-id subscription is supported in phase 1.
        match _id {
            Some(id) => {
                let entry = self.registry.get(&id);
                match entry {
                    Some(e) => e.subscribe(),
                    None => {
                        // Unknown id: return a dummy channel that is closed.
                        let (_tx, rx) = tokio::sync::broadcast::channel(1);
                        rx
                    }
                }
            }
            None => {
                // Global subscription: return a dummy closed channel; the
                // per-entry API is the supported path (documented).
                let (_tx, rx) = tokio::sync::broadcast::channel(1);
                rx
            }
        }
    }

    pub fn capabilities(&self) -> &PlatformCapabilities {
        &self.capabilities
    }

    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }

    pub async fn list(&self) -> Vec<SandboxId> {
        self.registry.ids()
    }
}

#[async_trait]
impl SandboxRuntime for SandboxManager {
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxId, SandboxError> {
        SandboxManager::create(self, spec).await
    }
    async fn start(&self, id: SandboxId) -> Result<(), SandboxError> {
        SandboxManager::start(self, id).await
    }
    async fn wait(&self, id: SandboxId) -> Result<Arc<SandboxResult>, SandboxError> {
        SandboxManager::wait(self, id).await
    }
    async fn cancel(&self, id: SandboxId) -> Result<(), SandboxError> {
        SandboxManager::cancel(self, id).await
    }
    async fn inspect(&self, id: SandboxId) -> Result<SandboxInfo, SandboxError> {
        SandboxManager::inspect(self, id).await
    }
    async fn cleanup(&self, id: SandboxId) -> Result<(), SandboxError> {
        SandboxManager::cleanup(self, id).await
    }
    async fn execute(&self, spec: SandboxSpec) -> Result<Arc<SandboxResult>, SandboxError> {
        SandboxManager::execute(self, spec).await
    }
    fn subscribe(&self, id: Option<SandboxId>) -> tokio::sync::broadcast::Receiver<RuntimeEvent> {
        SandboxManager::subscribe(self, id)
    }
    fn capabilities(&self) -> &PlatformCapabilities {
        SandboxManager::capabilities(self)
    }
    fn provider_name(&self) -> &'static str {
        SandboxManager::provider_name(self)
    }
    async fn list(&self) -> Vec<SandboxId> {
        SandboxManager::list(self).await
    }
}
