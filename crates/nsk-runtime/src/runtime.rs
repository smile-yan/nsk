//! Runtime API (§14.1–14.4) and builder (§14.2).

use std::sync::Arc;

use async_trait::async_trait;

use nsk_core::capability::PlatformCapabilities;
use nsk_core::error::SandboxError;
use nsk_core::event::RuntimeEvent;
use nsk_core::id::SandboxId;
use nsk_core::spec::SandboxSpec;
use nsk_provider::traits::SandboxProvider;
use nsk_workspace::manager::{WorkspaceManager, WorkspaceManagerConfig};

use crate::cleanup::CleanupManager;
use crate::manager::SandboxManager;
use crate::registry::{SandboxInfo, SandboxRegistry};

/// The public kernel API (§14.1).
#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    /// Create a sandbox (Created → Validating → Preparing → Ready).
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxId, SandboxError>;

    /// Start a prepared sandbox (Ready → Starting → Running).
    async fn start(&self, id: SandboxId) -> Result<(), SandboxError>;

    /// Wait for completion; returns the final result (§5.8).
    async fn wait(
        &self,
        id: SandboxId,
    ) -> Result<Arc<nsk_core::result::SandboxResult>, SandboxError>;

    /// Cancel a running sandbox (idempotent).
    async fn cancel(&self, id: SandboxId) -> Result<(), SandboxError>;

    /// Inspect the current lifecycle state.
    async fn inspect(&self, id: SandboxId) -> Result<SandboxInfo, SandboxError>;

    /// Run cleanup for a finished sandbox (idempotent, retryable).
    async fn cleanup(&self, id: SandboxId) -> Result<(), SandboxError>;

    /// Convenience: create + start + wait (§14.3).
    async fn execute(
        &self,
        spec: SandboxSpec,
    ) -> Result<Arc<nsk_core::result::SandboxResult>, SandboxError>;

    /// Subscribe to events of one sandbox (None = all sandboxes).
    ///
    /// The returned channel is bounded; lagging subscribers lose events
    /// (§14.4) — they must tolerate `RecvError::Lagged`.
    fn subscribe(&self, id: Option<SandboxId>) -> tokio::sync::broadcast::Receiver<RuntimeEvent>;

    /// Platform capabilities of the wired provider.
    fn capabilities(&self) -> &PlatformCapabilities;

    /// Provider name.
    fn provider_name(&self) -> &'static str;

    /// Ids of all live sandboxes.
    async fn list(&self) -> Vec<SandboxId>;
}

/// The concrete runtime (§14.2 build()).
#[derive(Debug, Clone)]
pub struct Runtime {
    inner: Arc<SandboxManager>,
}

impl Runtime {
    pub fn manager(&self) -> &Arc<SandboxManager> {
        &self.inner
    }
}

#[async_trait]
impl SandboxRuntime for Runtime {
    async fn create(&self, spec: SandboxSpec) -> Result<SandboxId, SandboxError> {
        self.inner.create(spec).await
    }

    async fn start(&self, id: SandboxId) -> Result<(), SandboxError> {
        self.inner.start(id).await
    }

    async fn wait(
        &self,
        id: SandboxId,
    ) -> Result<Arc<nsk_core::result::SandboxResult>, SandboxError> {
        self.inner.wait(id).await
    }

    async fn cancel(&self, id: SandboxId) -> Result<(), SandboxError> {
        self.inner.cancel(id).await
    }

    async fn inspect(&self, id: SandboxId) -> Result<SandboxInfo, SandboxError> {
        self.inner.inspect(id).await
    }

    async fn cleanup(&self, id: SandboxId) -> Result<(), SandboxError> {
        self.inner.cleanup(id).await
    }

    async fn execute(
        &self,
        spec: SandboxSpec,
    ) -> Result<Arc<nsk_core::result::SandboxResult>, SandboxError> {
        self.inner.execute(spec).await
    }

    fn subscribe(&self, id: Option<SandboxId>) -> tokio::sync::broadcast::Receiver<RuntimeEvent> {
        self.inner.subscribe(id)
    }

    fn capabilities(&self) -> &PlatformCapabilities {
        self.inner.capabilities()
    }

    fn provider_name(&self) -> &'static str {
        self.inner.provider_name()
    }

    async fn list(&self) -> Vec<SandboxId> {
        self.inner.list().await
    }
}

/// Builder (§14.2).
pub struct SandboxRuntimeBuilder {
    provider: Option<Arc<dyn SandboxProvider>>,
    workspace_config: Option<WorkspaceManagerConfig>,
}

impl std::fmt::Debug for SandboxRuntimeBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxRuntimeBuilder")
            .field("provider", &self.provider.as_ref().map(|p| p.name()))
            .field("workspace_config", &self.workspace_config)
            .finish()
    }
}

impl Default for SandboxRuntimeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxRuntimeBuilder {
    pub fn new() -> Self {
        Self {
            provider: None,
            workspace_config: None,
        }
    }

    /// Wire a provider explicitly (mock providers must be explicit).
    pub fn with_provider(mut self, provider: Arc<dyn SandboxProvider>) -> Self {
        self.provider = Some(provider);
        self
    }

    /// Configure the workspace manager.
    pub fn with_workspace_config(mut self, config: WorkspaceManagerConfig) -> Self {
        self.workspace_config = Some(config);
        self
    }

    /// Validate and assemble the runtime: probes the provider once and
    /// fails closed when the platform is unusable for *any* sandboxing
    /// decision-making (§2.4).
    pub async fn build(self) -> Result<Runtime, SandboxError> {
        let provider = self.provider.ok_or_else(|| {
            SandboxError::Internal(
                "no provider wired: use with_provider() (see nsk_runtime::provider_factory)".into(),
            )
        })?;
        let capabilities = provider.probe().await?;
        let workspace_manager = WorkspaceManager::new(self.workspace_config.unwrap_or_default());
        let registry = SandboxRegistry::new();
        let cleanup = CleanupManager::new(provider.name());
        Ok(Runtime {
            inner: Arc::new(SandboxManager {
                provider,
                capabilities,
                workspace_manager,
                registry,
                cleanup,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn build_requires_provider() {
        let err = SandboxRuntimeBuilder::new().build().await.unwrap_err();
        assert!(matches!(err, SandboxError::Internal(_)));
    }

    #[tokio::test]
    async fn build_with_mock_provider() {
        let runtime = SandboxRuntimeBuilder::new()
            .with_provider(nsk_provider::create_mock_provider())
            .build()
            .await
            .expect("runtime with mock");
        assert_eq!(runtime.provider_name(), "mock");
    }
}
