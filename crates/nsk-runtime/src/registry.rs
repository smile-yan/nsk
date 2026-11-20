//! Sandbox registry (§14.1, §4.1 Sandbox Execution Unit).
//!
//! Each registry entry holds the full lifecycle state of one sandbox:
//! identity, spec, effective policy, provider handles, result channel,
//! events and diagnostics. Only the Runtime Manager mutates entries (§4.3).

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use nsk_core::diagnostic::Diagnostic;
use nsk_core::event::{RuntimeEvent, SandboxEvent};
use nsk_core::id::SandboxId;
use nsk_core::result::{ExitInfo, ResourceUsage, SandboxResult, SandboxStatus};
use nsk_core::spec::SandboxSpec;
use nsk_core::state::SandboxState;
use nsk_policy::EffectivePolicy;
use nsk_provider::traits::{PreparedSandbox, RunningSandbox};
use nsk_workspace::manager::PreparedWorkspace;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;

/// Everything known about one sandbox instance (§4.1).
#[derive(Debug)]
pub struct SandboxEntry {
    pub id: SandboxId,
    pub created_at: SystemTime,
    /// Lifecycle state — mutated only through validated transitions.
    pub state: Mutex<SandboxState>,
    /// The normalized spec (set at creation).
    pub spec: Mutex<Option<SandboxSpec>>,
    /// Resolved policy (set during validation).
    pub effective: Mutex<Option<Arc<EffectivePolicy>>>,
    /// Prepared workspace (set during preparation).
    pub workspace: Mutex<Option<Arc<PreparedWorkspace>>>,
    /// Provider-prepared sandbox (set during preparation).
    pub prepared: Mutex<Option<PreparedSandbox>>,
    /// Running process (set during start).
    pub running: Mutex<Option<RunningSandbox>>,
    /// Result delivery (multi-consumer).
    pub result_tx: watch::Sender<Option<Arc<SandboxResult>>>,
    /// Cancellation for the whole lifecycle.
    pub cancel: CancellationToken,
    /// Sandbox event stream (bounded; lagging subscribers lose events).
    pub events: broadcast::Sender<RuntimeEvent>,
    /// Diagnostics accumulated across the lifecycle.
    pub diagnostics: Mutex<Vec<Diagnostic>>,
    /// Cleanup already ran (idempotency flag, §4.3).
    pub cleanup_done: AtomicBool,
    /// Last observed usage (for inspect).
    pub last_usage: Mutex<Option<ResourceUsage>>,
}

impl SandboxEntry {
    pub fn new(id: SandboxId) -> Self {
        let (result_tx, _) = watch::channel(None);
        let (events, _) = broadcast::channel(1024);
        Self {
            id,
            created_at: SystemTime::now(),
            state: Mutex::new(SandboxState::Created),
            spec: Mutex::new(None),
            effective: Mutex::new(None),
            workspace: Mutex::new(None),
            prepared: Mutex::new(None),
            running: Mutex::new(None),
            result_tx,
            cancel: CancellationToken::new(),
            events,
            diagnostics: Mutex::new(Vec::new()),
            cleanup_done: AtomicBool::new(false),
            last_usage: Mutex::new(None),
        }
    }

    /// Perform a validated state transition (§4.3).
    pub fn transition(
        &self,
        to: SandboxState,
    ) -> Result<SandboxState, nsk_core::error::SandboxError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let next = state.transition_to(to)?;
        *state = next;
        Ok(next)
    }

    pub fn state(&self) -> SandboxState {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Append diagnostics (best effort under poisoning).
    pub fn push_diagnostics(&self, mut diags: Vec<Diagnostic>) {
        let mut all = self
            .diagnostics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        all.append(&mut diags);
    }

    /// Take a snapshot of accumulated diagnostics.
    pub fn snapshot_diagnostics(&self) -> Vec<Diagnostic> {
        self.diagnostics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Emit an event to sandbox subscribers (non-blocking, §14.4).
    pub fn emit(&self, event: SandboxEvent) {
        let _ = self.events.send(RuntimeEvent::new(self.id, event));
    }

    /// Subscribe to this sandbox's events.
    pub fn subscribe(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.events.subscribe()
    }

    /// Store/observe the final result.
    pub fn set_result(&self, result: Arc<SandboxResult>) {
        self.result_tx.send_replace(Some(result));
    }

    pub fn result_rx(&self) -> watch::Receiver<Option<Arc<SandboxResult>>> {
        self.result_tx.subscribe()
    }

    /// Inspect snapshot for the public API.
    pub fn info(&self) -> SandboxInfo {
        SandboxInfo {
            id: self.id,
            state: self.state(),
            created_at: self.created_at,
            exit_info: self.result_tx.borrow().as_ref().and_then(|r| r.exit_info),
            status: self.result_tx.borrow().as_ref().map(|r| r.status),
            usage: self
                .last_usage
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
            diagnostics: self.snapshot_diagnostics(),
        }
    }
}

/// Public inspect payload (§14.1 inspect).
#[derive(Debug, Clone)]
pub struct SandboxInfo {
    pub id: SandboxId,
    pub state: SandboxState,
    pub created_at: SystemTime,
    pub exit_info: Option<ExitInfo>,
    pub status: Option<SandboxStatus>,
    pub usage: Option<ResourceUsage>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Registry of live sandbox entries (§13.1 registry.rs).
#[derive(Debug, Default)]
pub struct SandboxRegistry {
    entries: Mutex<HashMap<SandboxId, Arc<SandboxEntry>>>,
}

impl SandboxRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a new entry (created by the manager).
    pub fn insert(&self, entry: Arc<SandboxEntry>) {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(entry.id, entry);
    }

    pub fn get(&self, id: &SandboxId) -> Option<Arc<SandboxEntry>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(id)
            .cloned()
    }

    /// Remove an entry once fully completed (§4.3: no unmanaged leftovers).
    pub fn remove(&self, id: &SandboxId) -> Option<Arc<SandboxEntry>> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(id)
    }

    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// All sandbox ids currently registered.
    pub fn ids(&self) -> Vec<SandboxId> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_transitions_are_validated() {
        let entry = Arc::new(SandboxEntry::new(SandboxId::new()));
        entry
            .transition(SandboxState::Validating)
            .expect("created → validating");
        assert!(entry.transition(SandboxState::Running).is_err());
        assert_eq!(entry.state(), SandboxState::Validating);
    }

    #[tokio::test]
    async fn events_and_results_flow() {
        let entry = Arc::new(SandboxEntry::new(SandboxId::new()));
        let mut rx = entry.subscribe();
        entry.emit(SandboxEvent::Created);

        let event = rx.recv().await.expect("event");
        assert_eq!(event.event.kind(), "created");

        let result = Arc::new(SandboxResult::new(entry.id, SandboxStatus::Success));
        entry.set_result(result.clone());
        let got = entry.result_rx().borrow().clone().expect("result");
        assert_eq!(got.status, SandboxStatus::Success);
    }

    #[test]
    fn registry_operations() {
        let registry = SandboxRegistry::new();
        let entry = Arc::new(SandboxEntry::new(SandboxId::new()));
        registry.insert(entry.clone());
        assert_eq!(registry.len(), 1);
        assert!(registry.get(&entry.id).is_some());
        registry.remove(&entry.id);
        assert!(registry.is_empty());
    }
}
