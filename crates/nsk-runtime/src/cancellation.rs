//! Cancellation plumbing (§8.2 Cancellation, §14.4 event stream rules).
//!
//! One cancellation token per sandbox, fanned out to the supervisor and
//! lifecycle drivers. Cancelling never blocks on the process: termination is
//! asynchronous and observed through the normal outcome channel.

use tokio_util::sync::CancellationToken;

/// Per-sandbox cancellation hub.
#[derive(Debug, Clone, Default)]
pub struct CancellationHub {
    token: CancellationToken,
}

impl CancellationHub {
    pub fn new() -> Self {
        Self {
            token: CancellationToken::new(),
        }
    }

    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Request cancellation (idempotent).
    pub fn cancel(&self) {
        self.token.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Child token that also fires when the parent is cancelled.
    pub fn child_token(&self) -> CancellationToken {
        self.token.child_token()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn children_follow_parent() {
        let hub = CancellationHub::new();
        let child = hub.child_token();
        assert!(!hub.is_cancelled());
        hub.cancel();
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(child.is_cancelled());
    }
}
