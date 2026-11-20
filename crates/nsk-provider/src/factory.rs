//! Provider factory (§9.1 Provider Factory).
//!
//! Platform wiring lives in `nsk-runtime` (dependency rule §13.2: the
//! runtime composes modules; `nsk-provider` only defines the interface and
//! must not depend on concrete providers). This module offers the
//! provider-kind selection vocabulary and the explicit mock constructor.
//! The mock is never chosen automatically: callers must opt in.

use std::sync::Arc;

use crate::mock::MockProvider;
use crate::traits::SandboxProvider;

/// Which provider to instantiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// The real platform provider (Linux only in phase 1); wiring in
    /// `nsk-runtime`.
    Platform,
    /// Test/dev provider without isolation.
    Mock,
}

/// Create the mock provider (explicit opt-in only).
pub fn create_mock_provider() -> Arc<dyn SandboxProvider> {
    Arc::new(MockProvider::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_is_explicit() {
        let p = create_mock_provider();
        assert_eq!(p.name(), "mock");
    }
}
