//! # nsk-provider
//!
//! Platform Provider abstraction (design document §9, Phase 3 / M3).
//!
//! The trait models the provider-side resource lifecycle with typed handles
//! so illegal states are unrepresentable (§9.2):
//!
//! * [`PrepareContext`] — everything a provider needs to build isolation,
//! * [`ExecutionPlan`] — the concrete command the supervisor must run,
//! * [`PreparedSandbox`] — isolation established, not yet running,
//! * [`RunningSandbox`] — process running, resources attached,
//! * [`ProviderResources`] — provider-owned resources for termination,
//!   usage observation and cleanup.
//!
//! [`MockProvider`] executes real host processes **without any isolation**
//! and reports its capabilities honestly as `Unsupported`. It exists for
//! tests and kernel development only; the runtime refuses it for policies
//! that request isolation (fail-closed, §2.4).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod factory;
pub mod mock;
pub mod traits;

pub use factory::{ProviderKind, create_mock_provider};
pub use mock::MockProvider;
pub use traits::{
    ExecutionPlan, PrepareContext, PreparedSandbox, ProviderResources, RunningSandbox,
    SandboxProvider, SpawnContext, supervisor_config,
};
