//! # nsk-runtime
//!
//! Runtime Manager of the NSK kernel (design document §14, Phase 9 / M8).
//!
//! * [`SandboxRuntime`] — the public execution API
//!   (`create` / `start` / `wait` / `cancel` / `inspect` / `cleanup`),
//! * [`SandboxRegistry`] — per-sandbox lifecycle records,
//! * [`lifecycle`] — state machine orchestration (§4.2),
//! * [`cleanup`] — idempotent Cleanup Manager (§4.3),
//! * [`provider_factory`] — platform provider wiring (§9.1),
//! * [`SandboxRuntimeBuilder`] — assembly entry point.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod cancellation;
pub mod cleanup;
pub mod lifecycle;
pub mod manager;
pub mod provider_factory;
pub mod registry;
pub mod runtime;

pub use cancellation::CancellationHub;
pub use cleanup::CleanupManager;
pub use manager::SandboxManager;
pub use provider_factory::{create_default_provider, create_mock_provider, provider_for_platform};
pub use registry::{SandboxEntry, SandboxInfo, SandboxRegistry};
pub use runtime::{Runtime, SandboxRuntime, SandboxRuntimeBuilder};
