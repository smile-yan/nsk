//! # nsk-policy
//!
//! Policy Engine of the NSK kernel (design document §6).
//!
//! Responsibilities:
//! * validate `SandboxSpec` and `SandboxPolicy` (structural, security, path,
//!   resource and conflict rules),
//! * normalize policies into a canonical form,
//! * match requested policy against reported platform capabilities and
//!   produce an `EffectivePolicy` that records what is *actually* applied.
//!
//! This crate is pure: no OS access, no provider dependencies.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod effective;
pub mod normalize;
pub mod validate;

pub use effective::{
    AppliedFilesystem, AppliedIsolation, AppliedLimit, AppliedNetwork, AppliedPolicy,
    AppliedProcess, AppliedSecurity, EffectivePolicy, LimitKind,
};
