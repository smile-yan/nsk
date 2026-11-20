//! # nsk-core
//!
//! Platform-independent core layer of the NSK (Native Sandbox Kernel).
//!
//! This crate contains the fundamental data model shared by every other
//! component: sandbox identity, execution specification, execution policy,
//! lifecycle states, execution results, diagnostics and platform capability
//! descriptions.
//!
//! Design rules (see design document §2.5, §13.2):
//! * no OS-specific code,
//! * no dependency on providers or runtime components,
//! * all types are cheaply cloneable / serializable where useful.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod capability;
pub mod diagnostic;
pub mod error;
pub mod event;
pub mod id;
pub mod policy;
pub mod result;
pub mod spec;
pub mod state;
pub mod validation;

pub use capability::{
    CapabilityStatus, CgroupControllers, IsolationCapabilities, Platform, PlatformCapabilities,
    ResourceCapabilities, SecurityCapabilities, ToolInfo,
};
pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use error::SandboxError;
pub use event::{LimitType, RuntimeEvent, SandboxEvent};
pub use id::SandboxId;
pub use policy::{
    CpuQuota, FilesystemPolicy, IsolationPolicy, NetworkPolicy, OutputPolicy, ProcessPolicy,
    ResourceLimits, SandboxPolicy, SecurityPolicy,
};
pub use result::{ExitInfo, OutputData, OutputResult, ResourceUsage, SandboxResult, SandboxStatus};
pub use spec::{
    CommandSpec, EnvironmentSpec, EnvironmentVariable, SandboxSpec, StdinSpec, WorkspaceSpec,
};
pub use state::SandboxState;
