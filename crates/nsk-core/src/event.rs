//! Kernel event API (design document §14.4).
//!
//! Events are broadcast through a bounded channel; slow subscribers may lose
//! events (they observe a `Lagged` error) but can never block the kernel or
//! cause unbounded memory growth.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::id::SandboxId;
use crate::result::{ExitInfo, ResourceUsage};

/// The resource limit that was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitType {
    WallTime,
    CpuTime,
    Memory,
    Process,
    OpenFiles,
    FileSize,
    Disk,
    Output,
}

/// Lifecycle / streaming events of one sandbox (§14.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxEvent {
    Created,
    Preparing,
    Ready,
    Started,
    /// Streaming stdout chunk.
    Stdout(Vec<u8>),
    /// Streaming stderr chunk.
    Stderr(Vec<u8>),
    /// Periodic resource usage sample.
    ResourceUsage(ResourceUsage),
    /// A limit was exceeded; the sandbox will be terminated when the policy
    /// requests enforcement.
    LimitExceeded(LimitType),
    /// Termination has been initiated.
    Terminating,
    /// The program exited (any reason).
    Exited(ExitInfo),
    /// Cleanup finished (successfully or not — see diagnostics).
    CleanupCompleted,
}

impl SandboxEvent {
    /// Short name used for logging and tests.
    pub fn kind(&self) -> &'static str {
        match self {
            SandboxEvent::Created => "created",
            SandboxEvent::Preparing => "preparing",
            SandboxEvent::Ready => "ready",
            SandboxEvent::Started => "started",
            SandboxEvent::Stdout(_) => "stdout",
            SandboxEvent::Stderr(_) => "stderr",
            SandboxEvent::ResourceUsage(_) => "resource_usage",
            SandboxEvent::LimitExceeded(_) => "limit_exceeded",
            SandboxEvent::Terminating => "terminating",
            SandboxEvent::Exited(_) => "exited",
            SandboxEvent::CleanupCompleted => "cleanup_completed",
        }
    }
}

/// Event tagged with its sandbox and emission time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub id: SandboxId,
    pub at: SystemTime,
    pub event: SandboxEvent,
}

impl RuntimeEvent {
    pub fn new(id: SandboxId, event: SandboxEvent) -> Self {
        Self {
            id,
            at: SystemTime::now(),
            event,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_kinds() {
        assert_eq!(SandboxEvent::Created.kind(), "created");
        assert_eq!(SandboxEvent::Stdout(vec![]).kind(), "stdout");
        assert_eq!(
            SandboxEvent::LimitExceeded(LimitType::Memory).kind(),
            "limit_exceeded"
        );
    }

    #[test]
    fn serde_roundtrip() {
        let e = RuntimeEvent::new(SandboxId::new(), SandboxEvent::Started);
        let json = serde_json::to_string(&e).unwrap();
        let back: RuntimeEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.event.kind(), "started");
    }
}
