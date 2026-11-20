//! Sandbox identity (design document §5.1).

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identity of a sandbox execution instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SandboxId(Uuid);

impl SandboxId {
    /// Generate a fresh random sandbox id (UUID v4).
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wrap an existing UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Inner UUID representation.
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Short human-readable form (first 8 hex chars), used in logs.
    pub fn short(&self) -> String {
        self.0.simple().to_string()[..8].to_string()
    }
}

impl Default for SandboxId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique() {
        let a = SandboxId::new();
        let b = SandboxId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn short_form_is_stable() {
        let id = SandboxId::new();
        assert_eq!(id.short().len(), 8);
    }

    #[test]
    fn serde_roundtrip() {
        let id = SandboxId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: SandboxId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}
