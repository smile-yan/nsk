//! Kernel error model (design document §5, error system).
//!
//! Errors are the control-flow channel for failures that prevent a sandbox
//! from producing a meaningful result. Conditions that still allow a result
//! (e.g. a killed program) are expressed through [`crate::SandboxStatus`]
//! and diagnostics instead.

use crate::SandboxId;
use crate::diagnostic::Diagnostic;
use crate::state::SandboxState;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SandboxError {
    /// Policy validation failed; carries the offending diagnostics.
    #[error("policy validation failed ({count} issue(s))", count = .0.len())]
    PolicyValidation(Vec<Diagnostic>),

    /// The current platform cannot satisfy mandatory policy requirements.
    #[error("capability insufficient ({code}): {message}")]
    CapabilityInsufficient { code: String, message: String },

    /// An isolation mechanism could not be established (fail-closed).
    #[error("isolation setup failed: {0}")]
    Isolation(String),

    /// A resource limit could not be applied although it was mandatory.
    #[error("resource limit setup failed: {0}")]
    ResourceLimit(String),

    /// The process could not be spawned.
    #[error("process spawn failed: {0}")]
    Spawn(String),

    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Illegal lifecycle state transition.
    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: SandboxState,
        to: SandboxState,
    },

    /// The sandbox id is unknown to this runtime.
    #[error("sandbox {0} not found")]
    NotFound(SandboxId),

    /// The operation is not valid in the sandbox's current state.
    #[error("sandbox {id} is in state {state:?}; operation requires {required}")]
    InvalidOperation {
        id: SandboxId,
        state: SandboxState,
        required: &'static str,
    },

    /// Wall-time deadline exceeded (internal shortcut; usually reported via
    /// `SandboxStatus::TimeLimitExceeded`).
    #[error("timeout")]
    Timeout,

    /// Operation was cancelled.
    #[error("cancelled")]
    Cancelled,

    /// Provider-specific failure.
    #[error("provider '{provider}' failed: {message}")]
    Provider { provider: String, message: String },

    /// One or more cleanup steps failed; diagnostics describe what leaked.
    #[error("cleanup failed ({} issue(s))", .0.len())]
    Cleanup(Vec<Diagnostic>),

    /// Unexpected internal condition; always a kernel bug or corrupted env.
    #[error("internal error: {0}")]
    Internal(String),
}

impl SandboxError {
    /// Convenience constructor for provider errors.
    pub fn provider(provider: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Provider {
            provider: provider.into(),
            message: message.into(),
        }
    }
}

/// Result alias used across NSK.
pub type NskResult<T> = Result<T, SandboxError>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::codes;

    #[test]
    fn policy_error_lists_count() {
        let err = SandboxError::PolicyValidation(vec![
            Diagnostic::error(codes::POLICY_INVALID, "bad wall time"),
            Diagnostic::error(codes::POLICY_INVALID, "bad memory"),
        ]);
        assert!(err.to_string().contains("2 issue(s)"));
    }

    #[test]
    fn io_error_converts() {
        let ioerr = std::io::Error::new(std::io::ErrorKind::NotFound, "gone");
        let err: SandboxError = ioerr.into();
        assert!(err.to_string().contains("gone"));
    }
}
