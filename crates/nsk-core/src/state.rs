//! Sandbox lifecycle state machine (design document §4.2, §4.3).
//!
//! States may only be changed by the Execution Manager; transitions are
//! validated against the table below.

use serde::{Deserialize, Serialize};

use crate::error::SandboxError;

/// Lifecycle state of a sandbox instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxState {
    /// Instance created.
    Created,
    /// Spec and policy validation in progress.
    Validating,
    /// Isolation environment and resources are being prepared.
    Preparing,
    /// Environment ready, waiting to start.
    Ready,
    /// Process is being started.
    Starting,
    /// Program is executing.
    Running,
    /// Program is being terminated (timeout / cancel / limit).
    Terminating,
    /// Execution results are being collected.
    Collecting,
    /// Resources are being cleaned up.
    Cleaning,
    /// Terminal state: finished (result available).
    Completed,
    /// Internal kernel error occurred.
    Failed,
}

impl SandboxState {
    /// All lifecycle states.
    pub const ALL: [SandboxState; 11] = [
        SandboxState::Created,
        SandboxState::Validating,
        SandboxState::Preparing,
        SandboxState::Ready,
        SandboxState::Starting,
        SandboxState::Running,
        SandboxState::Terminating,
        SandboxState::Collecting,
        SandboxState::Cleaning,
        SandboxState::Completed,
        SandboxState::Failed,
    ];

    /// Check whether `self -> to` is a legal transition (§4.3).
    ///
    /// Rules:
    /// * `Failed` may still move to `Cleaning` so that cleanup always runs
    ///   even after an internal error;
    /// * `Completed` is the only fully terminal state;
    /// * cancellation (`Terminating`) is reachable from every active state.
    pub fn can_transition_to(self, to: SandboxState) -> bool {
        use SandboxState::*;
        matches!(
            (self, to),
            (Created, Validating)
                | (Validating, Preparing)
                | (Validating, Failed)
                | (Preparing, Ready)
                | (Preparing, Failed)
                | (Ready, Starting)
                | (Ready, Terminating)
                | (Ready, Failed)
                | (Starting, Running)
                | (Starting, Terminating)
                | (Starting, Failed)
                | (Running, Terminating)
                | (Running, Collecting)
                | (Running, Failed)
                | (Terminating, Collecting)
                | (Terminating, Failed)
                | (Collecting, Cleaning)
                | (Collecting, Failed)
                | (Cleaning, Completed)
                | (Cleaning, Failed)
                | (Failed, Cleaning)
        )
    }

    /// Perform a validated transition, returning the new state.
    ///
    /// # Errors
    /// [`SandboxError::InvalidTransition`] when the transition is illegal.
    pub fn transition_to(self, to: SandboxState) -> Result<SandboxState, SandboxError> {
        if self.can_transition_to(to) {
            Ok(to)
        } else {
            Err(SandboxError::InvalidTransition { from: self, to })
        }
    }

    /// True once the sandbox reached a state from which no forward progress
    /// is possible without a new lifecycle operation.
    pub fn is_terminal(self) -> bool {
        matches!(self, SandboxState::Completed)
    }

    /// True while the sandbox is executing or about to execute a program.
    pub fn is_active(self) -> bool {
        matches!(
            self,
            SandboxState::Starting | SandboxState::Running | SandboxState::Terminating
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_is_legal() {
        let mut s = SandboxState::Created;
        for next in [
            SandboxState::Validating,
            SandboxState::Preparing,
            SandboxState::Ready,
            SandboxState::Starting,
            SandboxState::Running,
            SandboxState::Collecting,
            SandboxState::Cleaning,
            SandboxState::Completed,
        ] {
            s = s.transition_to(next).expect("legal transition");
        }
        assert_eq!(s, SandboxState::Completed);
        assert!(s.is_terminal());
    }

    #[test]
    fn termination_paths_are_legal() {
        for from in [
            SandboxState::Ready,
            SandboxState::Starting,
            SandboxState::Running,
        ] {
            assert!(from.can_transition_to(SandboxState::Terminating));
        }
        assert!(SandboxState::Terminating.can_transition_to(SandboxState::Collecting));
    }

    #[test]
    fn failure_still_reaches_cleanup() {
        assert!(SandboxState::Failed.can_transition_to(SandboxState::Cleaning));
        assert!(SandboxState::Cleaning.can_transition_to(SandboxState::Completed));
    }

    #[test]
    fn illegal_transitions_rejected() {
        // Cannot skip stages.
        assert!(!SandboxState::Created.can_transition_to(SandboxState::Running));
        // Cannot go backwards.
        assert!(!SandboxState::Running.can_transition_to(SandboxState::Created));
        // Terminal state cannot move.
        assert!(!SandboxState::Completed.can_transition_to(SandboxState::Cleaning));
        // Cannot cleanup directly from running (must terminate first).
        assert!(!SandboxState::Running.can_transition_to(SandboxState::Cleaning));

        let err = SandboxState::Created
            .transition_to(SandboxState::Running)
            .unwrap_err();
        assert!(matches!(err, SandboxError::InvalidTransition { .. }));
    }

    #[test]
    fn active_states() {
        for s in [
            SandboxState::Starting,
            SandboxState::Running,
            SandboxState::Terminating,
        ] {
            assert!(s.is_active());
        }
        assert!(!SandboxState::Ready.is_active());
    }
}
