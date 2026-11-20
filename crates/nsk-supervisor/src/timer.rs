//! Wall-clock deadline helper (§8.2 Timer).

use std::time::{Duration, Instant};

/// An absolute monotonic deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    at: Instant,
}

impl Deadline {
    /// Deadline `duration` from now.
    pub fn after(duration: Duration) -> Self {
        Self {
            at: Instant::now() + duration,
        }
    }

    /// Deadline at an absolute instant.
    pub fn at(instant: Instant) -> Self {
        Self { at: instant }
    }

    /// The underlying instant.
    pub fn instant(&self) -> Instant {
        self.at
    }

    /// Time remaining until the deadline (zero when already passed).
    pub fn remaining(&self) -> Duration {
        self.at.saturating_duration_since(Instant::now())
    }

    /// Has the deadline passed?
    pub fn expired(&self) -> bool {
        Instant::now() >= self.at
    }
}

impl std::fmt::Display for Deadline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}ms remaining", self.remaining().as_millis())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn future_deadline_has_remaining_time() {
        let d = Deadline::after(Duration::from_millis(50));
        assert!(!d.expired());
        assert!(d.remaining() <= Duration::from_millis(50));
        std::thread::sleep(Duration::from_millis(60));
        assert!(d.expired());
        assert_eq!(d.remaining(), Duration::ZERO);
    }

    #[test]
    fn at_instant_matches() {
        let now = Instant::now();
        let d = Deadline::at(now + Duration::from_secs(10));
        assert!(d.remaining() > Duration::from_secs(9));
    }
}
