//! Output byte tracking with limit-crossing detection (§8.5).

use serde::{Deserialize, Serialize};

/// Which output stream produced the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// Tracks per-stream and combined byte totals against configured caps.
///
/// Pure accounting: the decision to terminate belongs to the supervisor,
/// which reacts to the returned flags.
#[derive(Debug)]
pub struct OutputTracker {
    max_stdout: u64,
    max_stderr: u64,
    max_combined: u64,
    stdout_bytes: u64,
    stderr_bytes: u64,
    stdout_exceeded: bool,
    stderr_exceeded: bool,
    combined_exceeded: bool,
}

/// Flags describing which limits were crossed by the latest push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LimitCrossing {
    pub stdout: bool,
    pub stderr: bool,
    pub combined: bool,
}

impl LimitCrossing {
    pub fn any(self) -> bool {
        self.stdout || self.stderr || self.combined
    }
}

impl OutputTracker {
    pub fn new(max_stdout: u64, max_stderr: u64, max_combined: u64) -> Self {
        Self {
            max_stdout,
            max_stderr,
            max_combined,
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_exceeded: false,
            stderr_exceeded: false,
            combined_exceeded: false,
        }
    }

    /// Account `n` bytes produced by `stream`; returns crossed limits.
    pub fn push(&mut self, stream: OutputStream, n: u64) -> LimitCrossing {
        match stream {
            OutputStream::Stdout => self.stdout_bytes += n,
            OutputStream::Stderr => self.stderr_bytes += n,
        }
        let mut crossed = LimitCrossing::default();
        if !self.stdout_exceeded && self.stdout_bytes > self.max_stdout {
            self.stdout_exceeded = true;
            crossed.stdout = true;
        }
        if !self.stderr_exceeded && self.stderr_bytes > self.max_stderr {
            self.stderr_exceeded = true;
            crossed.stderr = true;
        }
        if !self.combined_exceeded && self.output_bytes() > self.max_combined {
            self.combined_exceeded = true;
            crossed.combined = true;
        }
        crossed
    }

    pub fn stdout_bytes(&self) -> u64 {
        self.stdout_bytes
    }

    pub fn stderr_bytes(&self) -> u64 {
        self.stderr_bytes
    }

    pub fn output_bytes(&self) -> u64 {
        self.stdout_bytes + self.stderr_bytes
    }

    pub fn stdout_exceeded(&self) -> bool {
        self.stdout_exceeded
    }

    pub fn stderr_exceeded(&self) -> bool {
        self.stderr_exceeded
    }

    pub fn combined_exceeded(&self) -> bool {
        self.combined_exceeded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_totals() {
        let mut t = OutputTracker::new(100, 100, 150);
        t.push(OutputStream::Stdout, 40);
        t.push(OutputStream::Stderr, 30);
        assert_eq!(t.stdout_bytes(), 40);
        assert_eq!(t.stderr_bytes(), 30);
        assert_eq!(t.output_bytes(), 70);
        assert!(!t.push(OutputStream::Stdout, 10).any());
    }

    #[test]
    fn detects_single_stream_crossing() {
        let mut t = OutputTracker::new(100, 100, 1000);
        assert!(!t.push(OutputStream::Stdout, 100).any());
        let crossed = t.push(OutputStream::Stdout, 1);
        assert!(crossed.stdout);
        assert!(t.stdout_exceeded());
        // Crossing is reported once.
        assert!(!t.push(OutputStream::Stdout, 1).stdout);
    }

    #[test]
    fn detects_combined_crossing() {
        let mut t = OutputTracker::new(100, 100, 150);
        assert!(!t.push(OutputStream::Stdout, 80).any());
        let crossed = t.push(OutputStream::Stderr, 80);
        assert!(!crossed.stdout);
        assert!(!crossed.stderr);
        assert!(crossed.combined);
    }
}
