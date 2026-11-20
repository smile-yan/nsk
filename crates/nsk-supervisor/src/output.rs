//! Bounded output collection (§8.5).
//!
//! Pipeline per stream:
//! `process pipe → async reader → bounded OutputBuffer → byte counter
//!  (OutputTracker) → policy enforcement signal → snapshot / event`.
//!
//! Guarantees:
//! * streaming reads, bounded memory (retain cap per stream),
//! * totals are exact even when retention is truncated,
//! * limit crossings are signalled exactly once via a watch channel,
//! * event taps use a bounded broadcast channel and never block.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Output stream kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// Events emitted by the supervisor for higher layers (§14.4 consumers).
#[derive(Debug, Clone)]
pub enum SupervisorEvent {
    /// Streaming output chunk.
    OutputChunk(OutputStream, Vec<u8>),
    /// Output limit crossed.
    LimitCrossed(LimitCrossing),
    /// Group termination started.
    Terminating(crate::terminate::TerminateKind),
}

/// Which limits were crossed (single-shot flags, see `OutputTracker`).
pub type LimitCrossing = nsk_resource::usage::LimitCrossing;

/// Bounded retention buffer for one stream (§8.5 bounded buffer).
#[derive(Debug, Default)]
pub struct OutputBuffer {
    data: Vec<u8>,
    total: u64,
    truncated: bool,
    retain_cap: usize,
}

impl OutputBuffer {
    pub fn new(retain_cap: usize) -> Self {
        Self {
            data: Vec::with_capacity(retain_cap.min(4096)),
            total: 0,
            truncated: false,
            retain_cap,
        }
    }

    /// Append a chunk; retains only the first `retain_cap` bytes.
    pub fn append(&mut self, chunk: &[u8]) {
        self.total += chunk.len() as u64;
        let room = self.retain_cap.saturating_sub(self.data.len());
        if room > 0 {
            let take = room.min(chunk.len());
            self.data.extend_from_slice(&chunk[..take]);
            if take < chunk.len() {
                self.truncated = true;
            }
        } else if !chunk.is_empty() {
            self.truncated = true;
        }
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn retained(&self) -> &[u8] {
        &self.data
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Snapshot of one sandbox's collected output (§5.8 OutputResult input).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputSnapshot {
    pub stdout: nsk_core::result::OutputData,
    pub stderr: nsk_core::result::OutputData,
}

/// Shared state for one sandbox's two output streams.
#[derive(Debug)]
pub struct OutputShared {
    pub stdout: Mutex<OutputBuffer>,
    pub stderr: Mutex<OutputBuffer>,
    /// Byte accounting shared by both collectors.
    pub tracker: Mutex<nsk_resource::usage::OutputTracker>,
    /// Signalled when any limit is crossed (only the initial value matters;
    /// watchers observe subsequent sends).
    pub limits_tx: watch::Sender<LimitCrossing>,
}

impl OutputShared {
    pub fn new(
        max_stdout: u64,
        max_stderr: u64,
        max_combined: u64,
        retain_per_stream: usize,
    ) -> Arc<Self> {
        let (limits_tx, _) = watch::channel(LimitCrossing::default());
        Arc::new(Self {
            stdout: Mutex::new(OutputBuffer::new(retain_per_stream)),
            stderr: Mutex::new(OutputBuffer::new(retain_per_stream)),
            tracker: Mutex::new(nsk_resource::usage::OutputTracker::new(
                max_stdout,
                max_stderr,
                max_combined,
            )),
            limits_tx,
        })
    }

    /// Current snapshot from the shared buffers.
    pub fn snapshot(&self) -> OutputSnapshot {
        let stdout = self.stdout.lock().map(|b| nsk_core::result::OutputData {
            total_bytes: b.total(),
            retained: b.retained().to_vec(),
            truncated: b.truncated(),
        });
        let stderr = self.stderr.lock().map(|b| nsk_core::result::OutputData {
            total_bytes: b.total(),
            retained: b.retained().to_vec(),
            truncated: b.truncated(),
        });
        OutputSnapshot {
            stdout: stdout.unwrap_or_default(),
            stderr: stderr.unwrap_or_default(),
        }
    }

    /// Current byte totals (from the tracker, exact even when retention
    /// truncated).
    pub fn totals(&self) -> (u64, u64) {
        match self.tracker.lock() {
            Ok(t) => (t.stdout_bytes(), t.stderr_bytes()),
            Err(_) => (0, 0),
        }
    }
}

/// Subscribe to limit crossings.
pub fn limits_watcher(shared: &Arc<OutputShared>) -> watch::Receiver<LimitCrossing> {
    shared.limits_tx.subscribe()
}

/// One collector task reading a stream until EOF.
///
/// `tap` receives every chunk (bounded broadcast; lagging subscribers lose
/// chunks but never block collection — §14.4 event stream rules).
pub async fn collect_stream<R>(
    mut pipe: R,
    kind: OutputStream,
    shared: Arc<OutputShared>,
    tap: Option<tokio::sync::broadcast::Sender<SupervisorEvent>>,
    stop: CancellationToken,
) where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        tokio::select! {
            read = pipe.read(&mut buf) => {
                match read {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        let chunk = &buf[..n];
                        {
                            let buffer = match kind {
                                OutputStream::Stdout => shared.stdout.lock(),
                                OutputStream::Stderr => shared.stderr.lock(),
                            }
                            .map(|mut b| b.append(chunk));
                            let _ = buffer;
                        }
                        let crossed = match shared.tracker.lock() {
                            Ok(mut t) => Some(t.push(kind.into(), n as u64)),
                            Err(_) => None,
                        };
                        if let Some(crossed) = crossed {
                            if crossed.any() {
                                // Send regardless of subscribers; watch keeps
                                // the latest value for late watchers.
                                let _ = shared.limits_tx.send(crossed);
                            }
                        }
                        if let Some(tx) = &tap {
                            // Bounded channel: lagging subscribers lose
                            // chunks; the retained buffer stays authoritative.
                            let _ = tx.send(SupervisorEvent::OutputChunk(kind, chunk.to_vec()));
                        }
                    }
                    Err(e) => {
                        tracing::debug!(stream = ?kind, error = %e, "output pipe read error");
                        break;
                    }
                }
            }
            _ = stop.cancelled() => break,
        }
    }
}

impl From<OutputStream> for nsk_resource::usage::OutputStream {
    fn from(s: OutputStream) -> Self {
        match s {
            OutputStream::Stdout => nsk_resource::usage::OutputStream::Stdout,
            OutputStream::Stderr => nsk_resource::usage::OutputStream::Stderr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_retains_prefix_and_counts_total() {
        let mut b = OutputBuffer::new(8);
        b.append(b"12345678");
        assert!(!b.truncated());
        b.append(b"90");
        assert_eq!(b.total(), 10);
        assert_eq!(b.retained(), b"12345678");
        assert!(b.truncated());
    }

    #[test]
    fn buffer_exact_fit_not_truncated() {
        let mut b = OutputBuffer::new(4);
        b.append(b"abcd");
        assert!(!b.truncated());
        assert_eq!(b.total(), 4);
    }

    #[tokio::test]
    async fn collector_reads_from_memory_stream() {
        let shared = OutputShared::new(u64::MAX, u64::MAX, u64::MAX, 1024);
        let data = b"stream-data".to_vec();
        let cursor = std::io::Cursor::new(data.clone());
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            collect_stream(
                cursor,
                OutputStream::Stdout,
                shared.clone(),
                None,
                CancellationToken::new(),
            ),
        )
        .await
        .expect("collector finishes");
        assert_eq!(shared.snapshot().stdout.retained, b"stream-data");
        assert_eq!(shared.snapshot().stdout.total_bytes, data.len() as u64);
    }

    #[test]
    fn shared_snapshot_and_totals() {
        let shared = OutputShared::new(10, 10, 20, 10);
        shared
            .stdout
            .lock()
            .unwrap()
            .append(b"hello world longer than ten");
        let snap = shared.snapshot();
        assert_eq!(snap.stdout.total_bytes, 27);
        assert_eq!(snap.stdout.retained.len(), 10);
        assert!(snap.stdout.truncated);
    }
}
