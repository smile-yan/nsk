//! Usage sources and periodic sampling (§7.2, §7.3).
//!
//! A [`UsageSource`] provides current usage snapshots; the [`UsageSampler`]
//! polls a source at a fixed interval, feeding an accountant and optionally
//! delivering snapshots to a broadcast channel for event subscribers.
//! Sampling may lag, never blocks, and never terminates anything by itself.

use std::time::Duration;

use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use nsk_core::result::ResourceUsage;

use crate::accounting::UsageAccountant;

/// Provider of current usage snapshots for a running sandbox.
pub trait UsageSource: Send + Sync {
    /// Take one snapshot. Implementations must be cheap and non-blocking.
    fn snapshot(&self) -> ResourceUsage;
}

/// Simple static source (tests, mock provider).
#[derive(Debug, Clone)]
pub struct StaticUsageSource {
    pub usage: ResourceUsage,
}

impl UsageSource for StaticUsageSource {
    fn snapshot(&self) -> ResourceUsage {
        self.usage.clone()
    }
}

/// Source backed by a closure (used by providers to expose cgroup metrics).
pub struct FnUsageSource<F: Fn() -> ResourceUsage + Send + Sync> {
    f: F,
}

impl<F: Fn() -> ResourceUsage + Send + Sync> std::fmt::Debug for FnUsageSource<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FnUsageSource")
    }
}

impl<F: Fn() -> ResourceUsage + Send + Sync> FnUsageSource<F> {
    pub fn new(f: F) -> Self {
        Self { f }
    }
}

impl<F: Fn() -> ResourceUsage + Send + Sync> UsageSource for FnUsageSource<F> {
    fn snapshot(&self) -> ResourceUsage {
        (self.f)()
    }
}

/// Runs a periodic sampling loop for one sandbox.
#[derive(Debug, Default)]
pub struct UsageSampler;

impl UsageSampler {
    /// Sample `source` every `interval` until `token` is cancelled, feeding
    /// `accountant` and broadcasting snapshots on `events` when provided.
    ///
    /// Returns the final accumulated accountant.
    pub async fn run(
        source: std::sync::Arc<dyn UsageSource>,
        interval: Duration,
        token: CancellationToken,
        accountant: std::sync::Arc<std::sync::Mutex<UsageAccountant>>,
        events: Option<broadcast::Sender<ResourceUsage>>,
    ) -> UsageAccountant {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let usage = source.snapshot();
                    if let Ok(mut acc) = accountant.lock() {
                        acc.observe(&usage);
                        let snap = acc.snapshot();
                        if let Some(tx) = &events {
                            // Bounded broadcast: lagging subscribers lose
                            // samples; never blocks the loop.
                            let _ = tx.send(snap);
                        }
                    }
                }
                _ = token.cancelled() => {
                    // Final sample before exiting so peak data is complete.
                    let usage = source.snapshot();
                    if let Ok(mut acc) = accountant.lock() {
                        acc.observe(&usage);
                    }
                    break;
                }
            }
        }
        if let Ok(acc) = accountant.lock() {
            acc.clone()
        } else {
            UsageAccountant::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct CountingSource {
        count: AtomicU32,
    }

    impl UsageSource for CountingSource {
        fn snapshot(&self) -> ResourceUsage {
            let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
            ResourceUsage {
                wall_time: Duration::from_millis(n as u64 * 10),
                ..Default::default()
            }
        }
    }

    #[tokio::test]
    async fn sampler_accumulates_until_cancel() {
        let source = Arc::new(CountingSource {
            count: AtomicU32::new(0),
        });
        let acc = Arc::new(std::sync::Mutex::new(UsageAccountant::new()));
        let token = CancellationToken::new();

        let sampler_token = token.clone();
        let handle = tokio::spawn(UsageSampler::run(
            source,
            Duration::from_millis(10),
            sampler_token,
            acc.clone(),
            None,
        ));

        tokio::time::sleep(Duration::from_millis(60)).await;
        token.cancel();
        let final_acc = handle.await.expect("sampler task");

        // At least a few samples were taken.
        assert!(final_acc.snapshot().wall_time >= Duration::from_millis(20));
    }

    #[tokio::test]
    async fn sampler_broadcasts_snapshots() {
        let source = Arc::new(CountingSource {
            count: AtomicU32::new(0),
        });
        let acc = Arc::new(std::sync::Mutex::new(UsageAccountant::new()));
        let (tx, mut rx) = broadcast::channel(8);
        let token = CancellationToken::new();

        let handle = tokio::spawn(UsageSampler::run(
            source,
            Duration::from_millis(10),
            token.clone(),
            acc.clone(),
            Some(tx),
        ));

        let mut received = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
        while received < 2 && tokio::time::Instant::now() < deadline {
            if tokio::time::timeout(Duration::from_millis(50), rx.recv())
                .await
                .is_ok()
            {
                received += 1;
            }
        }
        token.cancel();
        let _ = handle.await;
        assert!(received >= 2, "expected broadcast samples, got {received}");
    }
}
