//! # nsk-scheduler
//!
//! Kernel-level FIFO scheduling with bounded concurrency (§3.1 Scheduler,
//! Phase 11 / M9).
//!
//! * FIFO submission queue with a maximum queue length,
//! * global concurrency limit (how many sandboxes may run at once),
//! * per-task handles with cancellation,
//! * task bookkeeping for diagnostics.
//!
//! The scheduler never touches OS resources (§13.2): it only decides *when*
//! a submitted sandbox is handed to the runtime.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nsk_core::diagnostic::{Diagnostic, codes};
use nsk_core::error::SandboxError;
use nsk_core::id::SandboxId;
use nsk_core::result::{SandboxResult, SandboxStatus};
use nsk_core::spec::SandboxSpec;
use nsk_runtime::SandboxRuntime;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Semaphore, watch};
use tracing::{debug, info, warn};

/// Scheduler configuration (§ Phase 11: Global Resource Budget).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerConfig {
    /// Maximum concurrently executing sandboxes (global budget).
    pub max_concurrency: usize,
    /// Maximum queued submissions before rejecting new ones.
    pub max_queue: usize,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 4,
            max_queue: 256,
        }
    }
}

/// Handle to one submitted task.
#[derive(Debug, Clone)]
pub struct TaskHandle {
    pub task_id: u64,
    sandbox_id: watch::Receiver<Option<SandboxId>>,
    result: watch::Receiver<Option<Arc<SandboxResult>>>,
    cancel: tokio_util::sync::CancellationToken,
}

impl TaskHandle {
    /// Await the sandbox result.
    pub async fn result(&self) -> Arc<SandboxResult> {
        let mut rx = self.result.clone();
        loop {
            if let Some(r) = rx.borrow().clone() {
                return r;
            }
            if rx.changed().await.is_err() {
                return Arc::new(SandboxResult::new(
                    self.sandbox_id().unwrap_or_default(),
                    SandboxStatus::InternalError,
                ));
            }
        }
    }

    /// Cancel the task (whether queued or already running).
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// The sandbox id once the task reached the runtime.
    pub fn sandbox_id(&self) -> Option<SandboxId> {
        *self.sandbox_id.borrow()
    }
}

struct QueueItem {
    pub spec: SandboxSpec,
    task_id: u64,
    sandbox_id_tx: watch::Sender<Option<SandboxId>>,
    result_tx: watch::Sender<Option<Arc<SandboxResult>>>,
    cancel: tokio_util::sync::CancellationToken,
}

/// Global counters for diagnostics.
#[derive(Debug, Default)]
pub struct SchedulerStats {
    pub submitted: AtomicU64,
    pub started: AtomicU64,
    pub completed: AtomicU64,
    pub rejected: AtomicU64,
    pub cancelled: AtomicU64,
}

impl SchedulerStats {
    pub fn snapshot(&self) -> SchedulerStatsSnapshot {
        SchedulerStatsSnapshot {
            submitted: self.submitted.load(Ordering::SeqCst),
            started: self.started.load(Ordering::SeqCst),
            completed: self.completed.load(Ordering::SeqCst),
            rejected: self.rejected.load(Ordering::SeqCst),
            cancelled: self.cancelled.load(Ordering::SeqCst),
        }
    }
}

/// Point-in-time scheduler statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerStatsSnapshot {
    pub submitted: u64,
    pub started: u64,
    pub completed: u64,
    pub rejected: u64,
    pub cancelled: u64,
}

/// FIFO scheduler with a concurrency budget.
pub struct Scheduler {
    config: SchedulerConfig,
    runtime: Arc<dyn SandboxRuntime>,
    queue: Arc<Mutex<VecDeque<QueueItem>>>,
    permits: Arc<Semaphore>,
    stats: Arc<SchedulerStats>,
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scheduler")
            .field("config", &self.config)
            .field("stats", &self.stats())
            .finish()
    }
}

impl Scheduler {
    /// Attach a scheduler to a runtime.
    pub fn new(config: SchedulerConfig, runtime: Arc<dyn SandboxRuntime>) -> Self {
        let permits = Arc::new(Semaphore::new(config.max_concurrency));
        Self {
            config,
            runtime,
            queue: Arc::new(Mutex::new(VecDeque::new())),
            permits,
            stats: Arc::new(SchedulerStats::default()),
        }
    }

    pub fn config(&self) -> SchedulerConfig {
        self.config
    }

    pub fn stats(&self) -> SchedulerStatsSnapshot {
        self.stats.snapshot()
    }

    /// Submit a spec for FIFO execution.
    ///
    /// # Errors
    /// [`SandboxError::InvalidOperation`] when the queue is full.
    pub async fn submit(&self, spec: SandboxSpec) -> Result<TaskHandle, SandboxError> {
        let mut queue = self.queue.lock().await;
        if queue.len() >= self.config.max_queue {
            self.stats.rejected.fetch_add(1, Ordering::SeqCst);
            warn!(queue_len = queue.len(), "submission rejected: queue full");
            return Err(SandboxError::InvalidOperation {
                id: spec.id,
                state: nsk_core::state::SandboxState::Created,
                required: "queue below max_queue",
            });
        }
        let task_id = self.stats.submitted.fetch_add(1, Ordering::SeqCst) + 1;
        let (sandbox_id_tx, sandbox_id_rx) = watch::channel(None);
        let (result_tx, result_rx) = watch::channel(None);
        let cancel = tokio_util::sync::CancellationToken::new();
        let item = QueueItem {
            spec,
            task_id,
            sandbox_id_tx,
            result_tx,
            cancel: cancel.clone(),
        };
        debug!(task = task_id, "task submitted");
        queue.push_back(item);
        drop(queue);

        // Ensure a worker drain loop is running.
        tokio::spawn(Self::run_worker(
            self.queue.clone(),
            self.permits.clone(),
            self.runtime.clone(),
            self.stats.clone(),
        ));

        Ok(TaskHandle {
            task_id,
            sandbox_id: sandbox_id_rx,
            result: result_rx,
            cancel,
        })
    }

    /// The worker loop: dequeue → acquire permit → execute → report.
    ///
    /// Multiple workers may run concurrently; dequeue order under the queue
    /// lock preserves FIFO. Workers exit when the queue drains.
    async fn run_worker(
        queue: Arc<Mutex<VecDeque<QueueItem>>>,
        permits: Arc<Semaphore>,
        runtime: Arc<dyn SandboxRuntime>,
        stats: Arc<SchedulerStats>,
    ) {
        loop {
            let item = {
                let mut q = queue.lock().await;
                loop {
                    match q.pop_front() {
                        Some(item) if item.cancel.is_cancelled() => {
                            stats.cancelled.fetch_add(1, Ordering::SeqCst);
                            item.result_tx
                                .send_replace(Some(Arc::new(SandboxResult::new(
                                    item.spec.id,
                                    SandboxStatus::Cancelled,
                                ))));
                            continue;
                        }
                        Some(item) => break item,
                        None => return, // queue drained: worker exits
                    }
                }
            };

            let _permit = match permits.acquire().await {
                Ok(p) => p,
                Err(_) => {
                    item.result_tx
                        .send_replace(Some(Arc::new(SandboxResult::new(
                            item.spec.id,
                            SandboxStatus::Cancelled,
                        ))));
                    return;
                }
            };
            stats.started.fetch_add(1, Ordering::SeqCst);

            if item.cancel.is_cancelled() {
                stats.cancelled.fetch_add(1, Ordering::SeqCst);
                item.result_tx
                    .send_replace(Some(Arc::new(SandboxResult::new(
                        item.spec.id,
                        SandboxStatus::Cancelled,
                    ))));
                continue;
            }

            let result = tokio::select! {
                r = async {
                    match runtime.create(item.spec.clone()).await {
                        Ok(id) => {
                            let _ = item.sandbox_id_tx.send_replace(Some(id));
                            if let Err(e) = runtime.start(id).await {
                                Err(e)
                            } else {
                                runtime.wait(id).await.map(|r| (*r).clone())
                            }
                        }
                        Err(e) => Err(e),
                    }
                } => Some(r),
                _ = item.cancel.cancelled() => None,
            };

            match result {
                Some(Ok(mut r)) => {
                    if item.cancel.is_cancelled() {
                        r.status = SandboxStatus::Cancelled;
                        stats.cancelled.fetch_add(1, Ordering::SeqCst);
                    }
                    stats.completed.fetch_add(1, Ordering::SeqCst);
                    item.result_tx.send_replace(Some(Arc::new(r)));
                }
                Some(Err(e)) => {
                    warn!(task = item.task_id, error = %e, "scheduled execution failed");
                    let mut failure =
                        SandboxResult::new(item.spec.id, SandboxStatus::InternalError);
                    failure.diagnostics.push(Diagnostic::error(
                        codes::SPAWN_FAILED,
                        format!("scheduled execution failed: {e}"),
                    ));
                    result_tx_replace(&item.result_tx, failure);
                }
                None => {
                    // Cancelled before/during execution.
                    // Copy out of the borrow before awaiting (Ref is !Send).
                    let maybe_id = *item.sandbox_id_tx.borrow();
                    if let Some(id) = maybe_id {
                        let _ = runtime.cancel(id).await;
                    }
                    stats.cancelled.fetch_add(1, Ordering::SeqCst);
                    result_tx_replace(
                        &item.result_tx,
                        SandboxResult::new(item.spec.id, SandboxStatus::Cancelled),
                    );
                }
            }
            info!(task = item.task_id, "task finished");
        }
    }
}

fn result_tx_replace(tx: &watch::Sender<Option<Arc<SandboxResult>>>, r: SandboxResult) {
    tx.send_replace(Some(Arc::new(r)));
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use nsk_core::spec::CommandSpec;
    use std::sync::atomic::AtomicUsize;

    fn relaxed_policy() -> nsk_core::policy::SandboxPolicy {
        let mut p = nsk_core::policy::SandboxPolicy::minimal();
        p.isolation = nsk_core::policy::IsolationPolicy {
            isolate_process: false,
            isolate_filesystem: false,
            isolate_network: false,
            isolate_ipc: false,
            isolate_uts: false,
        };
        p.filesystem.isolate_root = false;
        p.filesystem.deny_host_paths = false;
        p.security.no_new_privileges = false;
        p.security.drop_privileges = false;
        p
    }

    fn echo_spec(tag: &str) -> SandboxSpec {
        let mut spec = SandboxSpec::new(CommandSpec::new("/bin/echo").arg(tag));
        spec.policy = relaxed_policy();
        spec
    }

    async fn build_runtime() -> Arc<dyn SandboxRuntime> {
        Arc::new(
            nsk_runtime::SandboxRuntimeBuilder::new()
                .with_provider(nsk_provider::create_mock_provider())
                .build()
                .await
                .unwrap(),
        )
    }

    // Shared runtime: avoids per-test SIGCHLD contention (see
    // nsk-runtime tests for the rationale).
    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
        })
        .block_on(fut)
    }

    #[test]
    fn fifo_order_preserved() {
        block_on(async {
            let scheduler = Scheduler::new(
                SchedulerConfig {
                    max_concurrency: 1,
                    max_queue: 16,
                },
                build_runtime().await,
            );
            let order = Arc::new(Mutex::new(Vec::new()));
            let mut handles = Vec::new();
            for i in 0..6 {
                let order = order.clone();
                let h = scheduler
                    .submit(echo_spec(&format!("fifo-{i}")))
                    .await
                    .unwrap();
                handles.push((i, h, order));
            }
            for (expected, h, order) in handles {
                let result = h.result().await;
                assert_eq!(result.status, SandboxStatus::Success);
                order.lock().await.push(expected);
            }
            let got = order.lock().await.clone();
            assert_eq!(got, vec![0, 1, 2, 3, 4, 5], "strict FIFO with 1 permit");
        });
    }

    #[test]
    fn concurrency_budget_respected() {
        block_on(async {
            let scheduler = Scheduler::new(
                SchedulerConfig {
                    max_concurrency: 2,
                    max_queue: 32,
                },
                build_runtime().await,
            );
            let mut handles = Vec::new();
            for i in 0..10 {
                handles.push(
                    scheduler
                        .submit(echo_spec(&format!("conc-{i}")))
                        .await
                        .unwrap(),
                );
            }
            for h in handles {
                let r = h.result().await;
                assert_eq!(r.status, SandboxStatus::Success);
            }
            let stats = scheduler.stats();
            assert_eq!(stats.submitted, 10);
            assert_eq!(stats.completed, 10);
            assert_eq!(stats.rejected, 0);
        });
    }

    #[test]
    fn cancel_queued_task() {
        block_on(async {
            let scheduler = Scheduler::new(
                SchedulerConfig {
                    max_concurrency: 1,
                    max_queue: 8,
                },
                build_runtime().await,
            );
            // A slow task holds the only permit.
            let mut spec = SandboxSpec::new(CommandSpec::new("/bin/sleep").arg("2"));
            spec.policy = relaxed_policy();
            let slow = scheduler.submit(spec).await.unwrap();
            let queued = scheduler.submit(echo_spec("cancelled-tag")).await.unwrap();
            queued.cancel();

            let result = queued.result().await;
            assert_eq!(result.status, SandboxStatus::Cancelled);
            let _ = slow.result().await;
        });
    }

    #[test]
    fn cancel_running_task() {
        block_on(async {
            let scheduler = Scheduler::new(
                SchedulerConfig {
                    max_concurrency: 4,
                    max_queue: 8,
                },
                build_runtime().await,
            );
            let mut spec = SandboxSpec::new(CommandSpec::new("/bin/sleep").arg("30"));
            spec.policy = relaxed_policy();
            let h = scheduler.submit(spec).await.unwrap();
            // Wait until it actually started.
            while h.sandbox_id().is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            h.cancel();
            let result = h.result().await;
            assert_eq!(result.status, SandboxStatus::Cancelled);
        });
    }

    #[test]
    fn queue_overflow_rejects() {
        block_on(async {
            let scheduler = Arc::new(Scheduler::new(
                SchedulerConfig {
                    max_concurrency: 1,
                    max_queue: 1,
                },
                build_runtime().await,
            ));
            // One slow task deterministically holds the permit.
            let mut spec = SandboxSpec::new(CommandSpec::new("/bin/sleep").arg("1"));
            spec.policy = relaxed_policy();
            let slow = scheduler.submit(spec).await.unwrap();
            while slow.sandbox_id().is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            // The worker is busy: one submission fills the queue, the next is
            // rejected.
            let _queued = scheduler.submit(echo_spec("q2")).await.unwrap();
            let r = scheduler.submit(echo_spec("q3")).await;
            assert!(matches!(
                r,
                Err(SandboxError::InvalidOperation {
                    required: "queue below max_queue",
                    ..
                })
            ));
            let stats = scheduler.stats();
            assert_eq!(stats.rejected, 1);
            let _ = slow.result().await;
        });
    }

    #[test]
    fn stats_counting() {
        block_on(async {
            let scheduler = Scheduler::new(
                SchedulerConfig {
                    max_concurrency: 2,
                    max_queue: 8,
                },
                build_runtime().await,
            );
            for i in 0..4 {
                scheduler
                    .submit(echo_spec(&format!("stats-{i}")))
                    .await
                    .unwrap();
            }
            // Wait for completion via stats.
            for _ in 0..100 {
                if scheduler.stats().completed == 4 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            let stats = scheduler.stats();
            assert_eq!(stats.completed, 4);
            assert_eq!(stats.started, 4);
            assert_eq!(stats.submitted, 4);
        });
    }

    // Keep the atomic import used.
    #[allow(dead_code)]
    fn _use_atomic(a: &AtomicUsize) {
        let _ = a.load(Ordering::SeqCst);
    }
}
