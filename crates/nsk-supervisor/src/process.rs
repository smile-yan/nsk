//! Process specification and supervised process handle (§8.1, §8.2).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use nsk_core::error::SandboxError;
use nsk_core::result::ExitInfo;
use nsk_resource::limits::RlimitSpec;
use tracing::debug;
#[cfg(not(unix))]
use tracing::warn;

use crate::monitor::{ExecOutcome, OutcomeReason};
use crate::output::OutputShared;

/// Full command line to execute. `argv[0]` is the program; providers may
/// pass a launcher command line (e.g. `bwrap … -- program args…`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpec {
    pub argv: Vec<OsString>,
    pub cwd: Option<PathBuf>,
    /// Explicit environment whitelist (never inherits the host env).
    pub env: Vec<(String, String)>,
    pub stdin: nsk_core::spec::StdinSpec,
    /// Make the child a process-group leader (required for tree kills).
    pub process_group: bool,
    /// rlimits applied pre-exec (Unix; skipped elsewhere with a warning).
    pub rlimits: Vec<RlimitSpec>,
    /// Files opened pre-exec and duplicated onto fixed fds (launcher aux
    /// fds such as bwrap's `--seccomp-fd`).
    pub pre_open_files: Vec<(PathBuf, i32)>,
    /// Extra `CreateProcess` flags (Windows only; e.g. `CREATE_SUSPENDED`
    /// so a provider can assign the child to a Job Object before resume).
    pub creation_flags: u32,
}

impl ProcessSpec {
    /// Spec for `program` with no arguments, empty environment.
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            argv: vec![program.into()],
            cwd: None,
            env: Vec::new(),
            stdin: nsk_core::spec::StdinSpec::Closed,
            process_group: true,
            rlimits: Vec::new(),
            pre_open_files: Vec::new(),
            creation_flags: 0,
        }
    }

    /// Open `file` pre-exec and dup it onto `fd` (for launcher aux fds).
    pub fn pre_open(mut self, file: impl Into<PathBuf>, fd: i32) -> Self {
        self.pre_open_files.push((file.into(), fd));
        self
    }

    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.argv.push(arg.into());
        self
    }

    pub fn args(mut self, args: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        self.argv.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn stdin(mut self, stdin: nsk_core::spec::StdinSpec) -> Self {
        self.stdin = stdin;
        self
    }

    pub fn rlimits(mut self, rlimits: Vec<RlimitSpec>) -> Self {
        self.rlimits = rlimits;
        self
    }

    /// Render a redacted command line for logs (arguments kept — they are
    /// part of the spec the caller supplied; environment values are never
    /// logged, §15.4).
    pub fn display_command(&self) -> String {
        self.argv
            .iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Supervised process handle: spawn, wait, terminate, inspect output.
///
/// Handles are cheap to clone; all state is shared.
#[derive(Debug, Clone)]
pub struct SupervisedProcess {
    inner: Arc<SupervisedInner>,
}

#[derive(Debug)]
pub struct SupervisedInner {
    pub pid: u32,
    pub started_at: Instant,
    /// Resolves to the outcome when the monitor task finishes.
    pub done_rx: watch::Receiver<Option<Arc<ExecOutcome>>>,
    pub output: Arc<OutputShared>,
    pub cancel: CancellationToken,
    /// Termination requests from outside the monitor loop.
    pub terminate_tx: watch::Sender<Option<crate::terminate::TerminateKind>>,
}

impl SupervisedProcess {
    pub(crate) fn new(
        pid: u32,
        started_at: Instant,
        done_rx: watch::Receiver<Option<Arc<ExecOutcome>>>,
        output: Arc<OutputShared>,
        cancel: CancellationToken,
        terminate_tx: watch::Sender<Option<crate::terminate::TerminateKind>>,
    ) -> Self {
        Self {
            inner: Arc::new(SupervisedInner {
                pid,
                started_at,
                done_rx,
                output,
                cancel,
                terminate_tx,
            }),
        }
    }

    pub fn pid(&self) -> u32 {
        self.inner.pid
    }

    pub fn started_at(&self) -> Instant {
        self.inner.started_at
    }

    /// Request cancellation (maps to `TerminateKind::Cancel`).
    ///
    /// The monitor performs the actual group termination and afterwards
    /// cancels the shared token to stop stdin/collector tasks.
    pub fn cancel(&self) {
        self.inner
            .terminate_tx
            .send_replace(Some(crate::terminate::TerminateKind::Cancel));
    }

    /// Request graceful termination (SIGTERM → SIGKILL escalation).
    pub fn terminate(&self, kind: crate::terminate::TerminateKind) {
        self.inner.terminate_tx.send_replace(Some(kind));
    }

    /// Is the outcome already available?
    pub fn is_finished(&self) -> bool {
        self.inner.done_rx.borrow().is_some()
    }

    /// Peek at the outcome without awaiting.
    pub fn try_outcome(&self) -> Option<Arc<ExecOutcome>> {
        self.inner.done_rx.borrow().clone()
    }

    /// Await the outcome (multi-consumer safe).
    pub async fn wait(&self) -> Arc<ExecOutcome> {
        let mut rx = self.inner.done_rx.clone();
        loop {
            if let Some(outcome) = rx.borrow().clone() {
                return outcome;
            }
            if rx.changed().await.is_err() {
                // Sender dropped: monitor task panicked; surface as internal.
                return Arc::new(ExecOutcome {
                    pid: self.inner.pid,
                    exit: ExitInfo::from_exit_code(-1),
                    wall_time: self.inner.started_at.elapsed(),
                    reason: OutcomeReason::Internal("monitor task dropped".into()),
                    output: crate::output::OutputSnapshot::default(),
                });
            }
        }
    }

    /// Current output snapshot.
    pub fn output_snapshot(&self) -> crate::output::OutputSnapshot {
        self.inner.output.snapshot()
    }

    /// Exact output byte totals.
    pub fn output_totals(&self) -> (u64, u64) {
        self.inner.output.totals()
    }

    /// Subscribe to limit crossings.
    pub fn limits_watcher(&self) -> watch::Receiver<crate::output::LimitCrossing> {
        crate::output::limits_watcher(&self.inner.output)
    }
}

/// Build a `tokio::process::Command` from a spec.
pub(crate) fn build_command(spec: &ProcessSpec) -> Result<tokio::process::Command, SandboxError> {
    if spec.argv.is_empty() {
        return Err(SandboxError::Spawn("empty argv".into()));
    }
    let mut cmd = tokio::process::Command::new(&spec.argv[0]);
    cmd.args(&spec.argv[1..]);
    if let Some(cwd) = &spec.cwd {
        cmd.current_dir(cwd);
    }
    cmd.env_clear();
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);

    #[cfg(unix)]
    {
        if spec.process_group {
            cmd.process_group(0);
        }
        for rl in &spec.rlimits {
            apply_rlimit(&mut cmd, *rl)?;
        }
        for (path, fd) in &spec.pre_open_files {
            apply_pre_open(&mut cmd, path.clone(), *fd)?;
        }
    }
    #[cfg(windows)]
    {
        if spec.creation_flags != 0 {
            cmd.creation_flags(spec.creation_flags);
        }
        if !spec.rlimits.is_empty() {
            warn!(
                "rlimits requested but this platform has no pre-exec rlimit support; limits ignored"
            );
        }
        if !spec.process_group {
            debug!("process_group flag ignored on this platform");
        }
    }
    #[cfg(all(not(unix), not(windows)))]
    {
        if !spec.rlimits.is_empty() {
            warn!(
                "rlimits requested but this platform has no pre-exec rlimit support; limits ignored"
            );
        }
        if !spec.process_group {
            debug!("process_group flag ignored on this platform");
        }
    }

    Ok(cmd)
}

/// Open a file pre-exec and dup it onto a fixed fd.
#[cfg(unix)]
fn apply_pre_open(
    cmd: &mut tokio::process::Command,
    path: PathBuf,
    target_fd: i32,
) -> Result<(), SandboxError> {
    // SAFETY: the closure only calls open/dup2/close (async-signal-safe)
    // and runs between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            let c_path = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
                Ok(p) => p,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "path contains NUL",
                    ));
                }
            };
            let fd = libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(fd, target_fd) == -1 {
                let e = std::io::Error::last_os_error();
                libc::close(fd);
                return Err(e);
            }
            libc::close(fd);
            Ok(())
        });
    }
    Ok(())
}

/// Apply one rlimit inside the pre-exec hook.
#[cfg(unix)]
fn apply_rlimit(cmd: &mut tokio::process::Command, rl: RlimitSpec) -> Result<(), SandboxError> {
    use nsk_resource::limits::RlimitSpec as R;
    let resource = match rl {
        R::OpenFiles(_) => libc::RLIMIT_NOFILE,
        R::FileSize(_) => libc::RLIMIT_FSIZE,
        R::CpuTime(_) => libc::RLIMIT_CPU,
        R::AddressSpace(_) => libc::RLIMIT_AS,
        R::Processes(_) => libc::RLIMIT_NPROC,
    };
    let value = rl.value() as libc::rlim_t;
    let lim = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: the closure only calls setrlimit (async-signal-safe) before exec.
    unsafe {
        cmd.pre_exec(move || {
            let rc = libc::setrlimit(resource, &lim);
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    debug!(
        rlimit = rl.name(),
        value = rl.value(),
        "rlimit will be applied"
    );
    Ok(())
}

/// Serialization support for result reporting (§5.8 consumers).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessReport {
    pub pid: u32,
    pub command: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_builder() {
        let spec = ProcessSpec::new("/bin/sh")
            .arg("-c")
            .arg("echo hi")
            .cwd("/tmp")
            .env("A", "1")
            .stdin(nsk_core::spec::StdinSpec::Bytes(b"x".to_vec()))
            .rlimits(vec![RlimitSpec::OpenFiles(64)]);
        assert_eq!(spec.argv.len(), 3);
        assert_eq!(spec.env.len(), 1);
        assert_eq!(spec.rlimits.len(), 1);
        assert!(spec.display_command().starts_with("/bin/sh"));
    }

    #[test]
    fn empty_argv_rejected() {
        let spec = ProcessSpec {
            argv: vec![],
            ..ProcessSpec::new("/bin/true")
        };
        let mut spec = spec;
        spec.argv.clear();
        assert!(build_command(&spec).is_err());
    }

    #[test]
    fn build_command_env_is_explicit() {
        let spec = ProcessSpec::new("/usr/bin/env").env("FOO", "bar");
        let _cmd = build_command(&spec).expect("command builds");
        // env_clear + explicit env applied at spawn time; here we only check
        // construction succeeds.
    }
}
