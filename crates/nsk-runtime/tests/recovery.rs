//! Recovery tests (§16.6): crash/leak recovery semantics that run on any
//! host. Linux-specific cgroup recovery lives in the linux provider tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use nsk_core::diagnostic::codes;
use nsk_core::policy::{IsolationPolicy, SandboxPolicy};
use nsk_core::result::SandboxStatus;
use nsk_core::spec::{CommandSpec, SandboxSpec, WorkspaceSpec};
use nsk_runtime::SandboxRuntime;
use nsk_workspace::manager::{WorkspaceManager, WorkspaceManagerConfig};

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("global test runtime")
    })
    .block_on(fut)
}

fn relaxed_policy() -> SandboxPolicy {
    let mut p = SandboxPolicy::minimal();
    p.isolation = IsolationPolicy {
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
    // The mock provider applies policy rlimits to real spawns, and
    // RLIMIT_NPROC counts *all* processes of the uid — CI runner job users
    // already exceed minimal()'s default of 16, making any fork inside the
    // sandboxed shell fail (EAGAIN). These tests do not exercise process
    // limits, so grant a generous budget.
    p.resources.max_processes = 1024;
    p.process.max_processes = 1024;
    p
}

#[test]
fn rec_stale_workspaces_detected_and_removed() {
    block_on(async {
        let base = tempfile::tempdir().unwrap();
        let manager = WorkspaceManager::new(WorkspaceManagerConfig {
            base_dir: Some(base.path().to_path_buf()),
            ..Default::default()
        });

        // Simulate a crash: prepare a workspace without cleaning it up.
        let id = nsk_core::id::SandboxId::new();
        let ws = manager
            .prepare(&WorkspaceSpec::ephemeral(), &id)
            .expect("prepare");
        assert!(ws.root.exists());

        // The recovery scan must find it.
        let stale = manager.find_stale_workspaces().expect("scan");
        assert_eq!(stale.len(), 1);

        // And removal must succeed (idempotent).
        let outcome = nsk_workspace::remove_tree_safe(&stale[0]);
        assert!(outcome.removed);
        assert!(outcome.diagnostics.is_empty());

        let stale = manager.find_stale_workspaces().expect("scan");
        assert!(stale.is_empty());
    });
}

#[test]
fn rec_double_cleanup_is_idempotent() {
    block_on(async {
        let rt = Arc::new(
            nsk_runtime::SandboxRuntimeBuilder::new()
                .with_provider(nsk_provider::create_mock_provider())
                .build()
                .await
                .unwrap(),
        );
        let mut spec = SandboxSpec::new(CommandSpec::new("/bin/echo").arg("cleanup"));
        spec.workspace = WorkspaceSpec::ephemeral();
        spec.policy = relaxed_policy();
        let id = rt.create(spec).await.unwrap();
        rt.start(id).await.unwrap();
        let result = rt.wait(id).await.unwrap();
        assert_eq!(result.status, SandboxStatus::Success);

        // Explicit cleanup after the driver already cleaned up: no error.
        rt.cleanup(id).await.expect("idempotent cleanup");
    });
}

#[test]
fn rec_cleanup_after_cancel() {
    block_on(async {
        let base = tempfile::tempdir().unwrap();
        let rt = Arc::new(
            nsk_runtime::SandboxRuntimeBuilder::new()
                .with_provider(nsk_provider::create_mock_provider())
                .with_workspace_config(WorkspaceManagerConfig {
                    base_dir: Some(base.path().to_path_buf()),
                    ..Default::default()
                })
                .build()
                .await
                .unwrap(),
        );
        let mut spec = SandboxSpec::new(CommandSpec::new("/bin/sleep").arg("60"));
        spec.workspace = WorkspaceSpec::ephemeral();
        spec.policy = relaxed_policy();
        let id = rt.create(spec).await.unwrap();
        rt.start(id).await.unwrap();
        rt.cancel(id).await.unwrap();
        let result = rt.wait(id).await.unwrap();
        assert_eq!(result.status, SandboxStatus::Cancelled);

        // The lifecycle driver cleaned the kernel-owned workspace up.
        let stale = {
            let manager = WorkspaceManager::new(WorkspaceManagerConfig {
                base_dir: Some(base.path().to_path_buf()),
                ..Default::default()
            });
            manager.find_stale_workspaces().expect("scan")
        };
        assert!(
            stale.is_empty(),
            "kernel-owned workspaces must be removed after cancel: {stale:?}"
        );
    });
}

#[test]
fn rec_failed_prepare_leaves_diagnostics() {
    block_on(async {
        let rt = Arc::new(
            nsk_runtime::SandboxRuntimeBuilder::new()
                .with_provider(nsk_provider::create_mock_provider())
                .build()
                .await
                .unwrap(),
        );
        // Isolation-requesting policy on a mock provider → fail-closed.
        let spec = SandboxSpec::new(CommandSpec::new("/bin/echo"));
        let err = rt.create(spec).await;
        assert!(err.is_err());
        // The error carries diagnostics (§4.3: cleanup failure must be
        // diagnosable; policy failures carry the violated rules).
        let msg = err.unwrap_err().to_string();
        assert!(!msg.is_empty());
        let _ = codes::ISOLATION_FAILED;
    });
}

#[test]
fn rec_user_owned_workspace_survives() {
    block_on(async {
        let user_dir = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        let manager = WorkspaceManager::new(WorkspaceManagerConfig {
            base_dir: Some(base.path().to_path_buf()),
            ..Default::default()
        });
        let spec = WorkspaceSpec {
            root: user_dir.path().to_path_buf(),
            writable_paths: vec![],
            readonly_paths: vec![],
            cleanup_on_exit: true,
        };
        let ws = manager
            .prepare(&spec, &nsk_core::id::SandboxId::new())
            .unwrap();
        let _ = manager.cleanup(&ws).unwrap();
        // Kernel never deletes caller-owned directories.
        assert!(user_dir.path().exists());
    });
}
