#![allow(clippy::unwrap_used, clippy::expect_used)]

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemonized_child_is_swept() {
    use nsk_supervisor::monitor::{SupervisorConfig, spawn};
    let spec = nsk_supervisor::process::ProcessSpec::new("/bin/sh")
        .arg("-c")
        .arg("/bin/sleep 91 & echo spawned; exit 0");
    let p = spawn(spec, SupervisorConfig::default()).expect("spawn");
    let outcome = p.wait().await;
    assert_eq!(outcome.exit.exit_code, Some(0));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // Check no leftover.
    let out = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("ps -ef | grep 'sleep 91' | grep -v grep | wc -l | tr -d ' '")
        .output()
        .expect("ps");
    let count = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(count, "0", "sweep must kill orphaned group members");
}
