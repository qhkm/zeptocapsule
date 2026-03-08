#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

#[tokio::test]
async fn namespace_capsule_exposes_raw_stdio() {
    if !namespace_tests_enabled() {
        return;
    }

    let mut capsule = zeptokernel::create(namespace_spec(unique_workspace("stdio"))).unwrap();
    let mut child = capsule.spawn("/bin/cat", &[], HashMap::new()).unwrap();

    child.stdin.write_all(b"ping\n").await.unwrap();
    child.stdin.flush().await.unwrap();

    let mut buf = [0u8; 5];
    child.stdout.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping\n");

    drop(child);
    let report = capsule.destroy().unwrap();
    assert_eq!(report.killed_by, None);
}

#[tokio::test]
async fn namespace_capsule_mounts_workspace_via_zk_init() {
    if !namespace_tests_enabled() {
        return;
    }

    let workspace = unique_workspace("mount");
    let mut capsule = zeptokernel::create(namespace_spec(workspace.clone())).unwrap();
    let command = "printf ok > /workspace/probe && cat /workspace/probe";

    let mut child = capsule
        .spawn("/bin/sh", &["-c", &command], HashMap::new())
        .unwrap();

    let mut buf = [0u8; 2];
    child.stdout.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ok");

    drop(child);
    let report = capsule.destroy().unwrap();
    assert_eq!(report.killed_by, None);
    assert_eq!(
        std::fs::read_to_string(workspace.join("probe")).unwrap(),
        "ok"
    );
}

#[tokio::test]
async fn namespace_capsule_enforces_wall_clock_timeout() {
    if !namespace_tests_enabled() {
        return;
    }

    let mut capsule = zeptokernel::create(zeptokernel::CapsuleSpec {
        isolation: zeptokernel::Isolation::Namespace,
        workspace: zeptokernel::WorkspaceConfig {
            host_path: Some(unique_workspace("timeout-host")),
            guest_path: PathBuf::from("/workspace"),
            size_mib: Some(16),
        },
        limits: zeptokernel::ResourceLimits {
            timeout_sec: 1,
            ..Default::default()
        },
        init_binary: Some(zk_init_binary()),
    })
    .unwrap();

    let _child = capsule
        .spawn("/bin/sh", &["-c", "sleep 5"], HashMap::new())
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let report = capsule.destroy().unwrap();
    assert_eq!(
        report.killed_by,
        Some(zeptokernel::ResourceViolation::WallClock)
    );
}

fn namespace_spec(workspace: PathBuf) -> zeptokernel::CapsuleSpec {
    zeptokernel::CapsuleSpec {
        isolation: zeptokernel::Isolation::Namespace,
        workspace: zeptokernel::WorkspaceConfig {
            host_path: Some(workspace),
            guest_path: PathBuf::from("/workspace"),
            size_mib: Some(16),
        },
        limits: zeptokernel::ResourceLimits {
            timeout_sec: 10,
            ..Default::default()
        },
        init_binary: Some(zk_init_binary()),
    }
}

fn namespace_tests_enabled() -> bool {
    std::env::var_os("ZK_RUN_NAMESPACE_TESTS").is_some()
}

fn unique_workspace(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("zeptokernel-{label}-{}-{id}", std::process::id()))
}

fn zk_init_binary() -> PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_zk-init") {
        return PathBuf::from(path);
    }
    if let Some(path) = option_env!("CARGO_BIN_EXE_zk_init") {
        return PathBuf::from(path);
    }

    let mut path = std::env::current_exe().expect("current test executable path");
    path.pop();
    path.pop();
    path.push("zk-init");
    path
}
