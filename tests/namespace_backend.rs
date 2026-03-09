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

    let mut capsule = zeptocapsule::create(namespace_spec(unique_workspace("stdio"))).unwrap();
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
    let mut capsule = zeptocapsule::create(namespace_spec(workspace.clone())).unwrap();
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

    let mut capsule = zeptocapsule::create(zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Namespace,
        workspace: zeptocapsule::WorkspaceConfig {
            host_path: Some(unique_workspace("timeout-host")),
            guest_path: PathBuf::from("/workspace"),
            size_mib: Some(16),
        },
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 1,
            ..Default::default()
        },
        init_binary: Some(zk_init_binary()),
        ..Default::default()
    })
    .unwrap();

    let _child = capsule
        .spawn("/bin/sh", &["-c", "sleep 5"], HashMap::new())
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let report = capsule.destroy().unwrap();
    assert_eq!(
        report.killed_by,
        Some(zeptocapsule::ResourceViolation::WallClock)
    );
}

#[tokio::test]
async fn namespace_hardened_hides_host_filesystem() {
    if !namespace_tests_enabled() {
        return;
    }

    let mut capsule = zeptocapsule::create(zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Namespace,
        security: zeptocapsule::SecurityProfile::Hardened,
        workspace: zeptocapsule::WorkspaceConfig {
            host_path: Some(unique_workspace("pivot-host")),
            guest_path: std::path::PathBuf::from("/workspace"),
            size_mib: Some(16),
        },
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 5,
            ..Default::default()
        },
        init_binary: Some(zk_init_binary()),
        ..Default::default()
    })
    .unwrap();

    // Try to read /etc/hostname from host — should fail in pivoted root
    let mut child = capsule
        .spawn(
            "/bin/sh",
            &[
                "-c",
                "cat /etc/hostname 2>/dev/null && echo VISIBLE || echo HIDDEN",
            ],
            HashMap::new(),
        )
        .unwrap();

    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut child.stdout, &mut buf)
        .await
        .ok();
    let output = String::from_utf8_lossy(&buf);

    drop(child);
    let _report = capsule.destroy().unwrap();
    assert!(
        output.contains("HIDDEN"),
        "expected host /etc to be hidden, got: {output}"
    );
}

#[tokio::test]
async fn namespace_hardened_has_dev_null() {
    if !namespace_tests_enabled() {
        return;
    }

    let mut capsule = zeptocapsule::create(zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Namespace,
        security: zeptocapsule::SecurityProfile::Hardened,
        workspace: zeptocapsule::WorkspaceConfig {
            host_path: Some(unique_workspace("devnull")),
            guest_path: std::path::PathBuf::from("/workspace"),
            size_mib: Some(16),
        },
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 5,
            ..Default::default()
        },
        init_binary: Some(zk_init_binary()),
        ..Default::default()
    })
    .unwrap();

    let mut child = capsule
        .spawn(
            "/bin/sh",
            &["-c", "echo test > /dev/null && echo OK || echo FAIL"],
            HashMap::new(),
        )
        .unwrap();

    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut child.stdout, &mut buf)
        .await
        .ok();
    let output = String::from_utf8_lossy(&buf);

    drop(child);
    capsule.destroy().unwrap();
    assert!(
        output.contains("OK"),
        "expected /dev/null to work, got: {output}"
    );
}

fn namespace_spec(workspace: PathBuf) -> zeptocapsule::CapsuleSpec {
    zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Namespace,
        workspace: zeptocapsule::WorkspaceConfig {
            host_path: Some(workspace),
            guest_path: PathBuf::from("/workspace"),
            size_mib: Some(16),
        },
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 10,
            ..Default::default()
        },
        init_binary: Some(zk_init_binary()),
        ..Default::default()
    }
}

fn namespace_tests_enabled() -> bool {
    std::env::var_os("ZK_RUN_NAMESPACE_TESTS").is_some()
}

fn unique_workspace(label: &str) -> PathBuf {
    let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("zeptocapsule-{label}-{}-{id}", std::process::id()))
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
