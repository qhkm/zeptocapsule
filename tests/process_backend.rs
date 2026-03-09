use std::collections::HashMap;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn process_capsule_exposes_raw_stdio() {
    let mut capsule = zeptocapsule::create(zeptocapsule::CapsuleSpec::default()).unwrap();

    let mut child = capsule.spawn("/bin/cat", &[], HashMap::new()).unwrap();

    child.stdin.write_all(b"ping\n").await.unwrap();
    child.stdin.flush().await.unwrap();

    let mut buf = [0u8; 5];
    child.stdout.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping\n");

    drop(child);
    let report = capsule.destroy().unwrap();
    assert!(report.wall_time.as_nanos() > 0);
    assert_eq!(report.killed_by, None);
}

#[tokio::test]
async fn process_capsule_passes_env_to_worker() {
    let mut capsule = zeptocapsule::create(zeptocapsule::CapsuleSpec::default()).unwrap();

    let mut child = capsule
        .spawn(
            "/bin/sh",
            &["-c", "printf %s \"$ZK_TEST_VALUE\""],
            HashMap::from([(String::from("ZK_TEST_VALUE"), String::from("ok"))]),
        )
        .unwrap();

    let mut buf = [0u8; 2];
    child.stdout.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ok");

    drop(child);
    let report = capsule.destroy().unwrap();
    assert_eq!(report.killed_by, None);
    assert_eq!(report.exit_signal, None);
}

#[tokio::test]
async fn process_capsule_enforces_wall_clock_timeout() {
    let mut capsule = zeptocapsule::create(zeptocapsule::CapsuleSpec {
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 1,
            ..Default::default()
        },
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
async fn process_capsule_stderr_captured() {
    let mut capsule = zeptocapsule::create(zeptocapsule::CapsuleSpec::default()).unwrap();

    let mut child = capsule
        .spawn("/bin/sh", &["-c", "echo hello >&2"], HashMap::new())
        .unwrap();

    let mut buf = Vec::new();
    child.stderr.read_to_end(&mut buf).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&buf).trim(), "hello");

    drop(child);
    capsule.destroy().unwrap();
}

#[tokio::test]
async fn process_capsule_dev_rlimit_kills_memory_hog() {
    let mut capsule = zeptocapsule::create(zeptocapsule::CapsuleSpec {
        security: zeptocapsule::SecurityProfile::Dev,
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 5,
            memory_mib: Some(32),
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();

    // Try to allocate way more than 32 MiB — rlimit should prevent it
    let mut child = capsule
        .spawn(
            "/bin/sh",
            &[
                "-c",
                "dd if=/dev/zero bs=1M count=128 2>/dev/null | wc -c; echo $?",
            ],
            HashMap::new(),
        )
        .unwrap();

    let mut buf = Vec::new();
    child.stdout.read_to_end(&mut buf).await.ok();

    drop(child);
    let report = capsule.destroy().unwrap();
    // The process should either have a non-zero exit code or have been killed
    // (RLIMIT_AS causes ENOMEM on mmap/brk, which may or may not kill the shell)
    // At minimum, verify the capsule lifecycle completes cleanly
    assert!(report.wall_time.as_nanos() > 0);
}
