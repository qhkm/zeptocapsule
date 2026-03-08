use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn process_capsule_exposes_raw_stdio() {
    let mut capsule = zeptokernel::create(zeptokernel::CapsuleSpec::default()).unwrap();

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
    let mut capsule = zeptokernel::create(zeptokernel::CapsuleSpec::default()).unwrap();

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
    let mut capsule = zeptokernel::create(zeptokernel::CapsuleSpec {
        limits: zeptokernel::ResourceLimits {
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
        Some(zeptokernel::ResourceViolation::WallClock)
    );
}
