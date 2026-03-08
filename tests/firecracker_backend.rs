//! Firecracker backend integration tests.
//!
//! These tests require:
//! - Linux with /dev/kvm
//! - Firecracker binary installed
//! - A kernel image (vmlinux) and rootfs image
//! - ZK_RUN_FIRECRACKER_TESTS=1 env var
//!
//! Set env vars:
//!   ZK_FC_BIN=/path/to/firecracker
//!   ZK_FC_KERNEL=/path/to/vmlinux
//!   ZK_FC_ROOTFS=/path/to/rootfs.ext4

#[cfg(target_os = "linux")]
mod firecracker_tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn skip_unless_enabled() -> bool {
        std::env::var("ZK_RUN_FIRECRACKER_TESTS").is_err()
    }

    fn test_config() -> zeptokernel::CapsuleSpec {
        let fc_bin = std::env::var("ZK_FC_BIN")
            .unwrap_or_else(|_| "/usr/bin/firecracker".to_string());
        let kernel = std::env::var("ZK_FC_KERNEL")
            .unwrap_or_else(|_| "/var/lib/zeptokernel/vmlinux".to_string());
        let rootfs = std::env::var("ZK_FC_ROOTFS")
            .unwrap_or_else(|_| "/var/lib/zeptokernel/rootfs.ext4".to_string());

        zeptokernel::CapsuleSpec {
            isolation: zeptokernel::Isolation::Firecracker,
            security: zeptokernel::SecurityProfile::Standard,
            limits: zeptokernel::ResourceLimits {
                timeout_sec: 30,
                memory_mib: Some(128),
                ..Default::default()
            },
            firecracker: Some(zeptokernel::FirecrackerConfig {
                firecracker_bin: PathBuf::from(fc_bin),
                kernel_path: PathBuf::from(kernel),
                rootfs_path: PathBuf::from(rootfs),
                vcpus: Some(1),
                memory_mib: Some(128),
                enable_network: false,
                tap_name: None,
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn firecracker_stdio_round_trip() {
        if skip_unless_enabled() { return; }

        let spec = test_config();
        let mut capsule = zeptokernel::create(spec).unwrap();
        let child = capsule.spawn("/bin/cat", &[], HashMap::new()).unwrap();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stdin = child.stdin;
        let mut stdout = child.stdout;

        stdin.write_all(b"hello from host\n").await.unwrap();
        drop(stdin);

        let mut output = String::new();
        stdout.read_to_string(&mut output).await.unwrap();
        assert_eq!(output.trim(), "hello from host");

        let report = capsule.destroy().unwrap();
        assert_eq!(report.exit_code, Some(0));
    }

    #[tokio::test]
    async fn firecracker_workspace_round_trip() {
        if skip_unless_enabled() { return; }

        let tmp = std::env::temp_dir().join(format!("zk-ws-test-{}", std::process::id()));
        let host_ws = tmp.join("workspace");
        std::fs::create_dir_all(&host_ws).unwrap();
        std::fs::write(host_ws.join("input.txt"), b"test data").unwrap();

        let mut spec = test_config();
        spec.workspace.host_path = Some(host_ws.clone());

        let mut capsule = zeptokernel::create(spec).unwrap();

        let child = capsule.spawn(
            "/bin/sh",
            &["-c", "cat /workspace/input.txt > /workspace/output.txt"],
            HashMap::new(),
        ).unwrap();

        use tokio::io::AsyncReadExt;
        let mut stdout = child.stdout;
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf).await;

        let report = capsule.destroy().unwrap();

        let output = std::fs::read_to_string(host_ws.join("output.txt")).unwrap();
        assert_eq!(output.trim(), "test data");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn firecracker_timeout_kills_worker() {
        if skip_unless_enabled() { return; }

        let mut spec = test_config();
        spec.limits.timeout_sec = 3;

        let mut capsule = zeptokernel::create(spec).unwrap();
        let _child = capsule.spawn("/bin/sleep", &["60"], HashMap::new()).unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let report = capsule.destroy().unwrap();
        assert_eq!(
            report.killed_by,
            Some(zeptokernel::ResourceViolation::WallClock)
        );
    }

    #[tokio::test]
    async fn firecracker_kill_terminate_reaches_worker() {
        if skip_unless_enabled() { return; }

        let spec = test_config();
        let mut capsule = zeptokernel::create(spec).unwrap();
        let _child = capsule.spawn("/bin/sleep", &["60"], HashMap::new()).unwrap();

        capsule.kill(zeptokernel::Signal::Terminate).unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let report = capsule.destroy().unwrap();
        assert!(report.wall_time.as_secs() < 15);
    }

    #[test]
    fn firecracker_missing_kvm_is_not_supported() {
        let spec = zeptokernel::CapsuleSpec {
            isolation: zeptokernel::Isolation::Firecracker,
            security: zeptokernel::SecurityProfile::Standard,
            firecracker: Some(zeptokernel::FirecrackerConfig {
                firecracker_bin: PathBuf::from("/nonexistent/firecracker"),
                kernel_path: PathBuf::from("/nonexistent/vmlinux"),
                rootfs_path: PathBuf::from("/nonexistent/rootfs.ext4"),
                vcpus: None,
                memory_mib: None,
                enable_network: false,
                tap_name: None,
            }),
            ..Default::default()
        };

        let err = zeptokernel::create(spec).unwrap_err();
        assert!(
            matches!(err, zeptokernel::KernelError::NotSupported(_)),
            "expected NotSupported, got: {err}"
        );
    }
}
