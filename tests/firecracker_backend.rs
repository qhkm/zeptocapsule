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

    fn test_config() -> zeptocapsule::CapsuleSpec {
        let fc_bin =
            std::env::var("ZK_FC_BIN").unwrap_or_else(|_| "/usr/bin/firecracker".to_string());
        let kernel = std::env::var("ZK_FC_KERNEL")
            .unwrap_or_else(|_| "/var/lib/zeptocapsule/vmlinux".to_string());
        let rootfs = std::env::var("ZK_FC_ROOTFS")
            .unwrap_or_else(|_| "/var/lib/zeptocapsule/rootfs.ext4".to_string());
        let init_binary = std::env::var_os("ZK_FC_INIT_BIN").map(PathBuf::from);

        zeptocapsule::CapsuleSpec {
            isolation: zeptocapsule::Isolation::Firecracker,
            security: zeptocapsule::SecurityProfile::Standard,
            limits: zeptocapsule::ResourceLimits {
                timeout_sec: 30,
                memory_mib: Some(128),
                ..Default::default()
            },
            firecracker: Some(zeptocapsule::FirecrackerConfig {
                firecracker_bin: PathBuf::from(fc_bin),
                kernel_path: PathBuf::from(kernel),
                rootfs_path: PathBuf::from(rootfs),
                vcpus: Some(1),
                memory_mib: Some(128),
                enable_network: false,
                tap_name: None,
            }),
            init_binary,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn firecracker_stdio_round_trip() {
        if skip_unless_enabled() {
            return;
        }

        let spec = test_config();
        let mut capsule = zeptocapsule::create(spec).unwrap();
        let child = capsule.spawn("/bin/cat", &[], HashMap::new()).unwrap();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stdin = child.stdin;
        let mut stdout = child.stdout;
        drop(child.stderr);

        stdin.write_all(b"hello from host\n").await.unwrap();
        stdin.shutdown().await.unwrap();
        drop(stdin);

        // Use bounded read — Firecracker's vsock proxy may not propagate EOF
        // from the guest, so read_to_end would hang. A single read with timeout
        // is sufficient since cat echoes the input immediately.
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), stdout.read(&mut buf))
            .await
            .expect("stdout read timed out")
            .expect("stdout read error");
        drop(stdout);

        let output = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(output.trim(), "hello from host");

        // Give guest time to exit and send EXIT status via control channel.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let report = capsule.destroy().unwrap();
        assert_eq!(report.exit_code, Some(0));
    }

    #[tokio::test]
    async fn firecracker_workspace_round_trip() {
        if skip_unless_enabled() {
            return;
        }

        let tmp = std::env::temp_dir().join(format!("zk-ws-test-{}", std::process::id()));
        let host_ws = tmp.join("workspace");
        std::fs::create_dir_all(&host_ws).unwrap();
        std::fs::write(host_ws.join("input.txt"), b"test data").unwrap();

        let mut spec = test_config();
        spec.workspace.host_path = Some(host_ws.clone());

        let mut capsule = zeptocapsule::create(spec).unwrap();

        let child = capsule
            .spawn(
                "/bin/sh",
                &["-c", "cat /workspace/input.txt > /workspace/output.txt"],
                HashMap::new(),
            )
            .unwrap();

        // Don't wait for stdout EOF — Firecracker vsock proxy may not propagate it.
        // The shell command writes to a file, not stdout, so just drop streams
        // and give the guest time to finish.
        drop(child.stdin);
        drop(child.stdout);
        drop(child.stderr);
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        let report = capsule.destroy().unwrap();

        let output = std::fs::read_to_string(host_ws.join("output.txt")).unwrap();
        assert_eq!(output.trim(), "test data");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn firecracker_timeout_kills_worker() {
        if skip_unless_enabled() {
            return;
        }

        let mut spec = test_config();
        spec.limits.timeout_sec = 3;

        let mut capsule = zeptocapsule::create(spec).unwrap();
        let _child = capsule
            .spawn("/bin/sleep", &["60"], HashMap::new())
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let report = capsule.destroy().unwrap();
        assert_eq!(
            report.killed_by,
            Some(zeptocapsule::ResourceViolation::WallClock)
        );
    }

    #[tokio::test]
    async fn firecracker_kill_terminate_reaches_worker() {
        if skip_unless_enabled() {
            return;
        }

        let spec = test_config();
        let mut capsule = zeptocapsule::create(spec).unwrap();
        let _child = capsule
            .spawn("/bin/sleep", &["60"], HashMap::new())
            .unwrap();

        capsule.kill(zeptocapsule::Signal::Terminate).unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let report = capsule.destroy().unwrap();
        assert!(report.wall_time.as_secs() < 15);
    }

    #[test]
    fn firecracker_missing_kvm_is_not_supported() {
        let spec = zeptocapsule::CapsuleSpec {
            isolation: zeptocapsule::Isolation::Firecracker,
            security: zeptocapsule::SecurityProfile::Standard,
            firecracker: Some(zeptocapsule::FirecrackerConfig {
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

        let err = zeptocapsule::create(spec).err().expect("expected error");
        assert!(
            matches!(err, zeptocapsule::KernelError::NotSupported(_)),
            "expected NotSupported, got: {err}"
        );
    }
}
