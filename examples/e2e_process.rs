use std::collections::HashMap;

#[tokio::main]
async fn main() {
    let spec = zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Process,
        security: zeptocapsule::SecurityProfile::Dev,
        workspace: zeptocapsule::WorkspaceConfig {
            host_path: Some(std::path::PathBuf::from("/tmp/zk-e2e-test")),
            guest_path: std::path::PathBuf::from("/tmp/zk-e2e-test"),
            size_mib: None,
        },
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 10,
            memory_mib: None,
            cpu_quota: None,
            max_pids: None,
        },
        init_binary: None,
        security_overrides: Default::default(),
        firecracker: None,
        fallback: None,
    };

    std::fs::create_dir_all("/tmp/zk-e2e-test").unwrap();
    let mut capsule = zeptocapsule::create(spec).expect("capsule creation failed");
    println!("[OK] capsule created");

    let child = capsule
        .spawn(
            "/bin/sh",
            &["-c", "echo HELLO_FROM_CAPSULE && exit 0"],
            HashMap::new(),
        )
        .expect("spawn failed");
    println!("[OK] worker spawned, pid={}", child.pid);

    use tokio::io::AsyncReadExt;
    let mut stdout = child.stdout;
    let mut output = String::new();
    let mut buf = vec![0u8; 4096];
    loop {
        let n = stdout.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        output.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    println!("[OK] stdout: {:?}", output.trim());
    assert!(
        output.contains("HELLO_FROM_CAPSULE"),
        "unexpected output: {output}"
    );

    let report = capsule.destroy().expect("destroy failed");
    println!("[OK] capsule destroyed");
    println!("     exit_code: {:?}", report.exit_code);
    println!("     wall_time: {:?}", report.wall_time);
    println!("     actual_isolation: {:?}", report.actual_isolation);
    println!("     actual_security: {:?}", report.actual_security);
    println!("     init_error: {:?}", report.init_error);

    assert_eq!(report.exit_code, Some(0));
    assert_eq!(
        report.actual_isolation,
        Some(zeptocapsule::Isolation::Process)
    );

    let _ = std::fs::remove_dir_all("/tmp/zk-e2e-test");
    println!("\n=== PROCESS E2E PASSED ===");
}
