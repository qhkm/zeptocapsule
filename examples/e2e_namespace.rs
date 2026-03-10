use std::collections::HashMap;

#[tokio::main]
async fn main() {
    let zk_init = std::path::PathBuf::from(
        std::env::var("ZEPTOCAPSULE_INIT_BINARY")
            .unwrap_or_else(|_| "/home/ubuntu/zeptocapsule/target/debug/zk-init".into()),
    );
    assert!(
        zk_init.exists(),
        "zk-init not found at {}",
        zk_init.display()
    );
    println!("[OK] zk-init binary: {}", zk_init.display());

    let spec = zeptocapsule::CapsuleSpec {
        isolation: zeptocapsule::Isolation::Namespace,
        security: zeptocapsule::SecurityProfile::Standard,
        workspace: zeptocapsule::WorkspaceConfig {
            host_path: Some(std::path::PathBuf::from("/tmp/zk-e2e-ns-test")),
            guest_path: std::path::PathBuf::from("/workspace"),
            size_mib: None,
        },
        limits: zeptocapsule::ResourceLimits {
            timeout_sec: 10,
            memory_mib: None,
            cpu_quota: None,
            max_pids: None,
        },
        init_binary: Some(zk_init),
        security_overrides: Default::default(),
        firecracker: None,
        fallback: None,
    };

    std::fs::create_dir_all("/tmp/zk-e2e-ns-test").unwrap();

    // Write a test file in workspace to verify mount works
    std::fs::write("/tmp/zk-e2e-ns-test/input.txt", "WORKSPACE_MOUNTED").unwrap();

    let mut capsule = zeptocapsule::create(spec).expect("capsule creation failed");
    println!("[OK] namespace capsule created");

    let child = capsule
        .spawn(
            "/bin/sh",
            &[
                "-c",
                "cat /workspace/input.txt && echo FROM_NAMESPACE",
            ],
            HashMap::new(),
        )
        .expect("spawn failed");
    println!("[OK] worker spawned in namespace, pid={}", child.pid);

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
        output.contains("WORKSPACE_MOUNTED"),
        "workspace not visible: {output}"
    );
    assert!(
        output.contains("FROM_NAMESPACE"),
        "worker didn't run: {output}"
    );

    let report = capsule.destroy().expect("destroy failed");
    println!("[OK] namespace capsule destroyed");
    println!("     exit_code: {:?}", report.exit_code);
    println!("     wall_time: {:?}", report.wall_time);
    println!("     actual_isolation: {:?}", report.actual_isolation);
    println!("     actual_security: {:?}", report.actual_security);
    println!("     init_error: {:?}", report.init_error);

    assert_eq!(report.exit_code, Some(0));
    assert_eq!(
        report.actual_isolation,
        Some(zeptocapsule::Isolation::Namespace)
    );
    assert_eq!(
        report.actual_security,
        Some(zeptocapsule::SecurityProfile::Standard)
    );
    assert!(
        report.init_error.is_none(),
        "init_error: {:?}",
        report.init_error
    );

    let _ = std::fs::remove_dir_all("/tmp/zk-e2e-ns-test");
    println!("\n=== NAMESPACE E2E PASSED ===");
}
