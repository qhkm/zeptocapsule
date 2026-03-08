//! Integration tests for the namespace backend.
//!
//! These tests ONLY compile and run on Linux with the `namespace` feature.
//! Run via: ./scripts/test-linux.sh (inside Docker with --privileged)

#![cfg(all(target_os = "linux", feature = "namespace"))]

use std::collections::HashMap;
use std::path::PathBuf;

use zk_proto::*;
use zk_host::backend::{Backend, CapsuleHandle};
use zk_host::namespace_backend::NamespaceBackend;
use zk_host::supervisor::Supervisor;

fn guest_binary() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // out of zk-host/
    path.pop(); // out of crates/
    path.push("target/debug/zk-guest");
    path
}

fn mock_worker_binary() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("target/debug/mock-worker");
    path
}

fn test_spec(job_id: &str, mode: &str) -> JobSpec {
    let mut env = HashMap::new();
    env.insert("MOCK_MODE".into(), mode.into());
    // ZEPTOCLAW_BINARY in spec.env: guest will read it from spec.env since
    // the namespace backend doesn't inject it via process env (uses execv).
    env.insert(
        "ZEPTOCLAW_BINARY".into(),
        mock_worker_binary().to_str().unwrap().into(),
    );
    JobSpec {
        job_id: job_id.into(),
        run_id: "ns-test".into(),
        role: "researcher".into(),
        profile_id: "researcher".into(),
        instruction: "test".into(),
        input_artifacts: vec![],
        env,
        limits: ResourceLimits::default(),
        workspace: WorkspaceConfig {
            guest_path: PathBuf::from(format!("/tmp/zk-ns-{}", job_id)),
            size_mib: Some(32),
        },
    }
}

async fn drain_to_terminal(handle: &impl CapsuleHandle) -> GuestEvent {
    loop {
        let event = handle.recv().await.unwrap();
        match &event {
            GuestEvent::Completed { .. }
            | GuestEvent::Failed { .. }
            | GuestEvent::Cancelled { .. } => return event,
            _ => {}
        }
    }
}

#[tokio::test]
async fn test_namespace_full_lifecycle() {
    let backend = NamespaceBackend::new(guest_binary());
    let spec = test_spec("ns-lifecycle", "complete");
    let handle = backend.spawn(&spec, "").await.unwrap();

    // Ready
    let event = handle.recv().await.unwrap();
    assert!(matches!(event, GuestEvent::Ready), "got {:?}", event);

    // Handshake
    handle.send(HostCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        worker_profile: "researcher".into(),
    }).await.unwrap();
    let _ = handle.recv().await.unwrap(); // HandshakeAck

    // Start job
    handle.send(HostCommand::StartJob(spec.clone())).await.unwrap();
    let ev = handle.recv().await.unwrap();
    assert!(matches!(ev, GuestEvent::Started { .. }), "got {:?}", ev);

    let terminal = drain_to_terminal(&handle).await;
    assert!(
        matches!(terminal, GuestEvent::Completed { .. }),
        "got {:?}", terminal
    );

    handle.send(HostCommand::Shutdown).await.unwrap();
    handle.terminate().await.unwrap();
}

#[tokio::test]
async fn test_namespace_supervisor_run_job() {
    let backend = NamespaceBackend::new(guest_binary());
    let mut supervisor = Supervisor::new();
    let spec = test_spec("ns-supervised", "complete");

    let outcome = supervisor.run_job(&backend, &spec, "").await.unwrap();
    assert!(
        matches!(outcome, zk_host::supervisor::JobOutcome::Completed { .. }),
        "got {:?}", outcome
    );
    assert_eq!(supervisor.active_count(), 0);
}

#[tokio::test]
async fn test_namespace_job_failure() {
    let backend = NamespaceBackend::new(guest_binary());
    let mut supervisor = Supervisor::new();
    let spec = test_spec("ns-fail", "fail");

    let outcome = supervisor.run_job(&backend, &spec, "").await.unwrap();
    assert!(
        matches!(outcome, zk_host::supervisor::JobOutcome::Failed { .. }),
        "got {:?}", outcome
    );
}

#[tokio::test]
async fn test_namespace_cancel() {
    let backend = NamespaceBackend::new(guest_binary());
    let spec = test_spec("ns-cancel", "hang");
    let handle = backend.spawn(&spec, "").await.unwrap();

    let _ = handle.recv().await.unwrap(); // Ready

    handle.send(HostCommand::Handshake {
        protocol_version: PROTOCOL_VERSION,
        worker_profile: "researcher".into(),
    }).await.unwrap();
    let _ = handle.recv().await.unwrap(); // HandshakeAck

    handle.send(HostCommand::StartJob(spec.clone())).await.unwrap();
    let _ = handle.recv().await.unwrap(); // Started

    // Wait for one heartbeat (worker is running)
    let got_heartbeat = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        async {
            loop {
                match handle.recv().await {
                    Ok(GuestEvent::Heartbeat { .. }) => break,
                    Ok(_) => {} // other events, keep waiting
                    Err(e) => panic!("guest died waiting for heartbeat: {}", e),
                }
            }
        },
    )
    .await;
    assert!(got_heartbeat.is_ok(), "timed out waiting for heartbeat from namespace worker");

    handle.send(HostCommand::CancelJob { job_id: "ns-cancel".into() })
        .await.unwrap();

    let terminal = drain_to_terminal(&handle).await;
    assert!(
        matches!(terminal, GuestEvent::Cancelled { .. }),
        "got {:?}", terminal
    );

    handle.terminate().await.unwrap();
}

#[tokio::test]
async fn test_namespace_no_network() {
    // Worker runs in a network namespace with only loopback.
    // Verify the job completes (network namespace was set up without error).
    let backend = NamespaceBackend::new(guest_binary());
    let mut supervisor = Supervisor::new();
    let spec = test_spec("ns-no-net", "complete");

    let outcome = supervisor.run_job(&backend, &spec, "").await.unwrap();
    assert!(
        matches!(outcome, zk_host::supervisor::JobOutcome::Completed { .. }),
        "got {:?}", outcome
    );
}
