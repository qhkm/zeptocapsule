//! Integration tests for the process backend.
//!
//! These tests spawn the real `zk-guest` binary as a child process
//! and verify the full host↔guest lifecycle.

use std::collections::HashMap;
use std::path::PathBuf;

use zk_proto::*;

use zk_host::backend::{Backend, CapsuleHandle};
use zk_host::process_backend::ProcessBackend;
use zk_host::supervisor::Supervisor;

fn guest_binary() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/
    path.pop(); // workspace root
    path.push("target/debug/zk-guest");
    path
}

fn test_spec(job_id: &str) -> JobSpec {
    JobSpec {
        job_id: job_id.into(),
        run_id: "test-run".into(),
        role: "researcher".into(),
        profile_id: "researcher".into(),
        instruction: "Test instruction".into(),
        input_artifacts: vec![],
        env: HashMap::new(),
        limits: ResourceLimits::default(),
        workspace: WorkspaceConfig::default(),
    }
}

#[tokio::test]
async fn test_spawn_and_ready() {
    let backend = ProcessBackend::new(guest_binary());
    let spec = test_spec("spawn-ready");
    let handle = backend.spawn(&spec, "").await.unwrap();

    // Should receive Ready as first event
    let event = handle.recv().await.unwrap();
    assert!(matches!(event, GuestEvent::Ready));

    // Clean shutdown
    handle.send(HostCommand::Shutdown).await.unwrap();
    handle.terminate().await.unwrap();
}

#[tokio::test]
async fn test_handshake() {
    let backend = ProcessBackend::new(guest_binary());
    let spec = test_spec("handshake");
    let handle = backend.spawn(&spec, "").await.unwrap();

    // Ready
    let event = handle.recv().await.unwrap();
    assert!(matches!(event, GuestEvent::Ready));

    // Send handshake
    handle
        .send(HostCommand::Handshake {
            protocol_version: PROTOCOL_VERSION,
            worker_profile: "researcher".into(),
        })
        .await
        .unwrap();

    // Expect HandshakeAck
    let event = handle.recv().await.unwrap();
    match event {
        GuestEvent::HandshakeAck {
            protocol_version,
            capabilities,
            ..
        } => {
            assert_eq!(protocol_version, PROTOCOL_VERSION);
            assert_eq!(capabilities, vec!["researcher"]);
        }
        other => panic!("expected HandshakeAck, got {:?}", other),
    }

    handle.send(HostCommand::Shutdown).await.unwrap();
    handle.terminate().await.unwrap();
}

#[tokio::test]
async fn test_ping_pong() {
    let backend = ProcessBackend::new(guest_binary());
    let spec = test_spec("ping");
    let handle = backend.spawn(&spec, "").await.unwrap();

    // Ready
    let _ = handle.recv().await.unwrap();

    // Ping
    handle.send(HostCommand::Ping { seq: 42 }).await.unwrap();

    let event = handle.recv().await.unwrap();
    match event {
        GuestEvent::Pong { seq } => assert_eq!(seq, 42),
        other => panic!("expected Pong, got {:?}", other),
    }

    handle.send(HostCommand::Shutdown).await.unwrap();
    handle.terminate().await.unwrap();
}

#[tokio::test]
async fn test_start_job_completes() {
    let backend = ProcessBackend::new(guest_binary());
    let spec = test_spec("job-complete");
    let handle = backend.spawn(&spec, "").await.unwrap();

    // Ready
    let _ = handle.recv().await.unwrap();

    // Handshake
    handle
        .send(HostCommand::Handshake {
            protocol_version: PROTOCOL_VERSION,
            worker_profile: "researcher".into(),
        })
        .await
        .unwrap();
    let _ = handle.recv().await.unwrap(); // HandshakeAck

    // Start job
    handle
        .send(HostCommand::StartJob(spec.clone()))
        .await
        .unwrap();

    // Expect Started then Completed (placeholder guest impl)
    let event = handle.recv().await.unwrap();
    assert!(matches!(event, GuestEvent::Started { .. }));

    let event = handle.recv().await.unwrap();
    match event {
        GuestEvent::Completed { job_id, .. } => {
            assert_eq!(job_id, "job-complete");
        }
        other => panic!("expected Completed, got {:?}", other),
    }

    handle.send(HostCommand::Shutdown).await.unwrap();
    handle.terminate().await.unwrap();
}

#[tokio::test]
async fn test_cancel_job() {
    let backend = ProcessBackend::new(guest_binary());
    let spec = test_spec("cancel-me");
    let handle = backend.spawn(&spec, "").await.unwrap();

    // Ready
    let _ = handle.recv().await.unwrap();

    // Cancel a job (guest will acknowledge even without an active job)
    handle
        .send(HostCommand::CancelJob {
            job_id: "cancel-me".into(),
        })
        .await
        .unwrap();

    let event = handle.recv().await.unwrap();
    match event {
        GuestEvent::Cancelled { job_id } => assert_eq!(job_id, "cancel-me"),
        other => panic!("expected Cancelled, got {:?}", other),
    }

    handle.send(HostCommand::Shutdown).await.unwrap();
    handle.terminate().await.unwrap();
}

#[tokio::test]
async fn test_supervisor_run_job() {
    let backend = ProcessBackend::new(guest_binary());
    let mut supervisor = Supervisor::new();
    let spec = test_spec("supervised");

    let outcome = supervisor.run_job(&backend, &spec, "").await.unwrap();
    match outcome {
        zk_host::supervisor::JobOutcome::Completed { job_id, .. } => {
            assert_eq!(job_id, "supervised");
        }
        other => panic!("expected Completed, got {:?}", other),
    }

    // Capsule should be cleaned up
    assert_eq!(supervisor.active_count(), 0);
}

#[tokio::test]
async fn test_reject_second_job() {
    let backend = ProcessBackend::new(guest_binary());
    let spec = test_spec("second-job");
    let handle = backend.spawn(&spec, "").await.unwrap();

    // Ready + handshake
    let _ = handle.recv().await.unwrap();
    handle
        .send(HostCommand::Handshake {
            protocol_version: PROTOCOL_VERSION,
            worker_profile: "researcher".into(),
        })
        .await
        .unwrap();
    let _ = handle.recv().await.unwrap();

    // First job — will complete immediately (placeholder)
    handle
        .send(HostCommand::StartJob(spec.clone()))
        .await
        .unwrap();
    let _ = handle.recv().await.unwrap(); // Started
    let _ = handle.recv().await.unwrap(); // Completed

    // Second job should also work (first one finished)
    let mut spec2 = test_spec("second-job-2");
    spec2.job_id = "second-job-2".into();
    handle
        .send(HostCommand::StartJob(spec2))
        .await
        .unwrap();
    let event = handle.recv().await.unwrap();
    assert!(matches!(event, GuestEvent::Started { .. }));

    handle.send(HostCommand::Shutdown).await.unwrap();
    handle.terminate().await.unwrap();
}
