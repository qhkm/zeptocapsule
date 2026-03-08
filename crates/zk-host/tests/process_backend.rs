//! Integration tests for the process backend.
//!
//! These tests spawn the real `zk-guest` binary as a child process
//! and verify the full host↔guest lifecycle.
//!
//! The guest is configured to launch `mock-worker` (via ZEPTOCLAW_BINARY env var)
//! instead of the real `/zeptoclaw/worker`.

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

fn mock_worker_binary() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/
    path.pop(); // workspace root
    path.push("target/debug/mock-worker");
    path
}

fn test_spec(job_id: &str) -> JobSpec {
    let mut env = HashMap::new();
    // Tell the mock worker which mode to use (injected via spec.env)
    env.insert("MOCK_MODE".into(), "complete".into());
    JobSpec {
        job_id: job_id.into(),
        run_id: "test-run".into(),
        role: "researcher".into(),
        profile_id: "researcher".into(),
        instruction: "Test instruction".into(),
        input_artifacts: vec![],
        env,
        limits: ResourceLimits::default(),
        workspace: WorkspaceConfig {
            // Use a writable temp dir; /workspace doesn't exist outside a capsule
            guest_path: std::env::temp_dir()
                .join("zeptokernel-tests")
                .join(job_id),
            size_mib: None,
        },
    }
}

fn test_spec_mode(job_id: &str, mode: &str) -> JobSpec {
    let mut spec = test_spec(job_id);
    spec.env.insert("MOCK_MODE".into(), mode.into());
    spec
}

/// Drain events from a handle until a terminal event (Completed/Failed/Cancelled)
/// is received, collecting all non-terminal events encountered along the way.
async fn drain_to_terminal(handle: &impl CapsuleHandle) -> GuestEvent {
    loop {
        let event = handle.recv().await.unwrap();
        match &event {
            GuestEvent::Completed { .. }
            | GuestEvent::Failed { .. }
            | GuestEvent::Cancelled { .. } => return event,
            _ => {
                // Heartbeats, progress etc — keep draining
            }
        }
    }
}

#[tokio::test]
async fn test_spawn_and_ready() {
    let backend = ProcessBackend::new(guest_binary()).with_env(
        "ZEPTOCLAW_BINARY",
        mock_worker_binary().to_str().unwrap(),
    );
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
    let backend = ProcessBackend::new(guest_binary()).with_env(
        "ZEPTOCLAW_BINARY",
        mock_worker_binary().to_str().unwrap(),
    );
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
    let backend = ProcessBackend::new(guest_binary()).with_env(
        "ZEPTOCLAW_BINARY",
        mock_worker_binary().to_str().unwrap(),
    );
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
    let backend = ProcessBackend::new(guest_binary()).with_env(
        "ZEPTOCLAW_BINARY",
        mock_worker_binary().to_str().unwrap(),
    );
    let spec = test_spec_mode("job-complete", "complete");
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

    // Expect Started
    let event = handle.recv().await.unwrap();
    assert!(
        matches!(event, GuestEvent::Started { .. }),
        "expected Started, got {:?}",
        event
    );

    // Drain heartbeats and other intermediate events until Completed
    let terminal = drain_to_terminal(&handle).await;
    match terminal {
        GuestEvent::Completed { job_id, .. } => {
            assert_eq!(job_id, "job-complete");
        }
        other => panic!("expected Completed, got {:?}", other),
    }

    handle.send(HostCommand::Shutdown).await.unwrap();
    handle.terminate().await.unwrap();
}

#[tokio::test]
async fn test_start_job_receives_heartbeats() {
    let backend = ProcessBackend::new(guest_binary()).with_env(
        "ZEPTOCLAW_BINARY",
        mock_worker_binary().to_str().unwrap(),
    );
    let spec = test_spec_mode("job-heartbeats", "events");
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

    handle
        .send(HostCommand::StartJob(spec.clone()))
        .await
        .unwrap();

    // Expect Started
    let event = handle.recv().await.unwrap();
    assert!(matches!(event, GuestEvent::Started { .. }));

    // Collect all events until terminal — verify we get at least one heartbeat
    let mut got_heartbeat = false;
    loop {
        let event = handle.recv().await.unwrap();
        match event {
            GuestEvent::Heartbeat { .. } => got_heartbeat = true,
            GuestEvent::Progress { .. } => {} // also expected from "events" mode
            GuestEvent::Completed { .. } => break,
            GuestEvent::Failed { .. } => panic!("unexpected failure"),
            _ => {}
        }
    }

    assert!(got_heartbeat, "expected at least one Heartbeat from mock worker");

    handle.send(HostCommand::Shutdown).await.unwrap();
    handle.terminate().await.unwrap();
}

#[tokio::test]
async fn test_start_job_fails() {
    let backend = ProcessBackend::new(guest_binary()).with_env(
        "ZEPTOCLAW_BINARY",
        mock_worker_binary().to_str().unwrap(),
    );
    let spec = test_spec_mode("job-fail", "fail");
    let handle = backend.spawn(&spec, "").await.unwrap();

    let _ = handle.recv().await.unwrap(); // Ready

    handle
        .send(HostCommand::Handshake {
            protocol_version: PROTOCOL_VERSION,
            worker_profile: "researcher".into(),
        })
        .await
        .unwrap();
    let _ = handle.recv().await.unwrap(); // HandshakeAck

    handle
        .send(HostCommand::StartJob(spec.clone()))
        .await
        .unwrap();

    let event = handle.recv().await.unwrap();
    assert!(matches!(event, GuestEvent::Started { .. }));

    let terminal = drain_to_terminal(&handle).await;
    match terminal {
        GuestEvent::Failed { job_id, .. } => {
            assert_eq!(job_id, "job-fail");
        }
        other => panic!("expected Failed, got {:?}", other),
    }

    handle.send(HostCommand::Shutdown).await.unwrap();
    handle.terminate().await.unwrap();
}

#[tokio::test]
async fn test_cancel_job_while_running() {
    let backend = ProcessBackend::new(guest_binary()).with_env(
        "ZEPTOCLAW_BINARY",
        mock_worker_binary().to_str().unwrap(),
    );
    let spec = test_spec_mode("job-cancel", "hang");
    let handle = backend.spawn(&spec, "").await.unwrap();

    let _ = handle.recv().await.unwrap(); // Ready

    handle
        .send(HostCommand::Handshake {
            protocol_version: PROTOCOL_VERSION,
            worker_profile: "researcher".into(),
        })
        .await
        .unwrap();
    let _ = handle.recv().await.unwrap(); // HandshakeAck

    handle
        .send(HostCommand::StartJob(spec.clone()))
        .await
        .unwrap();

    // Wait for Started
    let event = handle.recv().await.unwrap();
    assert!(matches!(event, GuestEvent::Started { .. }));

    // Wait for the worker's heartbeat (so we know it's running) then cancel
    loop {
        let e = handle.recv().await.unwrap();
        if matches!(e, GuestEvent::Heartbeat { .. }) {
            break;
        }
    }

    handle
        .send(HostCommand::CancelJob {
            job_id: "job-cancel".into(),
        })
        .await
        .unwrap();

    let terminal = drain_to_terminal(&handle).await;
    assert!(
        matches!(terminal, GuestEvent::Cancelled { .. }),
        "expected Cancelled, got {:?}",
        terminal
    );

    handle.terminate().await.unwrap();
}

#[tokio::test]
async fn test_cancel_job_no_active() {
    let backend = ProcessBackend::new(guest_binary()).with_env(
        "ZEPTOCLAW_BINARY",
        mock_worker_binary().to_str().unwrap(),
    );
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
    let backend = ProcessBackend::new(guest_binary()).with_env(
        "ZEPTOCLAW_BINARY",
        mock_worker_binary().to_str().unwrap(),
    );
    let mut supervisor = Supervisor::new();
    let spec = test_spec_mode("supervised", "complete");

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
    let backend = ProcessBackend::new(guest_binary()).with_env(
        "ZEPTOCLAW_BINARY",
        mock_worker_binary().to_str().unwrap(),
    );
    let spec = test_spec_mode("second-job", "complete");
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

    // First job — complete it
    handle
        .send(HostCommand::StartJob(spec.clone()))
        .await
        .unwrap();
    let _ = handle.recv().await.unwrap(); // Started
    drain_to_terminal(&handle).await; // Completed

    // Second job should also work (first one finished)
    let spec2 = test_spec_mode("second-job-2", "complete");
    handle
        .send(HostCommand::StartJob(spec2))
        .await
        .unwrap();
    let event = handle.recv().await.unwrap();
    assert!(matches!(event, GuestEvent::Started { .. }));

    drain_to_terminal(&handle).await;

    handle.send(HostCommand::Shutdown).await.unwrap();
    handle.terminate().await.unwrap();
}
