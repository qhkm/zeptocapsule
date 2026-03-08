//! Guest agent — the control loop running inside the capsule.
//!
//! Reads HostCommands from the control channel, launches the worker
//! binary, and forwards GuestEvents back to the host.
//!
//! Transport-agnostic: accepts any AsyncBufRead/AsyncWrite pair.
//! - Dev mode: stdin/stdout
//! - Namespace mode: Unix socket
//! - MicroVM mode: vsock ports 7000 (control) / 7001 (events)

use zk_proto::{GuestEvent, HostCommand, JobSpec, PROTOCOL_VERSION};

/// Run the guest agent control loop.
pub async fn run_agent<R, W>(reader: R, mut writer: W)
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncBufReadExt;

    // Signal readiness
    send_event(&mut writer, &GuestEvent::Ready).await;

    let mut active_job: Option<String> = None;
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let cmd: HostCommand = match zk_proto::decode_line(&line) {
            Ok(c) => c,
            Err(_) => continue,
        };

        match cmd {
            HostCommand::Handshake {
                protocol_version,
                worker_profile,
            } => {
                send_event(
                    &mut writer,
                    &GuestEvent::HandshakeAck {
                        protocol_version: protocol_version.min(PROTOCOL_VERSION),
                        guest_id: format!("guest-{}", std::process::id()),
                        capabilities: vec![worker_profile],
                    },
                )
                .await;
            }
            HostCommand::StartJob(spec) => {
                if active_job.is_some() {
                    send_event(
                        &mut writer,
                        &GuestEvent::Failed {
                            job_id: spec.job_id.clone(),
                            error: "guest already running a job".into(),
                            retryable: false,
                        },
                    )
                    .await;
                    continue;
                }
                active_job = Some(spec.job_id.clone());
                handle_start_job(&spec, &mut writer).await;
                let _ = active_job.take();
            }
            HostCommand::CancelJob { job_id } => {
                // TODO: Send SIGTERM to worker process, wait, then SIGKILL.
                // For now, just acknowledge.
                active_job = None;
                send_event(&mut writer, &GuestEvent::Cancelled { job_id }).await;
            }
            HostCommand::Ping { seq } => {
                send_event(&mut writer, &GuestEvent::Pong { seq }).await;
            }
            HostCommand::Shutdown => {
                break;
            }
        }
    }
}

/// Handle a StartJob command: launch worker, forward events, report completion.
async fn handle_start_job<W: tokio::io::AsyncWrite + Unpin>(spec: &JobSpec, writer: &mut W) {
    send_event(
        &mut *writer,
        &GuestEvent::Started {
            job_id: spec.job_id.clone(),
        },
    )
    .await;

    // Write job spec to workspace for worker to read
    let spec_path = spec
        .workspace
        .guest_path
        .join(format!("{}.json", spec.job_id));
    if let Ok(json) = serde_json::to_string_pretty(spec) {
        // In dev mode workspace may not exist; best-effort
        let _ = std::fs::create_dir_all(&spec.workspace.guest_path);
        let _ = std::fs::write(&spec_path, json);
    }

    // TODO: Launch the actual ZeptoClaw worker binary:
    //   /zeptoclaw/worker --job-spec <spec_path>
    // and forward its stdout JSON-line events to host.
    //
    // For now, emit a placeholder completed event.

    send_event(
        &mut *writer,
        &GuestEvent::Completed {
            job_id: spec.job_id.clone(),
            output_artifact_ids: vec![],
            summary: String::new(),
        },
    )
    .await;
}

/// Send a GuestEvent to the host.
async fn send_event<W: tokio::io::AsyncWrite + Unpin>(writer: &mut W, event: &GuestEvent) {
    use tokio::io::AsyncWriteExt;

    if let Ok(line) = zk_proto::encode_line(event) {
        let _ = writer.write_all(line.as_bytes()).await;
        let _ = writer.flush().await;
    }
}
