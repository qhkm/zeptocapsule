//! Guest agent — the control loop running inside the capsule.
//!
//! Reads HostCommands from the control channel, launches the worker
//! binary, and forwards GuestEvents back to the host.

use zk_proto::{GuestEvent, HostCommand, JobSpec};

/// Run the guest agent loop.
///
/// In production this reads from vsock or a Unix socket.
/// For initial development, it reads from stdin and writes to stdout
/// (same JSON-line protocol as ZeptoPM workers).
pub async fn run_agent<R, W>(reader: R, mut writer: W)
where
    R: tokio::io::AsyncBufRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    // Signal readiness
    let ready = zk_proto::encode_line(&GuestEvent::Ready).unwrap();
    writer.write_all(ready.as_bytes()).await.ok();
    writer.flush().await.ok();

    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let cmd: HostCommand = match zk_proto::decode_line(&line) {
            Ok(c) => c,
            Err(_) => continue,
        };

        match cmd {
            HostCommand::StartJob(spec) => {
                handle_start_job(&spec, &mut writer).await;
            }
            HostCommand::CancelJob { job_id } => {
                let event = GuestEvent::Cancelled { job_id };
                let line = zk_proto::encode_line(&event).unwrap();
                writer.write_all(line.as_bytes()).await.ok();
                writer.flush().await.ok();
            }
            HostCommand::Ping { seq } => {
                let event = GuestEvent::Pong { seq };
                let line = zk_proto::encode_line(&event).unwrap();
                writer.write_all(line.as_bytes()).await.ok();
                writer.flush().await.ok();
            }
            HostCommand::Shutdown => {
                break;
            }
        }
    }
}

async fn handle_start_job<W: tokio::io::AsyncWrite + Unpin>(
    spec: &JobSpec,
    writer: &mut W,
) {
    use tokio::io::AsyncWriteExt;

    // Emit started
    let started = zk_proto::encode_line(&GuestEvent::Started {
        job_id: spec.job_id.clone(),
    })
    .unwrap();
    writer.write_all(started.as_bytes()).await.ok();
    writer.flush().await.ok();

    // TODO: Launch the actual ZeptoClaw worker binary here.
    // For now, emit a placeholder completed event.

    let completed = zk_proto::encode_line(&GuestEvent::Completed {
        job_id: spec.job_id.clone(),
        output_artifact_ids: vec![],
    })
    .unwrap();
    writer.write_all(completed.as_bytes()).await.ok();
    writer.flush().await.ok();
}
