//! Mock worker binary for testing zk-guest.
//!
//! Simulates a ZeptoClaw worker. Supports `--mode <mode>` and `--job-id <id>`.
//!
//! The mock worker emits only NON-TERMINAL events (heartbeat, progress,
//! artifact_produced) to stdout. The guest agent is responsible for emitting
//! Started, Completed, Failed, and Cancelled.
//!
//! Modes:
//! - `complete`  — emit one heartbeat, exit 0 (guest will send Completed)
//! - `fail`      — emit one heartbeat, exit 1 (guest will send Failed)
//! - `hang`      — emit one heartbeat, sleep forever (for cancel/timeout tests)
//! - `events`    — emit multiple heartbeats + progress events, exit 0

use std::time::Duration;

fn emit(event: &serde_json::Value) {
    println!("{}", event);
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Mode can be set via --mode argv or MOCK_MODE env var (env takes precedence)
    let mode_from_env = std::env::var("MOCK_MODE").unwrap_or_default();
    let mode_from_args = args
        .windows(2)
        .find(|w| w[0] == "--mode")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "complete".to_string());
    let mode_owned = if mode_from_env.is_empty() {
        mode_from_args
    } else {
        mode_from_env
    };
    let mode = mode_owned.as_str();

    let job_id = args
        .windows(2)
        .find(|w| w[0] == "--job-id")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "mock-job".to_string());

    match mode {
        "complete" => {
            tokio::time::sleep(Duration::from_millis(50)).await;
            emit(&serde_json::json!({
                "type": "heartbeat",
                "job_id": job_id,
                "phase": "running",
            }));
            // exit 0 → guest emits Completed
        }

        "fail" => {
            tokio::time::sleep(Duration::from_millis(50)).await;
            emit(&serde_json::json!({
                "type": "heartbeat",
                "job_id": job_id,
                "phase": "running",
            }));
            // exit 1 → guest emits Failed
            std::process::exit(1);
        }

        "hang" => {
            // Emit one heartbeat, then hang until killed
            tokio::time::sleep(Duration::from_millis(50)).await;
            emit(&serde_json::json!({
                "type": "heartbeat",
                "job_id": job_id,
                "phase": "running",
            }));
            // Sleep for a very long time to simulate a hung worker
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }

        "events" => {
            // Emit multiple heartbeats and progress events before exiting
            for i in 0..3u32 {
                tokio::time::sleep(Duration::from_millis(30)).await;
                emit(&serde_json::json!({
                    "type": "heartbeat",
                    "job_id": job_id,
                    "phase": "running",
                }));
                emit(&serde_json::json!({
                    "type": "progress",
                    "job_id": job_id,
                    "phase": "running",
                    "message": format!("step {}", i + 1),
                    "percent": (i + 1) * 33,
                }));
            }
            // exit 0 → guest emits Completed
        }

        other => {
            eprintln!("mock_worker: unknown mode {:?}", other);
            std::process::exit(2);
        }
    }
}
