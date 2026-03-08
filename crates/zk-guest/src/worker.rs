//! Worker launcher — spawns the ZeptoClaw worker binary inside the capsule.

use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::process::{Child, ChildStdout, Command};
use zk_proto::JobSpec;

/// Write the job spec to a file so the worker can read it.
pub fn write_job_spec(spec: &JobSpec, dir: &Path) -> std::io::Result<std::path::PathBuf> {
    let path = dir.join("job-spec.json");
    let json = serde_json::to_string_pretty(spec)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&path, json)?;
    Ok(path)
}

/// A running worker process with its stdout lines ready to read.
pub struct WorkerHandle {
    pub job_id: String,
    pub child: Child,
    pub stdout: Lines<BufReader<ChildStdout>>,
}

/// Spawn the worker binary for the given job spec.
///
/// The worker is started with:
///   `<worker_binary> --job-spec <spec_path> --job-id <job_id>`
///
/// Its env is set from `spec.env`. Stdout is piped for JSON-line event parsing.
/// Stderr is inherited (goes to capsule logs / tracing).
pub async fn launch_worker(
    spec: &JobSpec,
    spec_path: &Path,
    worker_binary: &str,
) -> std::io::Result<WorkerHandle> {
    let mut cmd = Command::new(worker_binary);
    cmd.arg("--job-spec")
        .arg(spec_path)
        .arg("--job-id")
        .arg(&spec.job_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);

    // Inject env vars from the job spec
    for (k, v) in &spec.env {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn()?;

    let stdout = child
        .stdout
        .take()
        .expect("stdout should be piped");

    Ok(WorkerHandle {
        job_id: spec.job_id.clone(),
        child,
        stdout: BufReader::new(stdout).lines(),
    })
}
