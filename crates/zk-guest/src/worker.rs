//! Worker launcher — spawns the ZeptoClaw worker binary inside the capsule.

use std::path::Path;
use zk_proto::JobSpec;

/// Write the job spec to a file so the worker can read it.
pub fn write_job_spec(spec: &JobSpec, dir: &Path) -> std::io::Result<std::path::PathBuf> {
    let path = dir.join("job-spec.json");
    let json = serde_json::to_string_pretty(spec)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&path, json)?;
    Ok(path)
}
