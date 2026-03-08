use std::collections::HashMap;

use zk_proto::{JobSpec, ResourceLimits, WorkspaceConfig};

use zk_host::process_backend::ProcessBackend;
use zk_host::supervisor::Supervisor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let guest_binary = std::env::args().nth(1).unwrap_or_else(|| {
        // Default: look for zk-guest in same directory as this binary
        let mut path = std::env::current_exe().unwrap();
        path.set_file_name("zk-guest");
        path.to_string_lossy().to_string()
    });

    tracing::info!(guest_binary, "starting zk-host supervisor");

    let backend = ProcessBackend::new(&guest_binary);
    let mut supervisor = Supervisor::new();

    let spec = JobSpec {
        job_id: "test-job-1".into(),
        run_id: "test-run-1".into(),
        role: "researcher".into(),
        profile_id: "researcher".into(),
        instruction: "Research the top 3 AI startups in Southeast Asia".into(),
        input_artifacts: vec![],
        env: HashMap::new(),
        limits: ResourceLimits::default(),
        workspace: WorkspaceConfig::default(),
    };

    let outcome = supervisor.run_job(&backend, &spec, "zeptoclaw-worker").await?;
    tracing::info!(?outcome, "job finished");

    Ok(())
}
