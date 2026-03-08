use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct MountConfig {
    pub tmp_size: String,
    pub workspace_size: String,
    pub host_workspace_path: Option<PathBuf>,
    pub workspace_path: PathBuf,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            tmp_size: "64m".into(),
            workspace_size: "128m".into(),
            host_workspace_path: None,
            workspace_path: PathBuf::from("/workspace"),
        }
    }
}

pub fn setup_guest_fs(config: &MountConfig) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        mount_proc()?;
        if let Some(host_workspace_path) = config.host_workspace_path.as_ref() {
            bind_mount(host_workspace_path, &config.workspace_path)?;
        } else {
            mount_tmpfs(&config.workspace_path, &config.workspace_size)?;
        }
        mount_tmpfs(std::path::Path::new("/tmp"), &config.tmp_size)?;
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = std::fs::create_dir_all("/tmp");
        let _ = std::fs::create_dir_all(&config.workspace_path);
        let _ = config;
    }

    Ok(())
}

pub fn is_init() -> bool {
    std::process::id() == 1
}

pub fn run_init_shim() -> Result<(), String> {
    let (config, worker, worker_args) = init_command_from_env_and_args()?;
    setup_guest_fs(&config)?;

    let status = Command::new(&worker)
        .args(&worker_args)
        .status()
        .map_err(|e| format!("exec {worker}: {e}"))?;

    match status.code() {
        Some(code) => std::process::exit(code),
        None => Err(format!("worker {worker} terminated by signal")),
    }
}

fn init_command_from_env_and_args() -> Result<(MountConfig, String, Vec<String>), String> {
    init_command_from_parts(std::env::args(), std::env::vars())
}

fn init_command_from_parts<I, E>(
    args: I,
    env: E,
) -> Result<(MountConfig, String, Vec<String>), String>
where
    I: IntoIterator<Item = String>,
    E: IntoIterator<Item = (String, String)>,
{
    let mut args = args.into_iter();
    let _ = args.next();
    let worker = args
        .next()
        .ok_or_else(|| "usage: zk-init <worker-binary> [worker-args...]".to_string())?;
    let worker_args: Vec<String> = args.collect();

    let mut config = MountConfig::default();
    for (key, value) in env {
        match key.as_str() {
            "ZK_INIT_WORKSPACE_HOST_PATH" => {
                config.host_workspace_path = Some(PathBuf::from(value))
            }
            "ZK_INIT_WORKSPACE_PATH" => config.workspace_path = PathBuf::from(value),
            "ZK_INIT_WORKSPACE_SIZE" => config.workspace_size = value,
            "ZK_INIT_TMP_SIZE" => config.tmp_size = value,
            _ => {}
        }
    }

    Ok((config, worker, worker_args))
}

#[cfg(target_os = "linux")]
fn mount_proc() -> Result<(), String> {
    use std::ffi::CString;

    let target = CString::new("/proc").unwrap();
    let fstype = CString::new("proc").unwrap();
    let source = CString::new("proc").unwrap();

    std::fs::create_dir_all("/proc").map_err(|e| format!("mkdir /proc: {e}"))?;

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "mount /proc failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_tmpfs(path: &std::path::Path, size: &str) -> Result<(), String> {
    use std::ffi::CString;

    let path_str = path.to_string_lossy();
    let target = CString::new(path_str.as_bytes()).unwrap();
    let fstype = CString::new("tmpfs").unwrap();
    let source = CString::new("tmpfs").unwrap();
    let opts = CString::new(format!("size={size},nosuid,nodev")).unwrap();

    std::fs::create_dir_all(path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            opts.as_ptr().cast(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "mount tmpfs {} failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_mount(source: &std::path::Path, target: &std::path::Path) -> Result<(), String> {
    use std::ffi::CString;

    std::fs::create_dir_all(source).map_err(|e| format!("mkdir {}: {e}", source.display()))?;
    std::fs::create_dir_all(target).map_err(|e| format!("mkdir {}: {e}", target.display()))?;

    let source_str = source.to_string_lossy();
    let target_str = target.to_string_lossy();
    let source_c = CString::new(source_str.as_bytes()).unwrap();
    let target_c = CString::new(target_str.as_bytes()).unwrap();

    let ret = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REC,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        return Err(format!(
            "bind mount {} -> {} failed: {}",
            source.display(),
            target.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_uses_default_mount_config() {
        let (config, worker, worker_args) = super::init_command_from_parts(
            vec![
                "zk-init".to_string(),
                "/bin/echo".to_string(),
                "hello".to_string(),
            ],
            Vec::<(String, String)>::new(),
        )
        .unwrap();
        assert_eq!(worker, "/bin/echo");
        assert_eq!(worker_args, vec!["hello".to_string()]);
        assert_eq!(config.host_workspace_path, None);
        assert_eq!(config.workspace_path.to_string_lossy(), "/workspace");
        assert_eq!(config.workspace_size, "128m");
        assert_eq!(config.tmp_size, "64m");
    }

    #[test]
    fn init_reads_mount_config_from_env() {
        let (config, _, _) = super::init_command_from_parts(
            vec!["zk-init".to_string(), "/bin/echo".to_string()],
            vec![
                (
                    "ZK_INIT_WORKSPACE_HOST_PATH".to_string(),
                    "/host/work".to_string(),
                ),
                (
                    "ZK_INIT_WORKSPACE_PATH".to_string(),
                    "/sandbox/work".to_string(),
                ),
                ("ZK_INIT_WORKSPACE_SIZE".to_string(), "256m".to_string()),
                ("ZK_INIT_TMP_SIZE".to_string(), "32m".to_string()),
            ],
        )
        .unwrap();
        assert_eq!(
            config.host_workspace_path.as_deref(),
            Some(std::path::Path::new("/host/work"))
        );
        assert_eq!(config.workspace_path.to_string_lossy(), "/sandbox/work");
        assert_eq!(config.workspace_size, "256m");
        assert_eq!(config.tmp_size, "32m");
    }
}
