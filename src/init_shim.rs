use std::path::PathBuf;
use std::process::Command;

#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::process::Stdio;

#[cfg(target_os = "linux")]
const FC_STAGE_DIR: &str = "/run/zeptocapsule";
#[cfg(target_os = "linux")]
const FC_MODE_MARKER: &str = "/run/zeptocapsule/firecracker.mode";
#[cfg(target_os = "linux")]
const FC_WORKER_PATH_FILE: &str = "/run/zeptocapsule/worker.path";
#[cfg(target_os = "linux")]
const FC_WORKER_ARGS_FILE: &str = "/run/zeptocapsule/worker.args";
#[cfg(target_os = "linux")]
const FC_WORKER_ENV_FILE: &str = "/run/zeptocapsule/worker.env";
#[cfg(target_os = "linux")]
const FC_WORKSPACE_DEVICE_FILE: &str = "/run/zeptocapsule/workspace.device";
#[cfg(target_os = "linux")]
const FC_WORKSPACE_PATH_FILE: &str = "/run/zeptocapsule/workspace.path";
#[cfg(target_os = "linux")]
const FC_TMP_SIZE_FILE: &str = "/run/zeptocapsule/tmp.size";

#[derive(Debug, Clone)]
pub struct MountConfig {
    pub tmp_size: String,
    pub workspace_size: String,
    pub host_workspace_path: Option<PathBuf>,
    pub workspace_path: PathBuf,
}

/// Configuration for Firecracker-mode zk-init.
#[derive(Debug, Clone)]
pub struct FcInitConfig {
    pub worker_path: String,
    pub worker_args: Vec<String>,
    pub worker_env: Vec<(String, String)>,
    pub workspace_device: Option<String>,
    pub workspace_path: PathBuf,
    pub tmp_size: String,
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

/// Check if env vars indicate Firecracker mode.
pub fn is_firecracker_mode<'a>(env: impl Iterator<Item = (&'a str, &'a str)>) -> bool {
    env.into_iter().any(|(k, _)| k == "ZK_FC_MODE")
}

/// Parse Firecracker init config from environment variables.
pub fn parse_fc_init_config(
    env: impl Iterator<Item = (String, String)>,
) -> Result<FcInitConfig, String> {
    let mut worker_path = None;
    let mut worker_args = Vec::new();
    let mut worker_env = Vec::new();
    let mut workspace_device = None;
    let mut workspace_path = PathBuf::from("/workspace");
    let mut tmp_size = "64m".to_string();

    for (key, value) in env {
        match key.as_str() {
            "ZK_FC_WORKER_PATH" => worker_path = Some(value),
            "ZK_FC_WORKER_ARGS" => {
                worker_args = value.split_whitespace().map(String::from).collect();
            }
            "ZK_FC_WORKER_ENV" => {
                worker_env = value
                    .split('\n')
                    .filter_map(|entry| entry.split_once('='))
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect();
            }
            "ZK_FC_WORKSPACE_DEVICE" => workspace_device = Some(value),
            "ZK_FC_WORKSPACE_PATH" => workspace_path = PathBuf::from(value),
            "ZK_FC_TMP_SIZE" => tmp_size = value,
            _ => {}
        }
    }

    let worker_path = worker_path
        .ok_or_else(|| "ZK_FC_WORKER_PATH is required in Firecracker mode".to_string())?;

    Ok(FcInitConfig {
        worker_path,
        worker_args,
        worker_env,
        workspace_device,
        workspace_path,
        tmp_size,
    })
}

/// Run init shim in Firecracker mode.
#[cfg(target_os = "linux")]
fn run_fc_init_shim() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let config = load_fc_init_config()?;
        setup_fc_guest_fs(&config)?;

        let stdin_listener = vsock_listen(crate::vsock::PORT_STDIN)?;
        let stdout_listener = vsock_listen(crate::vsock::PORT_STDOUT)?;
        let stderr_listener = vsock_listen(crate::vsock::PORT_STDERR)?;
        let control_listener = vsock_listen(crate::vsock::PORT_CONTROL)?;

        let stdin_fd = vsock_accept(stdin_listener)?;
        let stdout_fd = vsock_accept(stdout_listener)?;
        let stderr_fd = vsock_accept(stderr_listener)?;
        let mut control = unsafe { std::fs::File::from_raw_fd(vsock_accept(control_listener)?) };

        let mut child = Command::new(&config.worker_path);
        child
            .args(&config.worker_args)
            .stdin(unsafe { Stdio::from_raw_fd(stdin_fd) })
            .stdout(unsafe { Stdio::from_raw_fd(stdout_fd) })
            .stderr(unsafe { Stdio::from_raw_fd(stderr_fd) });

        for (key, value) in &config.worker_env {
            child.env(key, value);
        }

        let mut child = child
            .spawn()
            .map_err(|e| format!("exec {}: {e}", config.worker_path))?;

        control
            .write_all(b"READY\n")
            .map_err(|e| format!("write READY: {e}"))?;
        control.flush().map_err(|e| format!("flush READY: {e}"))?;

        let worker_pid = child.id() as i32;
        let mut control_reader = control
            .try_clone()
            .map_err(|e| format!("clone control socket: {e}"))?;
        let control_thread = std::thread::spawn(move || -> Result<(), String> {
            let mut reader = BufReader::new(&mut control_reader);
            loop {
                let mut line = String::new();
                let bytes = reader
                    .read_line(&mut line)
                    .map_err(|e| format!("read control: {e}"))?;
                if bytes == 0 {
                    break;
                }

                match line.trim() {
                    "TERMINATE" => {
                        let rc = unsafe { libc::kill(worker_pid, libc::SIGTERM) };
                        if rc != 0 {
                            return Err(format!(
                                "forward SIGTERM failed: {}",
                                std::io::Error::last_os_error()
                            ));
                        }
                    }
                    "KILL" => {
                        let rc = unsafe { libc::kill(worker_pid, libc::SIGKILL) };
                        if rc != 0 {
                            return Err(format!(
                                "forward SIGKILL failed: {}",
                                std::io::Error::last_os_error()
                            ));
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        });

        let status = child
            .wait()
            .map_err(|e| format!("wait {}: {e}", config.worker_path))?;

        // Flush all pending disk writes so workspace data reaches the host image
        // before the VM is killed.
        unsafe { libc::sync() };

        let message = match status.code() {
            Some(code) => format!("EXIT {code}\n"),
            None => {
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    format!("SIGNAL {}\n", status.signal().unwrap_or_default())
                }
                #[cfg(not(unix))]
                {
                    "SIGNAL 0\n".to_string()
                }
            }
        };

        control
            .write_all(message.as_bytes())
            .map_err(|e| format!("write exit status: {e}"))?;
        control
            .flush()
            .map_err(|e| format!("flush exit status: {e}"))?;
        drop(control);
        let _ = control_thread.join();

        match status.code() {
            Some(code) => std::process::exit(code),
            None => Err(format!(
                "worker {} terminated by signal",
                config.worker_path
            )),
        }
    }
}

pub fn run_init_shim() -> Result<(), String> {
    // Check for Firecracker mode
    #[cfg(target_os = "linux")]
    if std::path::Path::new(FC_MODE_MARKER).exists() {
        return run_fc_init_shim();
    }

    let (config, worker, worker_args) = init_command_from_env_and_args()?;
    // Skip mount operations when rootfs was already set up (Hardened namespace
    // profile calls setup_and_pivot before seccomp, so mount is blocked here).
    if std::env::var_os("ZK_ROOTFS_READY").is_none() {
        setup_guest_fs(&config)?;
    }

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
fn load_fc_init_config() -> Result<FcInitConfig, String> {
    Ok(FcInitConfig {
        worker_path: read_trimmed_file(PathBuf::from(FC_WORKER_PATH_FILE).as_path())?
            .unwrap_or_else(|| format!("{FC_STAGE_DIR}/worker")),
        worker_args: read_nul_delimited_strings(PathBuf::from(FC_WORKER_ARGS_FILE).as_path())?,
        worker_env: read_nul_delimited_key_values(PathBuf::from(FC_WORKER_ENV_FILE).as_path())?,
        workspace_device: read_trimmed_file(PathBuf::from(FC_WORKSPACE_DEVICE_FILE).as_path())?,
        workspace_path: read_trimmed_file(PathBuf::from(FC_WORKSPACE_PATH_FILE).as_path())?
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/workspace")),
        tmp_size: read_trimmed_file(PathBuf::from(FC_TMP_SIZE_FILE).as_path())?
            .unwrap_or_else(|| "64m".to_string()),
    })
}

#[cfg(target_os = "linux")]
fn setup_fc_guest_fs(config: &FcInitConfig) -> Result<(), String> {
    mount_proc()?;
    mount_tmpfs(std::path::Path::new("/tmp"), &config.tmp_size)?;

    if let Some(ref device) = config.workspace_device {
        std::fs::create_dir_all(&config.workspace_path)
            .map_err(|e| format!("mkdir workspace: {e}"))?;

        let output = Command::new("mount")
            .arg(device)
            .arg(&config.workspace_path)
            .output()
            .map_err(|e| format!("mount workspace: {e}"))?;

        if !output.status.success() {
            return Err(format!(
                "mount workspace failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    } else {
        std::fs::create_dir_all(&config.workspace_path)
            .map_err(|e| format!("mkdir workspace: {e}"))?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn read_trimmed_file(path: &std::path::Path) -> Result<Option<String>, String> {
    if !path.exists() {
        return Ok(None);
    }

    let content =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let trimmed = content.trim().to_string();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}

#[cfg(target_os = "linux")]
fn read_nul_delimited_strings(path: &std::path::Path) -> Result<Vec<String>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut values = Vec::new();
    for chunk in bytes.split(|byte| *byte == 0) {
        if chunk.is_empty() {
            continue;
        }
        values.push(
            String::from_utf8(chunk.to_vec())
                .map_err(|e| format!("decode {}: {e}", path.display()))?,
        );
    }
    Ok(values)
}

#[cfg(target_os = "linux")]
fn read_nul_delimited_key_values(path: &std::path::Path) -> Result<Vec<(String, String)>, String> {
    let mut pairs = Vec::new();
    for entry in read_nul_delimited_strings(path)? {
        if let Some((key, value)) = entry.split_once('=') {
            pairs.push((key.to_string(), value.to_string()));
        }
    }
    Ok(pairs)
}

#[cfg(target_os = "linux")]
fn vsock_listen(port: u32) -> Result<RawFd, String> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(format!(
            "vsock socket {port}: {}",
            std::io::Error::last_os_error()
        ));
    }

    let addr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: libc::VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };

    let rc = unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_vm).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("vsock bind {port}: {err}"));
    }

    let rc = unsafe { libc::listen(fd, 1) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("vsock listen {port}: {err}"));
    }

    Ok(fd)
}

#[cfg(target_os = "linux")]
fn vsock_accept(listener: RawFd) -> Result<RawFd, String> {
    let fd = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
    if fd < 0 {
        return Err(format!("vsock accept: {}", std::io::Error::last_os_error()));
    }
    unsafe { libc::close(listener) };
    Ok(fd)
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
    let opts = CString::new(format!("size={size}")).unwrap();

    std::fs::create_dir_all(path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
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

    #[test]
    fn detect_firecracker_mode_from_env() {
        let env = vec![
            ("ZK_FC_MODE", "1"),
            ("ZK_FC_WORKER_PATH", "/run/zeptocapsule/worker"),
        ];
        assert!(super::is_firecracker_mode(env.into_iter()));
    }

    #[test]
    fn detect_no_firecracker_mode() {
        let env: Vec<(&str, &str)> = vec![];
        assert!(!super::is_firecracker_mode(env.into_iter()));
    }

    #[test]
    fn parse_firecracker_config_full() {
        let env = vec![
            ("ZK_FC_MODE".to_string(), "1".to_string()),
            (
                "ZK_FC_WORKER_PATH".to_string(),
                "/run/zeptocapsule/worker".to_string(),
            ),
            ("ZK_FC_WORKER_ARGS".to_string(), "arg1 arg2".to_string()),
            ("ZK_FC_WORKSPACE_DEVICE".to_string(), "/dev/vdb".to_string()),
            ("ZK_FC_WORKSPACE_PATH".to_string(), "/workspace".to_string()),
            (
                "ZK_FC_WORKER_ENV".to_string(),
                "FOO=bar\nBAZ=qux".to_string(),
            ),
            ("ZK_FC_TMP_SIZE".to_string(), "16m".to_string()),
        ];
        let config = super::parse_fc_init_config(env.into_iter()).unwrap();
        assert_eq!(config.worker_path, "/run/zeptocapsule/worker");
        assert_eq!(config.worker_args, vec!["arg1", "arg2"]);
        assert_eq!(
            config.worker_env,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("BAZ".to_string(), "qux".to_string())
            ]
        );
        assert_eq!(config.workspace_device.as_deref(), Some("/dev/vdb"));
        assert_eq!(config.workspace_path.to_string_lossy(), "/workspace");
        assert_eq!(config.tmp_size, "16m");
    }

    #[test]
    fn parse_firecracker_config_defaults() {
        let env = vec![
            ("ZK_FC_MODE".to_string(), "1".to_string()),
            (
                "ZK_FC_WORKER_PATH".to_string(),
                "/run/zeptocapsule/worker".to_string(),
            ),
        ];
        let config = super::parse_fc_init_config(env.into_iter()).unwrap();
        assert_eq!(config.workspace_path.to_string_lossy(), "/workspace");
        assert!(config.workspace_device.is_none());
        assert!(config.worker_args.is_empty());
        assert!(config.worker_env.is_empty());
        assert_eq!(config.tmp_size, "64m");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_nul_delimited_key_values_parses_env_pairs() {
        let path = std::env::temp_dir().join(format!("zk-fc-env-{}", std::process::id()));
        std::fs::write(&path, b"FOO=bar\0BAZ=qux\0").unwrap();
        let envs = super::read_nul_delimited_key_values(&path).unwrap();
        assert_eq!(
            envs,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("BAZ".to_string(), "qux".to_string())
            ]
        );
        let _ = std::fs::remove_file(path);
    }
}
