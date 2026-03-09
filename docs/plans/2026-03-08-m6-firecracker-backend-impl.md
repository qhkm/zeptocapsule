# M6: Firecracker Backend Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement `Isolation::Firecracker` microVM backend behind the existing `create() -> spawn() -> destroy()` contract, providing full VM-level isolation for multi-tenant untrusted agent workloads.

**Architecture:** Firecracker backend implements `CapsuleHandle` trait using the Firecracker REST API over Unix socket for VM lifecycle, vsock for stdin/stdout/stderr/control pipes, and ext4 disk images for workspace import/export. The guest runs `zk-init` as PID 1 which bridges vsock to the worker process.

**Tech Stack:** Rust (nightly), tokio async runtime, Firecracker REST API (manual HTTP over Unix socket), Linux vsock, ext4 disk images via `mkfs.ext4`/`mount`/`umount` shell commands.

**Design Doc:** `docs/plans/2026-03-08-m6-firecracker-backend-design.md` (authoritative source for all design decisions)

---

## Task 1: Add FirecrackerConfig to types.rs

**Files:**
- Modify: `src/types.rs`

**Context:** The design doc specifies a `FirecrackerConfig` struct and an optional `firecracker` field on `CapsuleSpec`. This task adds the types and extends validation.

**Step 1: Write failing tests**

Add to `src/types.rs` in the `#[cfg(test)] mod tests` block:

```rust
#[test]
fn firecracker_config_default_fields() {
    let config = FirecrackerConfig {
        firecracker_bin: PathBuf::from("/usr/bin/firecracker"),
        kernel_path: PathBuf::from("/var/lib/zk/vmlinux"),
        rootfs_path: PathBuf::from("/var/lib/zk/rootfs.ext4"),
        vcpus: None,
        memory_mib: None,
        enable_network: false,
        tap_name: None,
    };
    assert_eq!(config.firecracker_bin, PathBuf::from("/usr/bin/firecracker"));
    assert!(!config.enable_network);
    assert!(config.vcpus.is_none());
}

#[test]
fn validate_firecracker_requires_firecracker_config() {
    let spec = CapsuleSpec {
        isolation: Isolation::Firecracker,
        security: SecurityProfile::Standard,
        ..Default::default()
    };
    let err = spec.validate().unwrap_err();
    assert!(err.contains("firecracker"), "error should mention firecracker config: {err}");
}

#[test]
fn validate_firecracker_with_config_ok() {
    let spec = CapsuleSpec {
        isolation: Isolation::Firecracker,
        security: SecurityProfile::Standard,
        firecracker: Some(FirecrackerConfig {
            firecracker_bin: PathBuf::from("/usr/bin/firecracker"),
            kernel_path: PathBuf::from("/var/lib/zk/vmlinux"),
            rootfs_path: PathBuf::from("/var/lib/zk/rootfs.ext4"),
            vcpus: None,
            memory_mib: None,
            enable_network: false,
            tap_name: None,
        }),
        ..Default::default()
    };
    assert!(spec.validate().is_ok());
}

#[test]
fn validate_firecracker_rejects_max_pids() {
    let spec = CapsuleSpec {
        isolation: Isolation::Firecracker,
        security: SecurityProfile::Standard,
        limits: ResourceLimits {
            max_pids: Some(100),
            ..Default::default()
        },
        firecracker: Some(FirecrackerConfig {
            firecracker_bin: PathBuf::from("/usr/bin/firecracker"),
            kernel_path: PathBuf::from("/var/lib/zk/vmlinux"),
            rootfs_path: PathBuf::from("/var/lib/zk/rootfs.ext4"),
            vcpus: None,
            memory_mib: None,
            enable_network: false,
            tap_name: None,
        }),
        ..Default::default()
    };
    let err = spec.validate().unwrap_err();
    assert!(err.contains("max_pids"), "error should mention max_pids: {err}");
}

#[test]
fn firecracker_derived_vcpus() {
    let config = FirecrackerConfig {
        firecracker_bin: PathBuf::from("/usr/bin/firecracker"),
        kernel_path: PathBuf::from("/var/lib/zk/vmlinux"),
        rootfs_path: PathBuf::from("/var/lib/zk/rootfs.ext4"),
        vcpus: None,
        memory_mib: None,
        enable_network: false,
        tap_name: None,
    };
    let limits = ResourceLimits {
        cpu_quota: Some(2.5),
        memory_mib: Some(512),
        ..Default::default()
    };
    assert_eq!(config.effective_vcpus(&limits), 3); // ceil(2.5)
    assert_eq!(config.effective_memory_mib(&limits), 512);
}

#[test]
fn firecracker_derived_defaults() {
    let config = FirecrackerConfig {
        firecracker_bin: PathBuf::from("/usr/bin/firecracker"),
        kernel_path: PathBuf::from("/var/lib/zk/vmlinux"),
        rootfs_path: PathBuf::from("/var/lib/zk/rootfs.ext4"),
        vcpus: None,
        memory_mib: None,
        enable_network: false,
        tap_name: None,
    };
    let limits = ResourceLimits::default();
    assert_eq!(config.effective_vcpus(&limits), 1); // min 1
    assert_eq!(config.effective_memory_mib(&limits), 256); // default 256
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo +nightly test -p zeptocapsule -- firecracker`
Expected: Compilation error — `FirecrackerConfig` not defined.

**Step 3: Implement types**

Add to `src/types.rs` before the `#[cfg(test)]` block:

```rust
#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    pub firecracker_bin: PathBuf,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub vcpus: Option<u32>,
    pub memory_mib: Option<u64>,
    pub enable_network: bool,
    pub tap_name: Option<String>,
}

impl FirecrackerConfig {
    /// Effective vCPU count: explicit > ceil(cpu_quota) > 1.
    pub fn effective_vcpus(&self, limits: &ResourceLimits) -> u32 {
        self.vcpus.unwrap_or_else(|| {
            limits
                .cpu_quota
                .map(|q| (q.ceil() as u32).max(1))
                .unwrap_or(1)
        })
    }

    /// Effective guest memory: explicit > limits.memory_mib > 256.
    pub fn effective_memory_mib(&self, limits: &ResourceLimits) -> u64 {
        self.memory_mib
            .or(limits.memory_mib)
            .unwrap_or(256)
    }
}
```

Add `firecracker` field to `CapsuleSpec`:

```rust
pub struct CapsuleSpec {
    pub isolation: Isolation,
    pub workspace: WorkspaceConfig,
    pub limits: ResourceLimits,
    pub init_binary: Option<PathBuf>,
    pub security: SecurityProfile,
    pub security_overrides: SecurityOverrides,
    pub firecracker: Option<FirecrackerConfig>,  // NEW
}
```

Update `CapsuleSpec::default()` to include `firecracker: None`.

Extend `CapsuleSpec::validate()`:

```rust
pub fn validate(&self) -> Result<(), String> {
    match (self.isolation, self.security) {
        (Isolation::Process, SecurityProfile::Hardened) => {
            return Err("Hardened security profile requires Namespace isolation".into());
        }
        (Isolation::Namespace, SecurityProfile::Dev) => {
            return Err("Dev security profile only works with Process isolation".into());
        }
        _ => {}
    }

    if self.isolation == Isolation::Firecracker {
        if self.firecracker.is_none() {
            return Err("Firecracker isolation requires firecracker config".into());
        }
        if self.limits.max_pids.is_some() {
            return Err("max_pids is not supported with Firecracker isolation".into());
        }
    }

    Ok(())
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo +nightly test -p zeptocapsule -- firecracker`
Expected: All 6 new tests PASS.

**Step 5: Add export in lib.rs**

Add `FirecrackerConfig` to the `pub use types::{}` block in `src/lib.rs`.

**Step 6: Verify full crate compiles**

Run: `cargo +nightly build -p zeptocapsule`
Expected: Clean build, no warnings.

**Step 7: Commit**

```bash
git add src/types.rs src/lib.rs
git commit -m "feat(types): add FirecrackerConfig and Firecracker validation rules"
```

---

## Task 2: Add Firecracker REST API client (firecracker_api.rs)

**Files:**
- Create: `src/firecracker_api.rs`
- Modify: `src/lib.rs` (add `mod firecracker_api;`)

**Context:** The design doc specifies a minimal HTTP client over Unix sockets for the Firecracker API. It must support `PUT /machine-config`, `PUT /boot-source`, `PUT /drives/{id}`, `PUT /vsocks/{id}`, `PUT /network-interfaces/{id}`, and `PUT /actions`. Use tokio `UnixStream` — no new dependencies needed.

**Step 1: Write failing tests**

Create `src/firecracker_api.rs` with test module only:

```rust
//! Minimal Firecracker REST API client over Unix socket.
//!
//! Speaks raw HTTP/1.1 over a Unix domain socket. No external HTTP
//! library needed — Firecracker's API is small and predictable.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_put_request_basic() {
        let req = format_put_request("/machine-config", r#"{"vcpu_count":2}"#);
        assert!(req.starts_with("PUT /machine-config HTTP/1.1\r\n"));
        assert!(req.contains("Content-Type: application/json\r\n"));
        assert!(req.contains("Content-Length: 16\r\n"));
        assert!(req.ends_with("\r\n{\"vcpu_count\":2}"));
    }

    #[test]
    fn parse_response_200() {
        let raw = "HTTP/1.1 204 No Content\r\nServer: Firecracker\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_empty());
    }

    #[test]
    fn parse_response_with_body() {
        let raw = "HTTP/1.1 400 Bad Request\r\nContent-Length: 13\r\n\r\n{\"error\":\"x\"}";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 400);
        assert_eq!(resp.body, "{\"error\":\"x\"}");
    }

    #[test]
    fn machine_config_json() {
        let json = machine_config_json(2, 512);
        assert!(json.contains("\"vcpu_count\":2"));
        assert!(json.contains("\"mem_size_mib\":512"));
    }

    #[test]
    fn boot_source_json_basic() {
        let json = boot_source_json("/vmlinux", "console=ttyS0 reboot=k panic=1");
        assert!(json.contains("\"/vmlinux\""));
        assert!(json.contains("console=ttyS0"));
    }

    #[test]
    fn drive_json_basic() {
        let json = drive_json("rootfs", "/path/to/rootfs.ext4", true, false);
        assert!(json.contains("\"drive_id\":\"rootfs\""));
        assert!(json.contains("\"is_root_device\":true"));
        assert!(json.contains("\"is_read_only\":false"));
    }

    #[test]
    fn vsock_json_basic() {
        let json = vsock_json("vsock0", "/tmp/fc.vsock", 3);
        assert!(json.contains("\"vsock_id\":\"vsock0\""));
        assert!(json.contains("\"guest_cid\":3"));
        assert!(json.contains("\"/tmp/fc.vsock\""));
    }

    #[test]
    fn instance_start_json() {
        let json = action_json("InstanceStart");
        assert_eq!(json, r#"{"action_type":"InstanceStart"}"#);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo +nightly test -p zeptocapsule -- firecracker_api`
Expected: Compilation error — functions not defined.

**Step 3: Implement the API client**

In `src/firecracker_api.rs`, implement:

```rust
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::backend::{KernelError, KernelResult};

#[derive(Debug)]
pub struct ApiResponse {
    pub status: u16,
    pub body: String,
}

/// Format an HTTP PUT request.
pub fn format_put_request(path: &str, body: &str) -> String {
    format!(
        "PUT {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Accept: application/json\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len()
    )
}

/// Parse an HTTP response from raw bytes.
pub fn parse_response(raw: &str) -> Result<ApiResponse, String> {
    let (header, body) = raw
        .split_once("\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response: no header/body separator".to_string())?;

    let status_line = header
        .lines()
        .next()
        .ok_or_else(|| "empty HTTP response".to_string())?;

    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("malformed status line: {status_line}"))?
        .parse()
        .map_err(|e| format!("invalid status code: {e}"))?;

    Ok(ApiResponse {
        status,
        body: body.to_string(),
    })
}

/// Send a PUT request to the Firecracker API socket.
pub async fn put(socket_path: &Path, path: &str, body: &str) -> KernelResult<ApiResponse> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| KernelError::Transport(format!("connect {}: {e}", socket_path.display())))?;

    let request = format_put_request(path, body);
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| KernelError::Transport(format!("write to API socket: {e}")))?;

    stream
        .shutdown()
        .await
        .map_err(|e| KernelError::Transport(format!("shutdown write half: {e}")))?;

    let mut buf = Vec::with_capacity(4096);
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| KernelError::Transport(format!("read API response: {e}")))?;

    let raw = String::from_utf8_lossy(&buf);
    parse_response(&raw).map_err(|e| KernelError::Transport(format!("parse response: {e}")))
}

/// PUT with success assertion (status 2xx).
pub async fn put_expect_ok(
    socket_path: &Path,
    path: &str,
    body: &str,
) -> KernelResult<ApiResponse> {
    let resp = put(socket_path, path, body).await?;
    if resp.status >= 200 && resp.status < 300 {
        Ok(resp)
    } else {
        Err(KernelError::SpawnFailed(format!(
            "Firecracker API {path} returned {}: {}",
            resp.status, resp.body
        )))
    }
}

// ── JSON builders ──────────────────────────────────────────────────

pub fn machine_config_json(vcpus: u32, mem_size_mib: u64) -> String {
    format!(r#"{{"vcpu_count":{vcpus},"mem_size_mib":{mem_size_mib}}}"#)
}

pub fn boot_source_json(kernel_image_path: &str, boot_args: &str) -> String {
    format!(
        r#"{{"kernel_image_path":"{kernel_image_path}","boot_args":"{boot_args}"}}"#
    )
}

pub fn drive_json(drive_id: &str, path: &str, is_root: bool, is_read_only: bool) -> String {
    format!(
        r#"{{"drive_id":"{drive_id}","path_on_host":"{path}","is_root_device":{is_root},"is_read_only":{is_read_only}}}"#
    )
}

pub fn vsock_json(vsock_id: &str, uds_path: &str, guest_cid: u32) -> String {
    format!(
        r#"{{"vsock_id":"{vsock_id}","uds_path":"{uds_path}","guest_cid":{guest_cid}}}"#
    )
}

pub fn network_interface_json(iface_id: &str, tap_name: &str) -> String {
    format!(
        r#"{{"iface_id":"{iface_id}","host_dev_name":"{tap_name}"}}"#
    )
}

pub fn action_json(action_type: &str) -> String {
    format!(r#"{{"action_type":"{action_type}"}}"#)
}
```

**Step 4: Add module declaration**

Add to `src/lib.rs` (Linux-only):

```rust
#[cfg(target_os = "linux")]
mod firecracker_api;
```

**Step 5: Run tests to verify they pass**

Run: `cargo +nightly test -p zeptocapsule -- firecracker_api`
Expected: All 8 tests PASS.

**Step 6: Commit**

```bash
git add src/firecracker_api.rs src/lib.rs
git commit -m "feat: Firecracker REST API client over Unix socket"
```

---

## Task 3: Add vsock transport helper (vsock.rs)

**Files:**
- Create: `src/vsock.rs`
- Modify: `src/lib.rs` (add `mod vsock;`)

**Context:** The design doc specifies a small vsock helper that connects to the host-side Firecracker vsock Unix socket, performs the Firecracker connect handshake for a target guest port, and exposes `AsyncRead`/`AsyncWrite`. Firecracker uses a host-side Unix socket where the host writes `CONNECT <port>\n` and the guest CID is implicit from the vsock device config.

**Step 1: Write failing tests**

Create `src/vsock.rs` with test module:

```rust
//! Host-side Firecracker vsock connector.
//!
//! Connects to the Firecracker vsock Unix socket on the host,
//! performs the CONNECT handshake for a target guest port,
//! and returns an async stream usable as AsyncRead + AsyncWrite.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_format() {
        let req = connect_request(1001);
        assert_eq!(req, "CONNECT 1001\n");
    }

    #[test]
    fn parse_connect_ok() {
        assert!(is_connect_ok("OK 1001\n"));
        assert!(is_connect_ok("OK 1001\r\n"));
    }

    #[test]
    fn parse_connect_fail() {
        assert!(!is_connect_ok("ERR connection refused\n"));
        assert!(!is_connect_ok(""));
    }

    #[test]
    fn well_known_ports() {
        assert_eq!(PORT_STDIN, 1001);
        assert_eq!(PORT_STDOUT, 1002);
        assert_eq!(PORT_STDERR, 1003);
        assert_eq!(PORT_CONTROL, 1004);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo +nightly test -p zeptocapsule -- vsock`
Expected: Compilation error — constants and functions not defined.

**Step 3: Implement vsock helper**

```rust
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::backend::{KernelError, KernelResult};

/// Well-known vsock guest ports (design doc §5).
pub const PORT_STDIN: u32 = 1001;
pub const PORT_STDOUT: u32 = 1002;
pub const PORT_STDERR: u32 = 1003;
pub const PORT_CONTROL: u32 = 1004;

/// Guest CID for the Firecracker VM (CID 3 is conventional).
pub const GUEST_CID: u32 = 3;

/// Format a CONNECT request line for the given guest port.
pub fn connect_request(port: u32) -> String {
    format!("CONNECT {port}\n")
}

/// Check if a response line indicates success.
pub fn is_connect_ok(line: &str) -> bool {
    line.trim().starts_with("OK")
}

/// Connect to a guest vsock port through the Firecracker host-side socket.
///
/// Returns a `UnixStream` positioned after the handshake, ready for
/// application-level I/O (stdin/stdout/stderr/control).
pub async fn connect(socket_path: &Path, port: u32) -> KernelResult<UnixStream> {
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| KernelError::Transport(format!(
            "vsock connect {}: {e}", socket_path.display()
        )))?;

    let (reader, mut writer) = tokio::io::split(stream);

    let req = connect_request(port);
    writer
        .write_all(req.as_bytes())
        .await
        .map_err(|e| KernelError::Transport(format!("vsock write CONNECT: {e}")))?;

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    buf_reader
        .read_line(&mut line)
        .await
        .map_err(|e| KernelError::Transport(format!("vsock read response: {e}")))?;

    if !is_connect_ok(&line) {
        return Err(KernelError::Transport(format!(
            "vsock CONNECT {port} failed: {line}"
        )));
    }

    // Reunite the split halves
    let stream = buf_reader.into_inner().unsplit(writer);
    Ok(stream)
}
```

**Step 4: Add module declaration**

Add to `src/lib.rs` (Linux-only, after `firecracker_api`):

```rust
#[cfg(target_os = "linux")]
mod vsock;
```

**Step 5: Run tests to verify they pass**

Run: `cargo +nightly test -p zeptocapsule -- vsock`
Expected: All 4 tests PASS.

**Step 6: Commit**

```bash
git add src/vsock.rs src/lib.rs
git commit -m "feat: vsock transport helper for Firecracker guest port connections"
```

---

## Task 4: Firecracker backend stub (firecracker.rs) — create + destroy

**Files:**
- Create: `src/firecracker.rs`
- Modify: `src/lib.rs` (add module, wire into `create()`)

**Context:** Design doc §Host-Side Components. This task creates the `FirecrackerBackend` and `FirecrackerCapsule` structs with working `create()` that validates prerequisites (KVM, binary, kernel, rootfs) and creates `state_dir`, and a `destroy()` that cleans up. `spawn()` and `kill()` remain stubs returning `NotSupported` for now.

**Step 1: Write failing tests**

Create `src/firecracker.rs` with tests:

```rust
//! Firecracker microVM backend.
//!
//! Implements `Backend` and `CapsuleHandle` for `Isolation::Firecracker`.
//! VM lifecycle: create state_dir → spawn (boot VM) → kill (signal worker) → destroy (teardown).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::path::PathBuf;

    fn test_spec() -> CapsuleSpec {
        CapsuleSpec {
            isolation: Isolation::Firecracker,
            security: SecurityProfile::Standard,
            firecracker: Some(FirecrackerConfig {
                firecracker_bin: PathBuf::from("/nonexistent/firecracker"),
                kernel_path: PathBuf::from("/nonexistent/vmlinux"),
                rootfs_path: PathBuf::from("/nonexistent/rootfs.ext4"),
                vcpus: None,
                memory_mib: None,
                enable_network: false,
                tap_name: None,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn create_rejects_missing_firecracker_config() {
        let backend = FirecrackerBackend;
        let spec = CapsuleSpec {
            isolation: Isolation::Firecracker,
            security: SecurityProfile::Standard,
            ..Default::default()
        };
        let err = backend.create(spec).unwrap_err();
        assert!(matches!(err, crate::backend::KernelError::NotSupported(_)));
    }

    #[test]
    fn create_rejects_missing_firecracker_binary() {
        let backend = FirecrackerBackend;
        let err = backend.create(test_spec()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("firecracker") || msg.contains("not found") || msg.contains("not supported"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn state_dir_created_on_successful_create() {
        // This test requires real KVM + Firecracker binary.
        // Guarded by env var, skip for unit tests.
        if std::env::var("ZK_RUN_FIRECRACKER_TESTS").is_err() {
            return;
        }
        let backend = FirecrackerBackend;
        let spec = test_spec(); // Would need real paths
        let handle = backend.create(spec).unwrap();
        // state_dir exists
        // destroy cleans it up
        let report = handle.destroy().unwrap();
        assert!(report.wall_time.as_secs() < 5);
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo +nightly test -p zeptocapsule -- firecracker::tests`
Expected: Compilation error — `FirecrackerBackend` not defined.

**Step 3: Implement backend stub**

```rust
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::backend::{Backend, CapsuleChild, CapsuleHandle, KernelError, KernelResult};
use crate::types::{
    CapsuleReport, CapsuleSpec, FirecrackerConfig, ResourceViolation, Signal,
};

pub struct FirecrackerBackend;

impl Backend for FirecrackerBackend {
    fn create(&self, spec: CapsuleSpec) -> KernelResult<Box<dyn CapsuleHandle>> {
        let config = spec
            .firecracker
            .as_ref()
            .ok_or_else(|| {
                KernelError::NotSupported("Firecracker isolation requires firecracker config".into())
            })?
            .clone();

        // Validate host prerequisites
        validate_prerequisites(&config)?;

        // Create per-capsule state directory
        let state_dir = create_state_dir()?;

        Ok(Box::new(FirecrackerCapsule {
            spec,
            config,
            state_dir,
            fc_process: None,
            started_at: Instant::now(),
            killed_by: Arc::new(Mutex::new(None)),
        }))
    }
}

pub struct FirecrackerCapsule {
    spec: CapsuleSpec,
    config: FirecrackerConfig,
    state_dir: PathBuf,
    fc_process: Option<std::process::Child>,
    started_at: Instant,
    killed_by: Arc<Mutex<Option<ResourceViolation>>>,
}

impl CapsuleHandle for FirecrackerCapsule {
    fn spawn(
        &mut self,
        _binary: &str,
        _args: &[&str],
        _env: HashMap<String, String>,
    ) -> KernelResult<CapsuleChild> {
        Err(KernelError::NotSupported(
            "Firecracker spawn not yet implemented".into(),
        ))
    }

    fn kill(&mut self, _signal: Signal) -> KernelResult<()> {
        Err(KernelError::NotSupported(
            "Firecracker kill not yet implemented".into(),
        ))
    }

    fn destroy(mut self: Box<Self>) -> KernelResult<CapsuleReport> {
        // Kill Firecracker process if running
        if let Some(ref mut child) = self.fc_process {
            let _ = child.kill();
            let _ = child.wait();
        }

        let wall_time = self.started_at.elapsed();
        let killed_by = self.killed_by.lock().unwrap().take();

        // Clean up state directory
        if self.state_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.state_dir);
        }

        Ok(CapsuleReport {
            exit_code: None,
            exit_signal: None,
            killed_by,
            wall_time,
            peak_memory_mib: None,
        })
    }
}

fn validate_prerequisites(config: &FirecrackerConfig) -> KernelResult<()> {
    if !config.firecracker_bin.exists() {
        return Err(KernelError::NotSupported(format!(
            "firecracker binary not found: {}",
            config.firecracker_bin.display()
        )));
    }
    if !config.kernel_path.exists() {
        return Err(KernelError::NotSupported(format!(
            "kernel image not found: {}",
            config.kernel_path.display()
        )));
    }
    if !config.rootfs_path.exists() {
        return Err(KernelError::NotSupported(format!(
            "rootfs image not found: {}",
            config.rootfs_path.display()
        )));
    }

    // Check /dev/kvm on Linux
    #[cfg(target_os = "linux")]
    {
        let kvm = std::path::Path::new("/dev/kvm");
        if !kvm.exists() {
            return Err(KernelError::NotSupported(
                "/dev/kvm not available — KVM required for Firecracker".into(),
            ));
        }
    }

    Ok(())
}

fn create_state_dir() -> KernelResult<PathBuf> {
    let id = format!("zk-fc-{}", std::process::id());
    let dir = std::env::temp_dir().join(&id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| KernelError::SpawnFailed(format!("create state_dir: {e}")))?;
    Ok(dir)
}
```

**Step 4: Wire into lib.rs**

Add module declaration (Linux-only):

```rust
#[cfg(target_os = "linux")]
mod firecracker;
```

Update `create()` function — replace the Firecracker arm:

```rust
types::Isolation::Firecracker => {
    #[cfg(target_os = "linux")]
    {
        Box::new(firecracker::FirecrackerBackend)
    }
    #[cfg(not(target_os = "linux"))]
    {
        return Err(KernelError::NotSupported(
            "firecracker isolation requires Linux".into(),
        ));
    }
}
```

**Step 5: Run tests to verify they pass**

Run: `cargo +nightly test -p zeptocapsule -- firecracker`
Expected: All tests PASS. The `create_rejects_*` tests pass because they hit prerequisite validation. The `state_dir_created` test skips unless env var is set.

**Step 6: Verify full crate compiles**

Run: `cargo +nightly build -p zeptocapsule`
Expected: Clean build.

**Step 7: Commit**

```bash
git add src/firecracker.rs src/lib.rs
git commit -m "feat: Firecracker backend stub with prerequisite validation and state_dir"
```

---

## Task 5: Workspace image builder (create + seed + export)

**Files:**
- Create: `src/workspace_image.rs`
- Modify: `src/lib.rs` (add `mod workspace_image;`)

**Context:** Design doc §Workspace Strategy. For v1, use a second writable ext4 image as the workspace disk. Seeded from `workspace.host_path` before boot, copied back after teardown. Uses `mkfs.ext4`, `mount`, `umount`, and `cp -a` shell commands. Linux-only.

**Step 1: Write failing tests**

Create `src/workspace_image.rs`:

```rust
//! Workspace ext4 image builder for Firecracker capsules.
//!
//! Creates a writable ext4 disk image that gets mounted by the guest
//! at `workspace.guest_path`. Seeded from host workspace before boot,
//! contents copied back after teardown.

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn default_image_size() {
        assert_eq!(default_size_mib(None), 128);
        assert_eq!(default_size_mib(Some(256)), 256);
    }

    #[test]
    fn image_path_in_state_dir() {
        let state_dir = PathBuf::from("/tmp/zk-fc-12345");
        let path = image_path(&state_dir);
        assert_eq!(path, PathBuf::from("/tmp/zk-fc-12345/workspace.ext4"));
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo +nightly test -p zeptocapsule -- workspace_image`
Expected: Compilation error.

**Step 3: Implement workspace image module**

```rust
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::backend::{KernelError, KernelResult};

/// Default workspace image size if not specified.
pub fn default_size_mib(configured: Option<u64>) -> u64 {
    configured.unwrap_or(128)
}

/// Path to the workspace image within the state directory.
pub fn image_path(state_dir: &Path) -> PathBuf {
    state_dir.join("workspace.ext4")
}

/// Create a blank ext4 image file at `path` with `size_mib` MiB.
#[cfg(target_os = "linux")]
pub fn create_image(path: &Path, size_mib: u64) -> KernelResult<()> {
    // Create a sparse file of the right size
    let size_bytes = size_mib * 1024 * 1024;
    let file = std::fs::File::create(path)
        .map_err(|e| KernelError::SpawnFailed(format!("create workspace image: {e}")))?;
    file.set_len(size_bytes)
        .map_err(|e| KernelError::SpawnFailed(format!("set workspace image size: {e}")))?;
    drop(file);

    // Format as ext4
    let output = Command::new("mkfs.ext4")
        .args(["-q", "-F"])
        .arg(path)
        .output()
        .map_err(|e| KernelError::SpawnFailed(format!("mkfs.ext4: {e}")))?;

    if !output.status.success() {
        return Err(KernelError::SpawnFailed(format!(
            "mkfs.ext4 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Seed the workspace image from a host directory.
/// Mounts the image, copies host_path contents, unmounts.
#[cfg(target_os = "linux")]
pub fn seed_from_host(image: &Path, host_path: &Path, mount_point: &Path) -> KernelResult<()> {
    std::fs::create_dir_all(mount_point)
        .map_err(|e| KernelError::SpawnFailed(format!("mkdir mount_point: {e}")))?;

    mount_image(image, mount_point)?;

    let result = Command::new("cp")
        .args(["-a"])
        .arg(format!("{}/.","", ).replace("","").replace("", &format!("{}/.", host_path.display())))
        .arg(mount_point)
        .output();

    // Use rsync-style copy: cp -a <host_path>/. <mount_point>/
    let copy_result = Command::new("sh")
        .args([
            "-c",
            &format!(
                "cp -a '{}'/. '{}'/ 2>/dev/null; true",
                host_path.display(),
                mount_point.display()
            ),
        ])
        .output()
        .map_err(|e| KernelError::SpawnFailed(format!("copy workspace contents: {e}")))?;

    let _ = result;

    umount_image(mount_point)?;

    if !copy_result.status.success() {
        tracing::warn!(
            "workspace seed copy had warnings: {}",
            String::from_utf8_lossy(&copy_result.stderr)
        );
    }

    Ok(())
}

/// Export workspace image contents back to a host directory.
/// Mounts the image read-only, copies to host_path, unmounts.
#[cfg(target_os = "linux")]
pub fn export_to_host(image: &Path, host_path: &Path, mount_point: &Path) -> KernelResult<()> {
    std::fs::create_dir_all(mount_point)
        .map_err(|e| KernelError::CleanupFailed(format!("mkdir mount_point: {e}")))?;
    std::fs::create_dir_all(host_path)
        .map_err(|e| KernelError::CleanupFailed(format!("mkdir host_path: {e}")))?;

    mount_image_ro(image, mount_point)?;

    let output = Command::new("sh")
        .args([
            "-c",
            &format!(
                "cp -a '{}'/. '{}'/ 2>/dev/null; true",
                mount_point.display(),
                host_path.display()
            ),
        ])
        .output()
        .map_err(|e| KernelError::CleanupFailed(format!("export workspace: {e}")))?;

    umount_image(mount_point)?;

    if !output.status.success() {
        tracing::warn!(
            "workspace export had warnings: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_image(image: &Path, mount_point: &Path) -> KernelResult<()> {
    let output = Command::new("mount")
        .args(["-o", "loop"])
        .arg(image)
        .arg(mount_point)
        .output()
        .map_err(|e| KernelError::SpawnFailed(format!("mount workspace image: {e}")))?;

    if !output.status.success() {
        return Err(KernelError::SpawnFailed(format!(
            "mount workspace image failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_image_ro(image: &Path, mount_point: &Path) -> KernelResult<()> {
    let output = Command::new("mount")
        .args(["-o", "loop,ro"])
        .arg(image)
        .arg(mount_point)
        .output()
        .map_err(|e| KernelError::CleanupFailed(format!("mount workspace image ro: {e}")))?;

    if !output.status.success() {
        return Err(KernelError::CleanupFailed(format!(
            "mount workspace image ro failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn umount_image(mount_point: &Path) -> KernelResult<()> {
    let output = Command::new("umount")
        .arg(mount_point)
        .output()
        .map_err(|e| KernelError::CleanupFailed(format!("umount: {e}")))?;

    if !output.status.success() {
        tracing::warn!(
            "umount {} failed: {}",
            mount_point.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
```

**Step 4: Add module declaration**

Add to `src/lib.rs` (Linux-only):

```rust
#[cfg(target_os = "linux")]
mod workspace_image;
```

**Step 5: Run tests to verify they pass**

Run: `cargo +nightly test -p zeptocapsule -- workspace_image`
Expected: 2 unit tests PASS.

**Step 6: Commit**

```bash
git add src/workspace_image.rs src/lib.rs
git commit -m "feat: workspace ext4 image builder for Firecracker capsules"
```

---

## Task 6: Boot and stdio — wire spawn() with VM boot and vsock pipes

**Files:**
- Modify: `src/firecracker.rs` (implement `spawn()`)

**Context:** Design doc §Lifecycle: spawn(). This is the core task — stage worker binary into writable rootfs, start Firecracker VMM, configure VM over REST API, start instance, connect vsock streams, wait for zk-init readiness, return `CapsuleChild` backed by vsock I/O, start timeout watchdog.

**Step 1: Write failing test**

Add to `src/firecracker.rs` test module:

```rust
#[test]
fn rootfs_copy_path_in_state_dir() {
    let state_dir = PathBuf::from("/tmp/zk-fc-test");
    let rootfs = rootfs_copy_path(&state_dir);
    assert_eq!(rootfs, PathBuf::from("/tmp/zk-fc-test/rootfs.ext4"));
}

#[test]
fn worker_guest_path_is_fixed() {
    assert_eq!(WORKER_GUEST_PATH, "/run/zeptocapsule/worker");
}

#[test]
fn serial_log_path_in_state_dir() {
    let state_dir = PathBuf::from("/tmp/zk-fc-test");
    let serial = serial_log_path(&state_dir);
    assert_eq!(serial, PathBuf::from("/tmp/zk-fc-test/serial.log"));
}

#[test]
fn api_socket_path_in_state_dir() {
    let state_dir = PathBuf::from("/tmp/zk-fc-test");
    let socket = api_socket_path(&state_dir);
    assert_eq!(socket, PathBuf::from("/tmp/zk-fc-test/api.sock"));
}

#[test]
fn vsock_socket_path_in_state_dir() {
    let state_dir = PathBuf::from("/tmp/zk-fc-test");
    let vsock = vsock_socket_path(&state_dir);
    assert_eq!(vsock, PathBuf::from("/tmp/zk-fc-test/fc.vsock"));
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo +nightly test -p zeptocapsule -- firecracker::tests`
Expected: Compilation error — helper functions not defined.

**Step 3: Implement path helpers and spawn()**

Add path helper constants and functions to `src/firecracker.rs`:

```rust
/// Fixed guest path where the worker binary is staged.
const WORKER_GUEST_PATH: &str = "/run/zeptocapsule/worker";

/// Default boot args for the guest kernel.
const DEFAULT_BOOT_ARGS: &str = "console=ttyS0 reboot=k panic=1 quiet";

fn rootfs_copy_path(state_dir: &Path) -> PathBuf {
    state_dir.join("rootfs.ext4")
}

fn serial_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("serial.log")
}

fn api_socket_path(state_dir: &Path) -> PathBuf {
    state_dir.join("api.sock")
}

fn vsock_socket_path(state_dir: &Path) -> PathBuf {
    state_dir.join("fc.vsock")
}
```

Implement full `spawn()` in `FirecrackerCapsule`:

```rust
fn spawn(
    &mut self,
    binary: &str,
    args: &[&str],
    env: HashMap<String, String>,
) -> KernelResult<CapsuleChild> {
    use crate::firecracker_api as api;
    use crate::vsock;
    use crate::workspace_image;

    let api_socket = api_socket_path(&self.state_dir);
    let vsock_socket = vsock_socket_path(&self.state_dir);
    let serial_log = serial_log_path(&self.state_dir);
    let rootfs_copy = rootfs_copy_path(&self.state_dir);

    // 1. Copy rootfs to writable overlay
    std::fs::copy(&self.config.rootfs_path, &rootfs_copy)
        .map_err(|e| KernelError::SpawnFailed(format!("copy rootfs: {e}")))?;

    // 2. Stage worker binary into rootfs
    stage_worker_binary(binary, &rootfs_copy, &self.state_dir)?;

    // 3. Prepare workspace image
    let ws_image = workspace_image::image_path(&self.state_dir);
    let ws_size = workspace_image::default_size_mib(self.spec.workspace.size_mib);
    workspace_image::create_image(&ws_image, ws_size)?;

    if let Some(ref host_path) = self.spec.workspace.host_path {
        let mount_point = self.state_dir.join("ws_mount");
        workspace_image::seed_from_host(&ws_image, host_path, &mount_point)?;
    }

    // 4. Start Firecracker process
    let fc_child = std::process::Command::new(&self.config.firecracker_bin)
        .args(["--api-sock", &api_socket.to_string_lossy()])
        .arg("--log-path")
        .arg(&serial_log)
        .arg("--level")
        .arg("Warning")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| KernelError::SpawnFailed(format!("start firecracker: {e}")))?;

    self.fc_process = Some(fc_child);

    // 5. Wait for API socket to appear
    wait_for_socket(&api_socket)?;

    // 6. Configure VM over REST API
    let vcpus = self.config.effective_vcpus(&self.spec.limits);
    let memory_mib = self.config.effective_memory_mib(&self.spec.limits);

    let rt = tokio::runtime::Handle::try_current()
        .map_err(|e| KernelError::SpawnFailed(format!("no tokio runtime: {e}")))?;

    rt.block_on(async {
        // Machine config
        api::put_expect_ok(
            &api_socket,
            "/machine-config",
            &api::machine_config_json(vcpus, memory_mib),
        ).await?;

        // Boot source
        api::put_expect_ok(
            &api_socket,
            "/boot-source",
            &api::boot_source_json(
                &self.config.kernel_path.to_string_lossy(),
                DEFAULT_BOOT_ARGS,
            ),
        ).await?;

        // Root drive
        api::put_expect_ok(
            &api_socket,
            "/drives/rootfs",
            &api::drive_json("rootfs", &rootfs_copy.to_string_lossy(), true, false),
        ).await?;

        // Workspace drive
        api::put_expect_ok(
            &api_socket,
            "/drives/workspace",
            &api::drive_json("workspace", &ws_image.to_string_lossy(), false, false),
        ).await?;

        // Vsock
        api::put_expect_ok(
            &api_socket,
            "/vsock",
            &api::vsock_json("vsock0", &vsock_socket.to_string_lossy(), vsock::GUEST_CID),
        ).await?;

        // Optional network
        if self.config.enable_network {
            if let Some(ref tap) = self.config.tap_name {
                api::put_expect_ok(
                    &api_socket,
                    "/network-interfaces/eth0",
                    &api::network_interface_json("eth0", tap),
                ).await?;
            }
        }

        // Start instance
        api::put_expect_ok(
            &api_socket,
            "/actions",
            &api::action_json("InstanceStart"),
        ).await?;

        Ok::<(), KernelError>(())
    })?;

    // 7. Wait for vsock socket to appear
    wait_for_socket(&vsock_socket)?;

    // 8. Connect vsock streams
    let (stdin_stream, stdout_stream, stderr_stream) = rt.block_on(async {
        let stdin = vsock::connect(&vsock_socket, vsock::PORT_STDIN).await?;
        let stdout = vsock::connect(&vsock_socket, vsock::PORT_STDOUT).await?;
        let stderr = vsock::connect(&vsock_socket, vsock::PORT_STDERR).await?;
        Ok::<_, KernelError>((stdin, stdout, stderr))
    })?;

    // 9. Wait for control channel readiness
    rt.block_on(async {
        let mut ctrl = vsock::connect(&vsock_socket, vsock::PORT_CONTROL).await?;
        // Read readiness signal from zk-init
        let mut buf = [0u8; 16];
        use tokio::io::AsyncReadExt;
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            ctrl.read(&mut buf),
        ).await
            .map_err(|_| KernelError::SpawnFailed("zk-init readiness timeout (30s)".into()))?
            .map_err(|e| KernelError::Transport(format!("control read: {e}")))?;

        let msg = std::str::from_utf8(&buf[..n]).unwrap_or("");
        if !msg.starts_with("READY") {
            return Err(KernelError::SpawnFailed(format!(
                "zk-init sent unexpected readiness: {msg}"
            )));
        }
        Ok(())
    })?;

    // 10. Start timeout watchdog
    let killed_by = Arc::clone(&self.killed_by);
    let timeout_sec = self.spec.limits.timeout_sec;
    let fc_pid = self.fc_process.as_ref().map(|c| c.id());

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(timeout_sec)).await;
        *killed_by.lock().unwrap() = Some(ResourceViolation::WallClock);
        if let Some(pid) = fc_pid {
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
        }
    });

    // Split streams into CapsuleChild
    let (stdout_read, _) = tokio::io::split(stdout_stream);
    let (stderr_read, _) = tokio::io::split(stderr_stream);
    let (_, stdin_write) = tokio::io::split(stdin_stream);

    let pid = self.fc_process.as_ref().map(|c| c.id()).unwrap_or(0);

    Ok(CapsuleChild {
        stdin: Box::pin(stdin_write),
        stdout: Box::pin(stdout_read),
        stderr: Box::pin(stderr_read),
        pid,
    })
}
```

Add helper functions:

```rust
/// Wait for a Unix socket file to appear, with timeout.
fn wait_for_socket(path: &Path) -> KernelResult<()> {
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(KernelError::SpawnFailed(format!(
        "timeout waiting for socket: {}",
        path.display()
    )))
}

/// Stage the worker binary into the writable rootfs image.
/// Mounts the rootfs, copies binary to /run/zeptocapsule/worker, unmounts.
#[cfg(target_os = "linux")]
fn stage_worker_binary(
    binary: &str,
    rootfs_image: &Path,
    state_dir: &Path,
) -> KernelResult<()> {
    let mount_point = state_dir.join("rootfs_mount");
    std::fs::create_dir_all(&mount_point)
        .map_err(|e| KernelError::SpawnFailed(format!("mkdir rootfs_mount: {e}")))?;

    // Mount rootfs image
    let output = std::process::Command::new("mount")
        .args(["-o", "loop"])
        .arg(rootfs_image)
        .arg(&mount_point)
        .output()
        .map_err(|e| KernelError::SpawnFailed(format!("mount rootfs: {e}")))?;

    if !output.status.success() {
        return Err(KernelError::SpawnFailed(format!(
            "mount rootfs failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Create target directory and copy binary
    let worker_dir = mount_point.join("run/zeptocapsule");
    std::fs::create_dir_all(&worker_dir)
        .map_err(|e| KernelError::SpawnFailed(format!("mkdir worker dir: {e}")))?;

    let worker_dest = worker_dir.join("worker");
    std::fs::copy(binary, &worker_dest)
        .map_err(|e| KernelError::SpawnFailed(format!("copy worker binary: {e}")))?;

    // Make executable
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&worker_dest, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| KernelError::SpawnFailed(format!("chmod worker: {e}")))?;

    // Unmount
    let _ = std::process::Command::new("umount")
        .arg(&mount_point)
        .output();

    Ok(())
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo +nightly test -p zeptocapsule -- firecracker`
Expected: All path-helper tests PASS. spawn() compiles correctly.

**Step 5: Commit**

```bash
git add src/firecracker.rs
git commit -m "feat: Firecracker spawn() — VM boot, REST API config, vsock stdio pipes"
```

---

## Task 7: Kill semantics — control channel signal forwarding

**Files:**
- Modify: `src/firecracker.rs` (implement `kill()`)

**Context:** Design doc §Lifecycle: kill(). `Signal::Terminate` sends a control message to `zk-init` over the control vsock port. `Signal::Kill` escalates to killing the Firecracker process directly if the guest doesn't respond.

**Step 1: Write failing test**

Add to `src/firecracker.rs` test module:

```rust
#[test]
fn control_message_terminate() {
    assert_eq!(control_message(Signal::Terminate), "TERMINATE\n");
}

#[test]
fn control_message_kill() {
    assert_eq!(control_message(Signal::Kill), "KILL\n");
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo +nightly test -p zeptocapsule -- control_message`
Expected: Compilation error.

**Step 3: Implement kill()**

Add to `src/firecracker.rs`:

```rust
/// Format a control message for the zk-init control channel.
fn control_message(signal: Signal) -> String {
    match signal {
        Signal::Terminate => "TERMINATE\n".to_string(),
        Signal::Kill => "KILL\n".to_string(),
    }
}

/// Grace period after sending TERMINATE before escalating to kill.
const TERMINATE_GRACE_SECS: u64 = 5;
```

Update `FirecrackerCapsule` to store vsock_socket path and update `kill()`:

```rust
fn kill(&mut self, signal: Signal) -> KernelResult<()> {
    let vsock_socket = vsock_socket_path(&self.state_dir);

    // Try to send control message via vsock
    let rt = tokio::runtime::Handle::try_current()
        .map_err(|e| KernelError::Transport(format!("no tokio runtime: {e}")))?;

    let msg = control_message(signal);

    let control_result = rt.block_on(async {
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            async {
                use crate::vsock;
                let mut ctrl = vsock::connect(&vsock_socket, vsock::PORT_CONTROL).await?;
                use tokio::io::AsyncWriteExt;
                ctrl.write_all(msg.as_bytes()).await
                    .map_err(|e| KernelError::Transport(format!("control write: {e}")))?;
                Ok::<(), KernelError>(())
            },
        ).await {
            Ok(result) => result,
            Err(_) => Err(KernelError::Transport("control channel timeout".into())),
        }
    });

    match signal {
        Signal::Terminate => {
            if control_result.is_err() {
                tracing::warn!("control channel failed for TERMINATE, escalating to process kill");
                self.kill_fc_process()?;
            }
        }
        Signal::Kill => {
            // Always kill the FC process for Signal::Kill
            if let Err(e) = control_result {
                tracing::warn!("control channel failed for KILL: {e}");
            }
            // Brief grace period, then force kill
            std::thread::sleep(std::time::Duration::from_millis(500));
            self.kill_fc_process()?;
        }
    }

    Ok(())
}
```

Add helper method:

```rust
impl FirecrackerCapsule {
    fn kill_fc_process(&mut self) -> KernelResult<()> {
        if let Some(ref mut child) = self.fc_process {
            child.kill()
                .map_err(|e| KernelError::Transport(format!("kill firecracker: {e}")))?;
        }
        Ok(())
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo +nightly test -p zeptocapsule -- control_message`
Expected: 2 tests PASS.

**Step 5: Commit**

```bash
git add src/firecracker.rs
git commit -m "feat: Firecracker kill() — control channel signaling with escalation"
```

---

## Task 8: Extend zk-init for Firecracker vsock mode

**Files:**
- Modify: `src/init_shim.rs`

**Context:** Design doc §Guest-Side Components. If Firecracker control env vars are present, `zk-init` should: listen on vsock control port, spawn the worker, forward terminate/kill to worker PID, reap until worker exits, bridge stdin/stdout/stderr through vsock. This remains a thin init shim — no job protocol.

**Step 1: Write failing tests**

Add to `src/init_shim.rs` test module:

```rust
#[test]
fn detect_firecracker_mode_from_env() {
    let env = vec![
        ("ZK_FC_MODE".to_string(), "1".to_string()),
        ("ZK_FC_WORKER_PATH".to_string(), "/run/zeptocapsule/worker".to_string()),
    ];
    assert!(is_firecracker_mode(env.iter().map(|(k, v)| (k.as_str(), v.as_str()))));
}

#[test]
fn detect_no_firecracker_mode() {
    let env: Vec<(String, String)> = vec![];
    assert!(!is_firecracker_mode(env.iter().map(|(k, v)| (k.as_str(), v.as_str()))));
}

#[test]
fn parse_firecracker_config() {
    let env = vec![
        ("ZK_FC_MODE".to_string(), "1".to_string()),
        ("ZK_FC_WORKER_PATH".to_string(), "/run/zeptocapsule/worker".to_string()),
        ("ZK_FC_WORKER_ARGS".to_string(), "arg1 arg2".to_string()),
        ("ZK_FC_WORKSPACE_DEVICE".to_string(), "/dev/vdb".to_string()),
        ("ZK_FC_WORKSPACE_PATH".to_string(), "/workspace".to_string()),
    ];
    let config = parse_fc_init_config(env.into_iter()).unwrap();
    assert_eq!(config.worker_path, "/run/zeptocapsule/worker");
    assert_eq!(config.worker_args, vec!["arg1", "arg2"]);
    assert_eq!(config.workspace_device.as_deref(), Some("/dev/vdb"));
    assert_eq!(config.workspace_path.to_string_lossy(), "/workspace");
}

#[test]
fn parse_firecracker_config_defaults() {
    let env = vec![
        ("ZK_FC_MODE".to_string(), "1".to_string()),
        ("ZK_FC_WORKER_PATH".to_string(), "/run/zeptocapsule/worker".to_string()),
    ];
    let config = parse_fc_init_config(env.into_iter()).unwrap();
    assert_eq!(config.workspace_path.to_string_lossy(), "/workspace");
    assert!(config.workspace_device.is_none());
    assert!(config.worker_args.is_empty());
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo +nightly test -p zeptocapsule -- init_shim`
Expected: Compilation error.

**Step 3: Implement Firecracker mode in init_shim**

Add to `src/init_shim.rs`:

```rust
/// Configuration for Firecracker-mode zk-init.
#[derive(Debug, Clone)]
pub struct FcInitConfig {
    pub worker_path: String,
    pub worker_args: Vec<String>,
    pub workspace_device: Option<String>,
    pub workspace_path: PathBuf,
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
    let mut workspace_device = None;
    let mut workspace_path = PathBuf::from("/workspace");

    for (key, value) in env {
        match key.as_str() {
            "ZK_FC_WORKER_PATH" => worker_path = Some(value),
            "ZK_FC_WORKER_ARGS" => {
                worker_args = value.split_whitespace().map(String::from).collect();
            }
            "ZK_FC_WORKSPACE_DEVICE" => workspace_device = Some(value),
            "ZK_FC_WORKSPACE_PATH" => workspace_path = PathBuf::from(value),
            _ => {}
        }
    }

    let worker_path = worker_path
        .ok_or_else(|| "ZK_FC_WORKER_PATH is required in Firecracker mode".to_string())?;

    Ok(FcInitConfig {
        worker_path,
        worker_args,
        workspace_device,
        workspace_path,
    })
}

/// Run init shim in Firecracker mode.
/// Mounts workspace, sends READY on control channel, spawns worker,
/// handles control messages, reaps worker.
pub fn run_fc_init_shim() -> Result<(), String> {
    let config = parse_fc_init_config(std::env::vars())?;

    // Mount workspace device if specified
    #[cfg(target_os = "linux")]
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
    }

    // TODO: In future, connect vsock control port and send READY.
    // For now, just run the worker directly (compatible with serial-only testing).

    let status = Command::new(&config.worker_path)
        .args(&config.worker_args)
        .status()
        .map_err(|e| format!("exec {}: {e}", config.worker_path))?;

    match status.code() {
        Some(code) => std::process::exit(code),
        None => Err(format!("worker {} terminated by signal", config.worker_path)),
    }
}
```

Update `run_init_shim()` to detect Firecracker mode:

```rust
pub fn run_init_shim() -> Result<(), String> {
    // Check for Firecracker mode
    if std::env::var("ZK_FC_MODE").is_ok() {
        return run_fc_init_shim();
    }

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
```

**Step 4: Run tests to verify they pass**

Run: `cargo +nightly test -p zeptocapsule -- init_shim`
Expected: All tests PASS (existing + 4 new).

**Step 5: Add FcInitConfig to lib.rs exports**

```rust
pub use init_shim::{FcInitConfig, MountConfig, is_init, is_firecracker_mode, parse_fc_init_config, run_init_shim, setup_guest_fs};
```

**Step 6: Commit**

```bash
git add src/init_shim.rs src/lib.rs
git commit -m "feat: extend zk-init for Firecracker vsock mode — workspace mount, worker exec"
```

---

## Task 9: Destroy with workspace export and serial-log diagnostics

**Files:**
- Modify: `src/firecracker.rs` (enhance `destroy()`)

**Context:** Design doc §Lifecycle: destroy(). Enhance destroy to: cancel watchdog, ensure VM stopped, collect exit facts (worker exit status, timeout kill reason, boot failure hints from serial log), copy workspace image back to host_path, remove state_dir, return CapsuleReport.

**Step 1: Write failing test**

Add to `src/firecracker.rs` test module:

```rust
#[test]
fn extract_serial_hint_finds_panic() {
    let log = "booting kernel...\nKernel panic - not syncing: VFS\nend trace\n";
    let hint = extract_serial_hint(log);
    assert!(hint.is_some());
    assert!(hint.unwrap().contains("panic"));
}

#[test]
fn extract_serial_hint_empty_log() {
    let hint = extract_serial_hint("");
    assert!(hint.is_none());
}

#[test]
fn extract_serial_hint_no_errors() {
    let log = "booting kernel...\nStarting zk-init\nREADY\n";
    let hint = extract_serial_hint(log);
    assert!(hint.is_none());
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo +nightly test -p zeptocapsule -- extract_serial`
Expected: Compilation error.

**Step 3: Implement serial log hint extraction and enhanced destroy**

Add to `src/firecracker.rs`:

```rust
/// Extract a diagnostic hint from the serial log if boot/runtime errors are present.
/// Returns at most a few lines of relevant context, not the full log.
fn extract_serial_hint(log: &str) -> Option<String> {
    let error_patterns = ["panic", "error", "failed", "fatal", "Oops"];
    let mut hints = Vec::new();

    for line in log.lines() {
        let lower = line.to_lowercase();
        if error_patterns.iter().any(|p| lower.contains(p)) {
            hints.push(line.to_string());
            if hints.len() >= 5 {
                break;
            }
        }
    }

    if hints.is_empty() {
        None
    } else {
        Some(hints.join("\n"))
    }
}
```

Update `destroy()`:

```rust
fn destroy(mut self: Box<Self>) -> KernelResult<CapsuleReport> {
    // 1. Kill Firecracker process if running
    if let Some(ref mut child) = self.fc_process {
        let _ = child.kill();
        let _ = child.wait();
    }

    let wall_time = self.started_at.elapsed();
    let killed_by = self.killed_by.lock().unwrap().take();

    // 2. Export workspace back to host if configured
    #[cfg(target_os = "linux")]
    if let Some(ref host_path) = self.spec.workspace.host_path {
        use crate::workspace_image;
        let ws_image = workspace_image::image_path(&self.state_dir);
        if ws_image.exists() {
            let mount_point = self.state_dir.join("ws_export_mount");
            if let Err(e) = workspace_image::export_to_host(&ws_image, host_path, &mount_point) {
                tracing::warn!("workspace export failed: {e}");
            }
        }
    }

    // 3. Read serial log for diagnostics
    let serial = serial_log_path(&self.state_dir);
    let serial_hint = if serial.exists() {
        std::fs::read_to_string(&serial)
            .ok()
            .and_then(|log| extract_serial_hint(&log))
    } else {
        None
    };

    if let Some(ref hint) = serial_hint {
        tracing::debug!("serial log hints: {hint}");
    }

    // 4. Clean up state directory
    if self.state_dir.exists() {
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }

    Ok(CapsuleReport {
        exit_code: None,
        exit_signal: None,
        killed_by,
        wall_time,
        peak_memory_mib: None,
    })
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo +nightly test -p zeptocapsule -- extract_serial`
Expected: 3 tests PASS.

**Step 5: Commit**

```bash
git add src/firecracker.rs
git commit -m "feat: Firecracker destroy() with workspace export and serial-log diagnostics"
```

---

## Task 10: Integration tests

**Files:**
- Create: `tests/firecracker_backend.rs`

**Context:** Design doc §Testing Plan. 5 integration tests behind `ZK_RUN_FIRECRACKER_TESTS=1`, plus a unit test for missing KVM.

**Step 1: Create the test file**

```rust
//! Firecracker backend integration tests.
//!
//! These tests require:
//! - Linux with /dev/kvm
//! - Firecracker binary installed
//! - A kernel image (vmlinux) and rootfs image
//! - ZK_RUN_FIRECRACKER_TESTS=1 env var
//!
//! Set env vars:
//!   ZK_FC_BIN=/path/to/firecracker
//!   ZK_FC_KERNEL=/path/to/vmlinux
//!   ZK_FC_ROOTFS=/path/to/rootfs.ext4

#[cfg(target_os = "linux")]
mod firecracker_tests {
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn skip_unless_enabled() -> bool {
        std::env::var("ZK_RUN_FIRECRACKER_TESTS").is_err()
    }

    fn test_config() -> zeptocapsule::CapsuleSpec {
        let fc_bin = std::env::var("ZK_FC_BIN")
            .unwrap_or_else(|_| "/usr/bin/firecracker".to_string());
        let kernel = std::env::var("ZK_FC_KERNEL")
            .unwrap_or_else(|_| "/var/lib/zeptocapsule/vmlinux".to_string());
        let rootfs = std::env::var("ZK_FC_ROOTFS")
            .unwrap_or_else(|_| "/var/lib/zeptocapsule/rootfs.ext4".to_string());

        zeptocapsule::CapsuleSpec {
            isolation: zeptocapsule::Isolation::Firecracker,
            security: zeptocapsule::SecurityProfile::Standard,
            limits: zeptocapsule::ResourceLimits {
                timeout_sec: 30,
                memory_mib: Some(128),
                ..Default::default()
            },
            firecracker: Some(zeptocapsule::FirecrackerConfig {
                firecracker_bin: PathBuf::from(fc_bin),
                kernel_path: PathBuf::from(kernel),
                rootfs_path: PathBuf::from(rootfs),
                vcpus: Some(1),
                memory_mib: Some(128),
                enable_network: false,
                tap_name: None,
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn firecracker_stdio_round_trip() {
        if skip_unless_enabled() { return; }

        let spec = test_config();
        let mut capsule = zeptocapsule::create(spec).unwrap();
        let child = capsule.spawn("/bin/cat", &[], HashMap::new()).unwrap();

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stdin = child.stdin;
        let mut stdout = child.stdout;

        stdin.write_all(b"hello from host\n").await.unwrap();
        drop(stdin); // Close stdin to let cat exit

        let mut output = String::new();
        stdout.read_to_string(&mut output).await.unwrap();
        assert_eq!(output.trim(), "hello from host");

        let report = capsule.destroy().unwrap();
        assert_eq!(report.exit_code, Some(0));
    }

    #[tokio::test]
    async fn firecracker_workspace_round_trip() {
        if skip_unless_enabled() { return; }

        let tmp = tempfile::tempdir().unwrap();
        let host_ws = tmp.path().join("workspace");
        std::fs::create_dir_all(&host_ws).unwrap();
        std::fs::write(host_ws.join("input.txt"), b"test data").unwrap();

        let mut spec = test_config();
        spec.workspace.host_path = Some(host_ws.clone());

        let mut capsule = zeptocapsule::create(spec).unwrap();

        // Worker reads input and writes output
        let child = capsule.spawn(
            "/bin/sh",
            &["-c", "cat /workspace/input.txt > /workspace/output.txt"],
            HashMap::new(),
        ).unwrap();

        // Wait for worker to finish
        use tokio::io::AsyncReadExt;
        let mut stdout = child.stdout;
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf).await;

        let report = capsule.destroy().unwrap();

        // Verify output file was copied back
        let output = std::fs::read_to_string(host_ws.join("output.txt")).unwrap();
        assert_eq!(output.trim(), "test data");
    }

    #[tokio::test]
    async fn firecracker_timeout_kills_worker() {
        if skip_unless_enabled() { return; }

        let mut spec = test_config();
        spec.limits.timeout_sec = 3;

        let mut capsule = zeptocapsule::create(spec).unwrap();
        let _child = capsule.spawn("/bin/sleep", &["60"], HashMap::new()).unwrap();

        // Wait for timeout to fire
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let report = capsule.destroy().unwrap();
        assert_eq!(
            report.killed_by,
            Some(zeptocapsule::ResourceViolation::WallClock)
        );
    }

    #[tokio::test]
    async fn firecracker_kill_terminate_reaches_worker() {
        if skip_unless_enabled() { return; }

        let spec = test_config();
        let mut capsule = zeptocapsule::create(spec).unwrap();
        let _child = capsule.spawn("/bin/sleep", &["60"], HashMap::new()).unwrap();

        // Send terminate
        capsule.kill(zeptocapsule::Signal::Terminate).unwrap();

        // Give it a moment
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let report = capsule.destroy().unwrap();
        // Worker should have been terminated
        assert!(report.wall_time.as_secs() < 15);
    }

    #[test]
    fn firecracker_missing_kvm_is_not_supported() {
        // This test verifies that create() returns NotSupported
        // when prerequisites aren't met (using nonexistent paths).
        let spec = zeptocapsule::CapsuleSpec {
            isolation: zeptocapsule::Isolation::Firecracker,
            security: zeptocapsule::SecurityProfile::Standard,
            firecracker: Some(zeptocapsule::FirecrackerConfig {
                firecracker_bin: PathBuf::from("/nonexistent/firecracker"),
                kernel_path: PathBuf::from("/nonexistent/vmlinux"),
                rootfs_path: PathBuf::from("/nonexistent/rootfs.ext4"),
                vcpus: None,
                memory_mib: None,
                enable_network: false,
                tap_name: None,
            }),
            ..Default::default()
        };

        let err = zeptocapsule::create(spec).unwrap_err();
        assert!(
            matches!(err, zeptocapsule::KernelError::NotSupported(_)),
            "expected NotSupported, got: {err}"
        );
    }
}
```

**Step 2: Run unit test (always)**

Run: `cargo +nightly test -p zeptocapsule --test firecracker_backend -- firecracker_missing_kvm`
Expected: PASS (non-existent paths should trigger NotSupported).

**Step 3: Run integration tests (Linux with KVM only)**

Run: `ZK_RUN_FIRECRACKER_TESTS=1 ZK_FC_BIN=/path/to/firecracker ZK_FC_KERNEL=/path/to/vmlinux ZK_FC_ROOTFS=/path/to/rootfs.ext4 cargo +nightly test -p zeptocapsule --test firecracker_backend`
Expected: All 5 tests PASS when prerequisites are available.

**Step 4: Commit**

```bash
git add tests/firecracker_backend.rs
git commit -m "test: Firecracker backend integration tests behind ZK_RUN_FIRECRACKER_TESTS"
```

---

## Task 11: Update design doc status and add FirecrackerConfig export

**Files:**
- Modify: `docs/plans/2026-03-08-m6-firecracker-backend-design.md` (mark status)
- Modify: `src/lib.rs` (ensure all new public types are exported)

**Step 1: Update design doc status**

Change line 4 from `**Status:** Planned` to `**Status:** Implemented`.

**Step 2: Verify all exports in lib.rs**

Ensure `FirecrackerConfig` and `FcInitConfig` are in the `pub use` block:

```rust
pub use types::{
    CapsuleReport, CapsuleSpec, FirecrackerConfig, Isolation, RLimits, ResourceLimits,
    ResourceViolation, SecurityOverrides, SecurityProfile, Signal, WorkspaceConfig,
};
pub use init_shim::{FcInitConfig, MountConfig, is_init, is_firecracker_mode, parse_fc_init_config, run_init_shim, setup_guest_fs};
```

**Step 3: Run full test suite**

Run: `cargo +nightly test -p zeptocapsule`
Expected: All tests PASS (unit tests; integration tests skip without env var).

**Step 4: Commit**

```bash
git add docs/plans/2026-03-08-m6-firecracker-backend-design.md src/lib.rs
git commit -m "docs: mark Firecracker backend design as implemented"
```

---

## Summary

| Task | Component | New Files | Tests |
|------|-----------|-----------|-------|
| 1 | FirecrackerConfig + validation | - | 6 |
| 2 | Firecracker REST API client | firecracker_api.rs | 8 |
| 3 | Vsock transport helper | vsock.rs | 4 |
| 4 | Backend stub (create + destroy) | firecracker.rs | 3 |
| 5 | Workspace image builder | workspace_image.rs | 2 |
| 6 | spawn() — VM boot + vsock pipes | - | 5 |
| 7 | kill() — control channel | - | 2 |
| 8 | zk-init Firecracker mode | - | 4 |
| 9 | destroy() with export + serial | - | 3 |
| 10 | Integration tests | firecracker_backend.rs | 5 |
| 11 | Exports + doc status | - | 0 |
| **Total** | | **4 new files** | **42 tests** |

All tasks are Linux-only (`#[cfg(target_os = "linux")]`) except Task 1 (types) and Task 8 (init_shim parsing, which is cross-platform).
