//! Minimal Firecracker REST API client over Unix socket.

use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::backend::{KernelError, KernelResult};

#[derive(Debug)]
pub struct ApiResponse {
    pub status: u16,
    pub body: String,
}

pub fn format_put_request(path: &str, body: &str) -> String {
    format!(
        "PUT {} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Accept: application/json\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        path,
        body.len(),
        body,
    )
}


pub async fn put(socket_path: &Path, path: &str, body: &str) -> KernelResult<ApiResponse> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| KernelError::Transport(format!("unix socket connect: {e}")))?;

    let request = format_put_request(path, body);
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| KernelError::Transport(format!("socket write: {e}")))?;

    // Read HTTP response: headers until \r\n\r\n, then Content-Length bytes of body.
    let mut header_buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| KernelError::Transport(format!("socket read header: {e}")))?;
        header_buf.push(byte[0]);
        if header_buf.len() >= 4 && header_buf[header_buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
    }

    let header_str = String::from_utf8(header_buf)
        .map_err(|e| KernelError::Transport(format!("header utf8: {e}")))?;

    // Extract Content-Length from headers (case-insensitive).
    let content_length: usize = header_str
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            if key.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    let mut body_buf = vec![0u8; content_length];
    if content_length > 0 {
        stream
            .read_exact(&mut body_buf)
            .await
            .map_err(|e| KernelError::Transport(format!("socket read body: {e}")))?;
    }

    let body = String::from_utf8(body_buf)
        .map_err(|e| KernelError::Transport(format!("body utf8: {e}")))?;

    // Parse status from first header line.
    let status_line = header_str
        .lines()
        .next()
        .ok_or_else(|| KernelError::Transport("empty response".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| KernelError::Transport("missing status code".into()))?
        .parse()
        .map_err(|e| KernelError::Transport(format!("invalid status: {e}")))?;

    Ok(ApiResponse { status, body })
}

pub async fn put_expect_ok(
    socket_path: &Path,
    path: &str,
    body: &str,
) -> KernelResult<ApiResponse> {
    let resp = put(socket_path, path, body).await?;
    if !(200..300).contains(&resp.status) {
        return Err(KernelError::Transport(format!(
            "Firecracker API {} returned {}: {}",
            path, resp.status, resp.body,
        )));
    }
    Ok(resp)
}

pub fn machine_config_json(vcpus: u32, mem_size_mib: u64) -> String {
    format!(
        r#"{{"vcpu_count":{},"mem_size_mib":{}}}"#,
        vcpus, mem_size_mib
    )
}

pub fn boot_source_json(kernel_image_path: &str, boot_args: &str) -> String {
    format!(
        r#"{{"kernel_image_path":"{}","boot_args":"{}"}}"#,
        kernel_image_path, boot_args,
    )
}

pub fn drive_json(drive_id: &str, path: &str, is_root: bool, is_read_only: bool) -> String {
    format!(
        r#"{{"drive_id":"{}","path_on_host":"{}","is_root_device":{},"is_read_only":{}}}"#,
        drive_id, path, is_root, is_read_only,
    )
}

pub fn vsock_json(vsock_id: &str, uds_path: &str, guest_cid: u32) -> String {
    format!(
        r#"{{"vsock_id":"{}","uds_path":"{}","guest_cid":{}}}"#,
        vsock_id, uds_path, guest_cid,
    )
}

pub fn network_interface_json(iface_id: &str, tap_name: &str) -> String {
    format!(
        r#"{{"iface_id":"{}","host_dev_name":"{}"}}"#,
        iface_id, tap_name,
    )
}

pub fn action_json(action_type: &str) -> String {
    format!(r#"{{"action_type":"{}"}}"#, action_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_put_request_basic() {
        let req = format_put_request("/machine-config", r#"{"vcpu_count":2}"#);
        assert!(req.starts_with("PUT /machine-config HTTP/1.1\r\n"));
        assert!(req.contains("Content-Type: application/json\r\n"));
        assert!(req.contains("Content-Length: 16\r\n"));
        assert!(req.ends_with(r#"{"vcpu_count":2}"#));
    }

    #[test]
    fn machine_config_json_test() {
        let json = machine_config_json(2, 512);
        assert!(json.contains("\"vcpu_count\":2"));
        assert!(json.contains("\"mem_size_mib\":512"));
    }

    #[test]
    fn boot_source_json_test() {
        let json = boot_source_json("/vmlinux", "console=ttyS0 reboot=k panic=1");
        assert!(json.contains("\"/vmlinux\""));
        assert!(json.contains("console=ttyS0"));
    }

    #[test]
    fn drive_json_test() {
        let json = drive_json("rootfs", "/path/to/rootfs.ext4", true, false);
        assert!(json.contains("\"drive_id\":\"rootfs\""));
        assert!(json.contains("\"is_root_device\":true"));
        assert!(json.contains("\"is_read_only\":false"));
    }

    #[test]
    fn vsock_json_test() {
        let json = vsock_json("vsock0", "/tmp/fc.vsock", 3);
        assert!(json.contains("\"vsock_id\":\"vsock0\""));
        assert!(json.contains("\"guest_cid\":3"));
        assert!(json.contains("\"/tmp/fc.vsock\""));
    }

    #[test]
    fn action_json_test() {
        let json = action_json("InstanceStart");
        assert_eq!(json, r#"{"action_type":"InstanceStart"}"#);
    }
}
