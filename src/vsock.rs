//! Host-side Firecracker vsock connector.

use std::path::Path;

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use crate::backend::{KernelError, KernelResult};

pub const PORT_STDIN: u32 = 1001;
pub const PORT_STDOUT: u32 = 1002;
pub const PORT_STDERR: u32 = 1003;
pub const PORT_CONTROL: u32 = 1004;
pub const GUEST_CID: u32 = 3;

pub fn connect_request(port: u32) -> String {
    format!("CONNECT {port}\n")
}

pub fn is_connect_ok(line: &str) -> bool {
    line.trim().starts_with("OK")
}

pub async fn connect(socket_path: &Path, port: u32) -> KernelResult<UnixStream> {
    // Retry CONNECT until the guest has bound to the port.
    // The guest zk-init may still be booting when the host tries to connect.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        match try_connect(socket_path, port).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(e);
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

async fn try_connect(socket_path: &Path, port: u32) -> KernelResult<UnixStream> {
    use tokio::io::AsyncReadExt;

    let mut stream = UnixStream::connect(socket_path).await.map_err(|e| {
        KernelError::Transport(format!("vsock connect {}: {e}", socket_path.display()))
    })?;

    let req = connect_request(port);
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| KernelError::Transport(format!("vsock write CONNECT: {e}")))?;

    // Read response line byte-by-byte to avoid buffering past the newline.
    let mut line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| KernelError::Transport(format!("vsock read response: {e}")))?;
        if n == 0 {
            break;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }

    let response = String::from_utf8_lossy(&line).to_string();
    if !is_connect_ok(&response) {
        return Err(KernelError::Transport(format!(
            "vsock CONNECT {port} failed: {response}"
        )));
    }

    Ok(stream)
}

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
