//! Host-side Firecracker vsock connector.

use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| {
            KernelError::Transport(format!(
                "vsock connect {}: {e}",
                socket_path.display()
            ))
        })?;

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

    let stream = buf_reader.into_inner().unsplit(writer);
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
