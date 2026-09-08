use std::io::{self, BufRead, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crate::resident_transport::{admit_connection, start_resident_workers};

#[cfg(unix)]
pub(crate) fn resident_parent_liveness() -> Result<Arc<AtomicBool>, String> {
    let alive = Arc::new(AtomicBool::new(true));
    let Ok(raw_descriptor) = std::env::var(crate::PARENT_LIVENESS_FD_ENV) else {
        return Ok(alive);
    };
    let descriptor = raw_descriptor
        .parse::<u32>()
        .map_err(|_| "native_parent_liveness_fd_invalid".to_owned())?;
    let dev_path = format!("/dev/fd/{descriptor}");
    let proc_path = format!("/proc/self/fd/{descriptor}");
    let mut pipe = std::fs::File::open(dev_path)
        .or_else(|_| std::fs::File::open(proc_path))
        .map_err(|_| "native_parent_liveness_fd_unavailable".to_owned())?;
    let watcher_state = Arc::clone(&alive);
    thread::spawn(move || {
        let mut byte = [0u8; 1];
        let _ = pipe.read(&mut byte);
        watcher_state.store(false, Ordering::Release);
    });
    Ok(alive)
}

#[cfg(unix)]
pub(crate) fn serve(socket_path: &str) -> Result<(), String> {
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    let path = Path::new(socket_path);
    let parent = path
        .parent()
        .ok_or_else(|| "native_socket_parent_missing".to_owned())?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| "native_socket_parent_stat_failed".to_owned())?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        return Err("native_socket_parent_not_private".to_owned());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
                return Err("native_socket_existing_path_rejected".to_owned());
            }
            fs::remove_file(path).map_err(|_| "native_socket_cleanup_failed".to_owned())?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err("native_socket_stat_failed".to_owned()),
    }
    let listener = UnixListener::bind(path).map_err(|_| "native_socket_bind_failed".to_owned())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "native_socket_permissions_failed".to_owned())?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "native_socket_nonblocking_failed".to_owned())?;

    let token = Arc::new(read_resident_auth_token()?);
    let sender = start_resident_workers(token, None);
    let parent_alive = resident_parent_liveness()?;
    let mut consecutive_accept_failures = 0;
    while parent_alive.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _address)) => {
                consecutive_accept_failures = 0;
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                admit_connection(&sender, Box::new(stream))?;
            }
            Err(error)
                if crate::hardening::classify_io_error(&error)
                    != crate::hardening::IoFailureClass::Other =>
            {
                consecutive_accept_failures += 1;
                thread::sleep(crate::hardening::accept_retry_delay(
                    consecutive_accept_failures,
                    &error,
                ));
            }
            Err(_) => return Err("native_socket_accept_failed".to_owned()),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn serve(_socket_path: &str) -> Result<(), String> {
    Err("native_unix_socket_not_available".into())
}

pub(crate) fn serve_loopback(address: &str) -> Result<(), String> {
    let requested: SocketAddr = address
        .parse()
        .map_err(|_| "native_resident_address_invalid".to_owned())?;
    if requested.ip() != Ipv4Addr::LOCALHOST || requested.port() == 0 {
        return Err("native_resident_address_not_loopback".into());
    }
    let listener = TcpListener::bind(requested)
        .map_err(|_| "native_resident_loopback_bind_failed".to_owned())?;
    let local = listener
        .local_addr()
        .map_err(|_| "native_resident_loopback_addr_failed".to_owned())?;
    if local != requested {
        return Err("native_resident_loopback_addr_changed".into());
    }

    let token = Arc::new(read_resident_auth_token()?);
    let sender = start_resident_workers(token, None);
    let mut consecutive_accept_failures = 0;
    loop {
        match listener.accept() {
            Ok((stream, _address)) => {
                consecutive_accept_failures = 0;
                admit_connection(&sender, Box::new(stream))?;
            }
            Err(error)
                if crate::hardening::classify_io_error(&error)
                    != crate::hardening::IoFailureClass::Other =>
            {
                consecutive_accept_failures += 1;
                thread::sleep(crate::hardening::accept_retry_delay(
                    consecutive_accept_failures,
                    &error,
                ));
            }
            Err(_) => return Err("native_resident_loopback_accept_failed".to_owned()),
        }
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn read_resident_auth_token() -> Result<[u8; crate::AUTH_TOKEN_BYTES], String> {
    let mut encoded = String::new();
    io::stdin()
        .lock()
        .take((crate::AUTH_TOKEN_BYTES * 2 + 2) as u64)
        .read_line(&mut encoded)
        .map_err(|error| {
            crate::hardening::read_error(&error, "native_resident_auth_read_failed")
        })?;
    let encoded = encoded.trim();
    if encoded.len() != crate::AUTH_TOKEN_BYTES * 2 {
        return Err("native_resident_auth_invalid".into());
    }
    let mut token = [0u8; crate::AUTH_TOKEN_BYTES];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| "native_resident_auth_invalid".to_owned())?;
        let low = hex_nibble(pair[1]).ok_or_else(|| "native_resident_auth_invalid".to_owned())?;
        token[index] = (high << 4) | low;
    }
    Ok(token)
}

pub(crate) fn resident_stdin_liveness() -> Arc<AtomicBool> {
    let alive = Arc::new(AtomicBool::new(true));
    let watcher_state = Arc::clone(&alive);
    thread::spawn(move || {
        let mut byte = [0u8; 1];
        let _ = io::stdin().read(&mut byte);
        watcher_state.store(false, Ordering::Release);
    });
    alive
}
