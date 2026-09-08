#![forbid(unsafe_code)]

#[cfg(unix)]
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use super::resident_state_retirement;
use crate::resident_state::publish_state;
#[cfg(unix)]
use crate::resident_state::socket_directory;

#[cfg(unix)]
pub(super) fn serve_unix_managed(
    scope: &Path,
    policy_store: std::sync::Arc<crate::policy_store::PolicySnapshotStore>,
    generation: u64,
    owner_process_id: u32,
    digest: &str,
    token: [u8; crate::AUTH_TOKEN_BYTES],
    owner_alive: Arc<AtomicBool>,
) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::os::unix::net::UnixListener;

    let socket_parent = socket_directory(scope, digest)?;
    let path = socket_parent.join(format!("h3-{}-{generation:016x}.sock", &digest[..8]));
    if path.as_os_str().as_encoded_bytes().len() > 100 {
        return Err("native_socket_path_too_long".to_owned());
    }
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(metadata) if metadata.file_type().is_socket() => {
            return Err("native_socket_generation_collision".to_owned())
        }
        Ok(_) => return Err("native_socket_existing_path_rejected".to_owned()),
        Err(_) => return Err("native_socket_stat_failed".to_owned()),
    }
    let listener = UnixListener::bind(&path).map_err(|_| "native_socket_bind_failed".to_owned())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "native_socket_permissions_failed".to_owned())?;
    listener
        .set_nonblocking(true)
        .map_err(|_| "native_socket_nonblocking_failed".to_owned())?;
    let published = publish_state(
        scope,
        generation,
        owner_process_id,
        digest,
        "unix",
        path.to_string_lossy().into_owned(),
        &token,
    )?;
    let result = managed_accept_loop(listener, Arc::new(token), owner_alive, policy_store);
    if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_socket()) {
        let _ = fs::remove_file(path);
    }
    resident_state_retirement::retire_state(
        scope,
        generation,
        published.process_id,
        &published.process_start_marker,
        digest,
        &token,
    );
    result
}

#[cfg(not(unix))]
pub(super) fn serve_unix_managed(
    _scope: &Path,
    _policy_store: std::sync::Arc<crate::policy_store::PolicySnapshotStore>,
    _generation: u64,
    _owner_process_id: u32,
    _digest: &str,
    _token: [u8; crate::AUTH_TOKEN_BYTES],
    _owner_alive: Arc<AtomicBool>,
) -> Result<(), String> {
    Err("native_unix_socket_not_available".to_owned())
}

#[cfg(unix)]
fn managed_accept_loop(
    listener: std::os::unix::net::UnixListener,
    token: Arc<[u8; crate::AUTH_TOKEN_BYTES]>,
    owner_alive: Arc<AtomicBool>,
    policy_store: std::sync::Arc<crate::policy_store::PolicySnapshotStore>,
) -> Result<(), String> {
    let sender = crate::resident_transport::start_resident_workers(token, Some(policy_store));
    let mut last_activity = Instant::now();
    let mut failures = 0;
    while owner_alive.load(Ordering::Acquire)
        && last_activity.elapsed() < super::MANAGED_IDLE_TIMEOUT
        && !super::shutdown_requested()
    {
        match listener.accept() {
            Ok((stream, _)) => {
                failures = 0;
                last_activity = Instant::now();
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                crate::resident_transport::admit_connection(&sender, Box::new(stream))?;
            }
            Err(error)
                if crate::hardening::classify_io_error(&error)
                    != crate::hardening::IoFailureClass::Other =>
            {
                failures += 1;
                thread::sleep(crate::hardening::accept_retry_delay(failures, &error));
            }
            Err(_) => return Err("native_socket_accept_failed".to_owned()),
        }
    }
    Ok(())
}

pub(super) fn serve_loopback_managed(
    scope: &Path,
    policy_store: std::sync::Arc<crate::policy_store::PolicySnapshotStore>,
    generation: u64,
    owner_process_id: u32,
    digest: &str,
    token: [u8; crate::AUTH_TOKEN_BYTES],
    owner_alive: Arc<AtomicBool>,
) -> Result<(), String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|_| "native_resident_loopback_bind_failed".to_owned())?;
    let address = listener
        .local_addr()
        .map_err(|_| "native_resident_loopback_addr_failed".to_owned())?;
    if address.ip() != Ipv4Addr::LOCALHOST || address.port() == 0 {
        return Err("native_resident_loopback_addr_invalid".to_owned());
    }
    listener
        .set_nonblocking(true)
        .map_err(|_| "native_resident_loopback_nonblocking_failed".to_owned())?;
    let published = publish_state(
        scope,
        generation,
        owner_process_id,
        digest,
        "loopback",
        address.to_string(),
        &token,
    )?;
    let sender =
        crate::resident_transport::start_resident_workers(Arc::new(token), Some(policy_store));
    let mut last_activity = Instant::now();
    let mut failures = 0;
    let result = loop {
        if !(owner_alive.load(Ordering::Acquire)
            && last_activity.elapsed() < super::MANAGED_IDLE_TIMEOUT
            && !super::shutdown_requested())
        {
            break Ok(());
        }
        match listener.accept() {
            Ok((stream, peer)) => {
                if peer.ip() != Ipv4Addr::LOCALHOST {
                    continue;
                }
                failures = 0;
                last_activity = Instant::now();
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                crate::resident_transport::admit_connection(&sender, Box::new(stream))?;
            }
            Err(error)
                if crate::hardening::classify_io_error(&error)
                    != crate::hardening::IoFailureClass::Other =>
            {
                failures += 1;
                thread::sleep(crate::hardening::accept_retry_delay(failures, &error));
            }
            Err(_) => break Err("native_resident_loopback_accept_failed".to_owned()),
        }
    };
    resident_state_retirement::retire_state(
        scope,
        generation,
        published.process_id,
        &published.process_start_marker,
        digest,
        &token,
    );
    result
}
