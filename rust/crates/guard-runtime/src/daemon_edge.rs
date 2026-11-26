//! Native Guard daemon edge: the connection loop behind `daemon-serve`.
//!
//! Every connection on the daemon's loopback port is answered here: the
//! token-authenticated store reads and writes in [`reads`], and everything
//! else through [`replay`], which answers natively or refuses.
//!
//! A write that makes no progress for [`STALLED_WRITE_TIMEOUT`] ends its
//! connection, so a peer that stops reading cannot hold a slot. Idle
//! connections are not affected: the timeout only runs while a write waits.

use std::io;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[path = "daemon_edge_auth.rs"]
mod auth;
#[path = "daemon_edge_http.rs"]
mod http;
#[path = "daemon_edge_library.rs"]
mod library;
#[path = "daemon_edge_lifecycle.rs"]
pub(crate) mod lifecycle;
#[path = "daemon_edge_reads.rs"]
mod reads;
#[path = "daemon_edge_replay.rs"]
mod replay;
#[path = "daemon_edge_serve.rs"]
pub(crate) mod standalone;

use reads::{NativeReads, Outcome};

pub(crate) fn note_resident_hook_counters(
    guard_home: &std::path::Path,
    epoch: &str,
    counters: &serde_json::Value,
) {
    reads::note_resident_hook_counters(guard_home, epoch, counters);
}

/// Connections served at once; further connections wait in the listen
/// backlog until one closes. Sized for a burst of thousands of hooks: each
/// connection is bounded by its hook's deadline and the review scheduler
/// sheds what it cannot admit at once, so the slots turn over quickly and a
/// health check or approval is not left behind a full house in the backlog.
const MAX_ACTIVE_CONNECTIONS: usize = 1024;
/// The listen backlog asked for; the system may cap it lower.
#[cfg(unix)]
const LISTEN_BACKLOG: i32 = 1024;
// A connection thread may answer from the store, whose page projections need
// a deep stack.
const CONNECTION_THREAD_STACK: usize = 2 * 1024 * 1024;
const STALLED_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a connection accepted just after start waits for the handshake.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(2);

struct Slots {
    active: Mutex<usize>,
    limit: usize,
}

impl Slots {
    fn try_acquire(&self) -> bool {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if *active >= self.limit {
            return false;
        }
        *active += 1;
        true
    }

    fn release(&self) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *active = active.saturating_sub(1);
    }
}

const OVERLOAD_RESPONSE: &[u8] = b"HTTP/1.0 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 16\r\nConnection: close\r\nRetry-After: 1\r\n\r\ndaemon overload\n";

/// The Guard package version the launcher named, which outbound requests
/// identify themselves with; the runtime's own version until it is set.
static PACKAGE_VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn set_package_version(version: &str) {
    if !version.is_empty() && version.len() <= 64 {
        let _ = PACKAGE_VERSION.set(version.to_owned());
    }
}

/// `hol-guard/<package version>`, the User-Agent of every outbound request.
pub(crate) fn user_agent() -> String {
    format!("hol-guard/{}", package_version())
}

/// The Guard package version the launcher named, or the runtime's own.
pub(crate) fn package_version() -> &'static str {
    PACKAGE_VERSION
        .get()
        .map_or(crate::PACKAGE_VERSION, String::as_str)
}

fn serve(
    listener: &TcpListener,
    limit: usize,
    stalled_write: Duration,
    native_reads: Arc<NativeReads>,
) -> io::Result<()> {
    let slots = Arc::new(Slots {
        active: Mutex::new(0),
        limit: limit.max(1),
    });
    let mut consecutive_errors = 0usize;
    loop {
        let client = match listener.accept() {
            Ok((client, _)) => {
                consecutive_errors = 0;
                client
            }
            Err(error) => {
                consecutive_errors += 1;
                if accept_error_is_transient(&error) && consecutive_errors <= 64 {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                return Err(error);
            }
        };
        if !slots.try_acquire() {
            reject_overloaded(client, stalled_write);
            continue;
        }
        let relay_slots = Arc::clone(&slots);
        let connection_reads = Arc::clone(&native_reads);
        let spawned = thread::Builder::new()
            .name("daemon-edge-conn".into())
            .stack_size(CONNECTION_THREAD_STACK)
            .spawn(move || {
                connection_reads.begin_connection();
                serve_connection(client, stalled_write, &connection_reads);
                connection_reads.end_connection();
                relay_slots.release();
            });
        if spawned.is_err() {
            slots.release();
        }
    }
}

fn reject_overloaded(mut client: TcpStream, stalled_write: Duration) {
    let timeout = stalled_write.min(Duration::from_millis(25));
    let _ = client.set_write_timeout(Some(timeout));
    let _ = std::io::Write::write_all(&mut client, OVERLOAD_RESPONSE);
    let _ = client.shutdown(Shutdown::Write);
    let _ = client.set_nonblocking(true);
    let mut sink = [0u8; 4096];
    for _ in 0..16 {
        match std::io::Read::read(&mut client, &mut sink) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    let _ = client.shutdown(Shutdown::Read);
}

/// Asks for a deeper listen backlog than the standard library's 128, so a
/// burst of connects waits to be accepted instead of timing out. Calling
/// `listen` again on a listening socket only changes its backlog.
#[cfg(unix)]
fn widen_backlog(listener: &TcpListener) {
    use nix::sys::socket::{listen, Backlog};
    if let Ok(backlog) = Backlog::new(LISTEN_BACKLOG) {
        let _ = listen(listener, backlog);
    }
}

#[cfg(not(unix))]
fn widen_backlog(_listener: &TcpListener) {}

fn accept_error_is_transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::WouldBlock
    ) || resource_exhausted(error.raw_os_error())
}

#[cfg(unix)]
fn resource_exhausted(code: Option<i32>) -> bool {
    matches!(
        code,
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

/// `WSAEMFILE` and `WSAENOBUFS`.
#[cfg(windows)]
fn resource_exhausted(code: Option<i32>) -> bool {
    matches!(code, Some(10024 | 10055))
}

/// Answers one connection's request.
fn serve_connection(client: TcpStream, stalled_write: Duration, native_reads: &NativeReads) {
    let mut config = native_reads.config();
    let deadline = std::time::Instant::now() + HANDSHAKE_WAIT;
    while config.is_none() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
        config = native_reads.config();
    }
    let Some(config) = config else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    if let Outcome::Relay(read_ahead) = reads::answer(&client, &config, native_reads, stalled_write)
    {
        replay::replay(&client, &config, read_ahead, stalled_write);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_edge_capacity_sheds_without_blocking_the_accept_loop() {
        let slots = Slots {
            active: Mutex::new(0),
            limit: 1,
        };
        assert!(slots.try_acquire());
        assert!(!slots.try_acquire());
        slots.release();
        assert!(slots.try_acquire());
    }

    #[test]
    fn overload_response_is_recognizable_to_hook_bridges() {
        let response = std::str::from_utf8(OVERLOAD_RESPONSE).expect("static response is utf8");
        assert!(response.contains("503 Service Unavailable"));
        assert!(response.contains("Retry-After: 1"));
        assert!(response.ends_with("daemon overload\n"));
    }
}
