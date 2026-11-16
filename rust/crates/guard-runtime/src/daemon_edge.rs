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
use std::sync::{Arc, Condvar, Mutex};
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

/// Connections served at once; further connections wait in the listen
/// backlog until one closes.
const MAX_ACTIVE_CONNECTIONS: usize = 256;
// A connection thread may answer from the store, whose page projections need
// a deep stack.
const CONNECTION_THREAD_STACK: usize = 2 * 1024 * 1024;
const STALLED_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a connection accepted just after start waits for the handshake.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(2);

struct Slots {
    active: Mutex<usize>,
    freed: Condvar,
    limit: usize,
}

impl Slots {
    fn acquire(&self) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        while *active >= self.limit {
            active = self
                .freed
                .wait(active)
                .unwrap_or_else(|poison| poison.into_inner());
        }
        *active += 1;
    }

    fn release(&self) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *active = active.saturating_sub(1);
        self.freed.notify_one();
    }
}

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
    format!(
        "hol-guard/{}",
        PACKAGE_VERSION
            .get()
            .map_or(crate::PACKAGE_VERSION, String::as_str)
    )
}

fn serve(
    listener: &TcpListener,
    limit: usize,
    stalled_write: Duration,
    native_reads: Arc<NativeReads>,
) -> io::Result<()> {
    let slots = Arc::new(Slots {
        active: Mutex::new(0),
        freed: Condvar::new(),
        limit: limit.max(1),
    });
    let mut consecutive_errors = 0usize;
    loop {
        slots.acquire();
        let client = match listener.accept() {
            Ok((client, _)) => {
                consecutive_errors = 0;
                client
            }
            Err(error) => {
                slots.release();
                consecutive_errors += 1;
                if accept_error_is_transient(&error) && consecutive_errors <= 64 {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                return Err(error);
            }
        };
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
