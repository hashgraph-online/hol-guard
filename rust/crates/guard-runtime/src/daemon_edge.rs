//! Native daemon edge (`daemon-edge-v1`).
//!
//! The Guard daemon binds its public loopback port and starts
//! `guard-runtime daemon-edge --upstream-port P --parent-pid N` with that
//! listening socket as standard input. The edge accepts every connection on
//! the socket and relays its bytes to the daemon's private loopback port, so
//! the daemon's routes can move to this runtime one at a time behind an
//! address that never changes.
//!
//! The relay works at the connection level: it never parses HTTP, so
//! keep-alive, streaming responses and the daemon's own overload replies pass
//! through untouched. It only accepts a loopback listener and only connects to
//! the same loopback address, and the daemon still applies its own loopback and
//! authentication checks to every request.
//!
//! Standard output is one end of a socket pair whose other end only the daemon
//! holds. The edge exits the moment that end closes, so its port stops
//! accepting as soon as the daemon dies. The daemon keeps its own copy of the
//! listening socket open, so connections queued while an edge restarts are not
//! lost.
//!
//! Once the daemon sends its handshake on that socket, the edge also answers
//! a few token-authenticated store reads itself; see [`reads`].
//!
//! A write that makes no progress for [`STALLED_WRITE_TIMEOUT`] ends its
//! connection, so a peer that stops reading cannot hold a slot. Idle
//! connections are not affected: the timeout only runs while a write waits.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

#[path = "daemon_edge_auth.rs"]
mod auth;
#[path = "daemon_edge_http.rs"]
mod http;
#[path = "daemon_edge_reads.rs"]
mod reads;
#[path = "daemon_edge_replay.rs"]
mod replay;

use reads::{NativeReads, Outcome};

pub(crate) const EDGE_COMMAND: &str = "daemon-edge";
pub(crate) const EDGE_FEATURE: &str = "daemon-edge-v1";

/// Connections relayed at once. Each takes two small threads; further
/// connections wait in the listen backlog until one closes.
const MAX_ACTIVE_CONNECTIONS: usize = 256;
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const RELAY_THREAD_STACK: usize = 64 * 1024;
// A connection thread may answer from the store, whose page projections need
// far more than a relay pump.
const CONNECTION_THREAD_STACK: usize = 2 * 1024 * 1024;
const STALLED_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a connection waits for the handshake when no daemon listens
/// behind the edge.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(2);

const EXIT_USAGE: i32 = 2;
const EXIT_LISTENER: i32 = 3;

#[derive(Debug, PartialEq, Eq)]
struct EdgeArgs {
    upstream_port: u16,
    parent_pid: u32,
}

pub(crate) fn run(args: &[String]) -> i32 {
    let Some(parsed) = parse_args(args) else {
        eprintln!("usage: guard-runtime daemon-edge --upstream-port P --parent-pid N");
        return EXIT_USAGE;
    };
    if std::os::unix::process::parent_id() != parsed.parent_pid {
        return EXIT_USAGE;
    }
    let Some((listener, upstream)) = io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .ok()
        .map(TcpListener::from)
        .and_then(|listener| {
            let upstream = upstream_address(&listener, parsed.upstream_port)?;
            Some((listener, upstream))
        })
    else {
        eprintln!("daemon-edge: standard input is not a loopback listener");
        return EXIT_LISTENER;
    };
    let Ok(liveness) = io::stdout().as_fd().try_clone_to_owned() else {
        return EXIT_LISTENER;
    };
    let liveness = UnixStream::from(liveness);
    let reads = Arc::new(NativeReads::new(liveness.try_clone().ok()));
    watch_parent(liveness, Arc::clone(&reads));
    match serve(
        &listener,
        upstream,
        MAX_ACTIVE_CONNECTIONS,
        STALLED_WRITE_TIMEOUT,
        reads,
    ) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("daemon-edge: listener failed: {error}");
            EXIT_LISTENER
        }
    }
}

fn parse_args(args: &[String]) -> Option<EdgeArgs> {
    let mut upstream_port = None;
    let mut parent_pid = None;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let value = rest.next()?;
        match flag.as_str() {
            "--upstream-port" if upstream_port.is_none() => {
                upstream_port = Some(value.parse::<u16>().ok()?);
            }
            "--parent-pid" if parent_pid.is_none() => {
                parent_pid = Some(value.parse::<u32>().ok().filter(|pid| *pid > 1)?);
            }
            _ => return None,
        }
    }
    Some(EdgeArgs {
        upstream_port: upstream_port?,
        parent_pid: parent_pid?,
    })
}

/// The daemon's private port on the listener's own loopback address, or
/// `None` when the socket is not a loopback TCP listener. Port 0 names no
/// upstream: the edge then replays every request it does not answer through
/// the Guard CLI.
fn upstream_address(listener: &TcpListener, upstream_port: u16) -> Option<Option<SocketAddr>> {
    let local = listener.local_addr().ok()?;
    if !local.ip().is_loopback() || local.port() == upstream_port {
        return None;
    }
    Some((upstream_port != 0).then(|| SocketAddr::new(local.ip(), upstream_port)))
}

/// Exits the process as soon as the daemon's end of the liveness socket on
/// standard output closes. The kernel closes it when the daemon exits for any
/// reason, so a daemon killed outright leaves no edge accepting on its port.
///
/// Each line the daemon writes on the socket is a handshake for [`reads`]; a
/// line too long to be one is dropped.
fn watch_parent(liveness: UnixStream, native_reads: Arc<NativeReads>) {
    let _ = thread::Builder::new()
        .name("daemon-edge-parent".into())
        .stack_size(RELAY_THREAD_STACK)
        .spawn(move || {
            let mut chunk = [0u8; 4096];
            let mut line = Vec::new();
            let mut oversized = false;
            let mut reader = &liveness;
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => std::process::exit(0),
                    Ok(read) => {
                        for &byte in &chunk[..read] {
                            if byte == b'\n' {
                                if !oversized {
                                    native_reads.accept_handshake(&line);
                                }
                                line.clear();
                                oversized = false;
                            } else if line.len() < reads::MAX_HANDSHAKE_BYTES {
                                line.push(byte);
                            } else {
                                oversized = true;
                            }
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => std::process::exit(0),
                }
            }
        });
}

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

fn serve(
    listener: &TcpListener,
    upstream: Option<SocketAddr>,
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
                serve_connection(client, upstream, stalled_write, &connection_reads);
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
    ) || matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    )
}

/// Answers one connection's request natively when it can, and relays the
/// connection to the daemon otherwise.
fn serve_connection(
    client: TcpStream,
    upstream: Option<SocketAddr>,
    stalled_write: Duration,
    native_reads: &NativeReads,
) {
    let mut config = native_reads.config();
    if upstream.is_none() {
        // Nothing else can answer, so give the daemon's handshake a moment
        // to arrive on a connection accepted just after the edge started.
        let deadline = std::time::Instant::now() + HANDSHAKE_WAIT;
        while config.is_none() && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
            config = native_reads.config();
        }
    }
    let read_ahead = match &config {
        Some(config) => match reads::answer(&client, config, native_reads, stalled_write) {
            Outcome::Answered => return,
            Outcome::Relay(bytes) => bytes,
        },
        None => Vec::new(),
    };
    match (upstream, config) {
        (Some(upstream), config) => {
            let Ok(server) = TcpStream::connect_timeout(&upstream, UPSTREAM_CONNECT_TIMEOUT) else {
                // The daemon's own listener is gone; its handler can still
                // answer through the CLI.
                match config {
                    Some(config) => replay::replay(&client, &config, read_ahead, stalled_write),
                    None => {
                        let _ = client.shutdown(Shutdown::Both);
                    }
                }
                return;
            };
            relay_connection(client, server, stalled_write, &read_ahead)
        }
        (None, Some(config)) => replay::replay(&client, &config, read_ahead, stalled_write),
        (None, None) => {
            let _ = client.shutdown(Shutdown::Both);
        }
    }
}

/// Relays one connection to the daemon's connected `server` both ways until
/// each side has finished, sending `read_ahead`, the bytes already read from
/// the client, first.
fn relay_connection(
    client: TcpStream,
    server: TcpStream,
    stalled_write: Duration,
    read_ahead: &[u8],
) {
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);
    if client.set_write_timeout(Some(stalled_write)).is_err()
        || server.set_write_timeout(Some(stalled_write)).is_err()
    {
        let _ = client.shutdown(Shutdown::Both);
        let _ = server.shutdown(Shutdown::Both);
        return;
    }
    if !read_ahead.is_empty() && (&server).write_all(read_ahead).is_err() {
        let _ = client.shutdown(Shutdown::Both);
        let _ = server.shutdown(Shutdown::Both);
        return;
    }
    let (Ok(client_reader), Ok(server_writer)) = (client.try_clone(), server.try_clone()) else {
        let _ = client.shutdown(Shutdown::Both);
        let _ = server.shutdown(Shutdown::Both);
        return;
    };
    // Requests: the client may half-close after its last request and still
    // read the answer, so only the daemon's read side is closed here.
    let request = thread::Builder::new()
        .name("daemon-edge-req".into())
        .stack_size(RELAY_THREAD_STACK)
        .spawn(move || {
            let mut reader = &client_reader;
            let mut writer = &server_writer;
            let _ = io::copy(&mut reader, &mut writer);
            let _ = server_writer.shutdown(Shutdown::Write);
        });
    let Ok(request) = request else {
        let _ = client.shutdown(Shutdown::Both);
        let _ = server.shutdown(Shutdown::Both);
        return;
    };
    // Responses: once the daemon has finished it reads nothing more, so the
    // whole connection closes and the request copy above stops too.
    {
        let mut reader = &server;
        let mut writer = &client;
        let _ = io::copy(&mut reader, &mut writer);
    }
    let _ = client.shutdown(Shutdown::Both);
    let _ = server.shutdown(Shutdown::Both);
    let _ = request.join();
}

#[cfg(test)]
#[path = "daemon_edge_tests.rs"]
mod tests;
