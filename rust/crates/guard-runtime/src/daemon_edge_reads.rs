//! Read routes the daemon edge answers without the Python daemon.
//!
//! Once the daemon starts the edge it writes one handshake line on the
//! liveness socket: the auth token and the store the daemon serves. Nothing
//! goes on disk, in the argument list or in the environment. Until that line
//! arrives, and for an older daemon that never sends it, the edge relays every
//! connection exactly as before.
//!
//! With a handshake the edge peeks at each new connection, without consuming
//! it, for a few milliseconds. A request that has not fully arrived by then,
//! or that is followed by more bytes, leaves the connection untouched for the
//! daemon. The edge answers a request itself only when it is a `GET` for one of
//! the store reads below, with no body, from a caller `auth` finds the daemon
//! would let through: its token, or a dashboard session, from an allowed
//! origin; or one of the `POST` and `DELETE` routes in `writes`. Anything else is replayed
//! byte for byte to the daemon, which keeps every rejection, audit record and
//! nonce check it has today. A store call that fails is replayed too, so the
//! daemon answers it as it always has.
//!
//! Each authenticated request writes one byte back on the liveness socket when
//! it starts and when it is answered, at most twice a second, so the daemon
//! still counts the activity it no longer sees.

use std::io::Write;
/// No edge mode runs on Windows; the standalone daemon has no activity socket.
#[cfg(not(unix))]
use std::net::TcpStream as ActivitySocket;
use std::net::{Shutdown, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream as ActivitySocket;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use serde::Deserialize;
use serde_json::Value;

use super::auth::{authorize, authorize_origin, authorize_token, session_allows};
use super::http::{parse_request, take_request, Request};
#[cfg(test)]
use super::http::{HEAD_PEEK_WINDOW, MAX_BODY_BYTES};

pub(super) const HANDSHAKE_SCHEMA: &str = "guard-daemon-edge-handshake.v1";
/// The request headers the daemon names in its CORS answer.
const CORS_ALLOW_HEADERS: &str =
    "Authorization, Content-Type, X-Guard-Dashboard-Session, X-Guard-Token";
const ACTIVITY_INTERVAL: Duration = Duration::from_millis(500);
const ACTIVITY_WRITE_TIMEOUT: Duration = Duration::from_millis(10);
const MAX_BUSY_TIMEOUT_MS: u64 = 60_000;
const MAX_READ_STATE_PAGES: usize = 100_000;
const MAX_SESSION_SIGNALS: usize = 16;
const MAX_SESSION_SIGNAL_BYTES: usize = 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handshake {
    schema: String,
    auth_token: String,
    guard_home: String,
    store_path: String,
    source: String,
    busy_timeout_ms: u64,
    #[serde(default)]
    dashboard_build: Option<String>,
    #[serde(default)]
    pub(super) user_home: Option<String>,
    #[serde(default)]
    session_signals: Option<Vec<String>>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    daemon_fingerprint: Option<String>,
    #[serde(default)]
    cli_command: Option<Vec<String>>,
    #[serde(default)]
    dashboard_dir: Option<String>,
}

impl ReadConfig {
    /// What the edge needs to run the daemon's Guard CLI: its argv prefix,
    /// the Guard home and the daemon's working directory.
    /// The dashboard bundle every response names.
    pub(super) fn dashboard_build(&self) -> Option<&str> {
        self.dashboard_build.as_deref()
    }

    pub(super) fn cli(&self) -> Option<(&[String], &str, Option<&str>)> {
        Some((
            self.cli_command.as_deref()?,
            &self.guard_home,
            self.daemon_cwd.as_deref(),
        ))
    }
}

pub(super) struct ReadConfig {
    token: Vec<u8>,
    guard_home: String,
    store_path: String,
    source: String,
    busy_timeout_ms: u64,
    dashboard_build: Option<String>,
    /// `str(Path.home())` in the daemon, which evidence reads shorten to `~`.
    pub(super) user_home: Option<String>,
    /// The daemon's local OS-session facts, which approval-gate checks bind a
    /// recent TOTP proof to. The edge runs in a session of its own.
    session_signals: Option<Vec<String>>,
    /// `os.getcwd()` in the daemon. The edge runs from its own directory, and
    /// store reads resolve a relative config path from the daemon's.
    daemon_cwd: Option<String>,
    /// `current_guard_daemon_runtime_fingerprint()`, which containment health
    /// evidence is bound to.
    daemon_fingerprint: Option<String>,
    /// The argv prefix that runs the daemon's own Guard CLI, for the answers
    /// that depend on how Guard was installed.
    cli_command: Option<Vec<String>>,
    /// The packaged dashboard's static directory, which the edge serves the
    /// shell and bundled files from.
    dashboard_dir: Option<PathBuf>,
}

impl ReadConfig {
    fn from_line(line: &[u8]) -> Option<Self> {
        let handshake: Handshake = serde_json::from_slice(line).ok()?;
        if handshake.schema != HANDSHAKE_SCHEMA
            || handshake.auth_token.is_empty()
            || !handshake.auth_token.is_ascii()
            || !Path::new(&handshake.guard_home).is_absolute()
            || !Path::new(&handshake.store_path).is_absolute()
            || handshake.source.is_empty()
            || !(1..=MAX_BUSY_TIMEOUT_MS).contains(&handshake.busy_timeout_ms)
        {
            return None;
        }
        let dashboard_build = handshake.dashboard_build.filter(|build| {
            !build.is_empty()
                && build.len() <= 64
                && build.bytes().all(|b| b.is_ascii_alphanumeric())
        });
        let session_signals = handshake.session_signals.filter(|signals| {
            (1..=MAX_SESSION_SIGNALS).contains(&signals.len())
                && signals
                    .iter()
                    .all(|signal| (1..=MAX_SESSION_SIGNAL_BYTES).contains(&signal.len()))
        });
        Some(Self {
            token: handshake.auth_token.into_bytes(),
            guard_home: handshake.guard_home,
            store_path: handshake.store_path,
            source: handshake.source,
            busy_timeout_ms: handshake.busy_timeout_ms,
            dashboard_build,
            user_home: handshake.user_home,
            session_signals,
            daemon_cwd: handshake.cwd.filter(|cwd| Path::new(cwd).is_absolute()),
            daemon_fingerprint: handshake.daemon_fingerprint.filter(|fingerprint| {
                fingerprint.len() == 64
                    && fingerprint
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            }),
            cli_command: handshake.cli_command.filter(|argv| {
                argv.first()
                    .is_some_and(|program| Path::new(program).is_absolute())
                    && argv.len() <= 16
                    && argv.iter().all(|arg| arg.len() <= 16 * 1024)
            }),
            dashboard_dir: handshake
                .dashboard_dir
                .map(PathBuf::from)
                .filter(|dir| dir.is_absolute()),
        })
    }
}

/// What the edge knows from its daemon: the handshake, once it arrives, and
/// the socket that reports answered requests back.
pub(super) struct NativeReads {
    config: RwLock<Option<Arc<ReadConfig>>>,
    activity: Option<ActivitySocket>,
    last_activity: Mutex<Option<Instant>>,
    request_ids: AtomicU64,
    /// Set when this process is the daemon itself rather than an edge in
    /// front of one: it then answers liveness probes and names itself as the
    /// daemon its replays serve.
    standalone: AtomicBool,
    /// The process the launcher started, when it waits on this one instead
    /// of becoming it (Windows has no exec); zero otherwise.
    launcher_pid: AtomicU32,
    state_id: std::sync::OnceLock<String>,
    /// The daemon state this process published, which names its release and
    /// install for the health details.
    published: std::sync::OnceLock<serde_json::Map<String, Value>>,
    /// When this process began serving, for the health details' uptime.
    started: Instant,
    /// Connections being served, and when the last one began or ended: what
    /// the standalone daemon's idle shutdown reads.
    connections: AtomicUsize,
    touched: Mutex<Instant>,
}

impl NativeReads {
    pub(super) fn new(activity: Option<ActivitySocket>) -> Self {
        // The timeout covers only writes, so the parent watcher's reads on the
        // same socket keep blocking.
        let activity = activity.filter(|socket| {
            socket
                .set_write_timeout(Some(ACTIVITY_WRITE_TIMEOUT))
                .is_ok()
        });
        Self {
            config: RwLock::new(None),
            activity,
            last_activity: Mutex::new(None),
            request_ids: AtomicU64::new(0),
            standalone: AtomicBool::new(false),
            launcher_pid: AtomicU32::new(0),
            state_id: std::sync::OnceLock::new(),
            published: std::sync::OnceLock::new(),
            started: Instant::now(),
            connections: AtomicUsize::new(0),
            touched: Mutex::new(Instant::now()),
        }
    }

    pub(super) fn begin_connection(&self) {
        self.connections.fetch_add(1, Ordering::AcqRel);
        self.touch();
    }

    pub(super) fn end_connection(&self) {
        self.touch();
        self.connections.fetch_sub(1, Ordering::AcqRel);
    }

    pub(super) fn active_connections(&self) -> usize {
        self.connections.load(Ordering::Acquire)
    }

    /// How long since a connection began or ended.
    pub(super) fn idle_for(&self) -> Duration {
        self.touched
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .elapsed()
    }

    fn touch(&self) {
        *self
            .touched
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Instant::now();
    }

    pub(super) fn mark_standalone(&self) {
        self.standalone.store(true, Ordering::Release);
    }

    /// Names the launcher that waits on this process as the daemon's pid.
    pub(super) fn set_launcher_pid(&self, pid: u32) {
        self.launcher_pid.store(pid, Ordering::Release);
    }

    /// Records the `state_id` of the daemon state this process published.
    pub(super) fn set_state_id(&self, state_id: String) {
        let _ = self.state_id.set(state_id);
    }

    /// The `state_id` this process published, when it serves on its own.
    pub(super) fn state_id(&self) -> Option<&str> {
        self.state_id.get().map(String::as_str)
    }

    /// Records the daemon state this process published.
    pub(super) fn set_published_state(&self, state: serde_json::Map<String, Value>) {
        if let Some(state_id) = state.get("state_id").and_then(Value::as_str) {
            self.set_state_id(state_id.to_owned());
        }
        let _ = self.published.set(state);
    }

    /// The daemon state this process published, when it serves on its own.
    pub(super) fn published_state(&self) -> Option<&serde_json::Map<String, Value>> {
        self.published.get()
    }

    /// How long this process has served.
    pub(super) fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    fn is_standalone(&self) -> bool {
        self.standalone.load(Ordering::Acquire)
    }

    /// The process the published daemon state names: this one when it is the
    /// daemon, otherwise the daemon that started this edge.
    pub(super) fn daemon_pid(&self) -> u32 {
        #[cfg(unix)]
        if !self.is_standalone() {
            return std::os::unix::process::parent_id();
        }
        match self.launcher_pid.load(Ordering::Acquire) {
            0 => std::process::id(),
            pid => pid,
        }
    }

    /// Takes one handshake line from the daemon. A line that does not parse
    /// leaves the current configuration, if any, in place.
    pub(super) fn accept_handshake(&self, line: &[u8]) {
        if let Some(config) = ReadConfig::from_line(line) {
            *self
                .config
                .write()
                .unwrap_or_else(|poison| poison.into_inner()) = Some(Arc::new(config));
        }
    }

    pub(super) fn config(&self) -> Option<Arc<ReadConfig>> {
        self.config
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    fn report_activity(&self) {
        let Some(activity) = &self.activity else {
            return;
        };
        {
            let mut last = self
                .last_activity
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let now = Instant::now();
            if last.is_some_and(|at| now.duration_since(at) < ACTIVITY_INTERVAL) {
                return;
            }
            *last = Some(now);
        }
        // A daemon that is not reading loses a heartbeat, not a request: the
        // write gives up after `ACTIVITY_WRITE_TIMEOUT`.
        let mut writer = activity;
        let _ = writer.write_all(b"a");
    }

    /// Tells the daemon an edge write changed Guard's policy inputs, so it
    /// republishes the native policy snapshot as its own writes do. Never
    /// throttled: a lost notice would leave the snapshot stale.
    fn report_policy_mutation(&self) {
        if let Some(activity) = &self.activity {
            let mut writer = activity;
            let _ = writer.write_all(b"p");
        }
    }

    fn store_call(&self, config: &ReadConfig, method: &str, args: Value) -> Option<Value> {
        self.store_write(config, method, args).ok()
    }

    /// `store_call` for a write: `Err(true)` when the call failed after its
    /// write committed, which the daemon must not repeat.
    fn store_write(&self, config: &ReadConfig, method: &str, args: Value) -> Result<Value, bool> {
        self.store_within(config, method, args, config.busy_timeout_ms)
    }

    /// `store_call` waiting at most `busy_ms` for a locked store, for a
    /// health read that must answer while the store is held.
    pub(super) fn store_read_within(
        &self,
        config: &ReadConfig,
        method: &str,
        args: Value,
        busy_ms: u64,
    ) -> Option<Value> {
        self.store_within(
            config,
            method,
            args,
            busy_ms.clamp(1, config.busy_timeout_ms.max(1)),
        )
        .ok()
    }

    fn store_within(
        &self,
        config: &ReadConfig,
        method: &str,
        args: Value,
        busy_timeout_ms: u64,
    ) -> Result<Value, bool> {
        let Value::Object(args) = args else {
            return Err(false);
        };
        let wait = Duration::from_millis(busy_timeout_ms);
        let _gate =
            crate::hook_evidence_store_gate::hold_storage_gate(Path::new(&config.guard_home), wait)
                .map_err(|_| false)?;
        let request = GuardStoreRequestV1 {
            schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
            request_id: format!(
                "daemon-edge-{}",
                self.request_ids.fetch_add(1, Ordering::Relaxed)
            ),
            store_path: config.store_path.clone(),
            guard_home: config.guard_home.clone(),
            method: method.to_owned(),
            source: config.source.clone(),
            busy_timeout_ms,
            args,
        };
        let (outcome, committed) = crate::guard_store_op::evaluate_committing(&request);
        outcome.map_err(|_| committed)
    }
}

/// The edge either answered the connection or hands back the bytes it read,
/// which must reach the daemon before anything else.
pub(super) enum Outcome {
    Answered,
    Relay(Vec<u8>),
}

pub(super) fn answer(
    client: &TcpStream,
    config: &ReadConfig,
    reads: &NativeReads,
    stalled_write: Duration,
) -> Outcome {
    let Some((bytes, head_len)) = take_request(client) else {
        if let Some(response) = early_refusal(client, config, reads) {
            return write_answer(client, &response, reads, stalled_write);
        }
        // Beside the daemon, only a body larger than the peek holds is read
        // here; standalone, so is a request still arriving when the peek
        // window closed. Either is read the way the daemon's handler would,
        // then answered here as well.
        if !reads.is_standalone()
            && !super::http::waiting_head(client)
                .is_some_and(|head| super::http::declares_large_body(&head))
        {
            return Outcome::Relay(Vec::new());
        }
        let Some(mut read) = super::replay::read_request(client, SLOW_REQUEST_READ_TIMEOUT) else {
            let _ = client.shutdown(std::net::Shutdown::Both);
            return Outcome::Answered;
        };
        if let Some(head_len) = super::replay::find_head_end(&read) {
            super::http::fold_header_bytes(&mut read[..head_len]);
        }
        let Some(head_len) = whole_request(&read) else {
            if let Some(response) = oversized_body(client, &read, config, reads) {
                return write_answer(client, &response, reads, stalled_write);
            }
            return Outcome::Relay(read);
        };
        return answer_request(client, read, head_len, config, reads, stalled_write);
    };
    answer_request(client, bytes, head_len, config, reads, stalled_write)
}

/// `do_POST`'s answer to a body declared past what the handler reads: the
/// caller check first on a guarded route, then `413`.
fn oversized_body(
    client: &TcpStream,
    read: &[u8],
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<Vec<u8>> {
    let head_len = super::replay::find_head_end(read)?;
    let request = parse_request(&read[..head_len])?;
    let declared = super::replay::content_length(&read[..head_len])?;
    if request.method != "POST" || declared <= super::replay::MAX_REPLAYED_BODY_BYTES {
        return None;
    }
    let token = &config.token;
    let refused = refusals::refusal(&request, &[], token).or_else(|| {
        refusals::post_checks_caller_first(&request)
            .then(|| refusals::credential_refusal(&request, token))
            .flatten()
    });
    if let Some(refusal) = refused {
        let (status, body, cors_origin) =
            refusals::respond(&request, &refusal, client.local_addr().ok(), config, reads);
        return Some(json_response(
            status,
            &body,
            config.dashboard_build.as_deref(),
            cors_origin.as_deref(),
            false,
        ));
    }
    let error = if refusals::post_checks_caller_first(&request) {
        "body_too_large"
    } else {
        "request_body_too_large"
    };
    let cors_origin = authorize_origin(&request).and_then(|caller| caller.cors_origin);
    Some(json_response(
        413,
        &serde_json::json!({ "error": error }),
        config.dashboard_build.as_deref(),
        cors_origin.as_deref(),
        false,
    ))
}

/// How long a client still sending its request has to finish it.
const SLOW_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The head length of `read` when it holds one whole request: a head and
/// exactly the body it declares, sent without chunking.
fn whole_request(read: &[u8]) -> Option<usize> {
    let head_len = super::replay::find_head_end(read)?;
    let head = parse_request(&read[..head_len])?;
    if head.has_header("Transfer-Encoding") {
        return None;
    }
    let body = read.len() - head_len;
    match super::replay::content_length(&read[..head_len]) {
        Some(length) => (length == body).then_some(head_len),
        None => (body == 0 && !head.has_header("Content-Length")).then_some(head_len),
    }
}

/// Answers the request `bytes` holds, whose head is `head_len` bytes long.
fn answer_request(
    client: &TcpStream,
    bytes: Vec<u8>,
    head_len: usize,
    config: &ReadConfig,
    reads: &NativeReads,
    stalled_write: Duration,
) -> Outcome {
    let (head, body) = bytes.split_at(head_len);
    let request = parse_request(head);
    if reads.is_standalone() && request.as_ref().is_some_and(is_public_health_probe) {
        // `_public_healthz_payload`: the probe every launcher and hook makes
        // before trusting the published state, within a one-second budget.
        let response = json_response(
            200,
            &serde_json::json!({"ok": true, "compatibility_version": DAEMON_COMPATIBILITY_VERSION}),
            config.dashboard_build.as_deref(),
            None,
            false,
        );
        return write_answer(client, &response, reads, stalled_write);
    }
    if let Some(opened) = request
        .as_ref()
        .and_then(|request| streams::opens(request, config))
    {
        let (stream, cors_origin) = match opened {
            Ok(opened) => opened,
            Err(response) => return write_answer(client, &response, reads, stalled_write),
        };
        streams::serve(
            client,
            stream,
            cors_origin.as_deref(),
            config,
            reads,
            stalled_write,
        );
        reads.report_activity();
        return Outcome::Answered;
    }
    if reads.is_standalone()
        && request.as_ref().is_some_and(|request| {
            request.method == "POST" && request.path == identity::CHALLENGE_PATH
        })
    {
        return identity::serve(client, body, config, reads, stalled_write);
    }
    if let Some(request) = request.as_ref().filter(|request| {
        reads.is_standalone() && request.method == "POST" && direct_hook::owns(request.path)
    }) {
        if let Some(response) = direct_hook::respond(request, body, config) {
            return write_answer(client, &response, reads, stalled_write);
        }
        if let Some(response) = hook_review_response(client, request, body, config, reads) {
            return write_answer(client, &response, reads, stalled_write);
        }
        return Outcome::Relay(bytes);
    }
    if let Some(request) = request.as_ref().filter(|request| {
        reads.is_standalone() && request.method == "POST" && hook_review::owns(request.path)
    }) {
        // A Codex or Claude Code hook without a redeemed proof, and every
        // hook readiness check.
        let Some(response) = hook_review_response(client, request, body, config, reads) else {
            return Outcome::Relay(bytes);
        };
        return write_answer(client, &response, reads, stalled_write);
    }
    if let Some(request) = request
        .as_ref()
        .filter(|request| request.method == "GET" && request.path == "/v1/evidence/export")
    {
        let Some(response) = export_response(request, config, reads) else {
            return Outcome::Relay(bytes);
        };
        return write_answer(client, &response, reads, stalled_write);
    }
    if let Some(request) = request
        .as_ref()
        .filter(|request| request.method == "POST" && request.path == "/v1/healthz/verify")
    {
        let port = client.local_addr().map(|address| address.port()).ok();
        let Some(response) = port.and_then(|port| verify_response(request, body, port, config))
        else {
            return Outcome::Relay(bytes);
        };
        return write_answer(client, &response, reads, stalled_write);
    }
    if let Some(request) = request
        .as_ref()
        .filter(|request| matches!(request.method, "GET" | "POST") && discovery::owns(request.path))
    {
        let response = discovery_response(request, body, config, reads);
        return write_answer(client, &response, reads, stalled_write);
    }
    if let Some(request) = request
        .as_ref()
        .filter(|request| request.method == "GET" && releases::owns(request.path))
    {
        let response = releases_response(request, config, reads).unwrap_or_else(|| {
            // `do_GET` refuses a caller without the token before the route.
            let refusal = refusals::refusal(request, body, &config.token)
                .unwrap_or(refusals::Refusal::Unauthorized);
            let (status, body, cors_origin) =
                refusals::respond(request, &refusal, client.local_addr().ok(), config, reads);
            json_response(
                status,
                &body,
                config.dashboard_build.as_deref(),
                cors_origin.as_deref(),
                false,
            )
        });
        return write_answer(client, &response, reads, stalled_write);
    }
    if let Some(request) = request
        .as_ref()
        .filter(|request| request.method == "GET" && dashboard::owns(request.path))
    {
        let refused = (!dashboard::is_public_static(request.path))
            .then(|| refusals::refusal(request, body, &config.token))
            .flatten();
        if let Some(refusal) = refused {
            let (status, body, cors_origin) =
                refusals::respond(request, &refusal, client.local_addr().ok(), config, reads);
            let response = json_response(
                status,
                &body,
                config.dashboard_build.as_deref(),
                cors_origin.as_deref(),
                false,
            );
            return write_answer(client, &response, reads, stalled_write);
        }
        if let Some(response) = dashboard::respond(
            request,
            config.dashboard_dir.as_deref(),
            &config.token,
            config.dashboard_build.as_deref(),
        ) {
            return write_answer(client, &response, reads, stalled_write);
        }
    }
    let answer = request.as_ref().and_then(|request| match request.method {
        // The daemon has no `DELETE` handler behind the edge, so every one is
        // answered here.
        "DELETE" => writes::respond(request, body, client.local_addr().ok(), config, reads)
            .or_else(|| {
                let refusal = refusals::delete_refusal(request);
                let (status, body, cors_origin) =
                    refusals::respond(request, &refusal, client.local_addr().ok(), config, reads);
                Some((status, body, cors_origin, false))
            }),
        "POST" => writes::respond(request, body, client.local_addr().ok(), config, reads),
        _ => respond(request, client.local_addr().ok(), config, reads),
    });
    let answer = answer.or_else(|| {
        // A standalone daemon has no server behind it to refuse a caller
        // without the token or from a disallowed origin.
        let request = request.as_ref().filter(|_| reads.is_standalone())?;
        let refusal = refusals::refusal(request, body, &config.token)
            .or_else(|| refusals::credential_refusal(request, &config.token))?;
        let (status, body, cors_origin) =
            refusals::respond(request, &refusal, client.local_addr().ok(), config, reads);
        Some((status, body, cors_origin, false))
    });
    let Some((status, body, cors_origin, no_store)) = answer else {
        return Outcome::Relay(bytes);
    };
    if status == writes::DROPPED {
        return Outcome::Answered;
    }
    let mut response = json_response(
        status,
        &body,
        config.dashboard_build.as_deref(),
        cors_origin.as_deref(),
        no_store,
    );
    if no_store
        && request
            .as_ref()
            .is_some_and(|request| dispatch::MAX_AGE_ZERO_PATHS.contains(&request.path))
    {
        response = max_age_zero(response);
    }
    write_answer(client, &response, reads, stalled_write)
}

/// `GUARD_DAEMON_COMPATIBILITY_VERSION`.
pub(super) const DAEMON_COMPATIBILITY_VERSION: i64 = 2;

/// A bodiless `GET /healthz` with no `Origin`. A browser's probe carries an
/// origin the daemon checks first, so it is replayed.
fn is_public_health_probe(request: &Request<'_>) -> bool {
    request.method == "GET"
        && request.path == "/healthz"
        && !request.has_header("Origin")
        && !request.has_header("Content-Length")
        && !request.has_header("Transfer-Encoding")
}

/// `do_DELETE` and a guarded `do_POST` checked the caller before reading a
/// body, so a request whose body has not arrived is refused on its head when
/// the caller is not authorized.
fn early_refusal(client: &TcpStream, config: &ReadConfig, reads: &NativeReads) -> Option<Vec<u8>> {
    if !reads.is_standalone() {
        return None;
    }
    let head = super::http::waiting_head(client)?;
    let request = parse_request(&head)?;
    let refusal = if request.method == "DELETE" {
        if super::auth::authorize_write(&request, &config.token).is_some() {
            return None;
        }
        refusals::delete_refusal(&request)
    } else if refusals::post_checks_caller_first(&request) {
        // `_require_auth` runs before `_load_request_body`, so a caller the
        // header check refuses never waits for its body to be read.
        refusals::refusal(&request, &[], &config.token)?
    } else {
        return None;
    };
    let (status, body, cors_origin) =
        refusals::respond(&request, &refusal, client.local_addr().ok(), config, reads);
    Some(json_response(
        status,
        &body,
        config.dashboard_build.as_deref(),
        cors_origin.as_deref(),
        false,
    ))
}

fn write_answer(
    client: &TcpStream,
    response: &[u8],
    reads: &NativeReads,
    stalled_write: Duration,
) -> Outcome {
    let mut writer = client;
    let _ = client.set_write_timeout(Some(stalled_write));
    let _ = writer.write_all(response);
    let _ = client.shutdown(Shutdown::Both);
    reads.report_activity();
    Outcome::Answered
}

/// `GET /v1/evidence/export` as the daemon writes it: the export body with
/// only its content type, or the daemon's JSON error.
fn export_response(
    request: &Request<'_>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<Vec<u8>> {
    if request.has_header("Content-Length") || request.has_header("Transfer-Encoding") {
        return None;
    }
    let caller = authorize(request, &config.token)?;
    reads.report_activity();
    Some(
        match evidence::export::export(request.query, config, reads)? {
            evidence::export::Export::Error(status, body) => json_response(
                status,
                &body,
                config.dashboard_build.as_deref(),
                caller.cors_origin.as_deref(),
                false,
            ),
            evidence::export::Export::Body(content_type, body) => {
                let mut bytes = format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                bytes.extend_from_slice(body.as_bytes());
                bytes
            }
        },
    )
}

/// The release feed behind the daemon's token check: the
/// projector's body verbatim and uncached, or the daemon's JSON error.
fn releases_response(
    request: &Request<'_>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<Vec<u8>> {
    let caller = authorize(request, &config.token)?;
    reads.report_activity();
    let build = config.dashboard_build.as_deref();
    let cors_origin = caller.cors_origin.as_deref();
    Some(match releases::read(request) {
        releases::Answer::Error(status, body) => {
            json_response(status, &body, build, cors_origin, false)
        }
        releases::Answer::Body(body) => encoded_response(200, body, build, cors_origin, true),
    })
}

/// `POST /v1/healthz/verify`: the HMAC of `"{port}:{nonce}"` under the auth
/// secret, which proves to a hook that this listener is the daemon that holds
/// it. Binding the port stops a relay on another port from reusing the proof.
fn verify_response(
    request: &Request<'_>,
    body: &[u8],
    port: u16,
    config: &ReadConfig,
) -> Option<Vec<u8>> {
    use hmac::{Hmac, Mac};
    let build = config.dashboard_build.as_deref();
    let Some(caller) = authorize_origin(request) else {
        let body = serde_json::json!({"error": "forbidden_origin"});
        return Some(json_response(403, &body, build, None, false));
    };
    let cors_origin = caller.cors_origin.as_deref();
    let payload = match writes::py_payload(request, body) {
        Ok(payload) => payload,
        Err(error) => {
            let (status, body) = error.answer();
            return Some(json_response(status, &body, build, cors_origin, false));
        }
    };
    let nonce = payload
        .iter()
        .rev()
        .find(|(key, _)| key == "nonce")
        .and_then(|(_, value)| value.as_str())
        .map(str::trim)
        .filter(|nonce| !nonce.is_empty());
    let Some(nonce) = nonce else {
        let body = serde_json::json!({"error": "missing_nonce"});
        return Some(json_response(400, &body, build, cors_origin, false));
    };
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&config.token).ok()?;
    mac.update(format!("{port}:{nonce}").as_bytes());
    let proof = hex::encode(mac.finalize().into_bytes());
    let body = serde_json::json!({"proof": proof});
    Some(json_response(200, &body, build, cors_origin, false))
}

/// The daemon's sponsored discovery routes behind its header-token check. A
/// `token` query parameter goes to the daemon, which records the refusal.
fn discovery_response(
    request: &Request<'_>,
    body: &[u8],
    config: &ReadConfig,
    reads: &NativeReads,
) -> Vec<u8> {
    let build = config.dashboard_build.as_deref();
    let refused = |refusal: refusals::Refusal| {
        let (status, body, cors_origin) = refusals::respond(request, &refusal, None, config, reads);
        json_response(status, &body, build, cors_origin.as_deref(), false)
    };
    if request.method == "POST" && authorize_origin(request).is_none() {
        return json_response(
            403,
            &serde_json::json!({"error": "forbidden_origin"}),
            build,
            None,
            false,
        );
    }
    if discovery::query_names_token(request.query) {
        return refused(refusals::Refusal::QueryToken);
    }
    let Some(caller) = authorize_token(request, &config.token) else {
        return refused(refusals::Refusal::Unauthorized);
    };
    let cors_origin = caller.cors_origin.as_deref();
    let answer = if request.method == "GET" {
        reads.report_activity();
        discovery::read(request, config, reads)
    } else {
        let payload = match writes::py_payload(request, body) {
            Ok(payload) => payload,
            Err(error) => {
                let (status, body) = error.answer();
                return json_response(status, &body, build, cors_origin, false);
            }
        };
        reads.report_activity();
        discovery::write(request, Some(&payload), config, reads)
    };
    match answer {
        Some(discovery::Answer::Json(status, body)) => {
            json_response(status, &body, build, cors_origin, false)
        }
        Some(discovery::Answer::Raw(status, body)) => {
            encoded_response(status, body, build, cors_origin, true)
        }
        // The preference store did not answer, which the daemon's handler
        // raised on.
        None => json_response(
            503,
            &serde_json::json!({"error": "daemon_route_unavailable"}),
            build,
            cors_origin,
            false,
        ),
    }
}

/// The response the daemon's `_write_json` writes: HTML-safe JSON, `nosniff`,
/// the dashboard build stamp and, for an allowed `Origin`, its CORS headers.
/// The daemon's own review of a hook its connection did not prove.
fn hook_review_response(
    client: &TcpStream,
    request: &Request<'_>,
    body: &[u8],
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<Vec<u8>> {
    let port = client.local_addr().ok()?.port();
    hook_review::respond(request, body, port, config, reads, false)
}

pub(super) fn json_response(
    status: u16,
    body: &Value,
    dashboard_build: Option<&str>,
    cors_origin: Option<&str>,
    no_store: bool,
) -> Vec<u8> {
    let encoded = serde_json::to_vec(body).unwrap_or_else(|_| b"null".to_vec());
    encoded_response(status, encoded, dashboard_build, cors_origin, no_store)
}

/// [`json_response`] for a body that is already encoded JSON.
pub(super) fn encoded_response(
    status: u16,
    encoded: Vec<u8>,
    dashboard_build: Option<&str>,
    cors_origin: Option<&str>,
    no_store: bool,
) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(encoded.len());
    for byte in encoded {
        match byte {
            b'&' => escaped.extend_from_slice(b"\\u0026"),
            b'<' => escaped.extend_from_slice(b"\\u003c"),
            b'>' => escaped.extend_from_slice(b"\\u003e"),
            byte => escaped.push(byte),
        }
    }
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Not Found",
    };
    let mut response = format!(
        "HTTP/1.0 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\n",
        escaped.len()
    );
    if let Some(origin) = cors_origin {
        response.push_str(&format!(
            "Access-Control-Allow-Origin: {origin}\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: {CORS_ALLOW_HEADERS}\r\nAccess-Control-Allow-Private-Network: true\r\nVary: Origin\r\n"
        ));
    }
    if let Some(build) = dashboard_build {
        response.push_str(&format!("X-Guard-Dashboard-Build: {build}\r\n"));
    }
    if no_store {
        response.push_str("Cache-Control: no-store\r\n");
    }
    response.push_str("Connection: close\r\n\r\n");
    let mut bytes = response.into_bytes();
    bytes.extend_from_slice(&escaped);
    bytes
}

/// `response` with its `Cache-Control: no-store` header forbidding
/// revalidation too, as the daemon's update status read did.
fn max_age_zero(response: Vec<u8>) -> Vec<u8> {
    const PLAIN: &[u8] = b"Cache-Control: no-store\r\n";
    const ZERO: &[u8] = b"Cache-Control: no-store, max-age=0\r\n";
    let Some(at) = response
        .windows(PLAIN.len())
        .position(|window| window == PLAIN)
    else {
        return response;
    };
    let mut patched = Vec::with_capacity(response.len() + ZERO.len() - PLAIN.len());
    patched.extend_from_slice(&response[..at]);
    patched.extend_from_slice(ZERO);
    patched.extend_from_slice(&response[at + PLAIN.len()..]);
    patched
}

#[path = "daemon_edge_reads_routes.rs"]
mod routes;
use routes::{read_state, respond};

#[path = "daemon_edge_evidence.rs"]
mod evidence;

#[path = "daemon_edge_identity.rs"]
mod identity;

#[path = "daemon_edge_hook_review.rs"]
mod hook_review;
#[path = "daemon_edge_hook_scheduler.rs"]
mod hook_scheduler;

#[path = "daemon_edge_direct_hook.rs"]
mod direct_hook;

#[path = "daemon_edge_records.rs"]
mod records;

#[path = "daemon_edge_inventory.rs"]
mod inventory;

#[path = "daemon_edge_activity.rs"]
mod activity;

#[path = "daemon_edge_requests.rs"]
mod requests;

#[path = "daemon_edge_business.rs"]
mod business;

#[path = "daemon_edge_recommend.rs"]
mod recommend;

#[path = "daemon_edge_settings.rs"]
mod settings;

#[path = "daemon_edge_dashboard.rs"]
mod dashboard;
#[path = "daemon_edge_discovery.rs"]
mod discovery;
#[path = "daemon_edge_network.rs"]
mod network;
#[path = "daemon_edge_plugin_updates.rs"]
mod plugin_updates;
#[path = "daemon_edge_refusals.rs"]
mod refusals;
#[path = "daemon_edge_releases.rs"]
mod releases;

#[path = "daemon_edge_composed.rs"]
mod composed;
#[path = "daemon_edge_dispatch.rs"]
mod dispatch;
#[path = "daemon_edge_health_details.rs"]
mod health_details;
#[path = "daemon_edge_streams.rs"]
mod streams;
#[path = "daemon_edge_writes.rs"]
mod writes;

#[cfg(all(test, unix))]
#[path = "daemon_edge_reads_tests.rs"]
mod tests;
