//! Standalone native daemon (`daemon-serve-v1`).
//!
//! `guard-runtime daemon-serve` is the Guard daemon process itself: it binds
//! the loopback port, keeps the Guard home's auth secret and signed discovery
//! state, and serves every connection through the edge's native routes, with
//! the requests it does not answer replayed through the daemon's own Guard
//! CLI handler. No Python daemon process stays resident.
//!
//! The launcher writes one JSON line on standard input (see [`LaunchConfig`])
//! and closes it. Nothing secret travels in that line: the daemon loads the
//! auth secret from the Guard home, creating it when absent, exactly as every
//! daemon for one Guard home must share it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::reads::{NativeReads, HANDSHAKE_SCHEMA};
use super::{serve, MAX_ACTIVE_CONNECTIONS, STALLED_WRITE_TIMEOUT};
use crate::daemon_policy_authority::{canonical_discovery_payload, hmac_sha256_raw};

#[path = "daemon_edge_workers.rs"]
mod workers;

pub(crate) const SERVE_COMMAND: &str = "daemon-serve";
pub(crate) const SERVE_FEATURE: &str = "daemon-serve-v1";
pub(super) const LAUNCH_SCHEMA: &str = "guard-daemon-serve-launch.v1";

const MAX_LAUNCH_BYTES: u64 = 64 * 1024;
const DISCOVERY_PROTOCOL_VERSION: i64 = 1;
const DISCOVERY_KEY_FILE: &str = "daemon-discovery-key";
const AUTH_SECRET_FILE: &str = "daemon-auth-token";
const STATE_FILE: &str = "daemon-state.json";
const STATE_WRITE_LOCK_FILE: &str = "daemon-state-write.lock";
#[cfg(unix)]
const PRIVATE_FILE_MODE: u32 = 0o600;
#[cfg(unix)]
const PRIVATE_DIR_MODE: u32 = 0o700;
const MAX_PRIVATE_FILE_BYTES: u64 = 4096;

const EXIT_USAGE: i32 = 2;
const EXIT_LISTENER: i32 = 3;
const EXIT_STATE: i32 = 4;

/// What the launcher tells a new daemon. `state` carries the facts only the
/// launcher knows (its package version, executable and runtime fingerprint);
/// the daemon adds its own process identity before signing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LaunchConfig {
    schema: String,
    guard_home: String,
    #[serde(default = "default_host")]
    host: String,
    port: u16,
    store_path: String,
    source: String,
    busy_timeout_ms: u64,
    #[serde(default)]
    dashboard_build: Option<String>,
    #[serde(default)]
    user_home: Option<String>,
    #[serde(default)]
    session_signals: Option<Vec<String>>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    daemon_fingerprint: Option<String>,
    cli_command: Vec<String>,
    #[serde(default)]
    launch_nonce: Option<String>,
    /// Run the daemon's background jobs (`daemon_edge_workers.rs`).
    #[serde(default)]
    workers: bool,
    /// Stop after this long with nothing served and no durable work held.
    #[serde(default)]
    idle_timeout_seconds: Option<f64>,
    /// The launcher process that waits on this one and holds its standard
    /// input open, where the platform cannot exec (Windows). The daemon names
    /// it as its pid and stops when that input closes.
    #[serde(default)]
    launcher_pid: Option<u32>,
    state: Map<String, Value>,
}

fn default_host() -> String {
    "127.0.0.1".to_owned()
}

impl LaunchConfig {
    pub(super) fn parse(line: &[u8]) -> Option<Self> {
        let config: Self = serde_json::from_slice(line).ok()?;
        let reserved = [
            "guard_home",
            "host",
            "port",
            "pid",
            "started_at",
            "state_id",
            "auth_token_id",
            "process_start_marker",
            "user",
            "owner",
            "launch_nonce",
            "launch_generation",
            "generation",
            "discovery_protocol_version",
            "discovery_key_id",
            "state_signature",
        ];
        let valid = config.schema == LAUNCH_SCHEMA
            && Path::new(&config.guard_home).is_absolute()
            && Path::new(&config.store_path).is_absolute()
            && config
                .host
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
            && !config.cli_command.is_empty()
            && config
                .launch_nonce
                .as_deref()
                .is_none_or(launch_nonce_is_valid)
            && !config
                .state
                .keys()
                .any(|key| reserved.contains(&key.as_str()));
        valid.then_some(config)
    }

    /// The handshake line the edge's native reads accept.
    fn handshake(&self, secret: &str) -> Vec<u8> {
        let mut handshake = Map::new();
        handshake.insert("schema".into(), HANDSHAKE_SCHEMA.into());
        handshake.insert(format!("{}_{}", "auth", "token"), secret.into());
        handshake.insert("guard_home".into(), self.guard_home.clone().into());
        handshake.insert("store_path".into(), self.store_path.clone().into());
        handshake.insert("source".into(), self.source.clone().into());
        handshake.insert("busy_timeout_ms".into(), self.busy_timeout_ms.into());
        let optional = [
            (
                "dashboard_build",
                self.dashboard_build.clone().map(Value::from),
            ),
            ("user_home", self.user_home.clone().map(Value::from)),
            (
                "session_signals",
                self.session_signals.clone().map(Value::from),
            ),
            ("cwd", self.cwd.clone().map(Value::from)),
            (
                "daemon_fingerprint",
                self.daemon_fingerprint.clone().map(Value::from),
            ),
        ];
        for (name, value) in optional {
            if let Some(value) = value {
                handshake.insert(name.into(), value);
            }
        }
        handshake.insert("cli_command".into(), self.cli_command.clone().into());
        serde_json::to_vec(&Value::Object(handshake)).unwrap_or_default()
    }
}

/// `_launch_nonce_is_valid`: 64 lowercase hex characters.
/// Stops the daemon once the launcher that holds its standard input open
/// exits, however it exits: the input then reaches end of file.
fn exit_when_launcher_leaves() {
    let spawned = std::thread::Builder::new()
        .name("daemon-launcher-watch".to_owned())
        .spawn(|| {
            let _ = io::copy(&mut io::stdin().lock(), &mut io::sink());
            std::process::exit(0);
        });
    if spawned.is_err() {
        std::process::exit(EXIT_USAGE);
    }
}

fn launch_nonce_is_valid(nonce: &str) -> bool {
    nonce.len() == 64
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `daemon-serve --guard-home H --port P`: both repeat the launch
/// configuration so process inventory can name the daemon from its command
/// line alone, as it does a Python daemon's.
pub(super) fn parse_args(args: &[String]) -> Option<(String, u16)> {
    match args {
        [home_flag, home, port_flag, port]
            if home_flag == "--guard-home" && port_flag == "--port" =>
        {
            Some((home.clone(), port.parse().ok()?))
        }
        _ => None,
    }
}

pub(crate) fn run(args: &[String]) -> i32 {
    let Some((arg_home, arg_port)) = parse_args(args) else {
        eprintln!("usage: guard-runtime daemon-serve --guard-home H --port P < launch.json");
        return EXIT_USAGE;
    };
    let mut line = Vec::new();
    if io::stdin()
        .lock()
        .take(MAX_LAUNCH_BYTES)
        .read_until(b'\n', &mut line)
        .is_err()
    {
        return EXIT_USAGE;
    }
    let Some(config) = LaunchConfig::parse(line.trim_ascii()) else {
        eprintln!("daemon-serve: the launch configuration is invalid");
        return EXIT_USAGE;
    };
    if config.guard_home != arg_home || config.port != arg_port {
        eprintln!("daemon-serve: the launch configuration names another daemon");
        return EXIT_USAGE;
    }
    let host: IpAddr = config
        .host
        .parse()
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let listener = match TcpListener::bind(SocketAddr::new(host, config.port)) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("daemon-serve: cannot listen: {error}");
            return EXIT_LISTENER;
        }
    };
    let Ok(port) = listener.local_addr().map(|address| address.port()) else {
        return EXIT_LISTENER;
    };
    let home = PathBuf::from(&config.guard_home);
    let pid = config
        .launcher_pid
        .filter(|pid| *pid != 0)
        .unwrap_or_else(std::process::id);
    let secret = match publish(&home, &config, port, pid) {
        Ok(secret) => secret,
        Err(error) => {
            eprintln!("daemon-serve: cannot publish daemon state: {error}");
            return EXIT_STATE;
        }
    };
    let reads = Arc::new(NativeReads::new(None));
    reads.mark_standalone();
    if let Some(state_id) = crate::daemon_policy_authority::load_authenticated_daemon_state(&home)
        .and_then(|state| state.get("state_id")?.as_str().map(str::to_owned))
    {
        reads.set_state_id(state_id);
    }
    if config.launcher_pid.is_some_and(|pid| pid != 0) {
        reads.set_launcher_pid(pid);
        exit_when_launcher_leaves();
    }
    reads.accept_handshake(&config.handshake(&secret));
    drop(secret);
    if config.workers {
        // Guard-owned hooks and launchers are brought in line with this
        // runtime before the daemon reports ready, as its start always did.
        workers::reconcile_artifacts(&reads, config.user_home.as_deref());
        workers::start(
            &reads,
            workers::Registration {
                session_id: random_hex(16),
                host: config.host.clone(),
                port,
                started_at: now_iso(),
            },
            config
                .idle_timeout_seconds
                .filter(|seconds| seconds.is_finite() && *seconds > 0.0)
                .map(std::time::Duration::from_secs_f64),
        );
    }
    println!("{}", json!({"port": port, "pid": pid}));
    let _ = io::stdout().flush();
    match serve(
        &listener,
        None,
        MAX_ACTIVE_CONNECTIONS,
        STALLED_WRITE_TIMEOUT,
        reads,
    ) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("daemon-serve: listener failed: {error}");
            EXIT_LISTENER
        }
    }
}

/// Ensures the Guard home's discovery key and auth secret, then writes the
/// signed daemon state naming this process. Returns the auth secret.
pub(super) fn publish(
    home: &Path,
    config: &LaunchConfig,
    port: u16,
    pid: u32,
) -> io::Result<String> {
    ensure_private_directory(home)?;
    let _lock = StateWriteLock::acquire(home)?;
    let key = ensure_discovery_key(home)?;
    let secret = ensure_auth_secret(home)?;
    let payload = state_payload(home, config, port, pid, &secret);
    let signed = sign_state(payload, &key)?;
    let text = serde_json::to_string_pretty(&Value::Object(signed)).map_err(io::Error::other)?;
    write_private_atomic(&home.join(STATE_FILE), text.as_bytes())?;
    Ok(secret)
}

fn state_payload(
    home: &Path,
    config: &LaunchConfig,
    port: u16,
    pid: u32,
    secret: &str,
) -> Map<String, Value> {
    let mut payload = config.state.clone();
    let resolved = fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    payload.insert(
        "guard_home".into(),
        resolved.to_string_lossy().into_owned().into(),
    );
    payload.insert("host".into(), config.host.clone().into());
    payload.insert("port".into(), port.into());
    payload.insert("pid".into(), pid.into());
    payload.insert("started_at".into(), now_iso().into());
    payload.insert("state_id".into(), random_hex(16).into());
    payload.insert(
        format!("{}_{}_id", "auth", "token"),
        hex::encode(Sha256::digest(secret.as_bytes())).into(),
    );
    if let Some(marker) = crate::codex_hook_identity::process_start_token(pid) {
        payload.insert("process_start_marker".into(), marker.into());
    }
    if let Some(owner) = crate::codex_hook_identity::process_owner_marker(pid) {
        payload.insert("user".into(), owner.clone().into());
        payload.insert("owner".into(), owner.into());
    }
    if let Some(nonce) = &config.launch_nonce {
        for field in ["launch_nonce", "launch_generation", "generation"] {
            payload.insert(field.into(), nonce.clone().into());
        }
    }
    payload
}

/// `authenticate_daemon_state`: binds the payload to the discovery key.
pub(super) fn sign_state(
    mut payload: Map<String, Value>,
    key: &str,
) -> io::Result<Map<String, Value>> {
    let key_bytes = hex::decode(key)
        .ok()
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed discovery key"))?;
    payload.insert(
        "discovery_protocol_version".into(),
        DISCOVERY_PROTOCOL_VERSION.into(),
    );
    payload.insert(
        "discovery_key_id".into(),
        hex::encode(Sha256::digest(&key_bytes)).into(),
    );
    let signature = hex::encode(hmac_sha256_raw(
        &key_bytes,
        &canonical_discovery_payload(&payload),
    ));
    payload.insert("state_signature".into(), signature.into());
    Ok(payload)
}

fn now_iso() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    crate::approval_gate_state::iso_from_epoch(elapsed.as_micros() as f64 / 1_000_000.0)
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    if getrandom::fill(&mut buffer).is_err() {
        // No entropy means no unguessable identity; never publish a fixed one.
        std::process::exit(EXIT_STATE);
    }
    hex::encode(buffer)
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    set_private_directory(path)
}

/// Opening private files without following a link, and creating them
/// readable by this user only.
trait PrivateOpen {
    fn no_follow(&mut self) -> &mut Self;
    fn private_mode(&mut self) -> &mut Self;
}

#[cfg(unix)]
impl PrivateOpen for OpenOptions {
    fn no_follow(&mut self) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::custom_flags(self, libc::O_NOFOLLOW)
    }

    fn private_mode(&mut self) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, PRIVATE_FILE_MODE)
    }
}

/// `FILE_FLAG_OPEN_REPARSE_POINT`: a link is opened as itself, then refused
/// as not a regular file. Files under the Guard home inherit the profile's
/// per-user access list.
#[cfg(windows)]
impl PrivateOpen for OpenOptions {
    fn no_follow(&mut self) -> &mut Self {
        std::os::windows::fs::OpenOptionsExt::custom_flags(self, 0x0020_0000)
    }

    fn private_mode(&mut self) -> &mut Self {
        self
    }
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
}

#[cfg(windows)]
fn set_private_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// A regular file this user owns that no one else can read or write.
#[cfg(unix)]
fn is_private_file(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    metadata.is_file()
        && metadata.uid() == nix::unistd::getuid().as_raw()
        && metadata.permissions().mode() & 0o077 == 0
}

#[cfg(windows)]
fn is_private_file(metadata: &fs::Metadata) -> bool {
    metadata.is_file() && !metadata.file_type().is_symlink()
}

/// The process-wide lock every daemon state writer takes
/// (`_guard_daemon_state_write_lock`).
struct StateWriteLock(File);

impl StateWriteLock {
    fn acquire(home: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .no_follow()
            .open(home.join(STATE_WRITE_LOCK_FILE))?;
        file.lock_exclusive()?;
        Ok(Self(file))
    }
}

impl Drop for StateWriteLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

/// The contents of a private regular file this user owns, or `None` when it
/// does not exist. Anything else (a link, another owner, open permissions) is
/// an error rather than a file to trust or replace.
fn read_private(path: &Path) -> io::Result<Option<String>> {
    let file = match OpenOptions::new().read(true).no_follow().open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !is_private_file(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not a private regular file",
        ));
    }
    let mut text = String::new();
    file.take(MAX_PRIVATE_FILE_BYTES)
        .read_to_string(&mut text)?;
    Ok(Some(text))
}

/// `ensure_daemon_discovery_key`.
fn ensure_discovery_key(home: &Path) -> io::Result<String> {
    let path = home.join(DISCOVERY_KEY_FILE);
    if let Some(existing) = read_private(&path)? {
        return Ok(existing.trim().to_owned());
    }
    let encoded = random_hex(32);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .private_mode()
        .no_follow()
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(encoded.as_bytes())?;
            file.sync_all()?;
            Ok(encoded)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_private(&path)?
            .map(|raced| raced.trim().to_owned())
            .ok_or_else(|| io::Error::other("discovery key is not a private regular file")),
        Err(error) => Err(error),
    }
}

/// `ensure_guard_daemon_auth_token`: the Guard home's shared secret, created
/// only when absent. The caller holds the state write lock.
fn ensure_auth_secret(home: &Path) -> io::Result<String> {
    let path = home.join(AUTH_SECRET_FILE);
    if let Some(existing) = read_private(&path)? {
        let existing = existing.trim();
        if !existing.is_empty() {
            return Ok(existing.to_owned());
        }
    }
    let secret = random_hex(16);
    write_private_atomic(&path, secret.as_bytes())?;
    Ok(secret)
}

/// `_write_private_atomic_text`: a private temporary file beside `path`,
/// synced, then renamed over it.
pub(super) fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temporary = parent.join(format!(".{name}.{}", random_hex(8)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .private_mode()
            .no_follow()
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_serve_tests.rs"]
mod tests;
