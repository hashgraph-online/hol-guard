//! Local stdio MCP catalog probe + bounded JSON-RPC mediation.
//!
//! Byte-parity port of
//! `src/codex_plugin_scanner/guard/runtime/local_mcp_stdio.py` and the launch
//! resolution of `runtime/local_mcp_probe.py`. The probe launches a candidate
//! stdio MCP server, negotiates `server/discover` (modern 2026-07-28) with a
//! legacy `initialize` fallback (2025-11-25 + older), performs bounded
//! `tools/list` cursor pagination, optionally lists the declared skills
//! extension, and tears the process group down on every exit path.
//!
//! `#[cfg(unix)]` because the launch attributes and process-group teardown are
//! unix-only.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const _PROTOCOL: &str = "2025-11-25";
const _MODERN_PROTOCOL: &str = "2026-07-28";
const _LEGACY_PROTOCOLS: &[&str] = &["2024-11-05", "2025-03-26", "2025-06-18", _PROTOCOL];
const _MODERN_ERROR_CODES: &[i64] = &[-32020, -32021, -32022];

const MCP_PROBE_OUTPUT_LIMIT: usize = 1_000_000;
const MAX_MCP_PROBE_TOOLS: usize = 100;
const _MAX_PAGES: usize = 8;
const _MAX_QUEUE: usize = 256;
const _MAX_SKILL_METADATA: usize = 512_000;
const _SKILL_EXTENSION: &str = "io.modelcontextprotocol/skills";
const _MIN_SKILLS_VERSION: (i64, u32, u32) = (2026, 7, 28);

/// `is_strict_package_mcp_launcher` (`local_mcp_probe.py:100`) — restricted
/// resolver surface that may invoke a shim package.
const _STRICT_PACKAGE_LAUNCHERS: &[&str] = &["bunx", "npx", "pipx", "uvx"];

pub fn probe_search_path() -> String {
    let fallback = std::env::var("PATH")
        .unwrap_or_else(|_| "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin".to_owned());
    let mut filtered: Vec<String> = fallback
        .split(':')
        .filter(|e| !e.is_empty() && !is_package_shim_dir(e))
        .map(str::to_owned)
        .collect();
    for extra in &["/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/local/bin"] {
        let p = Path::new(extra);
        if !filtered.iter().any(|e| e == extra) && p.is_dir() {
            filtered.push((*extra).to_owned());
        }
    }
    filtered.join(":")
}

/// `is_package_shim_executable` — true when `path` lives inside
/// `<something>/package-shims/bin`.
pub fn is_package_shim_executable(path: &str) -> bool {
    let candidate = Path::new(path);
    candidate
        .parent()
        .and_then(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n == "bin")
                .and_then(|_| p.parent())
                .and_then(|gp| {
                    gp.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n == "package-shims")
                })
        })
        .unwrap_or(false)
}

fn is_package_shim_dir(entry: &str) -> bool {
    let p = Path::new(entry);
    p.file_name().and_then(|n| n.to_str()) == Some("bin")
        && p.parent()
            .and_then(|gp| gp.file_name().and_then(|n| n.to_str()))
            == Some("package-shims")
}

fn _executable_basename(value: &str) -> String {
    let name = Path::new(value)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(value)
        .to_lowercase();
    if name.ends_with(".exe") || name.ends_with(".cmd") {
        name.rsplit_once('.')
            .map(|(s, _)| s.to_owned())
            .unwrap_or(name)
    } else {
        name
    }
}

pub fn probe_env(
    tmp: &str,
    extra: Option<&BTreeMap<String, String>>,
    home_dir: Option<&Path>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_owned(), probe_search_path());
    env.insert("HOME".to_owned(), tmp.to_owned());
    env.insert("TMPDIR".to_owned(), tmp.to_owned());
    env.insert("LANG".to_owned(), "C".to_owned());
    env.insert("LC_ALL".to_owned(), "C".to_owned());
    env.insert("TERM".to_owned(), "dumb".to_owned());
    env.insert("NO_COLOR".to_owned(), "1".to_owned());
    env.insert("PYTHONUNBUFFERED".to_owned(), "1".to_owned());
    env.insert("PYTHONDONTWRITEBYTECODE".to_owned(), "1".to_owned());
    env.insert("npm_config_update_notifier".to_owned(), "false".to_owned());
    env.insert("npm_config_fund".to_owned(), "false".to_owned());
    env.insert("NPM_CONFIG_UPDATE_NOTIFIER".to_owned(), "false".to_owned());
    env.insert("npm_config_loglevel".to_owned(), "error".to_owned());
    env.extend(_package_cache_env(home_dir));
    if let Some(extra) = extra {
        for (key, value) in extra {
            let name = key.trim();
            if name.is_empty() || _PROBE_ENV_LOCKED.contains(&name.to_ascii_uppercase().as_str()) {
                continue;
            }
            if name.contains('=') || name.contains('\0') || value.contains('\0') {
                continue;
            }
            env.insert(name.to_owned(), value.clone());
        }
    }
    env
}

fn _package_cache_env(home_dir: Option<&Path>) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    let home = home_dir.map(|p| p.to_path_buf());
    let npm_cache = home
        .as_ref()
        .map(|h| h.join(".npm/_cacache"))
        .filter(|p| p.is_dir());
    if let Some(cache) = npm_cache {
        env.insert("npm_config_cache".to_owned(), cache.display().to_string());
        env.insert("NPM_CONFIG_CACHE".to_owned(), cache.display().to_string());
    }
    env
}

const _PROBE_ENV_LOCKED: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "TERM",
    "NO_COLOR",
    "PYTHONUNBUFFERED",
    "PYTHONDONTWRITEBYTECODE",
    "NPM_CONFIG_UPDATE_NOTIFIER",
    "NPM_CONFIG_LOGLEVEL",
    "NPM_CONFIG_FUND",
    "NPM_CONFIG_CACHE",
    "BUN_INSTALL_CACHE_DIR",
    "SYSTEMROOT",
    "GITLAB_",
    "BITBUCKET_",
    "SSH_",
    "GPG_",
    "DBUS_",
    "XDG_",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "GNOME_",
    "KDE_",
    "LC_",
    "SSL_",
    "TLS_",
    "CERT_",
    "KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASS",
    "AUTH",
    "CREDENTIAL",
    "CREDENTIALS",
    "PRIVATE",
    "SESSION",
    "COOKIE",
    "BEARER",
    "API_KEY",
    "ACCESS_KEY",
    "SECRET_KEY",
    "ENCRYPTION",
    "DECRYPT",
    "SIGNING",
    "JWT",
    "OAUTH",
];

// ---------------------------------------------------------------------------
// Bounded catalog result (mirror of `McpCatalogResult`).
// ---------------------------------------------------------------------------

/// Bounded discovery evidence; a partial inventory is never a complete one.
#[derive(Debug, Clone)]
pub struct McpCatalog {
    pub tools: Vec<Value>,
    pub complete: bool,
    pub reason: Option<String>,
    pub pages: usize,
    pub protocol_version: Option<String>,
    pub server_info: Option<Value>,
    pub capabilities: Option<Value>,
    pub cache_ttl_ms: i64,
    pub cache_scope: String,
    pub cache_received_at: Option<String>,
    pub skills: Vec<Value>,
    pub skills_complete: Option<bool>,
    pub skills_reason: Option<String>,
}

impl McpCatalog {
    fn empty() -> Self {
        McpCatalog {
            tools: vec![],
            complete: false,
            reason: None,
            pages: 0,
            protocol_version: None,
            server_info: None,
            capabilities: None,
            cache_ttl_ms: 0,
            cache_scope: "private".to_owned(),
            cache_received_at: None,
            skills: vec![],
            skills_complete: None,
            skills_reason: None,
        }
    }
    fn reason_only(reason: &str) -> Self {
        let mut c = McpCatalog::empty();
        c.reason = Some(reason.to_owned());
        c
    }
    /// Serialize to the resident-op result payload consumed by
    /// `_native_catalog_result` in `local_mcp_stdio.py`.
    pub fn to_payload(&self) -> Value {
        let mut map = Map::new();
        map.insert(
            "status".to_owned(),
            json!(if self.reason.is_none() {
                "ok"
            } else {
                "failed"
            }),
        );
        map.insert("complete".to_owned(), json!(self.complete));
        map.insert(
            "reason".to_owned(),
            self.reason.clone().map(Value::from).unwrap_or(Value::Null),
        );
        map.insert("tools".to_owned(), Value::Array(self.tools.clone()));
        map.insert("pages".to_owned(), json!(self.pages));
        map.insert(
            "protocol_version".to_owned(),
            self.protocol_version
                .clone()
                .map(Value::from)
                .unwrap_or(Value::Null),
        );
        map.insert(
            "server_info".to_owned(),
            self.server_info.clone().unwrap_or(Value::Null),
        );
        map.insert(
            "capabilities".to_owned(),
            self.capabilities.clone().unwrap_or(Value::Null),
        );
        map.insert("cache_ttl_ms".to_owned(), json!(self.cache_ttl_ms));
        map.insert("cache_scope".to_owned(), json!(self.cache_scope));
        map.insert(
            "cache_received_at".to_owned(),
            self.cache_received_at
                .clone()
                .map(Value::from)
                .unwrap_or(Value::Null),
        );
        map.insert("skills".to_owned(), Value::Array(self.skills.clone()));
        map.insert(
            "skills_complete".to_owned(),
            self.skills_complete.map(Value::from).unwrap_or(Value::Null),
        );
        map.insert(
            "skills_reason".to_owned(),
            self.skills_reason
                .clone()
                .map(Value::from)
                .unwrap_or(Value::Null),
        );
        Value::Object(map)
    }
}

// ---------------------------------------------------------------------------
// Launch argv resolution (`local_mcp_probe.py::_resolve_launch_argv`).
// ---------------------------------------------------------------------------

/// Resolve a `command_text` launch spec into a concrete argv. Returns `None`
/// when the spec is not a single safe top-level invocation. Mirrors
/// `mcp_launch_tokens` + `_resolve_launch_argv`.
pub fn resolve_launch_argv(command_text: &str, cwd: &Path) -> Option<Vec<String>> {
    let tokens = mcp_launch_tokens(command_text, cwd, None)?;
    resolve_argv_from_tokens(&tokens, cwd)
}

/// `mcp_launch_tokens` (`local_mcp_probe.py:64`) — return launch tokens when
/// the pasted text is one safe invocation.
pub fn mcp_launch_tokens(
    command_text: &str,
    cwd: &Path,
    home_dir: Option<&Path>,
) -> Option<Vec<String>> {
    if command_text.trim().is_empty() {
        return None;
    }
    let model = crate::command_model::parse_shell_command(
        command_text,
        Some(cwd),
        home_dir,
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    if !unlisted_cli_invocation_is_safe(&model) || model.segments.is_empty() {
        return None;
    }
    let segment = &model.segments[0];
    let executable = segment.executable.as_ref()?;
    if executable.trim().is_empty() {
        return None;
    }
    let mut tokens = vec![executable.clone()];
    tokens.extend(segment.arguments.iter().cloned());
    Some(tokens)
}

/// `unlisted_cli_invocation_is_safe` (`local_cli_identity.py:155`) — single
/// top-level invocation without wrappers, redirects, or embedded commands.
pub fn unlisted_cli_invocation_is_safe(command: &crate::command_model::CanonicalCommand) -> bool {
    if command.confidence != "exact" {
        return false;
    }
    if !command.redirects.is_empty()
        || !command.embedded_commands.is_empty()
        || command.path_overridden()
    {
        return false;
    }
    if !command.wrapper_chain.is_empty() {
        return false;
    }
    if command.segments.len() != 1 {
        return false;
    }
    safe_primary_segment(&command.segments[0])
}

fn safe_primary_segment(segment: &crate::command_model::CommandSegment) -> bool {
    !segment.text.trim().is_empty()
        && segment
            .executable
            .as_ref()
            .map(|e| !e.trim().is_empty())
            .unwrap_or(false)
        && segment.environment_names.is_empty()
        && segment.wrapper_chain.is_empty()
        && !segment.path_overridden
}

/// `_resolve_launch_argv` (`local_mcp_probe.py:194`).
pub fn resolve_argv_from_tokens(tokens: &[String], cwd: &Path) -> Option<Vec<String>> {
    if tokens.is_empty() {
        return None;
    }
    let first = &tokens[0];
    let search_path = probe_search_path();
    let resolved: String;
    if is_package_shim_executable(first) {
        resolved = which(Path::new(first).file_name()?.to_str()?, &search_path)?;
    } else if Path::new(first).is_absolute() {
        resolved = first.clone();
    } else {
        match which(first, &search_path) {
            Some(found) => resolved = found,
            None => {
                let candidate = cwd.join(first);
                if !candidate.is_file() {
                    return None;
                }
                resolved = candidate.display().to_string();
            }
        }
    }
    let mut argv = vec![resolved];
    for token in &tokens[1..] {
        argv.push(absolute_existing_path(token, cwd));
    }
    Some(argv)
}

/// `shutil.which` equivalent over an explicit `search_path`.
fn which(name: &str, search_path: &str) -> Option<String> {
    if name.contains('/') {
        let p = Path::new(name);
        return if p.is_file() {
            Some(name.to_owned())
        } else {
            None
        };
    }
    for dir in search_path.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(candidate.display().to_string());
        }
    }
    None
}

/// `_absolute_existing_path` (`local_mcp_probe.py:216`).
fn absolute_existing_path(token: &str, cwd: &Path) -> String {
    if token.starts_with('-') || token.starts_with('@') || token.contains("://") {
        return token.to_owned();
    }
    let path = Path::new(token);
    if path.is_absolute() {
        return token.to_owned();
    }
    let candidate = cwd.join(token);
    match candidate.canonicalize() {
        Ok(resolved) if candidate.exists() => resolved.display().to_string(),
        _ => token.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Bounded JSON-RPC stdio session (`_RpcSession`).
// ---------------------------------------------------------------------------

struct RpcSession {
    stdin: std::process::ChildStdin,
    inbox: mpsc::Receiver<Value>,
    catalog_generation: u64,
    cancellation: Arc<AtomicBool>,
    _drain: Option<thread::JoinHandle<()>>,
}

impl RpcSession {
    fn spawn(child: &mut Child, cancellation: Arc<AtomicBool>) -> Option<RpcSession> {
        let stdin = child.stdin.take()?;
        let stdout = child.stdout.take()?;
        let (tx, rx) = mpsc::channel::<Value>();
        let drain = thread::spawn(move || {
            drain_stream(stdout, tx);
        });
        Some(RpcSession {
            stdin,
            inbox: rx,
            catalog_generation: 0,
            cancellation,
            _drain: Some(drain),
        })
    }

    fn write(&mut self, message: &Value) {
        let payload = serde_json::to_vec(message).unwrap_or_default();
        let mut framed = payload;
        framed.push(b'\n');
        let _ = self.stdin.write_all(&framed);
        let _ = self.stdin.flush();
    }

    /// Bounded read: block up to `timeout` for the next message.
    fn read(&mut self, timeout: Duration) -> Option<Value> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.cancellation.load(Ordering::Acquire) {
                return None;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match self
                .inbox
                .recv_timeout(remaining.min(Duration::from_millis(50)))
            {
                Ok(message) => return Some(message),
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
    }
}

/// Drain `fd` into parsed JSON-RPC messages, honoring the output cap and the
/// bounded 256-message queue. Runs on a dedicated thread.
pub(crate) fn drain_stream(mut stdout: std::process::ChildStdout, tx: mpsc::Sender<Value>) {
    let mut buffer: Vec<u8> = Vec::new();
    let mut output_bytes: usize = 0;
    let mut pending: usize = 0;
    loop {
        let mut chunk = [0u8; 8192];
        let n = match stdout.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        output_bytes += n;
        if output_bytes > MCP_PROBE_OUTPUT_LIMIT {
            return;
        }
        buffer.extend_from_slice(&chunk[..n]);
        while let Some((message, consumed)) = pop_json_message(&buffer) {
            buffer.drain(..consumed);
            if let Some(msg) = message {
                if is_rpc_message(&msg) {
                    if pending >= _MAX_QUEUE {
                        return;
                    }
                    if tx.send(msg).is_err() {
                        return;
                    }
                    pending += 1;
                }
            }
        }
        if buffer.len() > MCP_PROBE_OUTPUT_LIMIT {
            return;
        }
    }
}

/// `_is_rpc_message` — a JSON-RPC frame carries a method, id, or both.
pub(crate) fn is_rpc_message(message: &Value) -> bool {
    match message {
        Value::Object(map) => map.contains_key("method") || map.contains_key("id"),
        _ => false,
    }
}

/// `_pop_json_message` — return `(Option<message>, bytes_consumed)` for the
/// first complete frame. Supports both newline framing and `Content-Length`
/// header framing. `None` message with non-zero consumed = a skipped
/// blank/keepalive line; `None` with 0 consumed = need more bytes.
pub(crate) fn pop_json_message(buffer: &[u8]) -> Option<(Option<Value>, usize)> {
    if buffer.is_empty() {
        return None;
    }
    // Content-Length framing: headers terminated by a blank line.
    if buffer.starts_with(b"Content-Length:") {
        let mut idx = 0usize;
        let mut length: Option<usize> = None;
        while idx < buffer.len() {
            let line_end = find_crlf_or_lf(buffer, idx);
            let (line, next) = match line_end {
                Some((end, sep_len)) => (&buffer[idx..end], end + sep_len),
                None => return None, // incomplete header line
            };
            if line.is_empty() {
                // end of headers
                if let Some(len) = length {
                    let body_start = next;
                    if len > MCP_PROBE_OUTPUT_LIMIT {
                        return Some((None, buffer.len()));
                    }
                    if len > buffer.len() - body_start {
                        return None;
                    }
                    let body = &buffer[body_start..body_start + len];
                    let msg = strict_rpc_json(body).ok().and_then(|v| {
                        if v.is_object() {
                            Some(v)
                        } else {
                            None
                        }
                    });
                    return Some((msg, body_start + len));
                }
                return Some((None, next));
            }
            let line_str = std::str::from_utf8(line).ok()?;
            if let Some(rest) = line_str.strip_prefix("Content-Length:") {
                length = rest.trim().parse::<usize>().ok();
            }
            idx = next;
        }
        return None;
    }
    // Newline framing.
    let nl = buffer.iter().position(|&b| b == b'\n')?;
    let line = &buffer[..nl];
    let consumed = nl + 1;
    if line.iter().all(u8::is_ascii_whitespace) {
        return Some((None, consumed));
    }
    let msg = strict_rpc_json(line)
        .ok()
        .and_then(|v| if v.is_object() { Some(v) } else { None });
    Some((msg, consumed))
}

fn find_crlf_or_lf(buffer: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i < buffer.len() {
        if buffer[i] == b'\n' {
            if i > from && buffer[i - 1] == b'\r' {
                return Some((i - 1, 2));
            }
            return Some((i, 1));
        }
        i += 1;
    }
    None
}

/// Parse exactly one complete JSON value, rejecting duplicate decoded keys
/// and non-finite float values. The raw key scan follows syntax validation
/// because `serde_json` itself collapses duplicate object members.
pub(crate) fn strict_rpc_json(raw: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(raw).map_err(|e| e.to_string())?;
    let mut de = serde_json::Deserializer::from_str(text);
    let value: Value = serde::Deserialize::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    if has_duplicate_keys(text) {
        return Err("duplicate_key".to_owned());
    }
    reject_nonfinite(&value)?;
    Ok(value)
}

/// Scan JSON strings for repeated decoded keys, scoped to each object.
/// Escaped keys allocate only when decoding is required; ordinary keys borrow.
pub(crate) fn has_duplicate_keys(text: &str) -> bool {
    let b = text.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    // Stack of open scopes: '{' needs a key-set, '[' does not.
    let mut scopes: Vec<HashSet<Cow<'_, str>>> = Vec::new();
    while i < n {
        let c = b[i];
        match c {
            b'"' => {
                // parse a JSON string starting at i
                let start = i;
                let mut escaped = false;
                i += 1;
                while i < n {
                    match b[i] {
                        b'\\' => {
                            escaped = true;
                            i = (i + 2).min(n);
                        }
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
                let lit = &text[start..i];
                // peek: is this a key (next non-ws char ':')?
                let mut j = i;
                while j < n && (b[j] == b' ' || b[j] == b'\t' || b[j] == b'\r' || b[j] == b'\n') {
                    j += 1;
                }
                if j < n && b[j] == b':' {
                    let key = if escaped {
                        match serde_json::from_str::<String>(lit) {
                            Ok(key) => Cow::Owned(key),
                            Err(_) => return true,
                        }
                    } else {
                        Cow::Borrowed(&lit[1..lit.len() - 1])
                    };
                    if let Some(top) = scopes.last_mut() {
                        if !top.insert(key) {
                            return true;
                        }
                    }
                }
            }
            b'{' => {
                scopes.push(HashSet::new());
                i += 1;
            }
            b'[' => {
                scopes.push(HashSet::new());
                i += 1;
            }
            b'}' | b']' => {
                scopes.pop();
                i += 1;
            }
            _ => i += 1,
        }
    }
    false
}

pub(crate) fn reject_nonfinite(value: &Value) -> Result<(), String> {
    match value {
        Value::Number(n) => {
            let raw = n.as_str();
            if raw.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E'))
                && !n.as_f64().is_some_and(f64::is_finite)
            {
                return Err("nonfinite".to_owned());
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                reject_nonfinite(item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for v in map.values() {
                reject_nonfinite(v)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Protocol negotiation + bounded pagination.
// ---------------------------------------------------------------------------

fn _modern_request_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": _MODERN_PROTOCOL,
        "io.modelcontextprotocol/clientInfo": {"name": "hol-guard", "version": "3.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

fn _initialize_params() -> Value {
    json!({
        "protocolVersion": _PROTOCOL,
        "capabilities": {"roots": {"listChanged": false}},
        "clientInfo": {"name": "hol-guard", "version": "3.0"},
    })
}

fn _await_result(session: &mut RpcSession, request_id: i64, deadline: Instant) -> Option<Value> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let remaining = deadline - now;
        let message = session.read(remaining)?;
        if message.get("id").and_then(Value::as_i64) == Some(request_id) {
            return Some(message);
        }
        if let Some(method) = message.get("method").and_then(Value::as_str) {
            if method == "notifications/tools/list_changed" || method == "tools/list_changed" {
                session.catalog_generation += 1;
            }
        }
        reply_server_request(session, &message);
    }
}

fn reply_server_request(session: &mut RpcSession, message: &Value) {
    let method = message.get("method").and_then(Value::as_str);
    let req_id = message.get("id").cloned();
    if method.is_none() || req_id.is_none() || req_id == Some(Value::Null) {
        return;
    }
    if message.get("result").is_some() || message.get("error").is_some() {
        return;
    }
    let id = req_id.unwrap();
    match method.unwrap() {
        "roots/list" => {
            session.write(&json!({"jsonrpc":"2.0","id":id,"result":{"roots":[]}}));
        }
        "ping" => {
            session.write(&json!({"jsonrpc":"2.0","id":id,"result":{}}));
        }
        _ => {
            session.write(
                &json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method not found"}}),
            );
        }
    }
}

fn negotiate_catalog(session: &mut RpcSession, deadline: Instant) -> McpCatalog {
    session.write(&json!({
        "jsonrpc":"2.0","id":0,"method":"server/discover",
        "params":{"_meta": _modern_request_meta()},
    }));
    let now = Instant::now();
    let remaining = deadline.saturating_duration_since(now);
    let discover_deadline = now + remaining.min(Duration::from_secs(1)).min(remaining / 4);
    if let Some(discovered) = _await_result(session, 0, discover_deadline.min(deadline)) {
        let error = discovered.get("error");
        let code = error.and_then(|e| e.get("code")).and_then(Value::as_i64);
        if let Some(c) = code {
            if _MODERN_ERROR_CODES.contains(&c) {
                let reason = if c == -32022 {
                    "unsupported_protocol"
                } else {
                    "discovery_rejected"
                };
                return McpCatalog::reason_only(reason);
            }
        }
        if discovered.get("error").is_none() {
            let result = discovered.get("result");
            if !matches!(result, Some(Value::Object(_)))
                || result.and_then(|r| r.get("resultType")) != Some(&json!("complete"))
            {
                return McpCatalog::reason_only("invalid_discovery");
            }
            let result = result.unwrap();
            let versions = result.get("supportedVersions");
            if !matches!(versions, Some(Value::Array(_))) {
                return McpCatalog::reason_only("invalid_discovery");
            }
            let versions = versions.unwrap().as_array().unwrap();
            if !versions.iter().all(|v| v.is_string()) {
                return McpCatalog::reason_only("invalid_discovery");
            }
            if !versions
                .iter()
                .any(|v| v.as_str() == Some(_MODERN_PROTOCOL))
            {
                return McpCatalog::reason_only("unsupported_protocol");
            }
            let capabilities = result.get("capabilities");
            if !matches!(capabilities, Some(Value::Object(_))) {
                return McpCatalog::reason_only("invalid_discovery");
            }
            let meta = result.get("_meta");
            let server_info = meta
                .and_then(|m| m.get("io.modelcontextprotocol/serverInfo"))
                .cloned();
            let mut catalog = McpCatalog::empty();
            catalog.protocol_version = Some(_MODERN_PROTOCOL.to_owned());
            catalog.server_info = server_info.filter(|v| v.is_object());
            catalog.capabilities = capabilities.cloned();
            return catalog;
        }
    }
    // Legacy fallback: initialize with the pinned 2025-11-25 protocol.
    session.write(&json!({
        "jsonrpc":"2.0","id":1,"method":"initialize","params":_initialize_params(),
    }));
    let initialize = _await_result(session, 1, deadline);
    let initialize = match initialize {
        Some(v) => v,
        None => return McpCatalog::reason_only("initialize_failed"),
    };
    if initialize.get("error").is_some() {
        return McpCatalog::reason_only("initialize_failed");
    }
    let result = match initialize.get("result") {
        Some(Value::Object(_)) => initialize.get("result").unwrap(),
        _ => return McpCatalog::reason_only("invalid_initialize"),
    };
    let version = result.get("protocolVersion").and_then(Value::as_str);
    let version = match version {
        Some(v) if _LEGACY_PROTOCOLS.contains(&v) => v,
        _ => return McpCatalog::reason_only("unsupported_protocol"),
    };
    let capabilities = result.get("capabilities");
    if !matches!(capabilities, Some(Value::Object(_))) {
        return McpCatalog::reason_only("invalid_initialize");
    }
    let server_info = result.get("serverInfo");
    session.write(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    let mut catalog = McpCatalog::empty();
    catalog.protocol_version = Some(version.to_owned());
    catalog.server_info = server_info.filter(|v| v.is_object()).cloned();
    catalog.capabilities = capabilities.cloned();
    catalog
}

/// Bounded `tools/list` pagination with cache hints and change tracking.
fn exchange_tools_list(
    session: &mut RpcSession,
    catalog: McpCatalog,
    deadline: Instant,
    connection_identity_hash: Option<&str>,
) -> McpCatalog {
    let mut collected: Vec<Value> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors: HashSet<String> = HashSet::new();
    let mut seen_names: HashSet<String> = HashSet::new();
    let mut request_id: i64 = 2;
    let mut pages: usize = 0;
    let cache_start = Instant::now();
    let mut cache_deadline = cache_start;
    #[allow(unused_assignments)]
    let mut cache_scope = "private".to_owned();
    let mut page_scope: Option<String> = None;
    let catalog_generation = session.catalog_generation;

    macro_rules! partial {
        ($reason:expr) => {{
            let mut c = catalog.clone();
            c.tools = collected.clone();
            c.reason = Some($reason.to_owned());
            c.pages = pages;
            return c;
        }};
    }

    for _ in 0.._MAX_PAGES {
        let mut params = Map::new();
        if let Some(c) = &cursor {
            params.insert("cursor".to_owned(), json!(c));
        }
        if catalog.protocol_version.as_deref() == Some(_MODERN_PROTOCOL) {
            params.insert("_meta".to_owned(), _modern_request_meta());
        }
        session.write(&json!({
            "jsonrpc":"2.0","id":request_id,"method":"tools/list",
            "params": Value::Object(params),
        }));
        let listed = _await_result(session, request_id, deadline);
        if session.catalog_generation != catalog_generation {
            partial!("catalog_changed");
        }
        let listed = match listed {
            Some(v) if v.get("error").is_none() => v,
            _ => partial!("list_failed"),
        };
        let result = match listed.get("result") {
            Some(Value::Object(_)) => listed.get("result").unwrap(),
            _ => partial!("invalid_page"),
        };
        let modern = catalog.protocol_version.as_deref() == Some(_MODERN_PROTOCOL);
        if modern && result.get("resultType") != Some(&json!("complete")) {
            partial!("invalid_page");
        }
        if modern && !(result.get("ttlMs").is_some() && result.get("cacheScope").is_some()) {
            partial!("invalid_cache_hints");
        }
        let ttl = result.get("ttlMs").and_then(Value::as_i64).unwrap_or(0);
        let scope = result
            .get("cacheScope")
            .and_then(Value::as_str)
            .unwrap_or("private");
        if result
            .get("ttlMs")
            .is_some_and(|v| !v.is_i64() && !v.is_u64())
            || (scope != "private" && scope != "public")
        {
            partial!("invalid_cache_hints");
        }
        let page_deadline = Instant::now() + Duration::from_millis(ttl.clamp(0, 86_400_000) as u64);
        if let Some(ps) = &page_scope {
            if ps != scope {
                partial!("inconsistent_cache_scope");
            }
        }
        page_scope = Some(scope.to_owned());
        cache_scope = if scope == "public" {
            "public".to_owned()
        } else {
            "private".to_owned()
        };
        cache_deadline = if pages == 0 {
            page_deadline
        } else {
            cache_deadline.min(page_deadline)
        };
        let tools = match result.get("tools") {
            Some(Value::Array(items)) => items.clone(),
            _ => partial!("invalid_page"),
        };
        pages += 1;
        let mut page: Vec<Value> = Vec::new();
        let mut page_names: HashSet<String> = HashSet::new();
        for item in tools {
            if !item.is_object() {
                partial!("invalid_tool");
            }
            let name = item.get("name").and_then(Value::as_str);
            let name = match name {
                Some(n) if !n.is_empty() && n == n.trim() => n,
                _ => partial!("invalid_tool"),
            };
            if seen_names.contains(name) || page_names.contains(name) {
                partial!("duplicate_tool");
            }
            page_names.insert(name.to_owned());
            page.push(item);
        }
        let remaining = MAX_MCP_PROBE_TOOLS.saturating_sub(collected.len());
        collected.extend(page.iter().take(remaining).cloned());
        seen_names.extend(page_names);
        let next_cursor = result.get("nextCursor");
        let next_cursor = match next_cursor {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => partial!("invalid_cursor"),
        };
        if page.len() > remaining {
            partial!("tool_limit");
        }
        if next_cursor.is_none() {
            let mut complete = catalog.clone();
            complete.tools = collected;
            complete.complete = true;
            complete.pages = pages;
            let ttl_remaining = cache_deadline.saturating_duration_since(Instant::now());
            complete.cache_ttl_ms = ttl_remaining.as_millis() as i64;
            complete.cache_scope = cache_scope;
            complete.cache_received_at = Some(iso_now());
            return append_skill_metadata(complete, session, deadline, connection_identity_hash);
        }
        if collected.len() == MAX_MCP_PROBE_TOOLS {
            partial!("tool_limit");
        }
        let nc = next_cursor.unwrap();
        if seen_cursors.contains(&nc) {
            partial!("repeated_cursor");
        }
        seen_cursors.insert(nc.clone());
        cursor = Some(nc);
        request_id += 1;
    }
    partial!("page_limit")
}

// ---------------------------------------------------------------------------
// Skills extension (`mcp_skills.py`, bounded subset used by the probe).
// ---------------------------------------------------------------------------

fn iso_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // RFC3339 UTC, second precision matches Python isoformat() closely enough
    // for cache bookkeeping (the field is consumed as a timestamp, not parsed
    // for byte-identity).
    let (y, mo, d, h, mi, s) = epoch_to_utc(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}+00:00")
}

fn epoch_to_utc(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, h as u32, mi as u32, s as u32)
}

pub(crate) fn mcp_skills_declared(capabilities: Option<&Value>, protocol_version: &str) -> bool {
    if protocol_version.is_empty() {
        return false;
    }
    if !protocol_version_is_date(protocol_version) {
        return false;
    }
    if let Some((y, m, d)) = parse_iso_date(protocol_version) {
        let (my, mm, md) = _MIN_SKILLS_VERSION;
        if (y, m, d) < (my, mm, md) {
            return false;
        }
    } else {
        return false;
    }
    let caps = match capabilities {
        Some(Value::Object(m)) => m,
        _ => return false,
    };
    if !caps.get("resources").is_some_and(Value::is_object) {
        return false;
    }
    let ext = caps.get("extensions").and_then(|e| e.get(_SKILL_EXTENSION));
    matches!(ext, Some(v) if v.is_object())
}

fn protocol_version_is_date(v: &str) -> bool {
    v.len() == 10
        && v.chars().enumerate().all(|(i, c)| match i {
            4 | 7 => c == '-',
            _ => c.is_ascii_digit(),
        })
}

fn parse_iso_date(v: &str) -> Option<(i64, u32, u32)> {
    if !protocol_version_is_date(v) {
        return None;
    }
    let y = v[0..4].parse::<i64>().ok()?;
    let m = v[5..7].parse::<u32>().ok()?;
    let d = v[8..10].parse::<u32>().ok()?;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) => 29,
        2 => 28,
        _ => return None,
    };
    if y == 0 || d == 0 || d > days {
        return None;
    }
    Some((y, m, d))
}

fn append_skill_metadata(
    catalog: McpCatalog,
    session: &mut RpcSession,
    deadline: Instant,
    connection_identity_hash: Option<&str>,
) -> McpCatalog {
    if !mcp_skills_declared(
        catalog.capabilities.as_ref(),
        catalog.protocol_version.as_deref().unwrap_or(""),
    ) {
        return catalog;
    }
    let origin = match connection_identity_hash {
        Some(h)
            if h.len() == 64
                && h.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) =>
        {
            h
        }
        _ => {
            let mut c = catalog;
            c.skills_complete = Some(false);
            c.skills_reason = Some("skill_origin_not_bound".to_owned());
            return c;
        }
    };
    let mut request_id: i64 = 100;
    let generation = session.catalog_generation;
    let origin = origin.to_owned();

    let request =
        |session: &mut RpcSession, id: i64, method: &str, params: Value| -> Result<Value, String> {
            session.write(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
            let response = _await_result(session, id, deadline);
            let response = match response {
                Some(r) if r.get("error").is_none() => r,
                _ => return Err("skill_discovery_failed".to_owned()),
            };
            match response.get("result") {
                Some(Value::Object(_)) => Ok(response.get("result").unwrap().clone()),
                _ => Err("invalid_skills_result".to_owned()),
            }
        };

    let mut entries: Vec<Value> = Vec::new();
    let mut seen_uris: HashSet<String> = HashSet::new();
    let mut cursor: Option<String> = None;
    let mut seen_cursors: HashSet<String> = HashSet::new();
    let mut complete = true;
    let mut reason: Option<String> = None;
    for _ in 0..8 {
        request_id += 1;
        let params = match &cursor {
            None => json!({}),
            Some(c) => json!({"cursor": c}),
        };
        let result = match request(session, request_id, "skills/list", params) {
            Ok(r) => r,
            Err(e) => {
                complete = false;
                reason = Some(e);
                break;
            }
        };
        let skills = result
            .get("skills")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for item in skills {
            match parse_mcp_skill_entry(&item, &origin) {
                Ok(meta) => {
                    let uri = meta
                        .get("uri")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    if !uri.is_empty() && !seen_uris.contains(&uri) {
                        seen_uris.insert(uri);
                        entries.push(meta);
                    }
                }
                Err(e) => {
                    complete = false;
                    reason = Some(e);
                    break;
                }
            }
        }
        if !complete {
            break;
        }
        let next = result.get("nextCursor");
        let next = match next {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => {
                complete = false;
                reason = Some("invalid_skills_result".to_owned());
                None
            }
        };
        match next {
            None => break,
            Some(nc) => {
                if seen_cursors.contains(&nc) {
                    complete = false;
                    reason = Some("skill_page_limit".to_owned());
                    break;
                }
                seen_cursors.insert(nc.clone());
                cursor = Some(nc);
            }
        }
    }
    if cursor.is_some() && complete {
        complete = false;
        reason = Some("skill_page_limit".to_owned());
    }
    let mut public: Vec<Value> = Vec::new();
    let mut size = 0usize;
    for entry in &entries {
        let bytes = serde_json::to_vec(entry).unwrap_or_default().len();
        if size + bytes > _MAX_SKILL_METADATA {
            complete = false;
            reason = Some("skill_metadata_limit".to_owned());
            break;
        }
        size += bytes;
        public.push(entry.clone());
    }
    let mut result = catalog;
    result.skills = public;
    result.skills_complete = Some(complete);
    result.skills_reason = reason;
    if session.catalog_generation != generation {
        result.complete = false;
        result.reason = Some("catalog_changed".to_owned());
    }
    result
}

/// Validate origin-bound skill manifests and expose metadata only.
fn parse_mcp_skill_entry(value: &Value, origin: &str) -> Result<Value, String> {
    let valid_digest = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if !valid_digest(origin) {
        return Err("invalid_skill_origin_or_entry".to_owned());
    }
    let obj = value.as_object().ok_or("invalid_skill_origin_or_entry")?;
    let uri = obj
        .get("uri")
        .and_then(Value::as_str)
        .ok_or("invalid_skill_uri")?;
    if !resource_uri(uri) || !uri.ends_with("/SKILL.md") {
        return Err("invalid_skill_uri".to_owned());
    }
    let frontmatter = obj
        .get("frontmatter")
        .and_then(Value::as_object)
        .ok_or("invalid_skill_frontmatter")?;
    let name = frontmatter
        .get("name")
        .and_then(Value::as_str)
        .ok_or("invalid_skill_frontmatter")?;
    let description = frontmatter
        .get("description")
        .and_then(Value::as_str)
        .ok_or("invalid_skill_frontmatter")?;
    let path_name = percent_encoding::percent_decode_str(
        uri[..uri.len() - "/SKILL.md".len()]
            .rsplit('/')
            .next()
            .unwrap_or(""),
    )
    .decode_utf8_lossy();
    if name.is_empty()
        || name.len() > 64
        || name != path_name
        || !name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
        || description.is_empty()
        || description.chars().count() > 1024
    {
        return Err("invalid_skill_frontmatter".to_owned());
    }
    let canonical = |v: &Value| -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        guard_contracts::write_canonical_json(v, &mut bytes)
            .map_err(|_| "invalid_skill_frontmatter".to_owned())?;
        Ok(bytes)
    };
    if canonical(&obj["frontmatter"])?.len() > 262_144 {
        return Err("skill_metadata_limit".to_owned());
    }
    let resources = obj
        .get("resources")
        .ok_or("skill_manifest_resource_limit")?;
    let dynamic = resources.as_str() == Some("dynamic");
    let mut manifest_digest = Value::Null;
    let mut resource_count = Value::Null;
    if !dynamic {
        let entries = resources
            .as_array()
            .ok_or("skill_manifest_resource_limit")?;
        if entries.is_empty() || entries.len() > 512 {
            return Err("skill_manifest_resource_limit".to_owned());
        }
        let root = &uri[..uri.len() - "SKILL.md".len()];
        let mut total = 0u64;
        let mut seen = HashSet::new();
        let mut sorted = Vec::with_capacity(entries.len());
        for entry in entries {
            let entry = entry.as_object().ok_or("invalid_skill_resource")?;
            let resource_uri_value = entry
                .get("uri")
                .and_then(Value::as_str)
                .ok_or("invalid_skill_resource")?;
            let digest = entry
                .get("digest")
                .and_then(Value::as_str)
                .ok_or("invalid_skill_resource")?;
            let size = entry
                .get("size")
                .and_then(Value::as_u64)
                .ok_or("invalid_skill_resource")?;
            if !resource_uri(resource_uri_value)
                || !resource_uri_value.starts_with(root)
                || resource_uri_value == root
                || !seen.insert(resource_uri_value)
                || !digest.strip_prefix("sha256:").is_some_and(valid_digest)
            {
                return Err("invalid_skill_resource".to_owned());
            }
            total = total.checked_add(size).ok_or("skill_manifest_size_limit")?;
            if total > 16_777_216 {
                return Err("skill_manifest_size_limit".to_owned());
            }
            sorted.push((resource_uri_value, digest, size));
        }
        if !seen.contains(uri) {
            return Err("skill_primary_missing".to_owned());
        }
        sorted.sort_unstable();
        let payload =
            json!({"origin": origin, "uri": uri, "frontmatter": frontmatter, "resources": sorted});
        manifest_digest = json!(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(canonical(&payload)?))
        ));
        resource_count = json!(entries.len());
    }
    Ok(json!({
        "origin": "mcp-served-skill", "connection_identity_hash": origin,
        "uri": uri, "name": name, "description": description,
        "manifest_digest": manifest_digest, "dynamic": dynamic,
        "resource_count": resource_count, "activation_supported": false,
        "permissions_granted": false
    }))
}

/// `_resource_uri` — bounded URI acceptance for skill resources.
pub(crate) fn resource_uri(uri: &str) -> bool {
    if uri.chars().count() > 8192 {
        return false;
    }
    if uri.chars().any(|c| (c as u32) < 33) || uri.contains('\\') {
        return false;
    }
    // scheme required; no query or fragment
    let scheme_end = match uri.find(':') {
        Some(i) => i,
        None => return false,
    };
    let scheme = &uri[..scheme_end];
    if !scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    {
        return false;
    }
    if uri.contains('?') || uri.contains('#') {
        return false;
    }
    let rest = &uri[scheme_end + 1..];
    let path = if let Some(authority) = rest.strip_prefix("//") {
        authority.find('/').map_or("", |start| &authority[start..])
    } else {
        rest
    };
    for segment in path.split('/') {
        let mut segment = std::borrow::Cow::Borrowed(segment);
        let mut stable = false;
        for _ in 0..8 {
            let decoded = percent_encoding::percent_decode_str(&segment).decode_utf8_lossy();
            if decoded == segment {
                stable = true;
                break;
            }
            segment = std::borrow::Cow::Owned(decoded.into_owned());
        }
        if !stable
            || segment == "."
            || segment == ".."
            || segment.contains('/')
            || segment.contains('\\')
            || segment.chars().any(|c| (c as u32) < 33)
        {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Child lifecycle (`_exchange_tools_list` + `_stop`).
// ---------------------------------------------------------------------------

/// Run the full bounded catalog probe for a resolved argv. Mirrors
/// `_exchange_tools_list` + `run_mcp_catalog`: spawn in a private process
/// group with `probe_env`, negotiate, paginate, gather skills, and tear down.
pub fn run_mcp_stdio_probe(
    argv: &[String],
    timeout_seconds: f64,
    extra_env: Option<&BTreeMap<String, String>>,
    home_dir: Option<&Path>,
    connection_identity_hash: Option<&str>,
    cancellation: &Arc<AtomicBool>,
) -> McpCatalog {
    if cancellation.load(Ordering::Acquire) {
        return McpCatalog::reason_only("cancelled");
    }
    if argv.is_empty() || argv.iter().any(|p| p.is_empty() || p.contains('\0')) {
        return McpCatalog::reason_only("invalid_launch");
    }
    let timeout = timeout_seconds.max(0.05);
    let tmp = match std::env::temp_dir().canonicalize() {
        Ok(t) => t,
        Err(_) => PathBuf::from("/tmp"),
    };
    let env = probe_env(tmp.to_str().unwrap_or("/tmp"), extra_env, home_dir);
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(&tmp)
        .env_clear()
        .envs(&env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let child = cmd.process_group(0).spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(_) => return McpCatalog::reason_only("transport_failed"),
    };
    let deadline = Instant::now() + Duration::from_secs_f64(timeout);
    let mut session = match RpcSession::spawn(&mut child, Arc::clone(cancellation)) {
        Some(s) => s,
        None => {
            stop_child(&mut child);
            return McpCatalog::reason_only("transport_failed");
        }
    };
    let catalog = negotiate_catalog(&mut session, deadline);
    let result = if catalog.reason.is_some() {
        catalog
    } else {
        exchange_tools_list(&mut session, catalog, deadline, connection_identity_hash)
    };
    stop_child(&mut child);
    if cancellation.load(Ordering::Acquire) {
        McpCatalog::reason_only("cancelled")
    } else {
        result
    }
}

/// `_stop` — kill the process group (created via `process_group(0)`), then
/// reap the direct child. Group signalling goes through `nix::killpg` —
/// a raw `/bin/kill` spawn silently no-ops on images that ship no kill
/// binary (e.g. `python:3.12-slim`, the coverage-test container).
fn stop_child(child: &mut Child) {
    let pid = child.id() as i32;
    if pid > 0 {
        kill_process_group(pid);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// `os.killpg(child.pid, SIGKILL)` — group id equals the child pid after
/// `process_group(0)`; `nix::killpg` keeps the call safe-Rust.
pub(crate) fn kill_process_group(pgid: i32) {
    if process_group_operand(pgid).is_none() {
        return;
    }
    let _ = nix::sys::signal::killpg(
        nix::unistd::Pid::from_raw(pgid),
        nix::sys::signal::Signal::SIGKILL,
    );
}

pub(crate) fn process_group_operand(pgid: i32) -> Option<String> {
    // 0 targets the caller's group; -1 targets nearly every process. Neither
    // can identify a fresh child-owned group, including the reserved ID 1.
    (pgid > 1).then(|| format!("-{pgid}"))
}

#[cfg(test)]
mod skill_metadata_tests {
    use super::*;

    #[test]
    fn manifest_identity_binds_unicode_metadata_and_origin() {
        let origin = "b".repeat(64);
        let entry = json!({
            "uri": "skill://report/SKILL.md",
            "frontmatter": {"name": "report", "description": "Résumé 📖"},
            "resources": [{"uri": "skill://report/SKILL.md", "digest": format!("sha256:{}", "a".repeat(64)), "size": 50}]
        });
        let metadata = parse_mcp_skill_entry(&entry, &origin).unwrap();
        assert_eq!(
            metadata["manifest_digest"],
            "sha256:0077c49db7877e949c6c530a20fb63f48dd16fb31911918cdd0af21538f526e8"
        );
        assert_eq!(metadata["connection_identity_hash"], origin);
        assert_ne!(
            parse_mcp_skill_entry(&entry, &"c".repeat(64)).unwrap()["manifest_digest"],
            metadata["manifest_digest"]
        );
    }

    #[test]
    fn invalid_manifest_never_becomes_usable_skill_metadata() {
        let origin = "b".repeat(64);
        let mut entry = json!({
            "uri": "skill://report/SKILL.md",
            "frontmatter": {"name": "report", "description": "Bounded workflow"},
            "resources": [{"uri": "skill://report/SKILL.md", "digest": format!("sha256:{}", "a".repeat(64)), "size": 50}]
        });
        entry["resources"][0]["size"] = json!(true);
        assert!(parse_mcp_skill_entry(&entry, &origin).is_err());
        entry["resources"][0]["size"] = json!(50);
        entry["resources"][0]["uri"] = json!("skill://report/%252e%252e/private");
        assert!(parse_mcp_skill_entry(&entry, &origin).is_err());
        entry["resources"] = json!("dynamic");
        assert_eq!(
            parse_mcp_skill_entry(&entry, &origin).unwrap()["dynamic"],
            true
        );
        entry["frontmatter"]["name"] = json!("other");
        assert!(parse_mcp_skill_entry(&entry, &origin).is_err());
    }
}
