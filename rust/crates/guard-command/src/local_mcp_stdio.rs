//! Stdio JSON-RPC exchange for MCP `initialize` + `tools/list` probes
//! (RTM-020). Ports the `_exchange_tools_list` + `probe_search_path` +
//! `probe_env` spawn path from `local_mcp_stdio.py`/`local_mcp_probe_env.py`.
//!
//! Keep this module minimal: it only needs to drive a subprocess through the
//! initialize → initialized → tools/list handshake and return the bounded
//! catalog. All protocol versioning, pagination, and skills negotiation stays
//! in Python (`_negotiate_catalog`); Rust handles the spawn + framing only.
//!
//! `#[cfg(unix)]` because the launch attributes are unix-only.
#![cfg(unix)]

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Environment helpers — ported from local_mcp_probe_env.py.
// ---------------------------------------------------------------------------

/// `probe_search_path` — PATH without Guard package-shim wrapper directories.
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
                .filter(|name| *name == "bin")
                .and_then(|_| p.parent())
                .and_then(|gp| gp.file_name())
                .map(|name| name == "package-shims")
        })
        .unwrap_or(false)
}

fn is_package_shim_dir(entry: &str) -> bool {
    let path = Path::new(entry);
    path.file_name()
        .filter(|name| *name == "bin")
        .and_then(|_| path.parent())
        .and_then(|p| p.file_name())
        .map(|name| name == "package-shims")
        .unwrap_or(false)
}

fn _package_cache_env(home_dir: Option<&Path>) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let home_owned: Option<PathBuf>;
    let home = match home_dir {
        Some(h) => Some(h.to_path_buf()),
        None => {
            home_owned = std::env::var("HOME").ok().map(PathBuf::from);
            home_owned
        }
    };
    if let Some(home) = home {
        let bun_cache = home.join(".bun").join("install").join("cache");
        if bun_cache.is_dir() {
            m.insert(
                "BUN_INSTALL_CACHE_DIR".to_owned(),
                bun_cache.to_string_lossy().into_owned(),
            );
        }
        let npm_cache = home.join(".npm");
        if npm_cache.is_dir() {
            m.insert(
                "npm_config_cache".to_owned(),
                npm_cache.to_string_lossy().into_owned(),
            );
        }
    }
    m
}

/// `probe_env(tmp, extra)` — scrubbed probe environment.
/// `extra` overrides are applied except for the locked keys.
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
    "HOL_GUARD_",
    "CODEX_",
    "ANTHROPIC_",
    "OPENAI_",
    "GEMINI_",
    "GOOGLE_",
    "AWS_",
    "AZURE_",
    "GITHUB_",
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
// Stdio JSON-RPC exchange — minimal initialize → tools/list → teardown.
// ---------------------------------------------------------------------------

/// Outcome of a `tools/list` exchange.
#[derive(Debug)]
pub struct McpStdioExchange {
    pub tools: Vec<Value>,
    pub server_info: Option<Value>,
    pub capabilities: Option<Value>,
    pub protocol_version: Option<String>,
    pub reason: Option<String>,
}

fn _send_request(stdin: &mut impl Write, id: u64, method: &str, params: Value) {
    let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let line = serde_json::to_string(&msg).unwrap_or_default();
    let _ = stdin.write_all(line.as_bytes());
    let _ = stdin.write_all(b"\n");
    let _ = stdin.flush();
}

fn _send_notification(stdin: &mut impl Write, method: &str, params: Value) {
    let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
    let line = serde_json::to_string(&msg).unwrap_or_default();
    let _ = stdin.write_all(line.as_bytes());
    let _ = stdin.write_all(b"\n");
    let _ = stdin.flush();
}

fn _read_message(reader: &mut BufReader<impl std::io::Read>, deadline: Instant) -> Option<Value> {
    let mut line = String::new();
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return None,
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                return serde_json::from_str(trimmed).ok();
            }
            Err(_) => return None,
        }
    }
}

fn _read_response(
    reader: &mut BufReader<impl std::io::Read>,
    stdin: &mut impl Write,
    request_id: u64,
    deadline: Instant,
) -> Option<Value> {
    loop {
        let msg = _read_message(reader, deadline)?;
        if msg.get("id").and_then(Value::as_u64) == Some(request_id) {
            return Some(msg);
        }
        // Respond to server-initiated requests with method-not-found.
        if msg.get("id").is_some() && msg.get("method").is_some() {
            let resp = json!({
                "jsonrpc": "2.0",
                "id": msg["id"],
                "error": {"code": -32601, "message": "method not found"}
            });
            let line = serde_json::to_string(&resp).unwrap_or_default();
            let _ = stdin.write_all(line.as_bytes());
            let _ = stdin.write_all(b"\n");
            let _ = stdin.flush();
        }
    }
}

/// `run_mcp_stdio_probe` — launch the MCP server, negotiate initialize, and
/// run `tools/list`. Returns the bounded catalog on success, or `reason` on
/// failure. Pagination stays in Python for now (bounded at 100 tools).
pub fn run_mcp_stdio_probe(
    argv: &[String],
    cwd: &Path,
    timeout_seconds: f64,
    extra_env: Option<&BTreeMap<String, String>>,
    home_dir: Option<&Path>,
    _connection_identity_hash: Option<&str>,
) -> McpStdioExchange {
    if argv.is_empty() || argv.iter().any(|p| p.is_empty() || p.contains('\0')) {
        return McpStdioExchange {
            tools: vec![],
            server_info: None,
            capabilities: None,
            protocol_version: None,
            reason: Some("invalid_launch".to_owned()),
        };
    }
    let tmp = std::env::temp_dir().to_string_lossy().into_owned();
    let env = probe_env(&tmp, extra_env, home_dir);

    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // start_new_session: detach from the caller's process group so a
        // kill() can't propagate a signal to the guard process.
        .process_group(0);
    for (k, v) in &env {
        cmd.env(k, v);
    }
    cmd.env_remove("HOL_GUARD_SHIM_ACTIVE");
    cmd.env_remove("HOL_GUARD_WORKSPACE");

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(_) => {
            return McpStdioExchange {
                tools: vec![],
                server_info: None,
                capabilities: None,
                protocol_version: None,
                reason: Some("transport_failed".to_owned()),
            }
        }
    };

    let deadline = Instant::now() + Duration::from_secs_f64(timeout_seconds.max(0.05));
    let result = _run_protocol(&mut child, deadline);
    _stop_child(&mut child);
    result
}

fn _run_protocol(child: &mut Child, deadline: Instant) -> McpStdioExchange {
    let mut stdin = match child.stdin.take() {
        Some(s) => s,
        None => {
            return McpStdioExchange {
                tools: vec![],
                server_info: None,
                capabilities: None,
                protocol_version: None,
                reason: Some("transport_failed".to_owned()),
            }
        }
    };
    let stdout_raw = match child.stdout.take() {
        Some(s) => s,
        None => {
            return McpStdioExchange {
                tools: vec![],
                server_info: None,
                capabilities: None,
                protocol_version: None,
                reason: Some("transport_failed".to_owned()),
            }
        }
    };
    let mut stdout = BufReader::new(stdout_raw);

    let init_params = json!({
        "protocolVersion": "2025-11-25",
        "capabilities": {"roots": {"listChanged": false}, "sampling": {}},
        "clientInfo": {"name": "hol-guard", "version": "1.0.0"},
    });
    _send_request(&mut stdin, 1, "initialize", init_params);
    let init_resp = match _read_response(&mut stdout, &mut stdin, 1, deadline) {
        Some(r) => r,
        None => {
            return McpStdioExchange {
                tools: vec![],
                server_info: None,
                capabilities: None,
                protocol_version: None,
                reason: Some("initialize_failed".to_owned()),
            }
        }
    };
    if init_resp.get("error").is_some() {
        return McpStdioExchange {
            tools: vec![],
            server_info: None,
            capabilities: None,
            protocol_version: None,
            reason: Some("initialize_failed".to_owned()),
        };
    }
    let result = init_resp.get("result").cloned().unwrap_or(Value::Null);
    let protocol_version = result
        .get("protocolVersion")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let server_info = result.get("serverInfo").cloned();
    let capabilities = result.get("capabilities").cloned();

    _send_notification(&mut stdin, "notifications/initialized", json!({}));

    _send_request(&mut stdin, 2, "tools/list", json!({}));
    let list_resp = match _read_response(&mut stdout, &mut stdin, 2, deadline) {
        Some(r) => r,
        None => {
            return McpStdioExchange {
                tools: vec![],
                server_info,
                capabilities,
                protocol_version,
                reason: Some("list_failed".to_owned()),
            }
        }
    };
    let tools = list_resp
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .take(100)
        .collect();

    McpStdioExchange {
        tools,
        server_info,
        capabilities,
        protocol_version,
        reason: None,
    }
}

fn _stop_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
