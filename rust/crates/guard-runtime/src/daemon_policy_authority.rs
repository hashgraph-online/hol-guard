//! Resident daemon policy-authority client (RTM-030).
//!
//! Rust port of
//! `src/codex_plugin_scanner/guard/native_package_policy_resolve.py`
//! (:17-:57), `src/codex_plugin_scanner/guard/native_daemon_client.py`
//! (`GuardSurfaceDaemonClient` :184-:343, `_post` :434-:455,
//! `resolve_policy_decision` :337, `claim_policy_decision` :340,
//! `load_running_guard_surface_daemon_client` :538-:551), and
//! the retired Python daemon's `manager.py::load_running_guard_daemon_identity`
//! (:1205-:1206 → `_live_guard_daemon_identity` :1228-:1260,
//! `_load_authenticated_daemon_identity` :1263-:1281).
//!
//! Authority is the running Guard surface daemon, reached only over
//! authenticated loopback HTTP. Everything is fail-closed: identity,
//! transport, or shape errors resolve to `decision=None` /
//! `claimed=false`. The daemon state is authenticated by an HMAC over the
//! state payload keyed by `daemon-discovery-key`, and the bearer token is
//! pinned to `auth_token_id = sha256(token)` via `secrets.compare_digest`
//! parity. Live checks require `state_id` non-empty,
//! `compatibility_version == GUARD_DAEMON_COMPATIBILITY_VERSION` (2), a
//! valid `port`, a live `pid`, a `GET /healthz` that is 200 and
//! `_healthz_payload_is_current` (compat + REQUIRED_DAEMON_TABLES ⊆
//! tables), and either a pid command-line match for `guard_home` or an
//! authenticated `GET /v1/healthz/details` whose `guard_home` and runtime
//! state match.
//!
//! Only loopback HTTP to `127.0.0.1` is ever dialed (client.py:416-:426);
//! the daemon token is never sent to a redirected or non-loopback
//! authority.

use std::fs;
#[cfg(unix)]
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Child, Command, Stdio};
#[cfg(unix)]
use std::sync::mpsc;
#[cfg(unix)]
use std::thread;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use guard_command::local_supply_chain::{DaemonPolicyResolution, PolicyAuthorityApi};

use crate::resident_transport::constant_time_eq;

#[path = "daemon_policy_authority_compat.rs"]
mod compat;
pub(crate) use compat::{
    daemon_healthz_details_match, daemon_state_matches_compatible_runtime,
    healthz_payload_is_current, healthz_payload_matches_guard_home, paths_equal_resolved,
};

#[path = "daemon_policy_authority_identity.rs"]
mod identity;
pub(crate) use identity::{
    canonical_discovery_payload, hmac_sha256_raw, load_authenticated_daemon_identity,
    load_authenticated_daemon_state, load_daemon_discovery_key, load_guard_daemon_auth_token,
    load_running_guard_daemon_identity, verify_daemon_state,
};
#[path = "daemon_policy_authority_process.rs"]
mod process;
pub(crate) use process::{approval_center_daemon_url, daemon_pid_matches_command};
#[path = "daemon_policy_authority_http.rs"]
mod http;
pub(crate) use http::{http_get_json, loopback_json, post_json};

/// `GUARD_DAEMON_COMPATIBILITY_VERSION`. The daemon state
/// and `/healthz` payloads must carry this exact value.
const GUARD_DAEMON_COMPATIBILITY_VERSION: i64 = 2;
/// `DAEMON_DISCOVERY_PROTOCOL_VERSION` (discovery.py:13).
const DAEMON_DISCOVERY_PROTOCOL_VERSION: i64 = 1;
/// `_GUARD_DAEMON_AUTH_TOKEN_MAX_BYTES`.
const DAEMON_AUTH_TOKEN_MAX_BYTES: u64 = 4096;
/// `daemon-discovery-key` is a 32-byte hex key (discovery.py:18-:19,
/// `_DISCOVERY_KEY_BYTES = 32`), so the file is a 64-char lowercase hex
/// string.
const DAEMON_DISCOVERY_KEY_BYTES: usize = 32;
/// Bound on `daemon-state.json` and each HTTP response body we accept
/// (discovery.py:114 caps state at 64 KiB; client.py:222 caps payloads).
const DAEMON_STATE_JSON_MAX_BYTES: u64 = 64 * 1024;
const DAEMON_RESPONSE_MAX_BYTES: usize = 256 * 1024;
/// `_GUARD_DAEMON_PROCESS_QUERY_MAX_BYTES` / `_TIMEOUT_SECONDS`
///.
#[cfg(unix)]
const PROCESS_QUERY_MAX_BYTES: usize = 1024 * 1024;
#[cfg(unix)]
const PROCESS_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Health-request deadline (manager.py:1206 uses `health_timeout=1.0`;
/// native_package_policy_resolve.py uses 2s for the policy socket).
const HEALTH_TIMEOUT: Duration = Duration::from_secs(1);
/// Policy request socket timeout (native_package_policy_resolve.py).
const POLICY_TIMEOUT: Duration = Duration::from_secs(2);
/// Trusted `ps` locations.
#[cfg(unix)]
const POSIX_PS_PATHS: [&str; 2] = ["/bin/ps", "/usr/bin/ps"];
/// Launcher basenames recognized in serve argv.
const RECOGNIZED_LAUNCHERS: [&str; 4] = [
    "hol-guard",
    "hol-guard.exe",
    "plugin-guard",
    "plugin-guard.exe",
];
/// `_HOOK_LAUNCHER_ARGS` — hook command lines are not
/// daemon servers even when they carry guard flags.
const HOOK_LAUNCHER_ARGS: [&str; 3] = ["--hook-mode", "--hook-transport", "--hook-event"];
/// `REQUIRED_DAEMON_TABLES` — `healthz.tables` must cover
/// this set.
const REQUIRED_DAEMON_TABLES: [&str; 1] = ["guard_connect_states"];
/// `DAEMON_STATE_SIGNATURE_FIELD` (discovery.py:17).
const DAEMON_STATE_SIGNATURE_FIELD: &str = "state_signature";
/// Frozen serve argv marker shared with the lifecycle facts
/// (frozen_runtime_commands.py `FROZEN_DAEMON_SERVE_ARG`).
use crate::daemon_lifecycle_facts::FROZEN_DAEMON_SERVE_ARG;

/// Resident policy-authority client. Holds `guard_home` — the private
/// root containing `daemon-state.json`, `daemon-auth-token`, and
/// `daemon-discovery-key`.
pub struct ResidentPolicyAuthority {
    guard_home: PathBuf,
}

/// Verified daemon authority — the `GuardSurfaceDaemonClient` tuple
/// (client.py:185-:189): base URL + bearer token. Serialized into the
/// `authority` `Value` so `claim_package_policy` can rebuild it.
#[derive(Debug, Clone)]
pub(crate) struct DaemonAuthority {
    base_url: String,
    auth_token: String,
}

/// Verified identity record carried through `daemon-state.json` +
/// `daemon-auth-token` + discovery key.
pub(crate) struct DaemonIdentity {
    port: u16,
    auth_token: String,
}

impl ResidentPolicyAuthority {
    /// Construct a resident authority bound to `guard_home`. The caller
    /// (resident package-policy override) wires this in; kept as the
    /// public constructor even when no in-crate caller exists yet.
    #[allow(dead_code)]
    pub fn new(guard_home: PathBuf) -> Self {
        Self { guard_home }
    }

    /// `resolve_package_policy` (native_package_policy_resolve.py). Each
    /// workspace is tried in order; the first `decision` dict wins.
    pub(crate) fn resolve_package_policy(
        &self,
        harness: &str,
        artifact_id: Option<&str>,
        artifact_hash: &str,
        workspaces: &[String],
        publisher: Option<&str>,
    ) -> Option<(Value, Value)> {
        let authority = self.load_authority()?;
        for workspace in workspaces {
            let mut payload = Map::new();
            payload.insert("harness".into(), Value::String(harness.to_owned()));
            payload.insert(
                "artifact_id".into(),
                match artifact_id {
                    Some(id) if !id.is_empty() => Value::String(id.to_owned()),
                    _ => Value::Null,
                },
            );
            payload.insert(
                "artifact_hash".into(),
                Value::String(artifact_hash.to_owned()),
            );
            payload.insert("workspace".into(), Value::String(workspace.clone()));
            payload.insert(
                "publisher".into(),
                match publisher {
                    Some(p) if !p.is_empty() => Value::String(p.to_owned()),
                    _ => Value::Null,
                },
            );
            let lookup = post_json(&authority, "/v1/policy/resolve", &Value::Object(payload))?;
            let decision = lookup.get("decision").filter(|d| d.is_object());
            if let Some(decision) = decision {
                return Some((decision.clone(), serialize_authority(&authority)));
            }
        }
        None
    }

    /// `claim_package_policy` (native_package_policy_resolve.py) —
    /// `claimed` is true only when the daemon returns `claimed == true`
    /// (client.py:340-:342).
    fn claim(&self, authority: &DaemonAuthority, decision: &Value) -> bool {
        let payload = {
            let mut map = Map::new();
            map.insert("decision".into(), decision.clone());
            Value::Object(map)
        };
        match post_json(authority, "/v1/policy/claim", &payload) {
            Some(response) => response.get("claimed") == Some(&Value::Bool(true)),
            None => false,
        }
    }

    /// `load_running_guard_surface_daemon_client` (client.py:538-:551) →
    /// `load_running_guard_daemon_identity`.
    fn load_authority(&self) -> Option<DaemonAuthority> {
        let identity = load_running_guard_daemon_identity(&self.guard_home)?;
        Some(DaemonAuthority {
            base_url: format!("http://127.0.0.1:{}", identity.port),
            auth_token: identity.auth_token,
        })
    }
}

impl PolicyAuthorityApi for ResidentPolicyAuthority {
    fn resolve_package_policy(
        &self,
        guard_home: &Path,
        harness: &str,
        artifact_id: &str,
        artifact_hash: &str,
        workspaces: &[String],
        publisher: Option<&str>,
    ) -> DaemonPolicyResolution {
        // The trait threads `guard_home` for parity with the Python call
        // site; this resident is bound to one `guard_home` at construction.
        // Fail-closed: any error returns an empty resolution.
        let _ = guard_home;
        let artifact_id_opt = (!artifact_id.is_empty()).then_some(artifact_id);
        match self.resolve_package_policy(
            harness,
            artifact_id_opt,
            artifact_hash,
            workspaces,
            publisher,
        ) {
            Some((decision, authority)) => DaemonPolicyResolution {
                authority: Some(authority),
                decision: Some(decision),
            },
            None => DaemonPolicyResolution::default(),
        }
    }

    fn claim_package_policy(&self, authority: &Value, decision: &Value) -> bool {
        let Some(authority) = deserialize_authority(authority) else {
            return false;
        };
        self.claim(&authority, decision)
    }
}

/// Serialize the authority so the trait's `authority: &Value` can round-
/// trip back to a `DaemonAuthority` (client.py:185-:189).
fn serialize_authority(authority: &DaemonAuthority) -> Value {
    let mut map = Map::new();
    map.insert("base_url".into(), Value::String(authority.base_url.clone()));
    map.insert(
        "auth_token".into(),
        Value::String(authority.auth_token.clone()),
    );
    Value::Object(map)
}

/// Rebuild the authority from the `Value` (client.py:19-:26 shape checks).
fn deserialize_authority(value: &Value) -> Option<DaemonAuthority> {
    let map = value.as_object()?;
    let base_url = map.get("base_url")?.as_str()?;
    // Loopback-only authority (client.py:416-:426).
    if !base_url.starts_with("http://127.0.0.1:") {
        return None;
    }
    let auth_token = map.get("auth_token")?.as_str()?;
    if auth_token.is_empty() {
        return None;
    }
    Some(DaemonAuthority {
        base_url: base_url.to_owned(),
        auth_token: auth_token.to_owned(),
    })
}

// ---------------------------------------------------------------------------
// Identity: daemon-state.json + daemon-auth-token + daemon-discovery-key
// (discovery.py:97-:123; manager.py:1205-:1260)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Private file reads — `read_private_regular_bytes/text` parity
// (private_file_io.py:31-:108). Owner-only, no-follow, stable-metadata,
// bounded.
// ---------------------------------------------------------------------------

pub(crate) fn read_private_regular_text(
    path: &Path,
    max_bytes: u64,
    require_private_parent: bool,
) -> Option<String> {
    let bytes = read_private_regular_bytes(path, max_bytes, require_private_parent)?;
    String::from_utf8(bytes).ok()
}

#[cfg(unix)]
fn read_private_regular_bytes(
    path: &Path,
    max_bytes: u64,
    require_private_parent: bool,
) -> Option<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let parent_before = if require_private_parent {
        Some(fs::symlink_metadata(path.parent()?).ok()?)
    } else {
        None
    };
    if let Some(parent) = &parent_before {
        if !private_directory_metadata_is_valid(parent) {
            return None;
        }
    }
    let path_before = fs::symlink_metadata(path).ok()?;
    if !private_file_metadata_is_valid(&path_before) {
        return None;
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let opened = file.metadata().ok()?;
    if !private_file_metadata_is_valid(&opened)
        || opened.dev() != path_before.dev()
        || opened.ino() != path_before.ino()
    {
        return None;
    }
    if opened.len() > max_bytes {
        return None;
    }
    let mut bytes = Vec::new();
    let mut limited = file.try_clone().ok()?.take(max_bytes + 1);
    limited.read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > max_bytes {
        return None;
    }
    let after = file.metadata().ok()?;
    if !stable_file_metadata(&opened, &after) {
        return None;
    }
    if require_private_parent {
        let parent_after = fs::symlink_metadata(path.parent()?).ok()?;
        if !stable_directory_metadata(&parent_before?, &parent_after) {
            return None;
        }
    }
    Some(bytes)
}

#[cfg(unix)]
fn private_file_metadata_is_valid(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return false;
    }
    metadata.uid() == nix::unistd::getuid().as_raw() && metadata.permissions().mode() & 0o077 == 0
}

#[cfg(unix)]
fn private_directory_metadata_is_valid(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.is_dir() {
        return false;
    }
    metadata.uid() == nix::unistd::getuid().as_raw() && metadata.permissions().mode() & 0o077 == 0
}

#[cfg(unix)]
fn stable_file_metadata(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mtime() == after.mtime()
        && before.size() == after.size()
}

#[cfg(unix)]
fn stable_directory_metadata(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev() && before.ino() == after.ino()
}

#[cfg(windows)]
fn read_private_regular_bytes(
    path: &Path,
    max_bytes: u64,
    _require_private_parent: bool,
) -> Option<Vec<u8>> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > max_bytes {
        return None;
    }
    fs::read(path).ok()
}

#[cfg(not(any(unix, windows)))]
fn read_private_regular_bytes(_p: &Path, _m: u64, _r: bool) -> Option<Vec<u8>> {
    None
}

#[cfg(test)]
#[path = "daemon_policy_authority_hmac_vectors_tests.rs"]
mod hmac_vectors_tests;
