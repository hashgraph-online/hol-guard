//! Fail-closed launch identity API for non-Unix targets.
//!
//! The full launch identity implementation relies on POSIX filesystem metadata
//! and executable semantics. Keep its API available to cross-platform callers,
//! but do not claim runtime identities can be verified on other targets.

use std::collections::HashSet;
use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::launch_identity_common::{
    launch_argv_digest, normalized_launch_cwd, runtime_launch_argv, RuntimeLaunchArgv,
};

// Mirror the Unix implementation's contract shape on non-Unix targets: every
// key a cross-platform consumer indexes must be present, but the identity
// stays non-reusable (`reuse_nonce`) and `unsupported_platform`, so saved
// approvals still fail closed and nothing claims a verified launch.

// `reuse_nonce` must never be reusable, so mix entropy with the per-process
// counter, pid, and wall-clock nanos to avoid stable fallback identities —
// unsupported identities stay unverified. This is uniqueness, not a
// cryptographic guarantee if getrandom fails (wall-clock can repeat); a
// constant zero nonce would let an attacker pin a stable identity.
// Every call site produces a 16-byte nonce.
fn token_hex() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut entropy = [0u8; 16];
    let _ = getrandom::fill(&mut entropy);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(entropy);
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    hasher.update(nanos.to_be_bytes());
    hex::encode(&hasher.finalize()[..16])
}

// `launch_identity.rs::unreusable_executable_identity` — non-Unix executables
// are never verified, so reuse_nonce keeps the identity fail-closed.
fn unsupported_executable_identity(command: &Value) -> Value {
    let mut map = Map::new();
    map.insert(
        "command".to_string(),
        command
            .as_str()
            .map(|s| Value::String(s.to_string()))
            .unwrap_or(Value::Null),
    );
    map.insert("path".to_string(), Value::Null);
    map.insert(
        "status".to_string(),
        Value::String("unsupported_platform".to_string()),
    );
    map.insert("reuse_nonce".to_string(), Value::String(token_hex()));
    Value::Object(map)
}

// `launch_identity.rs::unproven_runtime_entrypoint` — non-Unix entrypoints are
// never bound, so the entrypoint stays unproven with a fresh reuse_nonce.
fn unsupported_entrypoint_identity() -> Value {
    let mut map = Map::new();
    map.insert(
        "kind".to_string(),
        Value::String("unknown-launch".to_string()),
    );
    map.insert(
        "reason".to_string(),
        Value::String("unsupported_platform".to_string()),
    );
    map.insert(
        "selector_sha256".to_string(),
        Value::String(launch_argv_digest(&[])),
    );
    map.insert("status".to_string(), Value::String("unproven".to_string()));
    map.insert("reuse_nonce".to_string(), Value::String(token_hex()));
    Value::Object(map)
}

pub fn build_runtime_executable_identity(
    command: &Value,
    search_path: Option<&str>,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    _require_executable: bool,
) -> Value {
    let _ = (search_path, home_dir);
    // Same `launch_cwd` semantics as the Unix identity: expanduser +
    // resolve(strict=False) via the shared normalizer, empty when no cwd is
    // supplied (the key itself is part of the cross-platform contract).
    let mut identity = unsupported_executable_identity(command);
    if let Some(obj) = identity.as_object_mut() {
        obj.insert(
            "launch_cwd".to_string(),
            Value::String(
                cwd.map(|c| {
                    normalized_launch_cwd(Some(c))
                        .to_string_lossy()
                        .into_owned()
                })
                .unwrap_or_default(),
            ),
        );
    }
    identity
}

pub fn runtime_launch_identity_is_reusable(_identity: &Value) -> bool {
    false
}

pub fn resolved_runtime_launch_executable(_identity: &Value) -> Option<String> {
    None
}

pub fn resolved_runtime_launch_argv(_identity: &Value, _args: &[String]) -> Option<Vec<String>> {
    None
}

#[allow(clippy::too_many_arguments)]
pub fn runtime_launch_identity_matches(
    _expected_identity: &Value,
    _command: &Value,
    _args: &[Value],
    _structured_command: bool,
    _direct_executable: bool,
    _search_path: Option<&str>,
    _cwd: Option<&Path>,
    _launch_env: Option<&Value>,
) -> bool {
    false
}

#[allow(clippy::too_many_arguments)]
pub fn build_runtime_launch_identity(
    command: &Value,
    args: &[Value],
    structured_command: bool,
    _direct_executable: bool,
    _search_path: Option<&str>,
    cwd: Option<&Path>,
    _home_dir: Option<&Path>,
    _launch_env: Option<&Value>,
) -> Value {
    // Derive the launch vector with the same rules the Unix implementation
    // uses (shared `runtime_launch_argv`) so `argv_sha256` is content-bound
    // and byte-identical across platforms: shell command strings are
    // tokenized, structured commands stay a single executable element, and a
    // malformed command or non-string arg fails closed to the empty-vector
    // digest exactly like Unix. The identity itself remains non-reusable and
    // unproven on unsupported platforms — the digest binds what was launched,
    // never claims it was verified.
    let effective_cwd = normalized_launch_cwd(cwd);
    let launch_cwd = effective_cwd.to_string_lossy().into_owned();
    let (argv_digest, executable_cmd) = match runtime_launch_argv(command, args, structured_command)
    {
        // The executable names the parsed first token of the launch vector,
        // not the raw command string — matching the Unix builder. Move the
        // token out of argv; a Valid vector always has at least one element.
        RuntimeLaunchArgv::Valid(argv) => (
            launch_argv_digest(&argv),
            argv.into_iter()
                .next()
                .map(Value::String)
                .unwrap_or(Value::Null),
        ),
        RuntimeLaunchArgv::Invalid(executable_cmd) => (launch_argv_digest(&[]), executable_cmd),
    };
    // Build the unsupported executable identity once with the already
    // normalized cwd — routing through build_runtime_executable_identity
    // would canonicalize the same path a second time.
    let mut executable = unsupported_executable_identity(&executable_cmd);
    if let Some(obj) = executable.as_object_mut() {
        obj.insert("launch_cwd".to_string(), Value::String(launch_cwd.clone()));
    }
    json!({
        "argv_sha256": argv_digest,
        "entrypoint": unsupported_entrypoint_identity(),
        "executable": executable,
        "launch_cwd": launch_cwd,
    })
}

fn python_str_is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn python_str_strip(value: &str) -> &str {
    value.trim_matches(python_str_is_space)
}

pub fn package_advisory_ids(package: &Map<String, Value>) -> Vec<String> {
    let mut advisory_ids: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut add_id = |value: Option<&Value>| {
        if let Some(text) = value.and_then(Value::as_str) {
            let trimmed = python_str_strip(text);
            if !trimmed.is_empty() && !seen.contains(trimmed) {
                seen.insert(trimmed.to_string());
                advisory_ids.push(trimmed.to_string());
            }
        }
    };
    for key in [
        "advisoryIds",
        "advisory_ids",
        "relatedAdvisoryIds",
        "related_advisory_ids",
    ] {
        if let Some(raw) = package.get(key).and_then(Value::as_array) {
            for entry in raw {
                add_id(Some(entry));
            }
        }
    }
    add_id(package.get("advisoryId"));
    add_id(package.get("advisory_id"));
    if let Some(reasons) = package.get("reasons").and_then(Value::as_array) {
        for reason in reasons {
            let Some(reason) = reason.as_object() else {
                continue;
            };
            add_id(reason.get("advisoryId"));
            add_id(reason.get("advisory_id"));
        }
    }
    advisory_ids
}

#[cfg(test)]
mod tests {
    use super::*;

    // Consumer-visible regression for the Windows KeyError 'argv_sha256' fix:
    // every key a cross-platform consumer hard-indexes must be present, and the
    // identity must stay non-reusable / non-matching so saved approvals fail
    // closed rather than ever pinning a stable launch on an unsupported target.
    #[test]
    fn unsupported_launch_identity_is_complete_and_never_reusable() {
        let cwd = Path::new("C:\\work");
        let command = Value::String("python".to_string());
        let args = vec![
            Value::String("-m".to_string()),
            Value::String("srv".to_string()),
        ];

        let first = build_runtime_launch_identity(
            &command,
            &args,
            false,
            false,
            None,
            Some(cwd),
            None,
            None,
        );
        let second = build_runtime_launch_identity(
            &command,
            &args,
            false,
            false,
            None,
            Some(cwd),
            None,
            None,
        );

        for identity in [&first, &second] {
            assert!(identity
                .get("argv_sha256")
                .and_then(Value::as_str)
                .is_some());
            assert!(identity.get("launch_cwd").and_then(Value::as_str).is_some());
            assert!(identity.get("executable").is_some());
            assert!(identity.get("entrypoint").is_some());
            // Fail closed: the identity is never reusable and never matches.
            assert!(!runtime_launch_identity_is_reusable(identity));
            assert!(resolved_runtime_launch_executable(identity).is_none());
        }
        // The executable names the first parsed argv token, not the raw
        // command string — `"python -m srv"` is a shell launch of `python`.
        let shelled = build_runtime_launch_identity(
            &Value::String("git status".to_string()),
            &[],
            false,
            false,
            None,
            Some(cwd),
            None,
            None,
        );
        assert_eq!(
            shelled
                .get("executable")
                .and_then(|e| e.get("command"))
                .and_then(Value::as_str),
            Some("git")
        );
        assert_eq!(
            first
                .get("executable")
                .and_then(|e| e.get("command"))
                .and_then(Value::as_str),
            Some("python")
        );
        // Two launches of the same vector produce distinct nonces, so a saved
        // approval can never pin a stable identity on this platform.
        assert_ne!(first, second);
        assert!(!runtime_launch_identity_matches(
            &first,
            &command,
            &args,
            false,
            false,
            None,
            Some(cwd),
            None,
        ));
    }
}
