//! `process-identity --stdin`: the start token and owner marker that
//! `live_process_identity.py` compares to tell a live process from one that
//! reused its PID. The Codex hook bridge records its own identity with the
//! same start token (`codex_hook_identity`), so the daemon now verifies it
//! with the code that produced it.
//!
//! - `start_token` answers `start_token` for `pid`, giving `ps` at most
//!   `timeout_ms` (never more than half a second);
//! - `owner_marker` answers `owner_marker` for `pid`: `uid:<n>` on POSIX,
//!   `sid:<SID>` on Windows;
//! - `matches` answers whether `identity`, a captured `{pid, startToken}`,
//!   still names the same live process.
//!
//! Each answer is `null` (or `false`) when the process cannot be read.

use std::io::Read;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::codex_hook_identity;

const SCHEMA: &str = "process-identity.v1";
const MAX_REQUEST_BYTES: u64 = 16 * 1024;
const PS_TIMEOUT_MS: u64 = 500;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    pid: Option<i64>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    identity: Option<Value>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "process-identity"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "process_identity_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("process_identity_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    let answer = match (request.op.as_str(), request.pid, &request.identity) {
        ("start_token", Some(pid), None) => {
            let timeout = Duration::from_millis(request.timeout_ms.unwrap_or(PS_TIMEOUT_MS));
            let token = process_id(pid)
                .and_then(|pid| codex_hook_identity::process_start_token_within(pid, timeout));
            json!({ "start_token": token })
        }
        ("owner_marker", Some(pid), None) if request.timeout_ms.is_none() => {
            let marker = process_id(pid).and_then(codex_hook_identity::process_owner_marker);
            json!({ "owner_marker": marker })
        }
        ("matches", None, Some(identity)) if request.timeout_ms.is_none() => {
            json!({ "matches": codex_hook_identity::process_identity_matches(identity) })
        }
        _ => return Err(invalid()),
    };
    Ok(answer.to_string().into_bytes())
}

fn invalid() -> String {
    "process_identity_request_invalid".to_owned()
}

/// A PID the operating system can name: positive and within `u32`.
fn process_id(pid: i64) -> Option<u32> {
    u32::try_from(pid).ok().filter(|pid| *pid > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(request: Value) -> Value {
        let bytes = run_command(request.to_string().as_bytes()).expect("answer");
        serde_json::from_slice(&bytes).expect("answer is JSON")
    }

    fn own_token() -> String {
        let answer =
            run(json!({ "schema": SCHEMA, "op": "start_token", "pid": std::process::id() }));
        answer["start_token"]
            .as_str()
            .expect("own token")
            .to_owned()
    }

    #[test]
    fn the_own_start_token_matches_the_bridge_identity() {
        let (_, bridge) = codex_hook_identity::current_process_identity().expect("identity");
        assert_eq!(own_token(), bridge);
    }

    #[test]
    fn a_captured_identity_matches_only_its_own_token() {
        let pid = std::process::id();
        let token = own_token();
        let matches = |identity: Value| {
            run(json!({ "schema": SCHEMA, "op": "matches", "identity": identity }))["matches"]
                .clone()
        };
        assert_eq!(matches(json!({ "pid": pid, "startToken": token })), true);
        assert_eq!(
            matches(json!({ "pid": pid, "startToken": "posix:other" })),
            false
        );
        assert_eq!(
            matches(json!({ "pid": pid, "startToken": token, "extra": 1 })),
            false
        );
        assert_eq!(matches(json!({ "pid": true, "startToken": token })), false);
        assert_eq!(matches(json!([pid, token])), false);
    }

    #[test]
    fn unnameable_pids_have_no_token_or_owner() {
        for pid in [0_i64, -1, i64::from(u32::MAX) + 1] {
            let token = run(json!({ "schema": SCHEMA, "op": "start_token", "pid": pid }));
            assert_eq!(token["start_token"], Value::Null, "{pid}");
            let owner = run(json!({ "schema": SCHEMA, "op": "owner_marker", "pid": pid }));
            assert_eq!(owner["owner_marker"], Value::Null, "{pid}");
        }
    }

    #[test]
    fn the_own_owner_marker_names_a_user() {
        let answer =
            run(json!({ "schema": SCHEMA, "op": "owner_marker", "pid": std::process::id() }));
        let marker = answer["owner_marker"].as_str().expect("owner");
        assert!(
            marker.starts_with("uid:") || marker.starts_with("sid:"),
            "{marker}"
        );
    }

    #[test]
    fn requests_are_validated() {
        for request in [
            json!({ "schema": "process-identity.v0", "op": "start_token", "pid": 1 }),
            json!({ "schema": SCHEMA, "op": "start_token" }),
            json!({ "schema": SCHEMA, "op": "start_token", "pid": 1, "identity": {} }),
            json!({ "schema": SCHEMA, "op": "owner_marker", "pid": 1, "timeout_ms": 5 }),
            json!({ "schema": SCHEMA, "op": "matches", "pid": 1 }),
            json!({ "schema": SCHEMA, "op": "matches", "identity": {}, "timeout_ms": 5 }),
            json!({ "schema": SCHEMA, "op": "current", "pid": 1 }),
            json!({ "schema": SCHEMA, "op": "start_token", "pid": 1, "extra": true }),
        ] {
            assert_eq!(
                run_command(request.to_string().as_bytes()).expect_err("refused"),
                "process_identity_request_invalid",
                "{request}"
            );
        }
    }
}
