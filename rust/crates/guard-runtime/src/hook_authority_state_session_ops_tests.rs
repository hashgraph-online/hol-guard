//! The single-transaction session ops against the op sequences the Python
//! helpers ran before them (`_load_cursor_pending_shell_permission`,
//! `_remove_cursor_pending_shell_permission` and
//! `_discard_claude_pending_permissions`). Every recorded vector store, after
//! every op step, is copied twice: one copy runs the old sequence of resident
//! ops (plus the plain SQL delete the discard ran itself), the other runs the
//! new op, and the result, the `sync_state` rows and the audit events must match.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use guard_contracts::HookAuthorityStateRequestV1;
use rusqlite::{params_from_iter, Connection};
use serde_json::{json, Value};

use super::evaluate;
use super::vectors::{apply_raw, events, fresh_store, op_request, owned_rows, recorded_vectors};

const CURSOR_PENDING: &str = "cursor_pending_shell:";
const CURSOR_INDEX: &str = "cursor_pending_shells:";
const CLAUDE_PENDING: &str = "claude_pending_permission:";
const CLAUDE_INDEX: &str = "claude_pending_permissions:";

struct Base<'a> {
    request: &'a HookAuthorityStateRequestV1,
}

impl Base<'_> {
    fn call(&self, path: &Path, op: &str, fields: Value) -> Value {
        let request = HookAuthorityStateRequestV1 {
            schema: self.request.schema.clone(),
            store_path: path.to_string_lossy().into_owned(),
            guard_home: self.request.guard_home.clone(),
            op: op.to_owned(),
            now: self.request.now.clone(),
            integrity_key_b64: self.request.integrity_key_b64.clone(),
            integrity_key_id: self.request.integrity_key_id.clone(),
            ..Default::default()
        };
        let mut wire = serde_json::to_value(&request).expect("request");
        for (name, value) in fields.as_object().expect("fields") {
            wire[name] = value.clone();
        }
        let request: HookAuthorityStateRequestV1 = serde_json::from_value(wire).expect("wire");
        evaluate(&request).unwrap_or_else(|code| panic!("{op}: {code}"))
    }

    fn keys(&self, path: &Path, op: &str, fields: Value) -> Vec<String> {
        self.call(path, op, fields)["pending_keys"]
            .as_array()
            .expect("pending_keys")
            .iter()
            .map(|key| key.as_str().expect("key").to_owned())
            .collect()
    }

    fn old_find(&self, path: &Path, conversation: &str, command: &str, expected: &str) -> Value {
        let load = |state_key: &str| {
            self.call(
                path,
                "cursor_load_pending_state",
                json!({ "conversation_id": conversation, "command": command,
                        "state_key": state_key, "expected_key": expected }),
            )["pending"]
                .clone()
        };
        let direct = load(expected);
        if !direct.is_null() {
            return direct;
        }
        let index = self.keys(
            path,
            "cursor_load_index",
            json!({ "conversation_id": conversation }),
        );
        for indexed_key in index {
            let candidate = load(&indexed_key);
            if candidate["command"].as_str() == Some(command) {
                return candidate;
            }
        }
        Value::Null
    }

    fn old_remove(&self, path: &Path, conversation: &str, pending_key: &str) {
        Connection::open(path)
            .expect("open")
            .execute("delete from sync_state where state_key = ?1", [pending_key])
            .expect("delete");
        let remaining: Vec<String> = self
            .keys(
                path,
                "cursor_load_index",
                json!({ "conversation_id": conversation }),
            )
            .into_iter()
            .filter(|key| key != pending_key)
            .collect();
        self.call(
            path,
            "cursor_store_index",
            json!({ "conversation_id": conversation, "pending_keys": remaining }),
        );
    }

    fn old_discard(&self, path: &Path, session: &str) -> usize {
        let mut keys = self.keys(path, "claude_load_index", json!({ "session_id": session }));
        if keys.is_empty() {
            return 0;
        }
        let discarded = keys.len();
        keys.push(format!("{CLAUDE_INDEX}{session}"));
        let placeholders = vec!["?"; keys.len()].join(",");
        Connection::open(path)
            .expect("open")
            .execute(
                &format!("delete from sync_state where state_key in ({placeholders})"),
                params_from_iter(&keys),
            )
            .expect("delete");
        discarded
    }
}

/// Owners, pending keys and commands present in the store, plus unknown ones.
struct Inputs {
    conversations: BTreeSet<String>,
    cursor_keys: BTreeSet<String>,
    commands: BTreeSet<String>,
    sessions: BTreeSet<String>,
}

fn inputs(connection: &Connection) -> Inputs {
    let mut found = Inputs {
        conversations: BTreeSet::from(["absent-conversation".to_owned()]),
        cursor_keys: BTreeSet::from([format!("{CURSOR_PENDING}absent-conversation:0")]),
        commands: BTreeSet::from(["true".to_owned()]),
        sessions: BTreeSet::from(["absent-session".to_owned()]),
    };
    for (key, (payload, _)) in owned_rows(connection) {
        if let Some(owner) = key.strip_prefix(CURSOR_INDEX) {
            found.conversations.insert(owner.to_owned());
        } else if let Some(rest) = key.strip_prefix(CURSOR_PENDING) {
            if let Some((owner, _)) = rest.rsplit_once(':') {
                found.conversations.insert(owner.to_owned());
            }
            found.cursor_keys.insert(key.clone());
        } else if let Some(owner) = key.strip_prefix(CLAUDE_INDEX) {
            found.sessions.insert(owner.to_owned());
        } else if let Some(rest) = key.strip_prefix(CLAUDE_PENDING) {
            if let Some((owner, _)) = rest.rsplit_once(':') {
                found.sessions.insert(owner.to_owned());
            }
        }
        if let Some(command) = payload.get("command").and_then(Value::as_str) {
            found.commands.insert(command.to_owned());
        }
    }
    found
}

fn copy_of(path: &Path, label: &str) -> PathBuf {
    let copy = path.with_extension(format!("{label}.db"));
    std::fs::copy(path, &copy).expect("copy store");
    copy
}

fn state(path: &Path) -> (Value, Value) {
    let connection = Connection::open(path).expect("open");
    let rows = serde_json::to_value(owned_rows(&connection)).expect("rows");
    let events = serde_json::to_value(events(&connection)).expect("events");
    (rows, events)
}

/// Runs `old` on one copy and `new` on another; both must agree.
fn agree(
    path: &Path,
    label: &str,
    old: impl FnOnce(&Path) -> Value,
    new: impl FnOnce(&Path) -> Value,
) {
    let old_path = copy_of(path, "old");
    let new_path = copy_of(path, "new");
    assert_eq!(new(&new_path), old(&old_path), "{label}: result");
    assert_eq!(state(&new_path), state(&old_path), "{label}: store");
    let _ = std::fs::remove_file(old_path);
    let _ = std::fs::remove_file(new_path);
}

#[test]
fn session_ops_match_the_op_sequences_they_replace() {
    let vectors = recorded_vectors();
    let key_b64 = vectors["key_b64"].as_str().expect("key").to_owned();
    let mut compared = 0;
    for scenario in vectors["scenarios"].as_array().expect("scenarios") {
        let name = scenario["name"].as_str().expect("name");
        let (path, connection) = fresh_store(&format!("session-ops-{name}"));
        for (step, action) in scenario["actions"]
            .as_array()
            .expect("actions")
            .iter()
            .enumerate()
        {
            if apply_raw(&connection, action) {
                continue;
            }
            let request = op_request(action, &path, &key_b64);
            evaluate(&request).unwrap_or_else(|code| panic!("{name} step {step}: {code}"));
            let base = Base { request: &request };
            let found = inputs(&connection);
            for conversation in &found.conversations {
                for expected in &found.cursor_keys {
                    let label = format!("{name} step {step}: {conversation} {expected}");
                    agree(
                        &path,
                        &format!("{label} remove"),
                        |at| {
                            base.old_remove(at, conversation, expected);
                            json!({})
                        },
                        |at| {
                            base.call(
                                at,
                                "cursor_remove_pending",
                                json!({ "conversation_id": conversation, "pending_key": expected }),
                            )
                        },
                    );
                    for command in &found.commands {
                        compared += 1;
                        agree(
                            &path,
                            &format!("{label} find {command}"),
                            |at| json!({ "pending": base.old_find(at, conversation, command, expected) }),
                            |at| {
                                base.call(
                                    at,
                                    "cursor_find_pending",
                                    json!({
                                "conversation_id": conversation, "command": command,
                                "expected_key": expected }),
                                )
                            },
                        );
                    }
                }
            }
            for session in &found.sessions {
                agree(
                    &path,
                    &format!("{name} step {step}: discard {session}"),
                    |at| json!({ "discarded": base.old_discard(at, session) }),
                    |at| {
                        base.call(
                            at,
                            "claude_discard_session",
                            json!({ "session_id": session }),
                        )
                    },
                );
            }
        }
        drop(connection);
        let _ = std::fs::remove_file(&path);
    }
    assert!(compared > 200, "only {compared} lookups compared");
}

#[test]
fn a_failed_cursor_removal_rolls_back_both_writes() {
    let vectors = recorded_vectors();
    let request = HookAuthorityStateRequestV1 {
        schema: guard_contracts::HOOK_AUTHORITY_STATE_REQUEST_SCHEMA.into(),
        guard_home: std::env::temp_dir().to_string_lossy().into_owned(),
        now: "2026-10-11T12:00:00.250000+00:00".into(),
        integrity_key_b64: vectors["key_b64"].as_str().map(str::to_owned),
        integrity_key_id: vectors["key_id"].as_str().map(str::to_owned),
        ..Default::default()
    };
    let base = Base { request: &request };
    let pending_key = format!("{CURSOR_PENDING}conv-rollback:abc");
    let index_key = format!("{CURSOR_INDEX}conv-rollback");
    for blocked in [&pending_key, &index_key] {
        let (path, connection) = fresh_store("session-ops-rollback");
        base.call(
            &path,
            "cursor_store_pending_state",
            json!({ "conversation_id": "conv-rollback", "state_key": pending_key,
                    "payload": { "conversation_id": "conv-rollback", "command": "true" } }),
        );
        base.call(
            &path,
            "cursor_append_key",
            json!({ "conversation_id": "conv-rollback", "pending_key": pending_key }),
        );
        let before = owned_rows(&connection);
        assert!(before.contains_key(&pending_key) && before.contains_key(&index_key));
        connection
            .execute_batch(&format!(
                "create trigger refuse before delete on sync_state when old.state_key = '{blocked}' \
                 begin select raise(abort, 'refused'); end;"
            ))
            .expect("trigger");
        let mut removal = request.clone();
        removal.op = "cursor_remove_pending".into();
        removal.store_path = path.to_string_lossy().into_owned();
        removal.conversation_id = Some("conv-rollback".into());
        removal.pending_key = Some(pending_key.clone());
        assert_eq!(
            evaluate(&removal),
            Err("native_hook_authority_state_store_unavailable"),
            "{blocked}"
        );
        assert_eq!(owned_rows(&connection), before, "{blocked}");
        drop(connection);
        let _ = std::fs::remove_file(&path);
    }
}
