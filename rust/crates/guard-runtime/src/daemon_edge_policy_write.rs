//! `POST /v1/policy/decisions` and `/v1/policy/clear`, answered by the edge.
//!
//! The order is the one `GuardStore.upsert_policy` and
//! `clear_policy_decisions` ran: the body check, the approval gate, then the
//! write under `policy-integrity-generation.lock`. The resident store writes
//! and signs the rows. The integrity key and the trusted control state stay
//! with the Guard library, so the edge asks it for the generation to advance
//! from before the write and hands back the state the store advanced to.
//!
//! Once the gate has run, a step that fails closes the connection rather than
//! hand the request on, which would run the gate a second time.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::super::super::library::call_resident;
use super::super::records::now_isoformat;
use super::gate::{self, Gate};
use super::{handler_field, NativeReads, ReadConfig, DROPPED};
use crate::daemon_handler_policy::{
    policy_clear, policy_upsert, PolicyClearInput, PolicyUpsertInput,
};
use crate::policy_bundle_store_identities::scoped_artifact_key;
use crate::policy_decision_lookup_op::{computed_workspace_policy_key, SCOPED_APPROVAL_FAMILIES};
use crate::resident_state::is_lock_contention;

/// `GuardStore.hold_policy_integrity_generation_lock`'s file, which every
/// writer that advances the generation takes, the library's included.
const LOCK_FILE: &str = "policy-integrity-generation.lock";
/// `_POLICY_INTEGRITY_GENERATION_LOCK_TIMEOUT_SECONDS`.
const LOCK_TIMEOUT: Duration = Duration::from_secs(30);
/// `_POLICY_INTEGRITY_GENERATION_LOCK_POLL_SECONDS`.
const LOCK_POLL: Duration = Duration::from_millis(50);

type Answer = Option<(u16, Value)>;

/// `POST /v1/policy/decisions`.
pub(super) fn upsert(
    payload: &Map<String, Value>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Answer {
    let (proceed, status, body, fields) = policy_upsert(&PolicyUpsertInput {
        harness: &handler_field(payload.get("harness")),
        scope: &handler_field(payload.get("scope")),
        action: &handler_field(payload.get("action")),
        artifact_id: &handler_field(payload.get("artifact_id")),
        workspace: &handler_field(payload.get("workspace")),
        publisher: &handler_field(payload.get("publisher")),
        reason: &handler_field(payload.get("reason")),
    })
    .into_parts();
    if !proceed {
        return Some((status, body));
    }
    let text = |key: &str| fields.get(key).and_then(Value::as_str);
    let (scope, action) = (text("scope")?, text("action")?);
    let refused = |status, mut refusal: Map<String, Value>| {
        refusal.insert("saved".to_owned(), Value::Bool(false));
        Some((status, Value::Object(refusal)))
    };
    let grant = match gate::require_high_risk("policy_write", payload, config)? {
        Gate::Refused(status, refusal) => return refused(status, refusal),
        Gate::Passed(grant) => grant,
    };
    // The high-risk check has run, so an unanswered check fails closed.
    if let Gate::Refused(status, refusal) =
        gate::require_policy_write(action, scope, grant, config).unwrap_or_else(gate::unavailable)
    {
        return refused(status, refusal);
    }
    if !scoped_family_supported(scope, text("artifact_id")) {
        return Some((
            400,
            json!({"saved": false, "error": "unsupported_scoped_policy_family"}),
        ));
    }
    let Some(row) = decision_row(&fields) else {
        return Some((DROPPED, Value::Null));
    };
    let saved = locked(config, || {
        let now = now_isoformat()?;
        let mut args = row;
        args.insert("now".to_owned(), Value::String(now.clone()));
        args.extend(integrity_begin(config, &now, true)?);
        let written = reads.store_write(config, "upsert_policy", Value::Object(args));
        integrity_finalize(config, written.ok()?.get("next_control_state"))
    });
    Some(match saved {
        Some(()) => (200, body),
        None => (DROPPED, Value::Null),
    })
}

/// `POST /v1/policy/clear`.
pub(super) fn clear(
    payload: &Map<String, Value>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Answer {
    let (proceed, status, body, fields) = policy_clear(&PolicyClearInput {
        harness: &handler_field(payload.get("harness")),
        source: &handler_field(payload.get("source")),
        scope: &handler_field(payload.get("scope")),
        artifact_id: &handler_field(payload.get("artifact_id")),
        artifact_hash: &handler_field(payload.get("artifact_hash")),
        workspace: &handler_field(payload.get("workspace")),
        publisher: &handler_field(payload.get("publisher")),
        all: &handler_field(payload.get("all")),
        artifact_id_is_null: &handler_field(payload.get("artifact_id_is_null")),
        artifact_hash_is_null: &handler_field(payload.get("artifact_hash_is_null")),
    })
    .into_parts();
    if !proceed {
        return Some((status, body));
    }
    let refused = |status, mut refusal: Map<String, Value>| {
        refusal.insert("cleared".to_owned(), Value::from(0));
        Some((status, Value::Object(refusal)))
    };
    let grant = match gate::require_high_risk("policy_clear", payload, config)? {
        Gate::Refused(status, refusal) => return refused(status, refusal),
        Gate::Passed(grant) => grant,
    };
    if let Gate::Refused(status, refusal) =
        gate::require_policy_clear(grant, config).unwrap_or_else(gate::unavailable)
    {
        return refused(status, refusal);
    }
    let Value::Object(filters) = fields else {
        return Some((DROPPED, Value::Null));
    };
    let cleared = locked(config, || {
        let now = now_isoformat()?;
        let clear = |sign: bool| {
            let mut args = filters.clone();
            args.insert("now".to_owned(), Value::String(now.clone()));
            // An unsigned clear may remove remote rows only; the store
            // refuses it in the same transaction when a local row matches.
            args.insert("unsigned_only".to_owned(), Value::Bool(!sign));
            args.extend(integrity_begin(config, &now, sign)?);
            reads
                .store_write(config, "clear_policy_decisions", Value::Object(args))
                .ok()
        };
        // The integrity status refreshes on every clear; a generation begins
        // only when local rows go, so there are rows left to sign over.
        let mut answer = clear(false)?;
        if answer.get("needs_signing") == Some(&Value::Bool(true)) {
            answer = clear(true)?;
        }
        integrity_finalize(config, answer.get("next_control_state"))?;
        answer.get("cleared")?.as_i64()
    });
    let Some(cleared) = cleared else {
        return Some((DROPPED, Value::Null));
    };
    let mut answer = Map::new();
    answer.insert("cleared".to_owned(), Value::from(cleared));
    answer.extend(body.as_object()?.clone());
    Some((200, Value::Object(answer)))
}

/// `_validate_scoped_policy_artifact_target`: a harness or global rule may
/// name only a family Guard scopes approvals to, or a risk group Guard knows
/// (`scoped_policy_artifact_key` refuses any other group).
fn scoped_family_supported(scope: &str, artifact_id: Option<&str>) -> bool {
    if !matches!(scope, "harness" | "global") {
        return true;
    }
    if let Some(group) = artifact_id.and_then(|id| id.strip_prefix("risk-group:")) {
        return crate::command_risk_groups::is_risk_group(group);
    }
    let Some(family) = artifact_id
        .filter(|id| !id.trim().is_empty())
        .and_then(|id| id.strip_prefix("family:"))
    else {
        return true;
    };
    SCOPED_APPROVAL_FAMILIES.contains(&family.trim().to_lowercase().as_str())
}

/// The row `_policy_write_args` writes for the decision the body names: the
/// keys `_normalized_policy_keys` keeps for its scope, from the local source.
fn decision_row(fields: &Value) -> Option<Map<String, Value>> {
    let text = |key: &str| fields.get(key).and_then(Value::as_str);
    let scope = text("scope")?;
    let artifact_id = match scope {
        "harness" | "global" => scoped_artifact_key(text("artifact_id")),
        "artifact" | "workspace" => text("artifact_id").map(str::to_owned),
        _ => None,
    };
    let workspace = if scope == "workspace" {
        computed_workspace_policy_key(text("workspace"))
    } else {
        None
    };
    let publisher = text("publisher").filter(|_| scope == "publisher");
    let Value::Object(row) = json!({
        "harness": text("harness")?,
        "scope": scope,
        "artifact_id": artifact_id,
        "artifact_hash": null,
        "workspace": workspace,
        "publisher": publisher,
        "action": text("action")?,
        "reason": text("reason"),
        "owner": null,
        "source": "local",
        "expires_at": null,
    }) else {
        return None;
    };
    Some(row)
}

/// `policy.integrity_begin`: the integrity material the store signs with, or
/// none when the store is not protected or `sign` is false.
fn integrity_begin(config: &ReadConfig, now: &str, sign: bool) -> Option<Map<String, Value>> {
    let Ok(Value::Object(begun)) = call_resident(
        config,
        "policy.integrity_begin",
        json!({"now": now, "sign": sign}),
    ) else {
        return None;
    };
    let mut material = Map::new();
    if begun.contains_key("current_generation") {
        for key in [
            "current_generation",
            "integrity_key_b64",
            "integrity_key_id",
        ] {
            material.insert(key.to_owned(), begun.get(key)?.clone());
        }
    }
    Some(material)
}

/// `_finalize_native_control_state`: adopt the generation the store advanced
/// to, when it advanced one.
fn integrity_finalize(config: &ReadConfig, next_control_state: Option<&Value>) -> Option<()> {
    match next_control_state {
        None | Some(Value::Null) => Some(()),
        Some(state @ Value::Object(_)) => call_resident(
            config,
            "policy.integrity_finalize",
            json!({"next_control_state": state}),
        )
        .ok()
        .map(|_| ()),
        Some(_) => None,
    }
}

/// Runs `work` holding the generation lock. `None` when the lock cannot be
/// taken in time, as the library's wait raises.
fn locked<T>(config: &ReadConfig, work: impl FnOnce() -> Option<T>) -> Option<T> {
    let file = generation_lock(config.guard_home())?;
    let answer = work();
    let _ = fs2::FileExt::unlock(&file);
    answer
}

fn generation_lock(home: &Path) -> Option<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(home.join(LOCK_FILE)).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let deadline = Instant::now().checked_add(LOCK_TIMEOUT)?;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Some(file),
            Err(error) if is_lock_contention(&error) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return None;
                }
                std::thread::sleep(remaining.min(LOCK_POLL));
            }
            Err(_) => return None,
        }
    }
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_policy_write_tests.rs"]
mod tests;
