//! `CodexHookManifestVerify` - resident op deciding whether an authenticated
//! Codex hook manifest still describes the live installation.
//!
//! Ported from `_verify_hook_manifest` in `codex_hook_manifest.py` and the
//! file checks it makes through `codex_hook_file_integrity.py`. Whether the
//! manifest still holds is what lets Guard's Codex hooks keep running, and
//! what `hol-guard doctor` and repair report, so it is one answer here rather
//! than one per caller.
//!
//! The caller authenticates the manifest; the key never crosses. It sends the
//! manifest, the live `[hooks]` table and the installation it expects, plus
//! three spellings only it can produce: canonical paths, which paths sit under
//! its own package roots, and how it splits each handler's command line. This
//! op reads every file the answer turns on and renders the integrity state.
//!
//! Whether a POSIX group is private to a file's owner is read from the
//! account database here; `private_group_questions` stays empty on the wire.

use std::fs;
use std::path::Path;

use guard_contracts::{CodexHookManifestExpectedV1, CodexHookManifestVerifyRequestV1};
use serde_json::{json, Map, Value};

use rules::{
    config_answer, fail, failure_status, field, file_failure, header, invalid_binding,
    invocation_executable, io_error, launch_identities, string_list, unreadable_identity, Failure,
    MANIFEST_SCHEMA_VERSION,
};

use crate::codex_hook_file_identity_op::{identity_answer, FileFacts, IdentityAsk};
use crate::cursor_hook_command::Syntax;
use crate::guard_config_update_value::py_eq;

/// `MANAGED_CODEX_HOOK_EVENTS`, in its order.
const MANAGED_EVENTS: [&str; 4] = [
    "PreToolUse",
    "PermissionRequest",
    "UserPromptSubmit",
    "PostToolUse",
];

/// Each packaged-file role with the last identity the manifest gave it.
type RoleIdentities = Vec<(String, Map<String, Value>)>;

/// The integrity state of `request`, as `{"state", "private_group_questions"}`.
pub(crate) fn evaluate_request(request: &CodexHookManifestVerifyRequestV1) -> Value {
    let mut verifier = Verifier {
        request,
        matches: [false; 4],
    };
    let outcome = match (&request.failure, &request.manifest, &request.expected) {
        (Some(failure), _, _) => Err(Failure {
            reason: failure.reason.clone(),
            message: failure.message.clone(),
        }),
        (None, Some(manifest), Some(expected)) => verifier.verify(manifest, expected),
        _ => Err(fail("codex_hook_integrity_io_error", "")),
    };
    let state = match outcome {
        Ok(valid) => valid,
        Err(failure) => verifier.failure_state(&failure),
    };
    json!({ "state": state, "private_group_questions": [] })
}

struct Verifier<'a> {
    request: &'a CodexHookManifestVerifyRequestV1,
    /// Which managed events hold their authenticated group, as far as the
    /// walk got; a failure reports the partial answer.
    matches: [bool; 4],
}

impl Verifier<'_> {
    fn verify(
        &mut self,
        manifest: &Value,
        expected: &CodexHookManifestExpectedV1,
    ) -> Result<Value, Failure> {
        let Some(manifest) = manifest.as_object() else {
            return Err(fail(
                "codex_hook_manifest_schema_unsupported",
                "The Codex hook manifest schema is stale; run `hol-guard install codex` to refresh it.",
            ));
        };
        header(manifest, expected)?;
        let ask = self.ask(None);
        let config = config_answer(&ask, Path::new(&expected.config_path));
        self.settle(config)?;
        let interpreter = field(manifest, "interpreter");
        self.executable(interpreter)?;
        let interpreter_object = interpreter.as_object().ok_or_else(unreadable_identity)?;
        if field(interpreter_object, "invocation_path").as_str()
            != Some(expected.interpreter_path.as_str())
        {
            return Err(fail(
                "codex_hook_interpreter_path_mismatch",
                "The Codex hook interpreter does not match this Guard installation; repair it.",
            ));
        }
        let packaged = self.packaged_files(manifest, expected)?;
        launch_identities(manifest, expected, interpreter, &packaged)?;
        let bindings: Vec<Value> = match field(manifest, "events") {
            Value::Array(events) => events
                .iter()
                .filter(|event| event.is_object())
                .cloned()
                .collect(),
            _ => Vec::new(),
        };
        if !py_eq(
            &Value::Array(bindings.clone()),
            &Value::Array(expected.event_bindings.clone()),
        ) {
            return Err(fail(
                "codex_hook_manifest_registration_stale",
                "The authenticated Codex hook registration no longer matches this Guard version; run repair.",
            ));
        }
        let Some(hooks) = self.request.hooks.as_ref().and_then(Value::as_object) else {
            return Err(fail(
                "codex_hook_registration_missing",
                "The authenticated Codex hooks are missing from Codex configuration; run repair.",
            ));
        };
        self.event_bindings(&bindings, expected, hooks)?;
        if !self.matches.iter().all(|matched| *matched) {
            return Err(fail(
                "codex_hook_registration_mismatch",
                "One or more authenticated Codex hook handlers changed or disappeared; run repair.",
            ));
        }
        // Every managed event holds its group, so all but one group per event
        // belongs to someone else.
        let foreign: usize = group_lists(hooks)
            .map(|groups| groups.len().saturating_sub(1))
            .sum();
        let bridge = packaged.iter().find(|(role, _)| role == "bridge");
        let bridge_sha256 = bridge.map_or(&Value::Null, |(_, identity)| field(identity, "sha256"));
        let interpreter_sha256 = match field(interpreter_object, "target") {
            Value::Object(target) => field(target, "sha256").clone(),
            _ => Value::Null,
        };
        Ok(json!({
            "event_matches": self.event_matches(),
            "foreign_hook_entries_present": foreign > 0,
            "foreign_hook_group_count": foreign,
            "integrity_message": "Authenticated manifest and live Codex hook identities are valid.",
            "integrity_reason": "codex_hook_manifest_valid",
            "integrity_status": "valid",
            "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
            "manifest_package_version": field(manifest, "package_version"),
            "manifest_generated_at": field(manifest, "generated_at"),
            "bridge_sha256": bridge_sha256,
            "interpreter_sha256": interpreter_sha256,
        }))
    }

    fn failure_state(&self, failure: &Failure) -> Value {
        let hooks = self.request.hooks.as_ref().and_then(Value::as_object);
        let lists: Vec<&Vec<Value>> = hooks
            .map(|hooks| group_lists(hooks).collect())
            .unwrap_or_default();
        json!({
            "event_matches": self.event_matches(),
            "foreign_hook_entries_present": lists.iter().any(|groups| !groups.is_empty()),
            "foreign_hook_group_count": lists.iter().map(|groups| groups.len()).sum::<usize>(),
            "integrity_message": failure.message,
            "integrity_reason": failure.reason,
            "integrity_status": failure_status(&failure.reason),
            "manifest_schema_version": Value::Null,
            "manifest_package_version": Value::Null,
            "manifest_generated_at": Value::Null,
            "bridge_sha256": Value::Null,
            "interpreter_sha256": Value::Null,
        })
    }

    fn event_matches(&self) -> Value {
        let mut matches = Map::new();
        for (event, matched) in MANAGED_EVENTS.iter().zip(self.matches) {
            matches.insert((*event).to_owned(), Value::Bool(matched));
        }
        Value::Object(matches)
    }

    fn ask<'p>(&'p self, path: Option<&'p str>) -> IdentityAsk<'p> {
        IdentityAsk {
            posix: self.request.posix,
            current_uid: self.request.current_uid,
            canonical_path: path.and_then(|path| self.canonical(path)),
            installed_python_package_file: path.is_some_and(|path| {
                self.request
                    .installed_python_package_files
                    .iter()
                    .any(|installed| installed == path)
            }),
        }
    }

    fn canonical(&self, path: &str) -> Option<&str> {
        self.request.canonical_paths.get(path).map(String::as_str)
    }

    /// Settles one file answer, settling its private-group question from the
    /// account database.
    fn settle(&mut self, answer: Value) -> Result<(), Failure> {
        let role = answer.get("role").and_then(Value::as_str).unwrap_or("file");
        if let Some(question) = answer.get("private_group_question") {
            let owner = question.get("owner_uid").and_then(Value::as_u64);
            let group = question.get("group_gid").and_then(Value::as_u64);
            let (Some(owner), Some(group)) = (
                owner.and_then(|value| u32::try_from(value).ok()),
                group.and_then(|value| u32::try_from(value).ok()),
            ) else {
                return Err(file_failure(role, "permissions_unsafe"));
            };
            let question = json!({ "owner_uid": owner, "group_gid": group });
            if !crate::codex_hook_bridge_trust_files::private_group(&question) {
                return Err(file_failure(role, "permissions_unsafe"));
            }
        }
        if answer.get("outcome").and_then(Value::as_str) == Some("verified") {
            return Ok(());
        }
        let kind = answer
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("identity_invalid");
        Err(file_failure(role, kind))
    }

    fn regular_identity(&mut self, identity: &Value) -> Result<(), Failure> {
        let Some(object) = identity.as_object() else {
            return Err(unreadable_identity());
        };
        let path = field(object, "path").as_str();
        let answer = identity_answer(&self.ask(path), identity);
        self.settle(answer)
    }

    /// `verify_executable_file_identity`.
    fn executable(&mut self, identity: &Value) -> Result<(), Failure> {
        let Some(object) = identity.as_object() else {
            return Err(fail(
                "codex_hook_interpreter_identity_invalid",
                "The Codex hook interpreter identity is invalid; repair the installation.",
            ));
        };
        let role = match field(object, "role").as_str() {
            Some(role) if !role.is_empty() => role,
            _ => "interpreter",
        };
        let invocation = field(object, "invocation_path")
            .as_str()
            .filter(|path| Path::new(path).is_absolute());
        let mode = match field(object, "invocation_mode") {
            Value::Number(number) if !number.is_f64() => Some(number.as_i64().unwrap_or(i64::MAX)),
            _ => None,
        };
        let (Some(invocation), Some(mode)) = (invocation, mode) else {
            return Err(file_failure(role, "identity_invalid"));
        };
        let path = Path::new(invocation);
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return Err(file_failure(role, "missing"));
        };
        let facts = FileFacts::of(path, &metadata);
        if i64::from(facts.mode & 0o7777) != mode {
            return Err(file_failure(role, "invocation_mode_mismatch"));
        }
        if self.request.posix {
            let owner = match field(object, "invocation_owner_uid") {
                Value::Bool(flag) => Some(i64::from(*flag)),
                Value::Number(number) if !number.is_f64() => number.as_i64().or(Some(i64::MAX)),
                _ => None,
            };
            if owner.is_some_and(|owner| owner != i64::from(facts.uid)) {
                return Err(file_failure(role, "invocation_owner_mismatch"));
            }
        }
        let is_symlink = metadata.file_type().is_symlink();
        match field(object, "link_target") {
            Value::Null if is_symlink || !metadata.file_type().is_file() => {
                return Err(file_failure(role, "invocation_type_mismatch"));
            }
            Value::Null => {}
            Value::String(target) if is_symlink => {
                let Ok(link) = fs::read_link(path) else {
                    return Err(io_error());
                };
                if link.to_str() != Some(target.as_str()) {
                    return Err(file_failure(role, "symlink_target_mismatch"));
                }
            }
            _ => return Err(file_failure(role, "invocation_type_mismatch")),
        }
        if !invocation_executable(self.request.posix, path) {
            return Err(file_failure(role, "not_executable"));
        }
        let target = field(object, "target");
        self.regular_identity(target)?;
        if field(target.as_object().ok_or_else(unreadable_identity)?, "path").as_str()
            != self.canonical(invocation)
            || self.canonical(invocation).is_none()
        {
            return Err(file_failure(role, "target_path_mismatch"));
        }
        Ok(())
    }

    /// `_verify_packaged_files`: the last identity per role, verified in the
    /// order its role first appears.
    fn packaged_files(
        &mut self,
        manifest: &Map<String, Value>,
        expected: &CodexHookManifestExpectedV1,
    ) -> Result<RoleIdentities, Failure> {
        let Value::Array(items) = field(manifest, "packaged_files") else {
            return Err(fail(
                "codex_hook_manifest_packaged_files_invalid",
                "The Codex hook manifest has no valid packaged-file identities; repair the installation.",
            ));
        };
        let mut by_role: RoleIdentities = Vec::new();
        for item in items {
            let Some(identity) = item.as_object() else {
                continue;
            };
            let Some(role) = field(identity, "role").as_str() else {
                continue;
            };
            match by_role.iter_mut().find(|(known, _)| known == role) {
                Some(slot) => slot.1 = identity.clone(),
                None => by_role.push((role.to_owned(), identity.clone())),
            }
        }
        for (_, identity) in &by_role {
            self.regular_identity(&Value::Object(identity.clone()))?;
        }
        let same_roles = by_role.len() == expected.packaged_paths.len()
            && by_role.iter().all(|(role, identity)| {
                expected.packaged_paths.get(role).map(String::as_str)
                    == field(identity, "path").as_str()
            });
        if !same_roles {
            return Err(fail(
                "codex_hook_manifest_packaged_files_stale",
                "The Codex hook packaged-file paths changed; run repair to authenticate the new installation.",
            ));
        }
        Ok(by_role)
    }

    /// `_verify_event_bindings`, recording each event's match as it goes.
    fn event_bindings(
        &mut self,
        bindings: &[Value],
        expected: &CodexHookManifestExpectedV1,
        hooks: &Map<String, Value>,
    ) -> Result<(), Failure> {
        let expected_argv = match expected.event_bindings.first() {
            None => Some(Vec::new()),
            Some(Value::Object(binding)) => match binding.get("argv") {
                None => Some(Vec::new()),
                Some(argv) => string_list(argv),
            },
            Some(_) => None,
        };
        let Some(expected_argv) = expected_argv else {
            return Err(fail(
                "codex_hook_manifest_registration_invalid",
                "The expected Codex hook registration has an invalid argv identity; repair the installation.",
            ));
        };
        for binding in bindings.iter().filter_map(Value::as_object) {
            let event = field(binding, "event").as_str();
            let slot =
                event.and_then(|event| MANAGED_EVENTS.iter().position(|known| *known == event));
            let group = field(binding, "group");
            let handler = field(binding, "handler");
            let argv = string_list(field(binding, "argv"));
            let (Some(event), Some(slot), true, Some(handler), Some(argv)) =
                (event, slot, group.is_object(), handler.as_object(), argv)
            else {
                return Err(invalid_binding());
            };
            if !py_eq(field(binding, "handler_index"), &json!(0))
                || field(binding, "handler_id").as_str()
                    != Some(format!("codex:{event}:guard-handler-v1").as_str())
            {
                return Err(invalid_binding());
            }
            let split = match field(handler, "command") {
                Value::String(command) => {
                    Syntax::new(self.request.windows, self.request.long_paths.clone())
                        .split_hook(command)
                }
                _ => None,
            };
            if split.as_ref() != Some(&argv) || argv != expected_argv {
                return Err(fail(
                    "codex_hook_manifest_argv_mismatch",
                    "The Codex hook manifest argv identity changed; repair the installation.",
                ));
            }
            if let Some(Value::Array(groups)) = hooks.get(event) {
                if groups.iter().any(|live| py_eq(live, group)) {
                    self.matches[slot] = true;
                }
            }
        }
        Ok(())
    }
}

/// The group lists of the managed events that hold one.
fn group_lists(hooks: &Map<String, Value>) -> impl Iterator<Item = &Vec<Value>> {
    MANAGED_EVENTS
        .iter()
        .filter_map(|event| hooks.get(*event).and_then(Value::as_array))
}

#[path = "codex_hook_manifest_rules.rs"]
mod rules;

#[cfg(test)]
#[path = "codex_hook_manifest_verify_op_fixture.rs"]
mod fixture;

#[cfg(test)]
#[path = "codex_hook_manifest_verify_op_tests.rs"]
mod tests;
