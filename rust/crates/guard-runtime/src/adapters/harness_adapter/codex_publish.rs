//! Codex: publishing an authenticated hook generation, ported from
//! `CodexHarnessAdapter._write_authenticated_hook_config_owned`.
//!
//! Python reads the publication target and prepares the generation; this op
//! commits it. The manifest goes first, then the config: during that window
//! an old config fails closed against the new manifest, so Codex never runs
//! a newly registered hook before its authenticated identity is durable.
//! The publication record is prepared, every file written, the written
//! config's inode recorded, its hook semantics read back, the live hook
//! state verified, and the record committed. Any failure runs the durable
//! inverse (`publication_abort`) and, when nothing was durable, removes a
//! key this install created.
//!
//! Request fields: `home`, `config`, `operation_id`, `files` (the planned
//! changes, written in order), `config_index`, `manifest_index`,
//! `receipt_index`, `original` and `original_identity` (the target's config
//! snapshot), `key_present`, `budget`, `package_roots`, and the fields
//! `live_hook_state` reads. Answer: `events` (the journal records and file
//! writes, in order) with `state` (the verified hook state as JSON text),
//! `reply` (short names to expand, the publication undone) or `error` (a
//! transition fault, or `{"runtime": message}`) and, when the inverse itself
//! failed, `rollback_error`.

use serde_json::{json, Map, Value};

use super::codex::{config_path, scope_for, HOOK_UNAVAILABLE};
use super::codex_live_state::live_hook_state;
use super::codex_merge;
use super::{Ctx, Failure, Step};
use crate::codex_hook_key;
use crate::codex_toml_read::{self, TomlVal};
use crate::pyjson::PyVal;

const INVALID: &str = "native_transition_invalid";
const CONFLICT: &str = "adapter_preparation_generation_conflict";

/// A fault as Python raises it: a transition fault the runtime sent, or a
/// `RuntimeError` message.
type Fault = Value;

fn runtime(message: impl Into<String>) -> Fault {
    json!({ "runtime": message.into() })
}

fn transition(reason: &str) -> Fault {
    json!({ "transition": reason })
}

fn from_failure(failure: Failure) -> Fault {
    match failure {
        Failure::Runtime(message) | Failure::Refusal(message) => runtime(message),
        Failure::Os(message) | Failure::NotFound(message) => json!({ "os": message }),
        // Short names the Guard process must expand: undone, then asked again.
        Failure::Reply(reply) => json!({ "reply": reply }),
        _ => transition(INVALID),
    }
}

/// One publication: the request, the journal so far and what the inverse
/// needs to know.
struct Publication<'a> {
    fields: &'a Map<String, Value>,
    events: Vec<Value>,
    prepared: bool,
    written: Value,
    written_identity: Value,
}

impl Publication<'_> {
    fn text(&self, key: &str) -> Result<&str, Fault> {
        self.fields
            .get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| transition(INVALID))
    }

    /// One `transition_files` op on this home, its journal records kept.
    fn ask(&mut self, op: &str, mut request: Map<String, Value>) -> Result<Value, Fault> {
        request.insert("op".to_owned(), json!(op));
        request.insert("home".to_owned(), json!(self.text("home")?));
        for key in ["package_roots", "budget"] {
            if let Some(value) = self.fields.get(key) {
                request.insert(key.to_owned(), value.clone());
            }
        }
        let answer = crate::transition_files::dispatch(&Value::Object(request))
            .map_err(|_| transition(INVALID))?;
        if let Some(events) = answer.get("events").and_then(Value::as_array) {
            self.events.extend(events.iter().cloned());
        }
        if let Some(error) = answer.get("error") {
            return Err(error.clone());
        }
        Ok(answer.get("value").cloned().unwrap_or(Value::Null))
    }

    fn change(&self, key: &str) -> Result<&Map<String, Value>, Fault> {
        let index = self
            .fields
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| transition(INVALID))?;
        self.fields
            .get("files")
            .and_then(Value::as_array)
            .and_then(|files| files.get(usize::try_from(index).ok()?))
            .and_then(Value::as_object)
            .ok_or_else(|| transition(INVALID))
    }

    fn side(&self, key: &str, side: &str) -> Result<Value, Fault> {
        Ok(self.change(key)?.get(side).cloned().unwrap_or(Value::Null))
    }

    fn forward(&mut self, ctx: &Ctx) -> Result<String, Fault> {
        let config = self.text("config")?.to_owned();
        let original = self.fields.get("original").cloned().unwrap_or(Value::Null);
        let after_config = self.side("config_index", "after")?;
        if self.side("config_index", "before")? != original || after_config.is_null() {
            return Err(transition(CONFLICT));
        }
        self.written = after_config.clone();
        let mut record = Map::new();
        record.insert("operation_id".to_owned(), json!(self.text("operation_id")?));
        record.insert("config".to_owned(), json!(config));
        record.insert("before_config".to_owned(), original);
        record.insert("after_config".to_owned(), after_config.clone());
        record.insert(
            "before_manifest".to_owned(),
            self.side("manifest_index", "before")?,
        );
        record.insert(
            "after_manifest".to_owned(),
            self.side("manifest_index", "after")?,
        );
        record.insert(
            "before_receipt".to_owned(),
            self.side("receipt_index", "before")?,
        );
        record.insert(
            "after_receipt".to_owned(),
            self.side("receipt_index", "after")?,
        );
        let key_present = self.fields.get("key_present").and_then(Value::as_bool) == Some(true);
        record.insert("key_created".to_owned(), json!(!key_present));
        self.ask("publication_prepare", record)?;
        self.prepared = true;
        // The journal restores the authenticated files; backups stay, as they
        // always have.
        let mut publish = Map::new();
        publish.insert(
            "files".to_owned(),
            self.fields.get("files").cloned().unwrap_or(Value::Null),
        );
        publish.insert("removals".to_owned(), json!(false));
        publish.insert("rollback".to_owned(), json!(false));
        self.ask("publish", publish)?;
        let identity = self.ask("publication_identity", path_request(&config))?;
        if identity.is_null() {
            return Err(runtime(
                "codex_hook_config_invalid: Codex configuration vanished after publication.",
            ));
        }
        self.written_identity = identity.clone();
        let mut owned = path_request(&config);
        owned.insert("config".to_owned(), json!(config));
        owned.insert("operation_id".to_owned(), json!(self.text("operation_id")?));
        owned.insert("identity".to_owned(), identity);
        self.ask("publication_config", owned)?;
        let actual = self.ask("publication_snapshot", path_request(&config))?;
        readback(ctx, &config, &after_config, &actual)?;
        let answer = live_hook_state(ctx, self.fields).map_err(from_failure)?;
        let state = answer
            .get("state")
            .and_then(Value::as_str)
            .ok_or_else(|| transition(INVALID))?
            .to_owned();
        let parsed: Value = serde_json::from_str(&state).map_err(|_| transition(INVALID))?;
        if parsed.get("protection_active") != Some(&json!(true)) {
            let reason = parsed
                .get("integrity_reason")
                .and_then(Value::as_str)
                .filter(|reason| !reason.is_empty())
                .unwrap_or("codex_hook_integrity_readback_failed");
            return Err(runtime(format!(
                "{HOOK_UNAVAILABLE}: Codex hook authentication readback failed: {reason}"
            )));
        }
        self.ask("publication_commit", Map::new())?;
        self.ask("publication_remove", Map::new())?;
        Ok(state)
    }

    /// The inverse: the runtime undoes a prepared publication, or marks the
    /// record as a config conflict when the config is no longer this writer's.
    /// Answers the fault to raise and, when the inverse itself failed, the
    /// rollback fault.
    fn abort(&mut self, failure: Fault) -> (Fault, Option<Fault>) {
        let mut request = Map::new();
        request.insert(
            "config".to_owned(),
            json!(self.text("config").unwrap_or_default()),
        );
        request.insert("prepared".to_owned(), json!(self.prepared));
        for (key, value) in [
            ("original", self.fields.get("original").cloned()),
            ("written", Some(self.written.clone())),
            (
                "original_identity",
                self.fields.get("original_identity").cloned(),
            ),
            ("written_identity", Some(self.written_identity.clone())),
            ("operation_id", self.fields.get("operation_id").cloned()),
        ] {
            request.insert(key.to_owned(), value.unwrap_or(Value::Null));
        }
        let aborted = match self.ask("publication_abort", request) {
            Ok(aborted) => aborted,
            Err(conflict) => return (conflict, None),
        };
        let key_present = self.fields.get("key_present").and_then(Value::as_bool) == Some(true);
        if let Some(error) = aborted.get("rollback_error") {
            return (failure, Some(error.clone()));
        }
        if aborted.get("durable") != Some(&json!(true)) && !key_present {
            // Preparation has not published either file. Restoring their
            // snapshots here would overwrite an intervening user edit.
            if let Err(error) = self.remove_unused_key() {
                return (failure, Some(runtime(error)));
            }
        }
        (failure, None)
    }

    fn remove_unused_key(&mut self) -> Result<(), String> {
        let home = self
            .text("home")
            .map_err(|fault| fault.to_string())?
            .to_owned();
        let answer = codex_hook_key::answer("key_remove_if_unused", &home)
            .ok_or_else(|| "codex_hook_key_unavailable".to_owned())?;
        if let Some(reason) = answer.get("error").and_then(Value::as_str) {
            return Err(reason.to_owned());
        }
        if answer.get("removed") == Some(&json!(true)) {
            let path = codex_hook_key::key_path(std::path::Path::new(&home));
            self.events.push(json!({ "mutation": {
                "operation": "remove_unused_key",
                "path": path.to_string_lossy(),
                "before_present": true,
                "after_present": false,
                "before_digest": EMPTY_SHA256,
                "after_digest": null,
            }}));
        }
        Ok(())
    }
}

/// `record_codex_mutation` journals the key's removal as empty bytes.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn path_request(path: &str) -> Map<String, Value> {
    let mut request = Map::new();
    request.insert("path".to_owned(), json!(path));
    request
}

fn toml_entries(encoded: &Value) -> Result<Vec<(String, TomlVal)>, Fault> {
    use base64::Engine as _;
    let invalid =
        || runtime("codex_hook_config_invalid: The rendered Codex config file is not valid TOML.");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_str().ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    let text = String::from_utf8(bytes).map_err(|_| invalid())?;
    codex_toml_read::read(&text).map_err(|_| invalid())
}

/// `_require_hook_semantics_readback` over the rendered and written config.
fn readback(ctx: &Ctx, config: &str, rendered: &Value, written: &Value) -> Result<(), Fault> {
    let both = vec![
        (
            "expected".to_owned(),
            TomlVal::Table(toml_entries(rendered)?),
        ),
        ("actual".to_owned(), TomlVal::Table(toml_entries(written)?)),
    ];
    let (payload, tokens) = codex_toml_read::wire(&both);
    let side = |key: &str| match payload.get(key) {
        Some(value @ PyVal::Dict(_)) => Ok(super::codex::compact(value, false)),
        _ => Err(transition(INVALID)),
    };
    let mut fields = Map::new();
    fields.insert("expected".to_owned(), json!(side("expected")?));
    fields.insert("actual".to_owned(), json!(side("actual")?));
    fields.insert("tokens".to_owned(), Value::Object(tokens));
    let path = std::path::Path::new(config);
    fields.insert("scope".to_owned(), json!(scope_for(ctx, path)));
    fields.insert("source_path".to_owned(), json!(config));
    codex_merge::dispatch("readback", &fields)
        .map(|_| ())
        .map_err(from_failure)
}

/// `publish_hooks`.
pub(super) fn publish_hooks(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let config = fields
        .get("config")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    if ctx.absolute(&config_path(ctx)) != std::path::Path::new(config) {
        return Err(Failure::Runtime(
            "Codex authenticated publication requires its canonical config target.".to_owned(),
        ));
    }
    let mut publication = Publication {
        fields,
        events: Vec::new(),
        prepared: false,
        written: Value::Null,
        written_identity: Value::Null,
    };
    let mut answer = match publication.forward(ctx) {
        Ok(state) => json!({ "state": state }),
        Err(fault) => match publication.abort(fault) {
            // Undone; the caller expands the short names and asks again.
            (fault, None) if fault.get("reply").is_some() => json!({ "reply": fault["reply"] }),
            (fault, None) => json!({ "error": fault }),
            (fault, Some(rollback)) => json!({ "error": fault, "rollback_error": rollback }),
        },
    };
    answer["events"] = Value::Array(publication.events);
    Ok(answer)
}

#[cfg(test)]
#[path = "codex_publish_tests.rs"]
mod tests;
