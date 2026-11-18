//! The authenticated record of a Codex manifest/config publication, ported
//! from `codex_hook_recovery`.
//!
//! The record authorizes an exact inverse of the config, the manifest and the
//! retained authority receipt, never another install or a forward replay. One
//! record exists per Guard home, signed with the home's Codex hook key. The
//! caller holds the home-wide installer lock for the record's whole lifetime
//! and names the operation that owns it. Snapshots stay private and are never
//! diagnostic or export material.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::inspect::{decode, recovery, resolve_lenient, sha256_hex, snapshot};
use super::publication_io::{encode, read_private, rollback_identity, write_private};
use super::{Budget, Fault, Step};
use crate::codex_hook_authority_record;
use crate::codex_hook_key;

pub(super) const SCHEMA: &str = "hol-guard.codex-hook-recovery.v1";
pub(super) const MAX_RECORD: usize = 24 * 1024 * 1024;
const AUTHORITY_SCHEMA: &str = "codex-hook-authority-record.v1";
const KEY_MISSING: &str =
    "The private Codex hook authentication key is missing; run `hol-guard install codex` to repair it.";
const KEY_UNUSABLE: &str =
    "The private Codex hook authentication key is not usable; repair the Codex installation.";

/// One request: its fields, the caller's deadlines, and the journal records
/// of every file it wrote, in order.
pub(super) struct Call<'a> {
    pub(super) args: &'a Map<String, Value>,
    pub(super) budget: &'a Budget,
    pub(super) events: Vec<Value>,
}

impl Call<'_> {
    pub(super) fn text(&self, key: &str) -> Step<&str> {
        self.args
            .get(key)
            .and_then(Value::as_str)
            .ok_or(Fault::Transition("files_invalid"))
    }

    pub(super) fn path(&self, key: &str) -> Step<PathBuf> {
        let path = PathBuf::from(self.text(key)?);
        if !path.is_absolute() {
            return Err(Fault::Transition("files_invalid"));
        }
        Ok(path)
    }

    pub(super) fn home(&self) -> Step<PathBuf> {
        self.path("home")
    }

    fn bytes(&self, key: &str) -> Step<Option<Vec<u8>>> {
        decode(self.args.get(key))
    }

    pub(super) fn snapshot(&self, path: &Path) -> Step<Option<Vec<u8>>> {
        snapshot(path, self.budget)
    }

    /// `canonical_path`: the non-strict resolved spelling identities use.
    pub(super) fn canonical(&self, path: &Path) -> Step<String> {
        self.budget.hook()?;
        let resolved = resolve_lenient(path).to_string_lossy().into_owned();
        self.budget.hook()?;
        Ok(resolved)
    }

    /// `hook_manifest_path` and `hook_authority_receipt_path`, for the
    /// canonical config spelling `config`.
    pub(super) fn targets(home: &Path, config: &str) -> (PathBuf, PathBuf) {
        let hash = &sha256_hex(config.as_bytes())[..24];
        let directory = home.join("managed").join("codex");
        (
            directory.join(format!("hooks-{hash}.manifest.json")),
            directory.join(format!("hooks-{hash}.authority-receipt.json")),
        )
    }

    pub(super) fn record_path(home: &Path) -> PathBuf {
        crate::codex_hook_paths_op::record_path(home)
    }

    /// The home's key ids, raised as `load_hook_secret` raises them.
    pub(super) fn key(home: &Path) -> Step<(String, String)> {
        let answer = codex_hook_key::answer("key_identity", &home.to_string_lossy())
            .unwrap_or_else(|| json!({"error": "codex_hook_manifest_secret_invalid"}));
        if let Some(reason) = answer.get("error").and_then(Value::as_str) {
            let message = if reason == "codex_hook_manifest_secret_missing" {
                KEY_MISSING
            } else {
                KEY_UNUSABLE
            };
            return Err(Fault::Integrity(reason.to_owned(), message.to_owned()));
        }
        let field = |key: &str| {
            answer
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| recovery("invalid"))
        };
        Ok((field("key_id")?, field("installation_id")?))
    }

    pub(super) fn installation_id(home: &Path) -> Step<String> {
        Ok(Self::key(home)?.1)
    }

    /// One authority-record operation signed or checked with the home's key.
    pub(super) fn authority(home: &Path, mut request: Map<String, Value>) -> Step<Value> {
        let (key_id, installation_id) = Self::key(home)?;
        request.insert("schema".to_owned(), json!(AUTHORITY_SCHEMA));
        request.insert("key_home".to_owned(), json!(home.to_string_lossy()));
        request.insert("key_id".to_owned(), json!(key_id));
        request.insert("installation_id".to_owned(), json!(installation_id));
        let answer = codex_hook_authority_record::ask(Value::Object(request))
            .map_err(|_| recovery("invalid"))?;
        match answer.get("error").and_then(Value::as_str) {
            Some(reason) => Err(recovery(reason)),
            None => Ok(answer),
        }
    }

    /// `_seal_record` then the private atomic write of the record.
    pub(super) fn store(&mut self, home: &Path, payload: &Map<String, Value>) -> Step<()> {
        let signed_at = payload
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or_else(|| recovery("record_invalid"))?;
        let mut request = Map::new();
        request.insert("op".to_owned(), json!("seal"));
        request.insert("kind".to_owned(), json!("recovery"));
        request.insert("payload".to_owned(), Value::Object(payload.clone()));
        request.insert("signed_at".to_owned(), json!(signed_at));
        let answer = Self::authority(home, request)?;
        let text = answer
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| recovery("invalid"))?;
        if text.len() > MAX_RECORD {
            return Err(recovery("record_too_large"));
        }
        write_private(&Self::record_path(home), text.as_bytes(), &mut self.events)
    }

    /// `_load_record`.
    pub(super) fn load(&self, home: &Path, live_config_conflict: bool) -> Step<Map<String, Value>> {
        self.budget.hook()?;
        let raw = read_private(&Self::record_path(home), MAX_RECORD, false)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .map(|text| text.trim().to_owned());
        self.budget.hook()?;
        let raw = raw.ok_or_else(|| recovery("record_invalid"))?;
        let guard_home = self.canonical(home)?;
        self.budget.hook()?;
        let mut request = Map::new();
        request.insert("op".to_owned(), json!("open"));
        request.insert("kind".to_owned(), json!("recovery"));
        request.insert("text".to_owned(), json!(raw));
        request.insert("guard_home".to_owned(), json!(guard_home));
        request.insert(
            "live_config_conflict".to_owned(),
            json!(live_config_conflict),
        );
        let answer = Self::authority(home, request)?;
        match answer.get("payload") {
            Some(Value::Object(payload)) => Ok(payload.clone()),
            _ => Err(recovery("record_invalid")),
        }
    }

    /// `_repair_proof_matches`.
    pub(super) fn proof_matches(
        home: &Path,
        payload: &Map<String, Value>,
        proof: &Value,
    ) -> Step<bool> {
        let mut request = Map::new();
        request.insert("op".to_owned(), json!("repair_proof"));
        request.insert("payload".to_owned(), Value::Object(payload.clone()));
        request.insert("proof".to_owned(), proof.clone());
        let answer = Self::authority(home, request)?;
        Ok(answer.get("matches").and_then(Value::as_bool) == Some(true))
    }
}

fn field<'a>(payload: &'a Map<String, Value>, key: &str) -> &'a Value {
    payload.get(key).unwrap_or(&Value::Null)
}

/// `prepare_hook_publication`.
pub(super) fn prepare(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let config = call.path("config")?;
    if path_present(&Call::record_path(&home)) {
        return Err(recovery("pending"));
    }
    let before_receipt = call.bytes("before_receipt")?;
    let after_receipt = call.bytes("after_receipt")?;
    if after_receipt.is_none() && before_receipt.is_some() {
        return Err(recovery("snapshot_invalid"));
    }
    let before_config = call.bytes("before_config")?;
    let before_manifest = call.bytes("before_manifest")?;
    let canonical = call.canonical(&config)?;
    let (manifest, receipt) = Call::targets(&home, &canonical);
    let before_identity = rollback_identity(&config)?;
    if call.snapshot(&config)? != before_config || call.snapshot(&manifest)? != before_manifest {
        return Err(recovery("generation_changed"));
    }
    if after_receipt.is_some() && call.snapshot(&receipt)? != before_receipt {
        return Err(recovery("generation_changed"));
    }
    if rollback_identity(&config)? != before_identity {
        return Err(recovery("generation_changed"));
    }
    let mut payload = Map::new();
    payload.insert("schema".to_owned(), json!(SCHEMA));
    payload.insert("phase".to_owned(), json!("prepared"));
    payload.insert("operation_id".to_owned(), json!(call.text("operation_id")?));
    payload.insert("guard_home".to_owned(), json!(call.canonical(&home)?));
    payload.insert("config_path".to_owned(), json!(canonical));
    payload.insert(
        "installation_id".to_owned(),
        json!(Call::installation_id(&home)?),
    );
    let key_created = call.args.get("key_created").and_then(Value::as_bool);
    payload.insert(
        "key_created".to_owned(),
        json!(key_created.ok_or(Fault::Transition("files_invalid"))?),
    );
    payload.insert(
        "before_config".to_owned(),
        encode(before_config.as_deref())?,
    );
    payload.insert(
        "before_config_identity".to_owned(),
        before_identity.unwrap_or(Value::Null),
    );
    payload.insert(
        "before_manifest".to_owned(),
        encode(before_manifest.as_deref())?,
    );
    for key in ["after_config", "after_manifest"] {
        let after = call.bytes(key)?.ok_or(Fault::Transition("files_invalid"))?;
        payload.insert(key.to_owned(), encode(Some(&after))?);
    }
    if after_receipt.is_some() {
        payload.insert(
            "before_receipt".to_owned(),
            encode(before_receipt.as_deref())?,
        );
        payload.insert(
            "after_receipt".to_owned(),
            encode(after_receipt.as_deref())?,
        );
    }
    let monotonic = field(call.args, "repair_publication_monotonic").clone();
    match call.args.get("repair_plan") {
        Some(plan @ Value::Object(_)) => {
            payload.insert("repair_plan".to_owned(), plan.clone());
            payload.insert("repair_publication_monotonic".to_owned(), monotonic);
        }
        _ if !monotonic.is_null() => return Err(recovery("repair_record_invalid")),
        _ => {}
    }
    call.store(&home, &payload)?;
    Ok(Value::Null)
}

pub(super) fn path_present(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// `assert_owned_hook_repair_publication`: only the authenticated, exact
/// provisional record owned now.
pub(super) fn assert_repair(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let config = call.path("config")?;
    let payload = call.load(&home, false)?;
    let config_bytes = encode(call.bytes("config_bytes")?.as_deref())?;
    let receipt_bytes = encode(call.bytes("receipt_bytes")?.as_deref())?;
    let expected = [
        ("operation_id", json!(call.text("operation_id")?)),
        ("config_path", json!(call.canonical(&config)?)),
        ("repair_plan", field(call.args, "repair_plan").clone()),
        ("phase", json!("prepared")),
        ("key_created", json!(false)),
        (
            "repair_publication_monotonic",
            field(call.args, "publication_monotonic").clone(),
        ),
        ("before_config", config_bytes.clone()),
        ("after_config", config_bytes),
        ("before_manifest", Value::Null),
        (
            "after_manifest",
            encode(call.bytes("manifest_bytes")?.as_deref())?,
        ),
        ("before_receipt", receipt_bytes.clone()),
        ("after_receipt", receipt_bytes),
    ];
    if expected
        .iter()
        .any(|(key, value)| field(&payload, key) != value)
    {
        return Err(recovery("repair_owner_mismatch"));
    }
    Ok(Value::Null)
}

/// `_config_publication_slot`: the parent resolved, the leaf as written, so
/// a substituted leaf symlink cannot move the publication.
fn publication_slot(config: &Path) -> String {
    match (config.parent(), config.file_name()) {
        (Some(parent), Some(name)) => resolve_lenient(parent)
            .join(name)
            .to_string_lossy()
            .into_owned(),
        _ => config.to_string_lossy().into_owned(),
    }
}

/// `mark_owned_hook_publication_conflict`: durably refuse an inverse once the
/// owner still holding the record sees a competing config.
pub(super) fn mark_conflict(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let config = call.path("config")?;
    let mut payload = call.load(&home, true)?;
    if field(&payload, "operation_id").as_str() != Some(call.text("operation_id")?)
        || field(&payload, "config_path").as_str() != Some(publication_slot(&config).as_str())
        || field(&payload, "phase").as_str() != Some("prepared")
        || payload.contains_key("repair_plan")
    {
        return Err(recovery("conflict_owner_mismatch"));
    }
    let slot = field(&payload, "config_path").as_str().unwrap_or_default();
    let (manifest, receipt) = Call::targets(&home, slot);
    let mut targets = vec![(manifest, "before_manifest", "after_manifest")];
    if payload.contains_key("after_receipt") {
        targets.push((receipt, "before_receipt", "after_receipt"));
    }
    for (target, before, after) in targets {
        let current = call.snapshot(&target)?;
        if current != decode(payload.get(before))? && current != decode(payload.get(after))? {
            return Err(recovery("generation_changed"));
        }
    }
    payload.insert("phase".to_owned(), json!("config_conflict"));
    call.store(&home, &payload)?;
    Ok(Value::Null)
}

/// `record_owned_hook_config_publication`: the observed published inode is
/// durable before the readback is accepted.
pub(super) fn record_config(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let config = call.path("config")?;
    let identity = field(call.args, "identity").clone();
    let mut payload = call.load(&home, false)?;
    if field(&payload, "operation_id").as_str() != Some(call.text("operation_id")?)
        || field(&payload, "phase").as_str() != Some("prepared")
        || field(&payload, "config_path").as_str() != Some(call.canonical(&config)?.as_str())
        || payload.contains_key("repair_plan")
    {
        return Err(recovery("config_publication_owner_mismatch"));
    }
    if rollback_identity(&config)?.as_ref() != Some(&identity)
        || call.snapshot(&config)? != decode(payload.get("after_config"))?
        || rollback_identity(&config)?.as_ref() != Some(&identity)
    {
        return Err(recovery("generation_changed"));
    }
    payload.insert("after_config_identity".to_owned(), identity);
    call.store(&home, &payload)?;
    Ok(Value::Null)
}
