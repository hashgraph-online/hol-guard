//! The retained authority receipt of a Codex hook publication, ported from
//! `codex_hook_recovery.load_hook_authority_receipt` and
//! `build_hook_authority_receipt`.
//!
//! A receipt keeps the exact manifest a config generation was published with.
//! Authenticating it never authorizes a restore: a repair planner must still
//! pin the files and key, validate the package and registration, and obtain a
//! fresh exact lifecycle approval before publishing anything.

use serde_json::{json, Map, Value};

use super::inspect::{decode, recovery, sha256_hex, MAX_SNAPSHOT};
use super::publication::Call;
use super::publication_io::{encode, read_private};
use super::{Fault, Step};
use crate::codex_hook_manifest_auth;

const RECEIPT_SCHEMA: &str = "hol-guard.codex-hook-authority-receipt.v1";
const MANIFEST_REFUSED: &str =
    "The Codex hook manifest authentication failed; run `hol-guard install codex` to repair it.";

fn request(op: &str, fields: [(&str, Value); 3]) -> Map<String, Value> {
    let mut request = Map::new();
    request.insert("op".to_owned(), json!(op));
    request.insert("kind".to_owned(), json!("receipt"));
    for (key, value) in fields {
        request.insert(key.to_owned(), value);
    }
    request
}

/// `load_hook_authority_receipt`: the receipt, its embedded manifest and the
/// config it was retained for, each read twice under one key generation.
pub(super) fn load(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let config = call.path("config")?;
    let guard_home = call.canonical(&home)?;
    let config_path = call.canonical(&config)?;
    let (_, receipt) = Call::targets(&home, &config_path);
    call.budget.hook()?;
    let raw =
        read_private(&receipt, MAX_SNAPSHOT, true).ok_or_else(|| recovery("receipt_invalid"))?;
    call.budget.hook()?;
    let key = Call::key(&home)?;
    call.budget.hook()?;
    let text = std::str::from_utf8(&raw).map_err(|_| recovery("undecodable"))?;
    let opened = Call::authority(
        &home,
        request(
            "open",
            [
                ("text", json!(text)),
                ("guard_home", json!(guard_home)),
                ("config_path", json!(config_path)),
            ],
        ),
    )?;
    let Some(Value::Object(payload)) = opened.get("payload") else {
        return Err(recovery("receipt_invalid"));
    };
    call.budget.hook()?;
    let manifest_bytes =
        decode(payload.get("manifest"))?.ok_or_else(|| recovery("receipt_invalid"))?;
    let manifest_text =
        std::str::from_utf8(&manifest_bytes).map_err(|_| recovery("receipt_invalid"))?;
    let manifest = codex_hook_manifest_auth::authenticate_text(
        &home.to_string_lossy(),
        manifest_text,
        Some(&key.0),
        Some(&key.1),
    )
    .map_err(|reason| Fault::Integrity(reason.to_owned(), MANIFEST_REFUSED.to_owned()))?;
    Call::authority(
        &home,
        request(
            "receipt_manifest",
            [
                ("manifest", Value::Object(manifest)),
                ("guard_home", json!(guard_home)),
                ("config_path", json!(config_path)),
            ],
        ),
    )?;
    call.budget.hook()?;
    let config_bytes = call.snapshot(&config)?;
    let recorded = payload.get("config_sha256").and_then(Value::as_str);
    let Some(config_bytes) =
        config_bytes.filter(|bytes| Some(sha256_hex(bytes).as_str()) == recorded)
    else {
        return Err(recovery("receipt_generation_changed"));
    };
    call.budget.hook()?;
    if read_private(&receipt, MAX_SNAPSHOT, true).as_deref() != Some(raw.as_slice())
        || call.snapshot(&config)?.as_deref() != Some(config_bytes.as_slice())
        || Call::key(&home)? != key
    {
        return Err(recovery("receipt_generation_changed"));
    }
    call.budget.hook()?;
    // The caller's plan names the manifest this receipt must retain.
    if let Some(reason) = call.args.get("mismatch").and_then(Value::as_str) {
        let fault = match reason {
            "generation_changed" => Fault::Transition("generation_changed"),
            "authority_repair_request_plan_invalid" => {
                Fault::Transition("authority_repair_request_plan_invalid")
            }
            _ => Fault::Transition("files_invalid"),
        };
        if decode(call.args.get("expect_manifest"))?.as_deref() != Some(manifest_bytes.as_slice()) {
            return Err(fault);
        }
    }
    Ok(json!({
        "manifest": encode(Some(&manifest_bytes))?,
        "receipt": encode(Some(&raw))?,
        "config": encode(Some(&config_bytes))?,
    }))
}

/// `build_hook_authority_receipt`: the sealed receipt text that retains
/// `manifest` for the config generation `config_bytes`.
pub(super) fn build(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let config = call.path("config")?;
    let config_bytes =
        decode(call.args.get("config_bytes"))?.ok_or(Fault::Transition("files_invalid"))?;
    let manifest_bytes =
        decode(call.args.get("manifest_bytes"))?.ok_or(Fault::Transition("files_invalid"))?;
    seal(call, &home, &config, &config_bytes, &manifest_bytes)
}

/// The receipt text for `config` at `config_bytes`, retaining `manifest_bytes`.
pub(super) fn seal(
    call: &Call<'_>,
    home: &std::path::Path,
    config: &std::path::Path,
    config_bytes: &[u8],
    manifest_bytes: &[u8],
) -> Step<Value> {
    let mut payload = Map::new();
    payload.insert("schema".to_owned(), json!(RECEIPT_SCHEMA));
    payload.insert("guard_home".to_owned(), json!(call.canonical(home)?));
    payload.insert("config_path".to_owned(), json!(call.canonical(config)?));
    payload.insert(
        "installation_id".to_owned(),
        json!(Call::installation_id(home)?),
    );
    payload.insert("config_sha256".to_owned(), json!(sha256_hex(config_bytes)));
    payload.insert("manifest".to_owned(), encode(Some(manifest_bytes))?);
    let mut sealed = Map::new();
    sealed.insert("op".to_owned(), json!("seal"));
    sealed.insert("kind".to_owned(), json!("receipt"));
    sealed.insert("payload".to_owned(), Value::Object(payload));
    let answer = Call::authority(home, sealed)?;
    answer
        .get("text")
        .filter(|text| text.is_string())
        .cloned()
        .ok_or_else(|| recovery("invalid"))
}
