//! A signed Codex config/manifest generation, ported from
//! `codex_hook_manifest.prepare_authenticated_hook_publication`.
//!
//! Nothing here writes a published file. The answer is the signed manifest
//! and four transition files: the config, the manifest, the key pinned by
//! digest (never its bytes) and the authority receipt, each prior file named
//! by digest; `publication_generation_before` returns those prior bytes. Without `create_key`
//! the prior baseline must authenticate and equal `previous_manifest`; with
//! it the caller already holds the install owner and has checked that
//! baseline, and a missing key is created.
//!
//! Request fields: `home`, `config` and the baseline fields
//! `publication_baseline` reads, `spec` (the manifest spec payload),
//! `rendered_config` (text), `previous_manifest` (object or null),
//! `create_key` and `package_roots`.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::inspect::{decode, mode_of, resolve_lenient, sha256_hex};
use super::publication::{path_present, Call};
use super::publication_io::encode;
use super::{compare, publication_baseline, publication_receipt, Ask, Fault, Step};
use crate::codex_hook_file_integrity_op;
use crate::codex_hook_key;
use crate::codex_hook_manifest_build::{self, Signer};

const PRIVATE_MODE: u32 = 0o600;
const SCHEMA_VERSION: i64 = 2;
const KEY_MISSING: &str =
    "The private Codex hook authentication key is missing; run `hol-guard install codex` to repair it.";
const KEY_UNUSABLE: &str =
    "The private Codex hook authentication key is not usable; repair the Codex installation.";
const UNAVAILABLE: &str = "codex_hook_manifest_verification_unavailable";

pub(super) fn generation(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let previous = match call.args.get("previous_manifest") {
        None | Some(Value::Null) => None,
        Some(Value::Object(manifest)) => Some(manifest.clone()),
        Some(_) => return Err(Fault::Transition("files_invalid")),
    };
    let create_key = call.args.get("create_key").and_then(Value::as_bool) == Some(true);
    let spec = call
        .args
        .get("spec")
        .and_then(Value::as_object)
        .cloned()
        .ok_or(Fault::Transition("files_invalid"))?;
    let rendered = call.text("rendered_config")?.as_bytes().to_vec();
    let roots = package_roots(call.args)?;

    if !create_key {
        let baseline = publication_baseline::load(call)?;
        let manifest = match baseline.as_object() {
            Some(answer) if answer.len() == 1 && answer.contains_key("manifest") => {
                answer["manifest"].clone()
            }
            _ => return Err(untrusted()),
        };
        if manifest != previous.clone().map_or(Value::Null, Value::Object) {
            return Err(Fault::Transition("adapter_preparation_generation_conflict"));
        }
    }

    let given = call.path("config")?;
    let config = match (given.parent(), given.file_name()) {
        (Some(parent), Some(name)) => resolve_lenient(parent).join(name),
        _ => given.clone(),
    };
    let (manifest_path, receipt_path) = Call::targets(&home, &call.canonical(&given)?);
    let before_config = call.snapshot(&config)?;
    let before_manifest = call.snapshot(&manifest_path)?;
    let before_receipt = call.snapshot(&receipt_path)?;
    if before_config.is_some() {
        let path_roots: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
        codex_hook_file_integrity_op::admit(&config, "config_target", false, &path_roots).map_err(
            |reason| {
                let message = codex_hook_file_integrity_op::message(&reason);
                Fault::Integrity(reason, message)
            },
        )?;
    }
    if before_config
        .as_deref()
        .is_some_and(|data| std::str::from_utf8(data).is_err())
    {
        return Err(Fault::Integrity(
            "codex_hook_config_invalid".to_owned(),
            "codex_hook_config_invalid: Codex configuration is not valid UTF-8.".to_owned(),
        ));
    }
    let mode = |path: &Path, present: bool| {
        if present {
            mode_of(path)
        } else {
            Ok(PRIVATE_MODE)
        }
    };
    let config_mode = mode(&config, before_config.is_some())?;
    let manifest_mode = mode(&manifest_path, before_manifest.is_some())?;
    let receipt_mode = mode(&receipt_path, before_receipt.is_some())?;

    let secret_path = codex_hook_key::key_path(&home);
    let authority_before = if path_present(&secret_path) {
        Some(identity_dependency(call, &secret_path)?)
    } else {
        None
    };
    let manifest = signed(call, &home, &spec, previous.as_ref(), &roots, create_key)?;
    reauthentication_safe(previous.as_ref(), &manifest)?;
    let authority = match authority_before {
        Some(dependency) => dependency,
        None => identity_dependency(call, &secret_path)?,
    };
    let ask = Ask {
        budget: *call.budget,
        package_roots: roots.iter().map(PathBuf::from).collect(),
    };
    // A key replaced while the manifest was built is a generation conflict.
    compare(std::slice::from_ref(&authority), "before", false, &ask)?;

    let mut manifest_bytes = canonical(&manifest)?.into_bytes();
    manifest_bytes.push(b'\n');
    let receipt = publication_receipt::seal(call, &home, &config, &rendered, &manifest_bytes)?;
    let receipt = receipt
        .as_str()
        .ok_or(Fault::Transition("files_invalid"))?
        .as_bytes()
        .to_vec();
    let files = vec![
        change(&config, before_config.as_deref(), &rendered, config_mode)?,
        change(
            &manifest_path,
            before_manifest.as_deref(),
            &manifest_bytes,
            manifest_mode,
        )?,
        authority,
        change(
            &receipt_path,
            before_receipt.as_deref(),
            &receipt,
            receipt_mode,
        )?,
    ];
    compare(&files, "before", false, &ask)?;
    // The resident answer is capped, and a manifest with retained bridge
    // generations is large: name each prior file by digest and let
    // `publication_generation_before` return its bytes in a second answer.
    let files: Vec<Value> = files.into_iter().map(by_digest).collect::<Step<_>>()?;
    Ok(json!({ "files": files }))
}

fn by_digest(mut file: Value) -> Step<Value> {
    let entry = file
        .as_object_mut()
        .ok_or(Fault::Transition("files_invalid"))?;
    if entry.contains_key("expected_digest") {
        return Ok(file);
    }
    let digest = decode(entry.get("before"))?.map(|data| sha256_hex(&data));
    entry.insert("before".to_owned(), Value::Null);
    entry.insert("before_sha256".to_owned(), json!(digest));
    Ok(file)
}

/// The prior bytes `generation` named by digest. Request field `files`:
/// `[{"path", "sha256"}]`, `sha256` null for an absent file. Answer:
/// `{"before": [base64 or null]}`. A file that no longer matches is
/// `generation_changed`, as the transition compare reports it.
pub(super) fn snapshot(call: &mut Call<'_>) -> Step<Value> {
    let files = call
        .args
        .get("files")
        .and_then(Value::as_array)
        .ok_or(Fault::Transition("files_invalid"))?
        .clone();
    let mut before = Vec::with_capacity(files.len());
    for file in &files {
        let path = file
            .get("path")
            .and_then(Value::as_str)
            .ok_or(Fault::Transition("files_invalid"))?;
        let expected = match file.get("sha256") {
            Some(Value::String(digest)) => Some(digest.as_str()),
            Some(Value::Null) | None => None,
            Some(_) => return Err(Fault::Transition("files_invalid")),
        };
        let data = call.snapshot(Path::new(path))?;
        if data.as_deref().map(sha256_hex).as_deref() != expected {
            return Err(Fault::Transition("generation_changed"));
        }
        before.push(encode(data.as_deref())?);
    }
    Ok(json!({ "before": before }))
}

pub(super) fn package_roots(args: &Map<String, Value>) -> Step<Vec<String>> {
    match args.get("package_roots") {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or(Fault::Transition("files_invalid"))
            })
            .collect(),
        Some(_) => Err(Fault::Transition("files_invalid")),
    }
}

fn untrusted() -> Fault {
    Fault::Integrity(
        "codex_hook_manifest_baseline_untrusted".to_owned(),
        "Guard refused to authenticate hook package bytes because the existing managed-hook \
         baseline is missing, invalid, or belongs to another installation. Reinstall hol-guard \
         from a trusted package, then run `hol-guard install codex` again."
            .to_owned(),
    )
}

/// `TransitionFile.identity_dependency`: the key pinned by its digest.
pub(super) fn identity_dependency(call: &Call<'_>, path: &Path) -> Step<Value> {
    let data = call
        .snapshot(path)?
        .ok_or(Fault::Transition("authority_dependency_missing"))?;
    let mode = mode_of(path)?;
    Ok(json!({
        "path": resolve_lenient(path).to_string_lossy(),
        "before": null,
        "after": null,
        "before_mode": mode,
        "after_mode": mode,
        "kind": "binding",
        "no_follow": true,
        "expected_digest": sha256_hex(&data),
    }))
}

fn change(path: &Path, before: Option<&[u8]>, after: &[u8], before_mode: u32) -> Step<Value> {
    Ok(json!({
        "path": resolve_lenient(path).to_string_lossy(),
        "before": encode(before)?,
        "after": encode(Some(after))?,
        "before_mode": before_mode,
        "after_mode": PRIVATE_MODE,
        "kind": "binding",
        "no_follow": true,
    }))
}

/// `build_authenticated_hook_manifest`, under the key `create_key` ensures.
fn signed(
    call: &Call<'_>,
    home: &Path,
    spec: &Map<String, Value>,
    previous: Option<&Map<String, Value>>,
    roots: &[String],
    create_key: bool,
) -> Step<Value> {
    let home_text = home.to_string_lossy();
    let op = if create_key {
        "key_ensure"
    } else {
        "key_identity"
    };
    let identity = codex_hook_key::answer(op, &home_text).ok_or_else(unavailable)?;
    if let Some(reason) = identity.get("error").and_then(Value::as_str) {
        let message = if reason == "codex_hook_manifest_secret_missing" {
            KEY_MISSING
        } else {
            KEY_UNUSABLE
        };
        return Err(Fault::Integrity(reason.to_owned(), message.to_owned()));
    }
    let id = |key: &str| {
        identity
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(unavailable)
    };
    let (key_id, installation_id) = (id("key_id")?, id("installation_id")?);
    call.budget.hook()?;
    let refused = |reason: String| {
        if reason == "runtime_unavailable" || reason == "invalid" {
            return unavailable();
        }
        Fault::Integrity(
            reason,
            "Guard cannot authenticate the Codex hook installation; repair the installation."
                .to_owned(),
        )
    };
    let held = codex_hook_key::read_matching(&home_text, Some(key_id), Some(installation_id))
        .map_err(|reason| refused(reason.to_owned()))?;
    let signer = Signer {
        key: &held.key,
        key_id: &held.key_id,
        installation_id: &held.installation_id,
    };
    codex_hook_manifest_build::build(spec, previous, roots, &signer).map_err(refused)
}

fn unavailable() -> Fault {
    Fault::Integrity(
        UNAVAILABLE.to_owned(),
        "Guard's native runtime did not build the Codex hook manifest; run `hol-guard repair`."
            .to_owned(),
    )
}

fn canonical(value: &Value) -> Step<String> {
    let mut output = Vec::new();
    guard_contracts::write_canonical_json(value, &mut output)
        .map_err(|_| Fault::Transition("files_invalid"))?;
    String::from_utf8(output).map_err(|_| Fault::Transition("files_invalid"))
}

/// `assert_package_reauthentication_is_safe`: a same-version manifest may
/// move the interpreter only when the managed package bytes match.
fn reauthentication_safe(previous: Option<&Map<String, Value>>, replacement: &Value) -> Step<()> {
    let Some(previous) = previous else {
        return Ok(());
    };
    if previous.get("schema_version").and_then(Value::as_i64) != Some(SCHEMA_VERSION) {
        return Ok(());
    }
    if previous.get("package_version") != replacement.get("package_version") {
        return Ok(());
    }
    let before = package_identity(previous.get("packaged_files"));
    if before.is_some() && before == package_identity(replacement.get("packaged_files")) {
        return Ok(());
    }
    Err(Fault::Integrity(
        "codex_hook_package_reauthentication_refused".to_owned(),
        "Guard refused to authenticate changed same-version hook code or interpreter bytes. \
         Reinstall hol-guard from a trusted package, then run `hol-guard install codex` again."
            .to_owned(),
    ))
}

type FileIdentity = (String, String, i64, i64, bool);

fn package_identity(files: Option<&Value>) -> Option<Vec<FileIdentity>> {
    let files = files?.as_array().filter(|files| !files.is_empty())?;
    let mut identities = Vec::with_capacity(files.len());
    for file in files {
        let file = file.as_object()?;
        let int = |key: &str| file.get(key).and_then(Value::as_i64);
        identities.push((
            file.get("role")?.as_str()?.to_owned(),
            file.get("sha256")?.as_str()?.to_owned(),
            int("size")?,
            int("mode")?,
            file.get("executable_required")?.as_bool()?,
        ));
    }
    let mut roles: Vec<&str> = identities.iter().map(|id| id.0.as_str()).collect();
    roles.sort_unstable();
    roles.dedup();
    if roles.len() != identities.len() {
        return None;
    }
    identities.sort();
    Some(identities)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: &str, files: Value) -> Map<String, Value> {
        json!({
            "schema_version": SCHEMA_VERSION,
            "package_version": version,
            "packaged_files": files,
        })
        .as_object()
        .cloned()
        .unwrap_or_default()
    }

    fn file(role: &str, digest: &str) -> Value {
        json!({"role": role, "sha256": digest, "size": 3, "mode": 420, "executable_required": false})
    }

    fn refused(result: Step<()>) -> bool {
        matches!(result, Err(Fault::Integrity(code, _)) if code == "codex_hook_package_reauthentication_refused")
    }

    #[test]
    fn incomplete_package_identity_is_refused() {
        let previous = manifest("2.1.0a6", json!([]));
        assert!(refused(reauthentication_safe(
            Some(&previous),
            &Value::Object(previous.clone())
        )));
    }

    #[test]
    fn same_version_needs_the_same_package_bytes() {
        let previous = manifest("2.1.0", json!([file("hook", "aa"), file("lib", "bb")]));
        let reordered = manifest("2.1.0", json!([file("lib", "bb"), file("hook", "aa")]));
        assert!(reauthentication_safe(Some(&previous), &Value::Object(reordered)).is_ok());
        let changed = manifest("2.1.0", json!([file("hook", "cc"), file("lib", "bb")]));
        assert!(refused(reauthentication_safe(
            Some(&previous),
            &Value::Object(changed)
        )));
        let duplicate = manifest("2.1.0", json!([file("hook", "aa"), file("hook", "aa")]));
        assert!(refused(reauthentication_safe(
            Some(&duplicate),
            &Value::Object(duplicate.clone())
        )));
    }

    #[test]
    fn a_new_version_or_first_install_is_not_reauthentication() {
        let previous = manifest("2.1.0", json!([]));
        let next = manifest("2.2.0", json!([]));
        assert!(reauthentication_safe(Some(&previous), &Value::Object(next.clone())).is_ok());
        assert!(reauthentication_safe(None, &Value::Object(next)).is_ok());
    }

    #[test]
    fn prior_bytes_leave_the_answer_by_digest() {
        let present =
            by_digest(json!({"path": "/c", "before": "YWJj", "after": "eA=="})).unwrap_or_default();
        assert_eq!(present["before"], Value::Null);
        assert_eq!(present["before_sha256"], json!(sha256_hex(b"abc")));
        let absent =
            by_digest(json!({"path": "/m", "before": null, "after": "eA=="})).unwrap_or_default();
        assert_eq!(absent["before_sha256"], Value::Null);
        let pinned = json!({"path": "/k", "before": null, "expected_digest": "00"});
        assert_eq!(by_digest(pinned.clone()).unwrap_or_default(), pinned);
    }
}
