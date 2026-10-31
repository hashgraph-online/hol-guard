//! `ownership-acl --stdin`: decide ownership and ACL health for the machine's
//! protected surfaces (`mdm/acl.py` before the decisions moved here).
//!
//! Python still does the platform I/O: it walks the macOS path chain with
//! `lstat` and `ls -lde`, and it runs the pinned PowerShell probe on Windows.
//! This module owns what those probes mean:
//!
//! - `windows-payload` lists the Windows surfaces to probe: each protected
//!   file, directory and registry key, and every ancestor up to the drive or
//!   `HKLM:\` root, once each regardless of case.
//! - `windows-verify` checks the probe's rows against that list and classifies
//!   each row by owner SID, attributes, container type and access rules.
//! - `aggregate` folds per-surface results into one verdict.
//!
//! A malformed or incomplete Windows probe never reports health: the verdict
//! is `unknown` with `ownership_acl_probe_failed`.

use std::collections::BTreeSet;
use std::io::Read;

use serde::Deserialize;
use serde_json::{json, Map, Value};

const SCHEMA: &str = "ownership-acl.v1";
const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;

const VALID: &str = "ownership_acl_valid";
const ABSENT: &str = "ownership_acl_surface_absent";
const PATH_ESCAPE: &str = "ownership_acl_path_escape";
const USER_WRITABLE: &str = "ownership_acl_standard_user_writable";
const WRONG_OWNER: &str = "ownership_acl_wrong_owner";
const PROBE_FAILED: &str = "ownership_acl_probe_failed";
const UNSUPPORTED: &str = "ownership_acl_platform_unsupported";
const STATES: [&str; 5] = ["healthy", "absent", "tampered", "unsupported", "unknown"];

const PRIVILEGED_OWNER_SIDS: [&str; 3] = [
    "S-1-5-18",                                                       // LocalSystem
    "S-1-5-32-544",                                                   // Builtin Administrators
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", // TrustedInstaller
];
/// Creator Owner and Owner Rights resolve to the separately verified
/// privileged owner.
const OWNER_ALIAS_SIDS: [&str; 2] = ["S-1-3-0", "S-1-3-4"];
const FILE_MUTATION_MASK: i64 = 852_310;
const REGISTRY_MUTATION_MASK: i64 = 851_974;
const FILE_ANCESTOR_MUTATION_MASK: i64 = 852_032;
const REGISTRY_ANCESTOR_MUTATION_MASK: i64 = 851_968;
const GENERIC_MUTATION_MASK: i64 = 0x5000_0000;
const REPARSE_POINT_ATTRIBUTE: i64 = 0x400;
const REGISTRY_PREFIX: &str = "HKLM:\\";
const WINDOWS_POLICY: &str = r"HKLM:\Software\Policies\HOL\Guard";
const WINDOWS_ACTIVE_SETUP: &str = r"HKLM:\Software\Microsoft\Active Setup\Installed Components\{AFA2F379-D7A2-4210-91E3-E71E43F1D994}";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    windows_paths: Option<WindowsPaths>,
    #[serde(default)]
    managed_file: Option<String>,
    #[serde(default)]
    rows: Option<Value>,
    #[serde(default)]
    surfaces: Option<Vec<Surface>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsPaths {
    runtime_root: String,
    manifest_path: String,
    state_root: String,
    log_root: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Surface {
    name: String,
    state: String,
    reason_code: String,
}

impl Surface {
    fn new(name: &str, state: &str, reason_code: &str) -> Self {
        Self {
            name: name.to_owned(),
            state: state.to_owned(),
            reason_code: reason_code.to_owned(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Verdict {
    status: &'static str,
    reason_code: &'static str,
    surfaces: Vec<Surface>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Filesystem,
    Registry,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Registry => "registry",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PayloadItem {
    name: String,
    path: String,
    kind: Kind,
    expected_container: bool,
    leaf: bool,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "ownership-acl"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "ownership_acl_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("ownership_acl_request_too_large".to_owned());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| "ownership_acl_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("ownership_acl_request_invalid".to_owned());
    }
    let response = respond(request)?;
    serde_json::to_vec(&response).map_err(|_| "ownership_acl_response_encode_failed".to_owned())
}

fn respond(request: Request) -> Result<Value, String> {
    let invalid = || "ownership_acl_request_invalid".to_owned();
    match request.op.as_str() {
        "windows-payload" => {
            let paths = request.windows_paths.ok_or_else(invalid)?;
            let payload = windows_payload(&paths).map_err(|_| invalid())?;
            Ok(json!({"ok": true, "payload": payload.iter().map(payload_json).collect::<Vec<_>>()}))
        }
        "windows-verify" => {
            let paths = request.windows_paths.ok_or_else(invalid)?;
            let rows = request.rows.ok_or_else(invalid)?;
            Ok(verdict_json(&windows_verify(windows_payload(&paths), rows)))
        }
        "windows-file-payload" => {
            let file = request.managed_file.ok_or_else(invalid)?;
            let payload = managed_file_payload(&file).map_err(|_| invalid())?;
            Ok(json!({"ok": true, "payload": payload.iter().map(payload_json).collect::<Vec<_>>()}))
        }
        "windows-file-verify" => {
            let file = request.managed_file.ok_or_else(invalid)?;
            let rows = request.rows.ok_or_else(invalid)?;
            Ok(verdict_json(&windows_verify(
                managed_file_payload(&file),
                rows,
            )))
        }
        "aggregate" => {
            let surfaces = request.surfaces.ok_or_else(invalid)?;
            if surfaces
                .iter()
                .any(|surface| !STATES.contains(&surface.state.as_str()))
            {
                return Err(invalid());
            }
            Ok(verdict_json(&aggregate(surfaces)))
        }
        _ => Err(invalid()),
    }
}

fn aggregate(surfaces: Vec<Surface>) -> Verdict {
    let verdict = |status, reason_code, surfaces| Verdict {
        status,
        reason_code,
        surfaces,
    };
    for reason in [PATH_ESCAPE, USER_WRITABLE, WRONG_OWNER] {
        if surfaces.iter().any(|surface| surface.reason_code == reason) {
            return verdict("tampered", reason, surfaces);
        }
    }
    let any_state = |state: &str| surfaces.iter().any(|surface| surface.state == state);
    if any_state("tampered") {
        return verdict("tampered", PROBE_FAILED, surfaces);
    }
    if any_state("absent") {
        return verdict("absent", ABSENT, surfaces);
    }
    if any_state("unknown") {
        return verdict("unknown", PROBE_FAILED, surfaces);
    }
    if any_state("unsupported") {
        return verdict("unsupported", UNSUPPORTED, surfaces);
    }
    verdict("healthy", VALID, surfaces)
}

fn probe_failed() -> Verdict {
    Verdict {
        status: "unknown",
        reason_code: PROBE_FAILED,
        surfaces: vec![Surface::new("platform", "unknown", PROBE_FAILED)],
    }
}

/// Drive letter and normalized components of a drive-absolute Windows path,
/// as `ntpath.normpath` would spell it.
fn windows_components(path: &str) -> Result<(String, Vec<String>), ()> {
    let path = path.replace('/', "\\");
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err(());
    }
    let mut components: Vec<String> = Vec::new();
    for component in path[3..].split('\\') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(component.to_owned()),
        }
    }
    Ok((path[..2].to_owned(), components))
}

fn filesystem_chain(path: &str) -> Result<Vec<String>, ()> {
    let (drive, components) = windows_components(path)?;
    let root = format!("{drive}\\");
    let mut chain = vec![root.clone()];
    for index in 1..=components.len() {
        chain.push(format!("{root}{}", components[..index].join("\\")));
    }
    Ok(chain)
}

fn registry_chain(path: &str) -> Result<Vec<String>, ()> {
    let prefix = path.get(..REGISTRY_PREFIX.len()).ok_or(())?;
    if !prefix.eq_ignore_ascii_case(REGISTRY_PREFIX) {
        return Err(());
    }
    let segments: Vec<&str> = path[REGISTRY_PREFIX.len()..]
        .split('\\')
        .filter(|segment| !segment.is_empty())
        .collect();
    let mut chain = vec![REGISTRY_PREFIX.to_owned()];
    for index in 1..=segments.len() {
        chain.push(format!("{REGISTRY_PREFIX}{}", segments[..index].join("\\")));
    }
    Ok(chain)
}

fn windows_payload(paths: &WindowsPaths) -> Result<Vec<PayloadItem>, ()> {
    let state_file = |name: &str| format!("{}\\{name}", paths.state_root);
    let requested = [
        (Kind::Filesystem, paths.runtime_root.clone(), true),
        (Kind::Filesystem, paths.manifest_path.clone(), false),
        (Kind::Filesystem, paths.state_root.clone(), true),
        (Kind::Filesystem, state_file("device-key.json"), false),
        (
            Kind::Filesystem,
            state_file("installation-continuity.json"),
            false,
        ),
        (
            Kind::Filesystem,
            state_file(".installation-continuity.lock"),
            false,
        ),
        (Kind::Filesystem, paths.log_root.clone(), true),
        (Kind::Registry, WINDOWS_POLICY.to_owned(), true),
        (Kind::Registry, WINDOWS_ACTIVE_SETUP.to_owned(), true),
    ];
    let mut payload: Vec<PayloadItem> = Vec::new();
    let mut seen: BTreeSet<(&'static str, String)> = BTreeSet::new();
    for (kind, leaf_path, leaf_container) in requested {
        let chain = match kind {
            Kind::Filesystem => filesystem_chain(&leaf_path)?,
            Kind::Registry => registry_chain(&leaf_path)?,
        };
        let last = chain.len() - 1;
        for (index, path) in chain.into_iter().enumerate() {
            let key = (kind.as_str(), path.to_lowercase());
            if seen.contains(&key) {
                if index == last {
                    if let Some(existing) = payload
                        .iter_mut()
                        .find(|item| item.kind == kind && item.path.to_lowercase() == key.1)
                    {
                        existing.leaf = true;
                    }
                }
                continue;
            }
            seen.insert(key);
            payload.push(PayloadItem {
                name: format!("{}-{:03}", kind.as_str(), payload.len()),
                path,
                kind,
                expected_container: index < last || leaf_container,
                leaf: index == last,
            });
        }
    }
    Ok(payload)
}

/// A machine-managed file and each ancestor, all of which must be
/// protected; only the file itself may be a non-container.
fn managed_file_payload(file: &str) -> Result<Vec<PayloadItem>, ()> {
    let chain = filesystem_chain(file)?;
    let last = chain.len() - 1;
    Ok(chain
        .into_iter()
        .enumerate()
        .map(|(index, path)| PayloadItem {
            name: format!("managed-file-{index:03}"),
            path,
            kind: Kind::Filesystem,
            expected_container: index < last,
            leaf: index == last,
        })
        .collect())
}

fn payload_json(item: &PayloadItem) -> Value {
    json!({
        "name": item.name,
        "path": item.path,
        "kind": item.kind.as_str(),
        "expectedContainer": item.expected_container,
        "leaf": item.leaf,
    })
}

fn windows_verify(payload: Result<Vec<PayloadItem>, ()>, rows: Value) -> Verdict {
    let Ok(payload) = payload else {
        return probe_failed();
    };
    let rows = match rows {
        Value::Array(rows) => rows,
        row => vec![row],
    };
    let Ok(results) = rows.iter().map(windows_row).collect::<Result<Vec<_>, _>>() else {
        return probe_failed();
    };
    let expected: BTreeSet<&str> = payload.iter().map(|item| item.name.as_str()).collect();
    let reported: BTreeSet<&str> = results.iter().map(|result| result.name.as_str()).collect();
    if results.len() != expected.len() || reported != expected {
        return probe_failed();
    }
    aggregate(results)
}

fn windows_row(row: &Value) -> Result<Surface, ()> {
    let row = row.as_object().ok_or(())?;
    let name = row.get("Name").and_then(Value::as_str).ok_or(())?;
    let result = |state: &str, reason: &str| Ok(Surface::new(name, state, reason));
    if row.get("Exists") != Some(&Value::Bool(true)) {
        return result("absent", ABSENT);
    }
    if row.get("Truncated") == Some(&Value::Bool(true)) {
        return result("unknown", PROBE_FAILED);
    }
    if row.get("NullDacl") == Some(&Value::Bool(true)) {
        return result("tampered", USER_WRITABLE);
    }
    match row.get("Attributes").and_then(Value::as_i64) {
        Some(attributes) if attributes & REPARSE_POINT_ATTRIBUTE == 0 => {}
        _ => return result("tampered", PATH_ESCAPE),
    }
    let kind = match row.get("Kind").and_then(Value::as_str) {
        Some("filesystem") => Kind::Filesystem,
        Some("registry") => Kind::Registry,
        _ => return Err(()),
    };
    let expected_container = row
        .get("ExpectedContainer")
        .and_then(Value::as_bool)
        .ok_or(())?;
    let leaf = row.get("Leaf").and_then(Value::as_bool).ok_or(())?;
    if row.get("Container") != Some(&Value::Bool(expected_container)) {
        return result("tampered", PATH_ESCAPE);
    }
    match row.get("Owner").and_then(Value::as_str) {
        Some(owner) if PRIVILEGED_OWNER_SIDS.contains(&owner) => {}
        _ => return result("tampered", WRONG_OWNER),
    }
    let rules = row.get("Rules").and_then(Value::as_array).ok_or(())?;
    let mutation_mask = GENERIC_MUTATION_MASK
        | match (kind, leaf) {
            (Kind::Registry, true) => REGISTRY_MUTATION_MASK,
            (Kind::Registry, false) => REGISTRY_ANCESTOR_MUTATION_MASK,
            (Kind::Filesystem, true) => FILE_MUTATION_MASK,
            (Kind::Filesystem, false) => FILE_ANCESTOR_MUTATION_MASK,
        };
    for rule in rules {
        if rule_grants_mutation(rule.as_object().ok_or(())?, mutation_mask)? {
            return result("tampered", USER_WRITABLE);
        }
    }
    result("healthy", VALID)
}

/// Whether one access rule lets an unprivileged SID mutate the surface; a rule
/// with missing or unexpected fields is an error.
fn rule_grants_mutation(rule: &Map<String, Value>, mutation_mask: i64) -> Result<bool, ()> {
    let sid = rule.get("Sid").and_then(Value::as_str).ok_or(())?;
    let rights = rule.get("Rights").and_then(Value::as_i64).ok_or(())?;
    let access_type = rule.get("Type").and_then(Value::as_str).ok_or(())?;
    let propagation = rule.get("Propagation").and_then(Value::as_str).ok_or(())?;
    if access_type != "Allow" && access_type != "Deny" {
        return Err(());
    }
    let flags: BTreeSet<&str> = propagation.split(',').map(str::trim).collect();
    if flags
        .iter()
        .any(|flag| !matches!(*flag, "None" | "InheritOnly" | "NoPropagateInherit"))
    {
        return Err(());
    }
    let privileged = PRIVILEGED_OWNER_SIDS.contains(&sid) || OWNER_ALIAS_SIDS.contains(&sid);
    Ok(access_type == "Allow"
        && !flags.contains("InheritOnly")
        && !privileged
        && rights & mutation_mask != 0)
}

fn verdict_json(verdict: &Verdict) -> Value {
    let surfaces: Vec<Value> = verdict
        .surfaces
        .iter()
        .map(|surface| {
            json!({
                "name": surface.name,
                "state": surface.state,
                "reason_code": surface.reason_code,
            })
        })
        .collect();
    json!({
        "ok": true,
        "status": verdict.status,
        "reason_code": verdict.reason_code,
        "surfaces": surfaces,
    })
}

#[cfg(test)]
#[path = "ownership_acl_verdict_tests.rs"]
mod tests;
