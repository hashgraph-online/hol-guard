//! Cloud v1 Extension catalog wire: privacy-safe projection of a registry,
//! the shared bounded shape/identity contract, the cross-language canonical
//! digest, and the Cloud negotiation verdicts. Refusal messages are the stable
//! reason strings the Python adapter raises; tests and Cloud diagnostics match
//! them verbatim.
use super::{hash, timestamp};
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::sync::OnceLock;

#[path = "cloud_catalog_wire_v1_sync.rs"]
mod negotiation;
#[path = "cloud_catalog_wire_v1_build.rs"]
mod projection;
pub use projection::build;

pub const SCHEMA: &str = "guard.extension-catalog.v1";
const CONTROL_SCHEMA: &str = "guard.extension-controls.v1";
const MAX_EXTENSIONS: usize = 512;
const MAX_PERMISSIONS: usize = 512;
const MAX_PAYLOAD_BYTES: usize = 1_000_000;
const MAX_STRING: usize = 8_192;
const MAX_IDENTITY: usize = 256;
const MAX_ARRAY: usize = 128;
const SOURCES: [&str; 4] = ["built-in", "local-admin", "signed-cloud", "custom"];
const TOP_FIELDS: [&str; 7] = [
    "schemaVersion",
    "catalogDigest",
    "guardVersion",
    "controlSchemaVersion",
    "generatedAt",
    "limits",
    "extensions",
];
const ENTRY_FIELDS: [&str; 11] = [
    "id",
    "version",
    "name",
    "source",
    "executables",
    "ecosystemIds",
    "riskClasses",
    "delegatedProtection",
    "deprecated",
    "replacementId",
    "permissions",
];
const PERMISSION_FIELDS: [&str; 6] = [
    "id",
    "name",
    "configurable",
    "required",
    "riskClasses",
    "typedCapabilities",
];
/// Normalized (no `_`/`-`, lowercase) keys that never cross the wire.
const FORBIDDEN_KEYS: [&str; 14] = [
    "actionclasses",
    "commandhistory",
    "description",
    "environment",
    "examplecommand",
    "filecontents",
    "projectmarkers",
    "referenceurls",
    "ruleids",
    "rules",
    "saferalternatives",
    "secrets",
    "sourcepath",
    "workingdirectory",
];

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Invalid(String),
    Limit(String),
    /// Cloud or the runtime answered outside the negotiated protocol.
    Protocol(String),
}
pub type Outcome<T> = std::result::Result<T, Refusal>;

fn invalid<T>(message: impl Into<String>) -> Outcome<T> {
    Err(Refusal::Invalid(message.into()))
}

fn limit<T>(message: impl Into<String>) -> Outcome<T> {
    Err(Refusal::Limit(message.into()))
}

fn protocol<T>(message: impl Into<String>) -> Outcome<T> {
    Err(Refusal::Protocol(message.into()))
}

fn limits() -> Value {
    json!({
        "maxExtensions": MAX_EXTENSIONS,
        "maxPermissionsPerExtension": MAX_PERMISSIONS,
        "maxPayloadBytes": MAX_PAYLOAD_BYTES,
        "maxStringLength": MAX_STRING,
    })
}

fn pattern(cell: &'static OnceLock<regex::Regex>, source: &str) -> &'static regex::Regex {
    cell.get_or_init(|| regex::Regex::new(source).expect("static regex"))
}

fn extension_pattern(value: &str) -> bool {
    static CELL: OnceLock<regex::Regex> = OnceLock::new();
    pattern(&CELL, r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$").is_match(value)
}

fn permission_pattern(value: &str) -> bool {
    static CELL: OnceLock<regex::Regex> = OnceLock::new();
    pattern(
        &CELL,
        r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$",
    )
    .is_match(value)
}

fn sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Compact, sorted-key, UTF-8 JSON (no ASCII escaping). Keys are sorted here
/// explicitly so the bytes never depend on the map's iteration order.
pub fn canonical(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_leaf(key.as_str(), out);
                out.push(b':');
                write_canonical(&map[key], out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        leaf => write_leaf(leaf, out),
    }
}

fn write_leaf<T: serde::Serialize + ?Sized>(value: &T, out: &mut Vec<u8>) {
    // Scalars cannot fail to serialize into memory.
    serde_json::to_writer(&mut *out, value).expect("scalar JSON");
}

fn text_length(value: &str) -> usize {
    value.chars().count()
}

fn reject_private_keys(value: &Value) -> Outcome<()> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let normalized: String = key
                    .chars()
                    .filter(|c| *c != '_' && *c != '-')
                    .collect::<String>()
                    .to_lowercase();
                if FORBIDDEN_KEYS.contains(&normalized.as_str()) {
                    return invalid(format!("private Extension catalog field: {key}"));
                }
                reject_private_keys(child)?;
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(reject_private_keys),
        _ => Ok(()),
    }
}

fn exact_fields(value: &Value, fields: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
    })
}

fn required_string(value: &Value, field: &str, maximum: usize) -> Outcome<String> {
    match value.get(field).and_then(Value::as_str) {
        Some(text) if !text.is_empty() && text_length(text) <= maximum => Ok(text.to_owned()),
        _ => invalid(format!("Invalid Extension catalog {field}")),
    }
}

fn bounded_string_array(value: Option<&Value>, label: &str) -> Outcome<Value> {
    let Some(items) = value
        .and_then(Value::as_array)
        .filter(|items| items.len() <= MAX_ARRAY)
    else {
        return invalid(format!("Invalid Extension catalog {label}"));
    };
    let mut seen = HashSet::new();
    let mut duplicate = false;
    for item in items {
        match item.as_str() {
            Some(text) if !text.is_empty() && text_length(text) <= MAX_STRING => {
                duplicate |= !seen.insert(text);
            }
            _ => return invalid(format!("Invalid Extension catalog {label}")),
        }
    }
    if duplicate {
        return invalid(format!("Duplicate Extension catalog {label}"));
    }
    Ok(Value::Array(items.clone()))
}

fn limits_match(value: Option<&Value>) -> bool {
    let expected = limits();
    let Some(object) = value.and_then(Value::as_object) else {
        return false;
    };
    let expected = expected.as_object().expect("limits object");
    object.len() == expected.len()
        && expected.iter().all(|(key, want)| {
            // Numeric equality, as the shared contract compares numbers, not spellings.
            object
                .get(key)
                .filter(|got| got.is_number())
                .and_then(Value::as_f64)
                .zip(want.as_f64())
                .is_some_and(|(got, want)| got == want)
        })
}

fn parse_permission(value: &Value, extension_id: &str) -> Outcome<Value> {
    if !exact_fields(value, &PERMISSION_FIELDS) {
        reject_private_keys(value)?;
        return invalid("Extension catalog permission contains unknown fields");
    }
    let permission_id = match value["id"].as_str() {
        Some(id)
            if text_length(id) <= MAX_IDENTITY
                && permission_pattern(id)
                && id.starts_with(&format!("{extension_id}.permission.")) =>
        {
            id.to_owned()
        }
        _ => return invalid("Invalid Extension permission identity"),
    };
    let (Some(configurable), Some(required)) =
        (value["configurable"].as_bool(), value["required"].as_bool())
    else {
        return invalid("Invalid Extension permission state");
    };
    let name = required_string(value, "name", MAX_STRING)?;
    let risk_classes = bounded_string_array(value.get("riskClasses"), "permission riskClasses")?;
    let typed = bounded_string_array(
        value.get("typedCapabilities"),
        "permission typedCapabilities",
    )?;
    Ok(json!({
        "id": permission_id, "name": name, "configurable": configurable,
        "required": required, "riskClasses": risk_classes, "typedCapabilities": typed,
    }))
}

fn parse_extension(value: &Value) -> Outcome<Value> {
    if !exact_fields(value, &ENTRY_FIELDS) {
        reject_private_keys(value)?;
        return invalid("Extension catalog entry contains unknown fields");
    }
    let extension_id = match value["id"].as_str() {
        Some(id) if text_length(id) <= MAX_IDENTITY && extension_pattern(id) => id.to_owned(),
        _ => return invalid("Invalid Extension catalog identity"),
    };
    let source = match value["source"].as_str() {
        Some(source) if SOURCES.contains(&source) => source.to_owned(),
        _ => return invalid("Invalid Extension catalog source"),
    };
    let delegated = &value["delegatedProtection"];
    if !delegated.is_null() && *delegated != "package-firewall" {
        return invalid("Invalid Extension delegated protection");
    }
    let Some(deprecated) = value["deprecated"].as_bool() else {
        return invalid("Invalid Extension deprecation state");
    };
    let replacement = &value["replacementId"];
    if !replacement.is_null()
        && !replacement
            .as_str()
            .is_some_and(|target| extension_pattern(target) && target != extension_id && deprecated)
    {
        return invalid("Invalid Extension replacement");
    }
    let Some(raw_permissions) = value["permissions"]
        .as_array()
        .filter(|items| items.len() <= MAX_PERMISSIONS)
    else {
        return invalid("Extension catalog permission limit exceeded");
    };
    let permissions = raw_permissions
        .iter()
        .map(|item| parse_permission(item, &extension_id))
        .collect::<Outcome<Vec<_>>>()?;
    let version = required_string(value, "version", 128)?;
    let name = required_string(value, "name", MAX_STRING)?;
    let executables = bounded_string_array(value.get("executables"), "executables")?;
    let ecosystems = bounded_string_array(value.get("ecosystemIds"), "ecosystemIds")?;
    let risk_classes = bounded_string_array(value.get("riskClasses"), "riskClasses")?;
    Ok(json!({
        "id": extension_id, "version": version, "name": name, "source": source,
        "executables": executables, "ecosystemIds": ecosystems, "riskClasses": risk_classes,
        "delegatedProtection": delegated, "deprecated": deprecated,
        "replacementId": replacement, "permissions": permissions,
    }))
}

fn sorted_by_id(items: &[Value]) -> Vec<Value> {
    let mut sorted = items.to_vec();
    sorted.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    sorted
}

/// Shared canonical JSON for an Extension projection: Extensions and their
/// permissions ordered by id, then sorted-key compact UTF-8 bytes.
pub fn canonical_extensions(extensions: &Value) -> Outcome<Vec<u8>> {
    let Some(items) = extensions.as_array() else {
        return invalid("Invalid Extension catalog extensions");
    };
    let mut canonical_items = Vec::with_capacity(items.len());
    for item in items {
        let (Some(object), Some(permissions)) = (item.as_object(), item["permissions"].as_array())
        else {
            return invalid("Invalid Extension catalog extensions");
        };
        let mut object: Map<String, Value> = object.clone();
        object.insert(
            "permissions".to_owned(),
            Value::Array(sorted_by_id(permissions)),
        );
        canonical_items.push(Value::Object(object));
    }
    Ok(canonical(&Value::Array(sorted_by_id(&canonical_items))))
}

pub fn catalog_digest(extensions: &Value) -> Outcome<String> {
    Ok(hash(&canonical_extensions(extensions)?))
}

fn unique_ids<'a>(ids: impl Iterator<Item = &'a str>, label: &str) -> Outcome<HashSet<&'a str>> {
    let mut seen = HashSet::new();
    let mut duplicate = false;
    for id in ids {
        duplicate |= !seen.insert(id);
    }
    if duplicate {
        return invalid(format!("Duplicate {label} identity"));
    }
    Ok(seen)
}

/// Execute the shared catalog's bounded shape, privacy, identity, and digest contract.
pub fn validate(payload: &Value) -> Outcome<Value> {
    if canonical(payload).len() > MAX_PAYLOAD_BYTES {
        return limit("Extension catalog payload limit exceeded");
    }
    if !payload.is_object() {
        return invalid("Extension catalog must be an object");
    }
    if !exact_fields(payload, &TOP_FIELDS) {
        reject_private_keys(payload)?;
        return invalid("Extension catalog contains unknown fields");
    }
    reject_private_keys(payload)?;
    if payload["schemaVersion"] != SCHEMA {
        return invalid("Unsupported Extension catalog schema");
    }
    let digest = match payload["catalogDigest"].as_str() {
        Some(digest) if sha256_hex(digest) => digest.to_owned(),
        _ => return invalid("Invalid Extension catalog digest"),
    };
    let guard_version = required_string(payload, "guardVersion", 128)?;
    let control_schema = required_string(payload, "controlSchemaVersion", 128)?;
    let generated_at = required_string(payload, "generatedAt", 128)?;
    if !timestamp(&generated_at) {
        return invalid("Invalid Extension catalog generatedAt");
    }
    if !limits_match(payload.get("limits")) {
        return invalid("Extension catalog limits do not match runtime limits");
    }
    let Some(raw_extensions) = payload["extensions"]
        .as_array()
        .filter(|items| items.len() <= MAX_EXTENSIONS)
    else {
        return invalid("Extension catalog limit exceeded");
    };
    let extensions = raw_extensions
        .iter()
        .map(parse_extension)
        .collect::<Outcome<Vec<_>>>()?;
    let extension_ids = unique_ids(
        extensions.iter().filter_map(|item| item["id"].as_str()),
        "Extension catalog",
    )?;
    unique_ids(
        extensions
            .iter()
            .flat_map(|item| item["permissions"].as_array().into_iter().flatten())
            .filter_map(|permission| permission["id"].as_str()),
        "Extension permission",
    )?;
    if extensions.iter().any(|item| {
        item["replacementId"]
            .as_str()
            .is_some_and(|target| !extension_ids.contains(target))
    }) {
        return invalid("Extension replacement is not present in the catalog");
    }
    let extensions = Value::Array(extensions);
    if catalog_digest(&extensions)? != digest {
        return invalid("Extension catalog digest does not match canonical bytes");
    }
    Ok(json!({
        "schemaVersion": SCHEMA, "catalogDigest": digest, "guardVersion": guard_version,
        "controlSchemaVersion": control_schema, "generatedAt": generated_at,
        "limits": limits(), "extensions": extensions,
    }))
}

fn answer(request: &Value) -> Outcome<Value> {
    match request["action"].as_str() {
        Some("v1_build") => {
            let (Some(version), Some(generated_at)) = (
                request["guard_version"].as_str(),
                request["generated_at"].as_str(),
            ) else {
                return invalid("guard_version and generated_at are required");
            };
            if version.trim().is_empty() || generated_at.trim().is_empty() {
                return invalid("guard_version and generated_at are required");
            }
            Ok(json!({"catalog": build(&request["extensions"], version, generated_at)?}))
        }
        Some("v1_validate") => Ok(json!({"catalog": validate(&request["payload"])?})),
        Some("v1_canonical") => {
            let bytes = canonical_extensions(&request["extensions"])?;
            let text = String::from_utf8(bytes)
                .map_err(|_| Refusal::Invalid("Invalid Extension catalog extensions".to_owned()))?;
            let digest = hash(text.as_bytes());
            Ok(json!({"canonical_json": text, "catalog_digest": digest}))
        }
        Some("v1_handshake") => negotiation::handshake(request),
        Some("v1_sync_ack") => negotiation::sync_ack(request),
        _ => invalid("Unsupported Extension catalog action"),
    }
}

/// Shared CLI/resident interface. Refusals are payloads, not transport errors,
/// so the adapter can raise the exact limit or validation reason.
pub fn evaluate(request: &Value) -> Value {
    let payload = match answer(request) {
        Ok(payload) => payload,
        Err(Refusal::Invalid(message)) => json!({"v1_error": "invalid", "message": message}),
        Err(Refusal::Limit(message)) => json!({"v1_error": "limit", "message": message}),
        Err(Refusal::Protocol(message)) => json!({"v1_error": "protocol", "message": message}),
    };
    json!({"schema": "guard-cloud-catalog-result.v2", "payload": payload})
}
