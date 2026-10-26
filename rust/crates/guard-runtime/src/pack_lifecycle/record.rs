//! The authenticated command-pack records: the active pack activation, the
//! legacy baseline a first commit retains, and the link that binds a pending
//! activation to one approved control transition.
//!
//! Sealing validates the record the reader will require, so a writer can only
//! store what verification accepts. A record that fails authentication answers
//! `{"fault":"tampered"}`; a record that authenticates but breaks the schema
//! answers `{"fault":"refused"}` with the reason the caller reports. Both are
//! answers, not transport errors: a refusal travels on stdout so the caller can
//! tell a record this reader will not accept from a runtime that could not
//! answer at all.

use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::extension_control_authority_op::records::{
    authenticated_record, canonical, field, py_eq, verify_record, Fault,
};

const ACTIVATION_PURPOSE: &str = "command-pack-activation.v1";
const BASELINE_PURPOSE: &str = "command-pack-legacy-baseline.v1";
const LINK_PURPOSE: &str = "command-pack-control-transition.v1";
const SCHEMA: &str = "guard.command-pack-activation.v1";
const SCHEMA_V2: &str = "guard.command-pack-activation.v2";
const BASELINE_SCHEMA: &str = "guard.command-pack-legacy-baseline.v1";
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_SELECTED: i128 = 32768;
const MAX_EXECUTABLES: i128 = 1048576;
const MAX_OBJECT_BYTES: i128 = 64 * 1024;
const MAX_BLOB_BYTES: i128 = 8 * 1024 * 1024;
const LINK_EXPECTED: [&str; 4] = [
    "control_revision",
    "snapshot_digest",
    "catalog_digest",
    "pack_record_digest",
];

type Result<T> = std::result::Result<T, String>;

/// Why a record was refused before it could be returned.
enum Refusal {
    /// The bytes do not authenticate under the key and purpose.
    Tampered(String),
    /// The record authenticates but is not a record this reader accepts.
    Invalid(String),
}

impl From<Fault> for Refusal {
    fn from(fault: Fault) -> Self {
        match fault {
            Fault::Tampered(reason) | Fault::Degraded(reason) => Self::Tampered(reason),
        }
    }
}

impl From<&str> for Refusal {
    fn from(reason: &str) -> Self {
        Self::Invalid(reason.to_owned())
    }
}

impl From<String> for Refusal {
    fn from(reason: String) -> Self {
        Self::Invalid(reason)
    }
}

fn digest(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64 && text.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn matches(pattern: &'static OnceLock<Regex>, source: &str, value: &Value) -> bool {
    let pattern = pattern.get_or_init(|| Regex::new(source).expect("static pattern"));
    value.as_str().is_some_and(|text| pattern.is_match(text))
}

/// Python `type(value) is int`: a JSON integer, never a bool or float.
fn int(value: &Value) -> Option<i128> {
    let Value::Number(number) = value else {
        return None;
    };
    number
        .as_i64()
        .map(i128::from)
        .or_else(|| number.as_u64().map(i128::from))
}

fn int_in(value: &Value, minimum: i128, maximum: i128) -> bool {
    int(value).is_some_and(|n| (minimum..=maximum).contains(&n))
}

/// `set(map) == set(expected)`.
fn has_exactly(map: &Map<String, Value>, expected: &[&str]) -> bool {
    let mut wanted = expected.to_vec();
    wanted.sort_unstable();
    wanted.dedup();
    let mut found: Vec<&str> = map.keys().map(String::as_str).collect();
    found.sort_unstable();
    found == wanted
}

/// `containers.location(value, digest, "object")`.
fn location(value: &Value, sha: &str) -> Result<()> {
    static TAG: OnceLock<Regex> = OnceLock::new();
    static CONTAINER: OnceLock<Regex> = OnceLock::new();
    let Some(map) = value.as_object() else {
        return Err("delivery asset location invalid".into());
    };
    if !(has_exactly(map, &["tag", "asset"]) || has_exactly(map, &["tag", "asset", "member"]))
        || !matches(
            &TAG,
            r"^extension-data-[0-9a-f]{40}-[0-9]{1,20}\.[0-9]{1,10}-[0-9]{6}$",
            &map["tag"],
        )
    {
        return Err("delivery asset location invalid".into());
    }
    let member = format!("object-{sha}.json");
    match map.get("member") {
        None if map["asset"] != member.as_str() => Err("delivery asset identity invalid".into()),
        None => Ok(()),
        Some(found)
            if found != member.as_str()
                || !matches(
                    &CONTAINER,
                    r"^(objects|packs)-[0-9]{6}\.zip$",
                    &map["asset"],
                )
                || !map["asset"]
                    .as_str()
                    .is_some_and(|asset| asset.starts_with("objects-")) =>
        {
            Err("delivery container location invalid".into())
        }
        Some(_) => Ok(()),
    }
}

/// `metadata_objects.validate_reference`.
fn reference(value: &Value) -> Result<()> {
    const FIELDS: [&str; 4] = ["sha256", "length", "expanded_length", "kind"];
    let invalid = || "delivery index object reference invalid".to_owned();
    let map = value.as_object().ok_or_else(invalid)?;
    if !(has_exactly(map, &FIELDS)
        || has_exactly(
            map,
            &["sha256", "length", "expanded_length", "kind", "location"],
        ))
        || !digest(&map["sha256"])
        || !int_in(&map["length"], 1, MAX_OBJECT_BYTES)
        || !int_in(&map["expanded_length"], 1, MAX_BLOB_BYTES)
        || !matches!(map["kind"].as_str(), Some("data" | "concat"))
        || (map["kind"] == "data" && int(&map["length"]) != int(&map["expanded_length"]))
    {
        return Err(invalid());
    }
    match map.get("location") {
        Some(found) => location(found, map["sha256"].as_str().unwrap_or_default()),
        None => Ok(()),
    }
}

/// `activation_record.verify_header` after authentication.
fn activation(value: &Map<String, Value>) -> Result<()> {
    static SHA: OnceLock<Regex> = OnceLock::new();
    static PUBLICATION: OnceLock<Regex> = OnceLock::new();
    let mut fields = vec![
        "authority_schema_version",
        "purpose",
        "schema",
        "revision",
        "previous_digest",
        "program_digest",
        "catalog_digest",
        "trust_digest",
        "engine",
        "source_sha",
        "publication_id",
        "root_digest",
        "authority_epoch",
        "revocation_epoch",
        "selection",
        "selected_count",
        "registry",
        "registry_count",
        "executables",
        "executable_count",
        "distribution",
        "issued_at",
        "expires_at",
    ];
    let profile = field(value, "authority_profile");
    if field(value, "schema") == SCHEMA_V2 {
        fields.push("authority_profile");
        if !matches!(
            profile.as_str(),
            Some("installed" | "committed-subset" | "remote")
        ) {
            return Err("activation authority profile invalid".into());
        }
    }
    if !has_exactly(value, &fields) || !matches!(value["schema"].as_str(), Some(SCHEMA | SCHEMA_V2))
    {
        return Err("activation record schema invalid".into());
    }
    let name = |field: &str| &value[field];
    if ![
        "program_digest",
        "catalog_digest",
        "trust_digest",
        "engine",
        "root_digest",
    ]
    .iter()
    .all(|field| digest(name(field)))
    {
        return Err("activation digest invalid".into());
    }
    let installed = name("issued_at").is_null() && name("expires_at").is_null();
    if installed && (name("schema") != SCHEMA_V2 || name("publication_id") != "0.0") {
        return Err("activation installed authority invalid".into());
    }
    if profile == "installed" && !installed {
        return Err("installed activation cannot claim remote freshness".into());
    }
    if profile == "committed-subset" && name("previous_digest").is_null() {
        return Err("offline subset requires a committed predecessor".into());
    }
    if !matches(&SHA, "^[0-9a-f]{40}$", name("source_sha"))
        || !matches(
            &PUBLICATION,
            r"^[0-9]{1,20}\.[0-9]{1,10}$",
            name("publication_id"),
        )
    {
        return Err("activation source identity invalid".into());
    }
    let below_u64 = (1_i128 << 64) - 1;
    if !int_in(name("revision"), 1, below_u64)
        || !int_in(name("authority_epoch"), 1, below_u64)
        || !int_in(name("revocation_epoch"), 0, below_u64)
    {
        return Err("activation epoch or revision invalid".into());
    }
    if !installed {
        let interval = int(name("issued_at")).zip(int(name("expires_at")));
        if !interval.is_some_and(|(issued, expires)| (0..expires).contains(&issued)) {
            return Err("activation validity interval invalid".into());
        }
    }
    if !name("previous_digest").is_null() && !digest(name("previous_digest")) {
        return Err("activation predecessor invalid".into());
    }
    if !int_in(name("selected_count"), 1, MAX_SELECTED)
        || !int_in(name("registry_count"), 1, MAX_SELECTED)
        || !int_in(name("executable_count"), 0, MAX_EXECUTABLES)
    {
        return Err("activation metadata count invalid".into());
    }
    for (field, count) in [
        ("selection", "selected_count"),
        ("registry", "registry_count"),
        ("executables", "executable_count"),
    ] {
        if name(field).is_null() != (int(name(count)) == Some(0)) {
            return Err("activation metadata reference missing".into());
        }
        if !name(field).is_null() {
            reference(name(field))?;
        }
    }
    reference(name("distribution"))
}

/// `activation_baseline.verify` after authentication.
fn baseline(value: &Map<String, Value>, row_revision: &Value) -> Result<()> {
    if !has_exactly(
        value,
        &[
            "authority_schema_version",
            "purpose",
            "schema",
            "revision",
            "program_digest",
            "catalog_digest",
            "trust_digest",
        ],
    ) || value["schema"] != BASELINE_SCHEMA
        || int(&value["revision"]) != Some(0)
        || !py_eq(row_revision, &json!(0))
    {
        return Err("legacy activation baseline invalid".into());
    }
    if !["program_digest", "catalog_digest", "trust_digest"]
        .iter()
        .all(|name| digest(&value[*name]))
    {
        return Err("legacy activation baseline digest invalid".into());
    }
    Ok(())
}

/// `activation_journal._verify_pending`'s link check.
fn link(value: &Map<String, Value>, expected: &Value) -> Result<()> {
    let mismatch = || "native_command_pack_transition_mismatch".to_owned();
    let expected = expected.as_object().ok_or_else(mismatch)?;
    let mut fields = vec!["authority_schema_version", "purpose", "admitted_at"];
    fields.extend(LINK_EXPECTED);
    if value.contains_key("lifecycle_before") {
        fields.extend(["lifecycle_before", "lifecycle_after"]);
    }
    if value.contains_key("security_digest") {
        fields.push("security_digest");
    }
    let bound = LINK_EXPECTED
        .iter()
        .all(|name| py_eq(field(value, name), field(expected, name)));
    if !has_exactly(value, &fields) || !has_exactly(expected, &LINK_EXPECTED) || !bound {
        return Err(mismatch());
    }
    Ok(())
}

/// The link a reservation seals binds exactly the transition it names.
fn link_payload(payload: &Map<String, Value>) -> Result<()> {
    let mut required = vec!["admitted_at"];
    required.extend(LINK_EXPECTED);
    let optional = ["lifecycle_before", "lifecycle_after", "security_digest"];
    let known = payload
        .keys()
        .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()));
    if !known
        || !required.iter().all(|name| payload.contains_key(*name))
        || payload.contains_key("lifecycle_before") != payload.contains_key("lifecycle_after")
        || int(&payload["admitted_at"]).is_none()
        || int(&payload["control_revision"]).is_none()
    {
        return Err("native_command_pack_link_invalid".into());
    }
    Ok(())
}

fn purpose(input: &Value) -> Result<&'static str> {
    match input["purpose"].as_str() {
        Some("activation") => Ok(ACTIVATION_PURPOSE),
        Some("baseline") => Ok(BASELINE_PURPOSE),
        Some("link") => Ok(LINK_PURPOSE),
        _ => Err("pack_lifecycle_record_purpose_invalid".into()),
    }
}

fn seal(input: &Value, key: &[u8]) -> Result<Value> {
    let purpose = purpose(input)?;
    let payload = input["payload"]
        .as_object()
        .ok_or("pack_lifecycle_record_payload_invalid")?;
    if payload.contains_key("authority_schema_version") || payload.contains_key("purpose") {
        return Err("pack_lifecycle_record_payload_invalid".into());
    }
    let (record, digest, mac) = authenticated_record(payload, key, purpose)
        .map_err(|_| "pack_lifecycle_record_payload_invalid")?;
    let framed: Map<String, Value> =
        serde_json::from_str(&record).map_err(|_| "pack_lifecycle_record_payload_invalid")?;
    match purpose {
        ACTIVATION_PURPOSE => {
            activation(&framed)?;
            if record.len() > MAX_RECORD_BYTES {
                return Err("activation record exceeds byte budget".into());
            }
        }
        BASELINE_PURPOSE => baseline(&framed, &json!(0))?,
        _ => link_payload(payload)?,
    }
    Ok(json!({"record": record, "digest": digest, "mac": mac}))
}

fn verify(input: &Value, key: &[u8]) -> std::result::Result<Value, Refusal> {
    let purpose = purpose(input)?;
    let record = input["record"].as_str().unwrap_or_default();
    if purpose == ACTIVATION_PURPOSE && !(1..=MAX_RECORD_BYTES).contains(&record.len()) {
        return Err("activation record byte bounds invalid".into());
    }
    // Every writer stores the canonical encoding it authenticated. Any other
    // spelling of the same record, including one with a duplicated field the
    // decoder would collapse, is not the record that was sealed.
    let parsed: Value = serde_json::from_str(record)
        .map_err(|_| Refusal::Tampered("invalid authenticated authority record".into()))?;
    if canonical(&parsed).ok().as_deref() != Some(record) {
        return Err(Refusal::Tampered(
            "invalid authenticated authority record".into(),
        ));
    }
    let digest = input["digest"].as_str().unwrap_or_default();
    let mac = input["mac"].as_str().unwrap_or_default();
    let value = verify_record(record, digest, mac, key, purpose)?;
    match purpose {
        ACTIVATION_PURPOSE => activation(&value),
        BASELINE_PURPOSE => baseline(&value, &input["revision"]),
        _ => link(&value, &input["expected"]),
    }
    .map_err(Refusal::Invalid)?;
    Ok(json!({"value": value}))
}

/// `activation_record.open_record`: the authenticated header, then the
/// publication and inventories it binds in the local delivery cache.
fn open_record(input: &Value, key: &[u8]) -> std::result::Result<Value, Refusal> {
    if input["purpose"] != "activation" {
        return Err("pack_lifecycle_record_purpose_invalid".into());
    }
    let directory = input["directory"]
        .as_str()
        .filter(|directory| !directory.is_empty())
        .ok_or("pack_lifecycle_record_directory_invalid")?;
    let verified = verify(input, key)?;
    Ok(open::open(&verified["value"], Path::new(directory))?)
}

fn answer(result: std::result::Result<Value, Refusal>) -> Result<Value> {
    match result {
        Ok(value) => Ok(value),
        Err(Refusal::Tampered(reason)) => Ok(json!({"fault": "tampered", "reason": reason})),
        Err(Refusal::Invalid(reason)) => Ok(json!({"fault": "refused", "reason": reason})),
    }
}

pub(super) fn evaluate(input: &Value, key: &[u8]) -> Result<Value> {
    match input["operation"].as_str() {
        // Every refusal these three reach is an answer about the record. Only
        // an operation this evaluator does not implement is an error, because
        // nothing about a record was decided.
        Some("seal") => answer(seal(input, key).map_err(Refusal::Invalid)),
        Some("verify") => answer(verify(input, key)),
        Some("open") => answer(open_record(input, key)),
        _ => Err("pack_lifecycle_record_operation_invalid".into()),
    }
}

mod open;

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
