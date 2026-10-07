//! `native_command_extension_evidence.py` + the strict wire validator in
//! `native_command_observations.py`.
//!
//! `observations_from_native_evidence` is the binding-validation bridge:
//! `evaluate_command` passes the `native_extension_evidence` payload (the
//! `guard.command-effect.v1`-shaped envelope carrying `command_model` +
//! `command_extensions`), this function validates the receipt digests +
//! redacted evidence, then materializes each wire observation into a
//! `NativeCommandExtensionObservation` carrying the resolved catalog rule
//! metadata the decision adapter reads.
//!
//! The validator operates on raw `serde_json::Value` to mirror Python
//! `isinstance` semantics exactly: a `null` `executable` is valid but a
//! non-string is not; `Option` deserialization would collapse `null` and
//! "absent" and must not be used inside validation. Materialization then
//! re-deserializes the *validated* payload into `NativeCommandObservationsV1`.

use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::OnceLock;

use guard_contracts::{
    NativeCommandControlBindingV1, NativeCommandObservationsV1, MAX_NATIVE_COMMAND_EVIDENCE_ITEMS,
    MAX_NATIVE_COMMAND_OBSERVATIONS, NATIVE_COMMAND_OBSERVATIONS_SCHEMA,
    NATIVE_COMMAND_RECEIPT_BINDING_SCHEMA,
};

use crate::canonical_command::CanonicalCommand;
use crate::command_evaluation::{
    NativeCommandExtensionObservation, NativeMatcherEvidence, NativeSafeVariantObservation,
};
use crate::effect_decision::UncertaintyKind;
use crate::native_command_catalog::CommandCatalog;

/// `NativeCommandExtensionEvidenceError` reasons — the caller maps every
/// `Err` to the Python `RuntimeError`/`None` boundary; the reason strings are
/// the Python exception messages verbatim.
const ERR_INVALID: &str = "native_command_extension_evidence_invalid";
const ERR_COMMAND_MISMATCH: &str = "native_command_extension_evidence_command_mismatch";
const ERR_BINDING_MISMATCH: &str = "native_command_extension_evidence_binding_mismatch";
const ERR_UNKNOWN_IDENTITY: &str = "native_command_extension_evidence_unknown_identity";

fn digest_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[0-9a-f]{64}").unwrap())
}
fn catalog_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"command\.[a-z0-9]+(?:[.-][a-z0-9]+)*").unwrap())
}
fn version_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[1-9][0-9]*\.[0-9]+\.[0-9]+").unwrap())
}
fn variant_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[a-z0-9][a-z0-9_.:-]{0,255}").unwrap())
}
fn executable_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}").unwrap())
}
fn mcp_tool_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[a-z0-9][a-z0-9_-]{0,127}").unwrap())
}

const DETAIL: &str = "Matched bounded structured command constraints.";

/// `_matches(value, pattern, maximum)` — `isinstance(str)` + `len <= maximum`
/// + `fullmatch`.
fn matches(value: &Value, pattern: &Regex, maximum: usize) -> bool {
    match value {
        Value::String(text) => {
            // Python `len` counts code points, not bytes.
            text.chars().count() <= maximum
                && pattern
                    .find(text)
                    .map(|m| m.start() == 0 && m.end() == text.len())
                    .unwrap_or(false)
        }
        _ => false,
    }
}

/// `_integer(value, maximum)` — `type(value) is int` (bool excluded —
/// `serde_json` has no bool/int confusion) + `0 <= value <= maximum`.
fn integer(value: &Value, maximum: u64) -> bool {
    match value {
        Value::Number(number) => number.as_u64().map(|v| v <= maximum).unwrap_or(false),
        _ => false,
    }
}

const BINDING_FIELDS: &[&str] = &[
    "schema",
    "program_digest",
    "catalog_digest",
    "trust_digest",
    "control_revision",
    "managed_control_revision",
    "control_effective_digest",
    "observations_digest",
    "observation_count",
    "uncertainty_count",
];

/// `set(value) == fields` for a JSON object.
fn exact_fields(value: &Value, fields: &[&str]) -> bool {
    match value {
        Value::Object(map) => {
            map.len() == fields.len() && fields.iter().all(|field| map.contains_key(*field))
        }
        _ => false,
    }
}

/// `valid_native_command_receipt_binding`.
pub fn valid_native_command_receipt_binding(value: &Value) -> bool {
    if !exact_fields(value, BINDING_FIELDS) {
        return false;
    }
    if value["schema"] != Value::String(NATIVE_COMMAND_RECEIPT_BINDING_SCHEMA.to_owned()) {
        return false;
    }
    for key in [
        "program_digest",
        "catalog_digest",
        "trust_digest",
        "control_effective_digest",
        "observations_digest",
    ] {
        if !matches(&value[key], digest_re(), 64) {
            return false;
        }
    }
    integer(&value["control_revision"], u64::MAX)
        && integer(&value["managed_control_revision"], u64::MAX)
        && integer(
            &value["observation_count"],
            MAX_NATIVE_COMMAND_OBSERVATIONS as u64,
        )
        && integer(
            &value["uncertainty_count"],
            (MAX_NATIVE_COMMAND_OBSERVATIONS + 1) as u64,
        )
}

/// `_evidence_indexes(value, budget)` — returns the segment-index list
/// preserving order and duplicates, or `None` on any violation. `budget` is
/// the shared mutable evidence counter (`budget[0] -= len`).
fn evidence_indexes(value: &Value, budget: &mut usize) -> Option<Vec<u64>> {
    let items = match value {
        Value::Array(items) if items.len() <= MAX_NATIVE_COMMAND_EVIDENCE_ITEMS => items,
        _ => return None,
    };
    // `budget[0] -= len(value)` can underflow; Python checks `< 0` after.
    if items.len() > *budget {
        *budget = 0;
        return None;
    }
    *budget -= items.len();
    let mut indexes = Vec::with_capacity(items.len());
    for item in items {
        if !exact_fields(item, &["segment_index", "executable", "detail"]) {
            return None;
        }
        if !integer(&item["segment_index"], 127)
            || item["detail"] != Value::String(DETAIL.to_owned())
        {
            return None;
        }
        let executable = &item["executable"];
        if !executable.is_null() && !matches(executable, executable_re(), 128) {
            return None;
        }
        indexes.push(item["segment_index"].as_u64()?);
    }
    Some(indexes)
}

const OBSERVATION_FIELDS: &[&str] = &[
    "extension_id",
    "extension_version",
    "rule_id",
    "rule_version",
    "match_class",
    "match_classes",
    "matcher_evidence",
    "safe_variants",
    "uncertainty_reasons",
    "effective_segment_indexes",
];

/// `_valid_observation(value, budget)`.
fn valid_observation(value: &Value, budget: &mut usize) -> bool {
    if !exact_fields(value, OBSERVATION_FIELDS) {
        return false;
    }
    for key in ["extension_id", "rule_id"] {
        if !matches(&value[key], catalog_id_re(), 256) {
            return false;
        }
    }
    let extension_id = match value["extension_id"].as_str() {
        Some(id) => id,
        None => return false,
    };
    let rule_id = match value["rule_id"].as_str() {
        Some(id) => id,
        None => return false,
    };
    if !rule_id.starts_with(&format!("{extension_id}.")) {
        return false;
    }
    for key in ["extension_version", "rule_version"] {
        if !matches(&value[key], version_re(), 64) {
            return false;
        }
    }
    let base = match evidence_indexes(&value["matcher_evidence"], budget) {
        Some(base) => base,
        None => return false,
    };
    let variants = match &value["safe_variants"] {
        Value::Array(variants) if variants.len() <= 64 => variants,
        _ => return false,
    };
    let uncertainty = &value["uncertainty_reasons"];
    let uncertainty_is_valid = matches!(uncertainty, Value::Array(items)
        if items.is_empty() || (items.len() == 1 && items[0] == Value::String("matcher-failure".to_owned())));
    if !uncertainty_is_valid {
        return false;
    }
    let has_uncertainty = matches!(uncertainty, Value::Array(items) if !items.is_empty());
    let mut expected_classes: Vec<&str> = if base.is_empty() {
        Vec::new()
    } else {
        vec!["unsafe"]
    };
    if has_uncertainty {
        expected_classes.push("uncertainty");
    }
    let expected_match_class = if has_uncertainty {
        "uncertainty"
    } else {
        "unsafe"
    };
    if value["match_class"] != Value::String(expected_match_class.to_owned()) {
        return false;
    }
    match &value["match_classes"] {
        Value::Array(classes)
            if classes.len() == expected_classes.len()
                && classes
                    .iter()
                    .zip(expected_classes.iter())
                    .all(|(actual, expected)| *actual == Value::String((*expected).to_owned())) => {
        }
        _ => return false,
    }
    if expected_classes.is_empty() || (base.is_empty() && !variants.is_empty()) {
        return false;
    }
    let mut variant_ids: BTreeSet<String> = BTreeSet::new();
    let mut safe_indexes: BTreeSet<u64> = BTreeSet::new();
    for variant in variants {
        if !exact_fields(variant, &["match_class", "variant_id", "matcher_evidence"]) {
            return false;
        }
        if variant["match_class"] != Value::String("safe-variant".to_owned())
            || !matches(&variant["variant_id"], variant_re(), 256)
        {
            return false;
        }
        let variant_id = variant["variant_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if !variant_ids.insert(variant_id) {
            return false;
        }
        let indexes = match evidence_indexes(&variant["matcher_evidence"], budget) {
            Some(indexes) if !indexes.is_empty() => indexes,
            _ => return false,
        };
        safe_indexes.extend(indexes);
    }
    let effective = match &value["effective_segment_indexes"] {
        Value::Array(indexes) if indexes.iter().all(|index| integer(index, 127)) => indexes.clone(),
        _ => return false,
    };
    let expected_effective: Vec<Value> = base
        .iter()
        .filter(|index| !safe_indexes.contains(index))
        .map(|index| Value::from(*index))
        .collect();
    effective == expected_effective
}

/// `_valid_permission_observation(value, budget)`.
fn valid_permission_observation(value: &Value, budget: &mut usize) -> bool {
    const FIELDS: &[&str] = &[
        "extension_id",
        "permission_id",
        "matcher_evidence",
        "uncertainty_reasons",
    ];
    let map = match value {
        Value::Object(map) => map,
        _ => return false,
    };
    let fields_ok = map.len() == FIELDS.len() && FIELDS.iter().all(|f| map.contains_key(*f));
    let fields_with_mcp_ok = map.len() == FIELDS.len() + 1
        && FIELDS.iter().all(|f| map.contains_key(*f))
        && map.contains_key("mcp_tool");
    if !fields_ok && !fields_with_mcp_ok {
        return false;
    }
    let has_mcp_tool = map.contains_key("mcp_tool");
    if has_mcp_tool {
        // `mcp_tool` present → must fullmatch the tool-name regex AND the
        // observation carries no matcher evidence.
        if !matches(&value["mcp_tool"], mcp_tool_re(), usize::MAX) {
            return false;
        }
        if matches!(&value["matcher_evidence"], Value::Array(items) if !items.is_empty()) {
            return false;
        }
    }
    if !matches(&value["extension_id"], catalog_id_re(), 256) {
        return false;
    }
    let permission_id = match value["permission_id"].as_str() {
        Some(id) if id.chars().count() <= 256 => id,
        _ => return false,
    };
    let extension_id = value["extension_id"].as_str().unwrap_or_default();
    if !permission_id.starts_with(&format!("{extension_id}.permission."))
        || !matches(&value["permission_id"], catalog_id_re(), 256)
    {
        return false;
    }
    let evidence = match evidence_indexes(&value["matcher_evidence"], budget) {
        Some(evidence) => evidence,
        None => return false,
    };
    let uncertainty = &value["uncertainty_reasons"];
    let uncertainty_is_valid = matches!(uncertainty, Value::Array(items)
        if items.is_empty() || (items.len() == 1 && items[0] == Value::String("matcher-failure".to_owned())));
    if !uncertainty_is_valid {
        return false;
    }
    let has_uncertainty = matches!(uncertainty, Value::Array(items) if !items.is_empty());
    !evidence.is_empty() || has_uncertainty || has_mcp_tool
}

const OBSERVATIONS_FIELDS: &[&str] = &[
    "schema",
    "binding",
    "observations",
    "permission_observations",
    "evaluation_error",
];

/// `validate_native_command_observations` — returns `Some(())` when the wire
/// payload passes every Python check (receipt binding shape, per-observation
/// semantics, shared evidence budget, dedup, count cross-checks, and the
/// `observations_digest` receipt recompute).
pub fn validate_native_command_observations(value: &Value) -> Option<()> {
    if !exact_fields(value, OBSERVATIONS_FIELDS) {
        return None;
    }
    if value["schema"] != Value::String(NATIVE_COMMAND_OBSERVATIONS_SCHEMA.to_owned())
        || !valid_native_command_receipt_binding(&value["binding"])
    {
        return None;
    }
    let observations = match &value["observations"] {
        Value::Array(items) => items,
        _ => return None,
    };
    let permission_observations = match &value["permission_observations"] {
        Value::Array(items) => items,
        _ => return None,
    };
    let error = &value["evaluation_error"];
    let count = observations.len() + permission_observations.len();
    if count > MAX_NATIVE_COMMAND_OBSERVATIONS {
        return None;
    }
    if !error.is_null()
        && (*error != Value::String("native_command_evaluation_failed".to_owned()) || count > 0)
    {
        return None;
    }
    let mut budget: usize = MAX_NATIVE_COMMAND_EVIDENCE_ITEMS;
    if !observations
        .iter()
        .all(|observation| valid_observation(observation, &mut budget))
    {
        return None;
    }
    if !permission_observations
        .iter()
        .all(|observation| valid_permission_observation(observation, &mut budget))
    {
        return None;
    }
    let rule_ids: BTreeSet<&str> = observations
        .iter()
        .filter_map(|item| item["rule_id"].as_str())
        .collect();
    if rule_ids.len() != observations.len() {
        return None;
    }
    let permission_ids: BTreeSet<&str> = permission_observations
        .iter()
        .filter_map(|item| item["permission_id"].as_str())
        .collect();
    if permission_ids.len() != permission_observations.len() {
        return None;
    }
    let mut uncertainty_count = observations
        .iter()
        .chain(permission_observations.iter())
        .filter(
            |item| matches!(&item["uncertainty_reasons"], Value::Array(items) if !items.is_empty()),
        )
        .count();
    if !error.is_null() {
        uncertainty_count += 1;
    }
    if value["binding"]["observation_count"].as_u64() != Some(count as u64)
        || value["binding"]["uncertainty_count"].as_u64() != Some(uncertainty_count as u64)
    {
        return None;
    }
    // Receipt digest: sha256("hol-guard.native-command-observations.v1\0" +
    // json.dumps({observations, permission_observations, evaluation_error},
    // ensure_ascii=False, sort_keys=True, separators=(",",":"))).
    // `serde_json::to_string` on a `Value` yields sorted keys (BTreeMap) with
    // compact separators and unescaped UTF-8 == `ensure_ascii=False`.
    let mut receipt = serde_json::Map::new();
    receipt.insert("observations".to_owned(), value["observations"].clone());
    receipt.insert(
        "permission_observations".to_owned(),
        value["permission_observations"].clone(),
    );
    receipt.insert("evaluation_error".to_owned(), error.clone());
    let canonical = serde_json::to_string(&Value::Object(receipt)).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(b"hol-guard.native-command-observations.v1\x00");
    hasher.update(canonical.as_bytes());
    let expected = format!("{:x}", hasher.finalize());
    if value["binding"]["observations_digest"].as_str() != Some(expected.as_str()) {
        return None;
    }
    Some(())
}

/// `observations_from_native_evidence(value, registry, *, command,
/// control_snapshot)`.
///
/// `value` is the full `native_extension_evidence` envelope; `command` is the
/// already-derived `CanonicalCommand` (for the `command_model.normalized_text`
/// binding); `control_snapshot` carries `revision`/`managed_revision`/
/// `effective_digest`.
pub fn observations_from_native_evidence(
    value: &Value,
    registry: &CommandCatalog,
    command: &CanonicalCommand,
    control_snapshot: &NativeCommandControlBindingV1,
) -> Result<Vec<NativeCommandExtensionObservation>, &'static str> {
    let envelope = match value {
        Value::Object(envelope) => envelope,
        _ => return Err(ERR_INVALID),
    };
    let command_model = envelope.get("command_model");
    let normalized_match = matches!(command_model, Some(Value::Object(model))
        if model.get("normalized_text") == Some(&Value::String(command.normalized_text.clone())));
    if !normalized_match {
        return Err(ERR_COMMAND_MISMATCH);
    }
    let command_extensions = match envelope.get("command_extensions") {
        Some(command_extensions) => command_extensions,
        None => return Err(ERR_INVALID),
    };
    if validate_native_command_observations(command_extensions).is_none() {
        return Err(ERR_INVALID);
    }
    let binding = &command_extensions["binding"];
    if binding["catalog_digest"].as_str() != Some(registry.catalog_digest.as_str())
        || binding["program_digest"].as_str() != Some(registry.program_digest.as_str())
        || binding["control_revision"].as_u64() != Some(control_snapshot.revision)
        || binding["managed_control_revision"].as_u64() != Some(control_snapshot.managed_revision)
        || binding["control_effective_digest"].as_str()
            != Some(control_snapshot.effective_digest.as_str())
    {
        return Err(ERR_BINDING_MISMATCH);
    }
    let evaluation_error = &command_extensions["evaluation_error"];
    if !evaluation_error.is_null() {
        // The wire validator accepts only the known evaluation failure with
        // empty observations and a matching digest. Preserve that rejection as
        // a native hard block; it cannot supply a semantic match or allow proof.
        if envelope.get("decision") != Some(&Value::String("deny".to_owned()))
            || envelope.get("policy_action") != Some(&Value::String("block".to_owned()))
            || envelope.get("minimum_action") != Some(&Value::String("block".to_owned()))
            || envelope.get("explicitly_benign") != Some(&Value::Bool(false))
        {
            return Err(ERR_INVALID);
        }
        return Ok(Vec::new());
    }
    // The payload passed strict validation — deserialize to the typed model
    // for materialization. This cannot fail: every field shape was checked.
    let validated: NativeCommandObservationsV1 =
        serde_json::from_value(command_extensions.clone()).map_err(|_| ERR_INVALID)?;
    let mut result: Vec<NativeCommandExtensionObservation> =
        Vec::with_capacity(validated.observations.len());
    for raw in &validated.observations {
        let extension = registry
            .get(&raw.extension_id)
            .ok_or(ERR_UNKNOWN_IDENTITY)?;
        let (rule_extension, rule) = registry
            .get_rule(&raw.rule_id)
            .ok_or(ERR_UNKNOWN_IDENTITY)?;
        // `rule not in extension.rules` — the wire rule must belong to the
        // wire extension, not merely resolve somewhere in the catalog.
        if !std::ptr::eq(rule_extension, extension)
            || raw.extension_version != extension.version
            || raw.rule_version != rule.rule_version
        {
            return Err(ERR_UNKNOWN_IDENTITY);
        }
        let known_variants: BTreeSet<&str> = rule
            .safe_variants
            .iter()
            .map(|variant| variant.variant_id.as_str())
            .collect();
        let mut safe_variants: Vec<NativeSafeVariantObservation> =
            Vec::with_capacity(raw.safe_variants.len());
        for variant in &raw.safe_variants {
            if !known_variants.contains(variant.variant_id.as_str()) {
                return Err(ERR_UNKNOWN_IDENTITY);
            }
            safe_variants.push(NativeSafeVariantObservation {
                variant_id: variant.variant_id.clone(),
                matcher_evidence: project_evidence(&variant.matcher_evidence),
            });
        }
        // Native uncertainty means the compatibility model could not attribute
        // the command to an owner; disabled controls still block it.
        let uncertainty = if raw.uncertainty_reasons.is_empty() {
            Vec::new()
        } else {
            vec![UncertaintyKind::UnsupportedInput]
        };
        result.push(NativeCommandExtensionObservation {
            extension_id: extension.extension_id.clone(),
            extension_version: extension.version.clone(),
            extension_required: extension.required,
            rule_id: rule.rule_id.clone(),
            rule_version: rule.rule_version.clone(),
            rule_severity: rule.severity.clone(),
            rule_default_mode: rule.default_mode.clone(),
            rule_risk_classes: rule.risk_classes.clone(),
            rule_action_classes: rule.action_classes.clone(),
            matcher_evidence: project_evidence(&raw.matcher_evidence),
            safe_variants,
            uncertainty_reasons: uncertainty,
        });
    }
    for raw in &validated.permission_observations {
        let extension = registry
            .get(&raw.extension_id)
            .ok_or(ERR_UNKNOWN_IDENTITY)?;
        let permission = registry
            .permission(&raw.permission_id)
            .ok_or(ERR_UNKNOWN_IDENTITY)?;
        // `permission not in extension.permissions` — ownership check.
        if !extension
            .permissions
            .iter()
            .any(|candidate| std::ptr::eq(candidate, permission))
        {
            return Err(ERR_UNKNOWN_IDENTITY);
        }
    }
    Ok(result)
}

/// `_evidence` — project validated wire `matcher_evidence` into
/// `NativeMatcherEvidence`.
fn project_evidence(
    items: &[guard_contracts::NativeMatcherEvidenceV1],
) -> Vec<NativeMatcherEvidence> {
    items
        .iter()
        .map(|item| NativeMatcherEvidence {
            segment_index: item.segment_index as u32,
            executable: item.executable.clone(),
            detail: item.detail.clone(),
        })
        .collect()
}
