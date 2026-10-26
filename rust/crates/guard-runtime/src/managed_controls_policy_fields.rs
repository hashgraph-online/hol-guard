//! Parse the signed Managed Controls policy fields after the envelope is
//! authenticated.
//!
//! Port of the former Python `managed_controls_policy_fields_core` parser;
//! parity vectors are recorded by
//! `scripts/record_managed_controls_policy_fields_vectors.py`. Pure: the client
//! sends the policy document, the negotiated capabilities and a projection of
//! the command catalog, and gets back either the parsed projection or a
//! bounded `{code, message}` refusal.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Map, Value};

#[path = "managed_controls_policy_projection.rs"]
mod projection;
use projection::{control_json, parse_layer, parse_rule_targets, target_json};
#[path = "managed_controls_cloud_projection.rs"]
mod cloud_projection;

const CONTROLS_FIELD: &str = "x-hol-extension-controls";
const TARGETS_FIELD: &str = "x-hol-extension-targets";
const CONTROLS_SCHEMA: &str = "guard.extension-controls.v1";
const TARGETS_SCHEMA: &str = "guard.policy-extension-targets.v1";
const LAYER_CAP: &str = "extension-control-layer.v1";
const TARGETS_CAP: &str = "policy-extension-targets.v1";
const ATOMIC_CAP: &str = "managed-controls-atomic-apply.v1";
const PACKAGE_FIREWALL_CAP: &str = "package-firewall.v1";
const LEGACY_ALIASES: &[(&str, &str)] = &[
    ("guard.managed-extension-controls.v1", LAYER_CAP),
    ("guard.policy-extension-targets.v1", TARGETS_CAP),
    ("guard.managed-controls-atomic-apply.v1", ATOMIC_CAP),
];
const AUTHORITY_MODES: &[&str] = &["personal-shared", "workspace-shared", "managed-restrictive"];
const RESTRICTIVE: &str = "managed-restrictive";
const MAX_CONTROL_SET_RULES: usize = 1_024;
const MAX_CONTROL_SET_TARGETS: usize = 1_024;
const MAX_CONTROLS_PER_LAYER: usize = 512;
const MAX_ID_CHARS: usize = 256;
const ERR_REQUEST: &str = "native_managed_controls_policy_fields_invalid_request";

type Obj = Map<String, Value>;

struct Refusal {
    code: &'static str,
    message: String,
}

fn refuse(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

struct Extension {
    required: bool,
    delegated: bool,
}

struct Permission {
    extension_id: String,
    /// `None` when the owning Extension is not in the catalog.
    owner_delegated: Option<bool>,
    configurable: bool,
}

struct Catalog {
    extensions: BTreeMap<String, Extension>,
    permissions: BTreeMap<String, Permission>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Extension,
    Permission,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Extension => "extension",
            Self::Permission => "permission",
        }
    }
}

type Target = (Kind, String);

struct Control {
    target: Target,
    enabled: bool,
}

pub(crate) fn evaluate(request: &Value) -> Result<Value, &'static str> {
    let request = request.as_object().ok_or(ERR_REQUEST)?;
    let capabilities = request
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or(ERR_REQUEST)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect::<Option<BTreeSet<String>>>()
        .ok_or(ERR_REQUEST)?;
    let document = request.get("document").ok_or(ERR_REQUEST)?;
    if !request.contains_key("catalog") {
        return Ok(match parse(document, &capabilities, None) {
            Ok(parsed) => json!({"ok": parsed}),
            Err(refusal) if refusal.code == "catalog_required" => json!({"catalog_required": true}),
            Err(refusal) => json!({"error": {"code": refusal.code, "message": refusal.message}}),
        });
    }
    let mut catalog = catalog(request.get("catalog")).ok_or(ERR_REQUEST)?;
    let metadata = if request.get("projection").is_some_and(|p| p["version"] == 2) {
        match cloud_projection::selected(request, document) {
            Ok(metadata) => {
                cloud_projection::extend_catalog(&mut catalog, &metadata)?;
                Some(metadata)
            }
            Err(code) => {
                return Ok(
                    json!({"error":{"code":code,"message":"Cloud policy observation is unavailable."}}),
                )
            }
        }
    } else {
        None
    };
    Ok(match parse(document, &capabilities, Some(&catalog)) {
        Ok(parsed) if request.contains_key("projection") => {
            match cloud_projection::evaluate(request, document, parsed, metadata.as_deref()) {
                Ok(answer) => answer,
                Err(code) => {
                    json!({"error":{"code":code,"message":"Cloud policy projection could not be authenticated."}})
                }
            }
        }
        Ok(parsed) => json!({ "ok": parsed }),
        Err(refusal) => json!({ "error": { "code": refusal.code, "message": refusal.message } }),
    })
}

fn catalog(value: Option<&Value>) -> Option<Catalog> {
    let value = value?.as_object()?;
    let mut extensions = BTreeMap::new();
    for (id, entry) in value.get("extensions")?.as_object()? {
        let entry = entry.as_object()?;
        extensions.insert(
            id.clone(),
            Extension {
                required: entry.get("required")?.as_bool()?,
                delegated: entry.get("delegated")?.as_bool()?,
            },
        );
    }
    let mut permissions = BTreeMap::new();
    for (id, entry) in value.get("permissions")?.as_object()? {
        let entry = entry.as_object()?;
        let owner_delegated = match entry.get("owner_delegated")? {
            Value::Null => None,
            other => Some(other.as_bool()?),
        };
        permissions.insert(
            id.clone(),
            Permission {
                extension_id: entry.get("extension_id")?.as_str()?.to_owned(),
                owner_delegated,
                configurable: entry.get("configurable")?.as_bool()?,
            },
        );
    }
    Some(Catalog {
        extensions,
        permissions,
    })
}

fn mapping<'a>(
    value: Option<&'a Value>,
    code: &'static str,
    label: &str,
) -> Result<&'a Obj, Refusal> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| refuse(code, format!("{label} must be an object.")))
}

fn exact_keys(value: &Obj, allowed: &[&str], label: &str) -> Result<(), Refusal> {
    if value.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(refuse(
            "unknown_field",
            format!("{label} contains unsupported fields."),
        ))
    }
}

fn rules_of(document: &Obj) -> Result<&Vec<Value>, Refusal> {
    let spec = mapping(
        document.get("spec"),
        "invalid_policy_document",
        "GuardPolicy spec",
    )?;
    spec.get("rules").and_then(Value::as_array).ok_or_else(|| {
        refuse(
            "invalid_policy_document",
            "GuardPolicy rules must be an array.",
        )
    })
}

fn rule_limit() -> Refusal {
    refuse(
        "rule_limit_exceeded",
        "Extension-targeted rules exceed the supported limit.",
    )
}

/// Reject explicit nulls and excessive targeted rules before projection.
fn validate_presence(document: &Obj) -> Result<(), Refusal> {
    if document.contains_key(CONTROLS_FIELD) {
        mapping(
            document.get(CONTROLS_FIELD),
            "invalid_extension_controls",
            CONTROLS_FIELD,
        )?;
    }
    let mut targeted = 0usize;
    for rule in rules_of(document)? {
        let rule = mapping(Some(rule), "invalid_policy_document", "GuardPolicy rule")?;
        if !rule.contains_key(TARGETS_FIELD) {
            continue;
        }
        targeted += 1;
        if targeted > MAX_CONTROL_SET_RULES {
            return Err(rule_limit());
        }
        mapping(
            rule.get(TARGETS_FIELD),
            "invalid_extension_targets",
            TARGETS_FIELD,
        )?;
    }
    Ok(())
}

fn normalize_capabilities(values: &BTreeSet<String>) -> BTreeSet<&'static str> {
    let mut normalized = BTreeSet::new();
    for item in values {
        if let Some(canonical) = [LAYER_CAP, TARGETS_CAP, ATOMIC_CAP, PACKAGE_FIREWALL_CAP]
            .into_iter()
            .find(|cap| cap == item)
        {
            normalized.insert(canonical);
        } else if let Some((_, canonical)) = LEGACY_ALIASES.iter().find(|(alias, _)| alias == item)
        {
            normalized.insert(*canonical);
        }
    }
    normalized
}

fn is_dotted_segments(text: &str) -> bool {
    // `[a-z0-9]+(?:[.-][a-z0-9]+)*`
    !text.is_empty()
        && text.split(['.', '-']).all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

fn is_extension_id(text: &str) -> bool {
    text.strip_prefix("command.")
        .is_some_and(is_dotted_segments)
}

fn is_permission_id(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("command.") else {
        return false;
    };
    // Any `.permission.` split whose halves both match the segment grammar.
    const SEPARATOR: &str = ".permission.";
    (0..rest.len()).any(|at| {
        rest.as_bytes()[at..].starts_with(SEPARATOR.as_bytes())
            && is_dotted_segments(&rest[..at])
            && is_dotted_segments(&rest[at + SEPARATOR.len()..])
    })
}

fn canonical_id(value: Option<&Value>, kind: Kind) -> Result<String, Refusal> {
    let (valid, code, message): (fn(&str) -> bool, _, _) = match kind {
        Kind::Extension => (
            is_extension_id,
            "invalid_extension_id",
            "Extension target ID is not canonical.",
        ),
        Kind::Permission => (
            is_permission_id,
            "invalid_permission_id",
            "Permission target ID is not canonical.",
        ),
    };
    match value.and_then(Value::as_str) {
        Some(text) if text.chars().count() <= MAX_ID_CHARS && valid(text) => Ok(text.to_owned()),
        _ => Err(refuse(code, message)),
    }
}

fn unknown_extension() -> Refusal {
    refuse(
        "unknown_extension_target",
        "Extension target is not in the current catalog.",
    )
}

fn unknown_permission() -> Refusal {
    refuse(
        "unknown_permission_target",
        "Permission target is not in the current catalog.",
    )
}

fn unknown_owner() -> Refusal {
    refuse(
        "unknown_extension_target",
        "Permission owner is not in the current catalog.",
    )
}

/// Whether the target's owning Extension delegates protection.
fn parse(
    document: &Value,
    capabilities: &BTreeSet<String>,
    catalog: Option<&Catalog>,
) -> Result<Value, Refusal> {
    let document = mapping(Some(document), "invalid_policy_document", "GuardPolicy")?;
    validate_presence(document)?;
    let controls_present = document.contains_key(CONTROLS_FIELD);
    let targets_present = rules_of(document)?.iter().any(|rule| {
        rule.as_object()
            .is_some_and(|rule| rule.contains_key(TARGETS_FIELD))
    });
    if !controls_present && !targets_present {
        return Ok(json!({
            "authority_mode": null,
            "signed_cloud_layer": null,
            "managed_controls": [],
            "managed_global_lockdown": false,
            "rule_targets": [],
            "delegated_targets": [],
        }));
    }
    let negotiated = normalize_capabilities(capabilities);
    if ![LAYER_CAP, TARGETS_CAP, ATOMIC_CAP]
        .iter()
        .all(|cap| negotiated.contains(cap))
    {
        return Err(refuse(
            "unnegotiated_extension_semantics",
            "Managed Controls fields require the complete negotiated capability set.",
        ));
    }
    let package_firewall = negotiated.contains(PACKAGE_FIREWALL_CAP);
    let catalog =
        catalog.ok_or_else(|| refuse("catalog_required", "Extension catalog required."))?;
    let mut answer = json!({
        "authority_mode": null,
        "signed_cloud_layer": null,
        "managed_controls": [],
        "managed_global_lockdown": false,
    });
    let mut delegated = BTreeSet::new();
    if controls_present {
        let field = mapping(
            document.get(CONTROLS_FIELD),
            "invalid_extension_controls",
            CONTROLS_FIELD,
        )?;
        let layer = parse_layer(field, catalog, package_firewall)?;
        let restrictive = layer.authority_mode == RESTRICTIVE;
        let projected: Vec<Value> = layer.projected.iter().map(control_json).collect();
        let managed: Vec<Value> = if restrictive {
            projected.clone()
        } else {
            layer.managed.iter().map(control_json).collect()
        };
        answer["authority_mode"] = json!(layer.authority_mode);
        answer["signed_cloud_layer"] = json!({
            "global_lockdown": layer.global_lockdown,
            "controls": projected,
        });
        answer["managed_controls"] = json!(managed);
        answer["managed_global_lockdown"] = json!(layer.global_lockdown);
        delegated.extend(layer.delegated);
    }
    let (rule_targets, rule_delegated) = parse_rule_targets(document, catalog, package_firewall)?;
    delegated.extend(rule_delegated);
    answer["rule_targets"] = json!(rule_targets);
    answer["delegated_targets"] = json!(delegated.iter().map(target_json).collect::<Vec<_>>());
    Ok(answer)
}

#[cfg(test)]
#[path = "managed_controls_policy_fields_tests.rs"]
mod tests;
