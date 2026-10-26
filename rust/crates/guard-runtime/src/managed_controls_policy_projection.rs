//! Control-layer and rule-target projection for the Managed Controls policy
//! fields parser.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::*;

fn target_delegated(target: &Target, catalog: &Catalog) -> Result<bool, Refusal> {
    match target.0 {
        Kind::Extension => catalog
            .extensions
            .get(&target.1)
            .map(|extension| extension.delegated)
            .ok_or_else(unknown_extension),
        Kind::Permission => catalog
            .permissions
            .get(&target.1)
            .ok_or_else(unknown_permission)?
            .owner_delegated
            .ok_or_else(unknown_owner),
    }
}

fn parse_control(value: &Value, catalog: &Catalog) -> Result<(Control, bool), Refusal> {
    let control = mapping(Some(value), "invalid_control", "Extension control")?;
    exact_keys(
        control,
        &["targetKind", "targetId", "state"],
        "Extension control",
    )?;
    let kind = match control.get("targetKind").and_then(Value::as_str) {
        Some("extension") => Kind::Extension,
        Some("permission") => Kind::Permission,
        _ => {
            return Err(refuse(
                "invalid_target_kind",
                "Extension control target kind is invalid.",
            ))
        }
    };
    let enabled = match control.get("state").and_then(Value::as_str) {
        Some("enabled") => true,
        Some("disabled") => false,
        _ => {
            return Err(refuse(
                "invalid_control_state",
                "Extension control state is invalid.",
            ))
        }
    };
    let target = (kind, canonical_id(control.get("targetId"), kind)?);
    if kind == Kind::Extension && target.1.contains(".permission.") {
        // The control contract keeps permission segments out of Extension
        // targets.
        return Err(refuse(
            "invalid_extension_id",
            "Extension target ID is not canonical.",
        ));
    }
    let delegated = target_delegated(&target, catalog)?;
    Ok((Control { target, enabled }, delegated))
}

pub(super) fn control_json(control: &Control) -> Value {
    json!({
        "target_kind": control.target.0.as_str(),
        "target_id": control.target.1,
        "state": if control.enabled { "enabled" } else { "disabled" },
    })
}

pub(super) fn target_json(target: &Target) -> Value {
    json!({ "target_kind": target.0.as_str(), "target_id": target.1 })
}

pub(super) struct Layer {
    pub(super) authority_mode: String,
    pub(super) projected: Vec<Control>,
    pub(super) managed: Vec<Control>,
    pub(super) global_lockdown: bool,
    pub(super) delegated: BTreeSet<Target>,
}

/// `globalLockdown` may be absent, null or true. A number equal to one is
/// accepted as "not locked down", as the reference parser did.
fn global_lockdown(value: Option<&Value>) -> Option<bool> {
    match value {
        None | Some(Value::Null) => Some(false),
        Some(Value::Bool(true)) => Some(true),
        Some(Value::Number(number)) if number.as_f64() == Some(1.0) => Some(false),
        _ => None,
    }
}

pub(super) fn parse_layer(
    field: &Obj,
    catalog: &Catalog,
    package_firewall: bool,
) -> Result<Layer, Refusal> {
    exact_keys(
        field,
        &[
            "schemaVersion",
            "authorityMode",
            "globalLockdown",
            "controls",
        ],
        CONTROLS_FIELD,
    )?;
    if field.get("schemaVersion").and_then(Value::as_str) != Some(CONTROLS_SCHEMA) {
        return Err(refuse(
            "unsupported_control_schema",
            "Extension control schema version is unsupported.",
        ));
    }
    let authority_mode = field
        .get("authorityMode")
        .and_then(Value::as_str)
        .filter(|mode| AUTHORITY_MODES.contains(mode))
        .ok_or_else(|| {
            refuse(
                "invalid_authority",
                "Managed Controls authority mode is invalid.",
            )
        })?;
    let restrictive = authority_mode == RESTRICTIVE;
    let global_lockdown = global_lockdown(field.get("globalLockdown")).ok_or_else(|| {
        refuse(
            "invalid_global_lockdown",
            "Global lockdown must be true when present.",
        )
    })?;
    if global_lockdown && !restrictive {
        return Err(refuse(
            "invalid_authority",
            "Global lockdown requires managed-restrictive authority.",
        ));
    }
    let controls = field
        .get("controls")
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("invalid_shape", "Extension controls must be an array."))?;
    if controls.len() > MAX_CONTROLS_PER_LAYER {
        return Err(refuse(
            "control_limit_exceeded",
            "Extension control layer exceeds the supported limit.",
        ));
    }
    let mut states: BTreeMap<Target, bool> = BTreeMap::new();
    let mut generic = Vec::new();
    let mut managed = Vec::new();
    let mut delegated = BTreeSet::new();
    for raw in controls {
        let (control, owner_delegated) = parse_control(raw, catalog)?;
        if let Some(previous) = states.get(&control.target) {
            let reason = if *previous == control.enabled {
                "duplicate_target"
            } else {
                "conflicting_target"
            };
            return Err(refuse(
                reason,
                "Duplicate or conflicting Extension controls are not allowed.",
            ));
        }
        states.insert(control.target.clone(), control.enabled);
        if restrictive && control.enabled {
            return Err(refuse(
                "managed_restrictive_broadening",
                "Managed-restrictive controls cannot enable a capability.",
            ));
        }
        if owner_delegated {
            if !package_firewall {
                return Err(refuse(
                    "unsupported_delegated_protection",
                    "Package Firewall is required for this control target.",
                ));
            }
            delegated.insert(control.target);
            continue;
        }
        if restrictive {
            managed.push(control);
            continue;
        }
        if control.enabled {
            if control.target.0 != Kind::Permission {
                return Err(refuse(
                    "shared_enable_requires_permission",
                    "Shared Cloud enablement must target one configurable permission.",
                ));
            }
            if !catalog
                .permissions
                .get(&control.target.1)
                .is_some_and(|permission| permission.configurable)
            {
                return Err(refuse(
                    "immutable_floor",
                    "Shared Cloud enablement cannot weaken an immutable permission floor.",
                ));
            }
        }
        if control.target.0 == Kind::Extension
            && !control.enabled
            && catalog
                .extensions
                .get(&control.target.1)
                .is_some_and(|extension| extension.required)
        {
            return Err(refuse(
                "immutable_floor",
                "A required Extension cannot be disabled by shared Cloud posture.",
            ));
        }
        generic.push(control);
    }
    let (projected, managed) = if restrictive {
        (managed, Vec::new())
    } else {
        (generic, managed)
    };
    // In managed-restrictive mode the signed layer and managed controls are
    // the same list; the client duplicates it.
    Ok(Layer {
        authority_mode: authority_mode.to_owned(),
        projected,
        managed,
        global_lockdown,
        delegated,
    })
}

fn parse_ids(value: Option<&Value>, label: &str, kind: Kind) -> Result<Vec<String>, Refusal> {
    let items = value
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("invalid_shape", format!("{label} must be an array.")))?;
    if items.len() > MAX_CONTROL_SET_TARGETS {
        return Err(refuse(
            "target_limit_exceeded",
            format!("{label} exceeds the supported limit."),
        ));
    }
    let mut parsed = items
        .iter()
        .map(|item| canonical_id(Some(item), kind))
        .collect::<Result<Vec<_>, _>>()?;
    parsed.sort();
    if parsed.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(refuse(
            "duplicate_target",
            format!("{label} contains a duplicate target."),
        ));
    }
    Ok(parsed)
}

fn package_firewall_required(what: &str) -> Refusal {
    refuse(
        "unsupported_delegated_protection",
        format!("Package Firewall is required for this {what} target."),
    )
}

pub(super) fn parse_rule_targets(
    document: &Obj,
    catalog: &Catalog,
    package_firewall: bool,
) -> Result<(Vec<Value>, BTreeSet<Target>), Refusal> {
    let mut parsed = Vec::new();
    let mut delegated = BTreeSet::new();
    let mut total = 0usize;
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
        let targets = mapping(
            rule.get(TARGETS_FIELD),
            "invalid_extension_targets",
            TARGETS_FIELD,
        )?;
        exact_keys(
            targets,
            &["schemaVersion", "extensionIds", "permissionIds"],
            TARGETS_FIELD,
        )?;
        if targets.get("schemaVersion").and_then(Value::as_str) != Some(TARGETS_SCHEMA) {
            return Err(refuse(
                "unsupported_target_schema",
                "Extension target schema version is unsupported.",
            ));
        }
        let extension_ids =
            parse_ids(targets.get("extensionIds"), "extensionIds", Kind::Extension)?;
        let permission_ids = parse_ids(
            targets.get("permissionIds"),
            "permissionIds",
            Kind::Permission,
        )?;
        total += extension_ids.len() + permission_ids.len();
        if total > MAX_CONTROL_SET_TARGETS {
            return Err(refuse(
                "target_limit_exceeded",
                "Control Set targets exceed the supported limit.",
            ));
        }
        for extension_id in &extension_ids {
            let extension = catalog
                .extensions
                .get(extension_id)
                .ok_or_else(unknown_extension)?;
            if extension.delegated {
                if !package_firewall {
                    return Err(package_firewall_required("Extension"));
                }
                delegated.insert((Kind::Extension, extension_id.clone()));
            }
        }
        for permission_id in &permission_ids {
            let permission = catalog
                .permissions
                .get(permission_id)
                .ok_or_else(unknown_permission)?;
            if !extension_ids.is_empty() && !extension_ids.contains(&permission.extension_id) {
                return Err(refuse(
                    "target_owner_mismatch",
                    "Permission target is not owned by one of the rule's Extension targets.",
                ));
            }
            if permission.owner_delegated.ok_or_else(unknown_owner)? {
                if !package_firewall {
                    return Err(package_firewall_required("permission"));
                }
                delegated.insert((Kind::Permission, permission_id.clone()));
            }
        }
        let rule_id = rule
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                refuse(
                    "invalid_policy_document",
                    "Extension-targeted rule requires an ID.",
                )
            })?;
        parsed.push(json!({
            "rule_id": rule_id,
            "extension_ids": extension_ids,
            "permission_ids": permission_ids,
        }));
    }
    Ok((parsed, delegated))
}
