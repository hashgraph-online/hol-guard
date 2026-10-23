//! `approval_extension_recommendation` -- resident op that re-checks a queued
//! extension allow hint into the recommendation shown with a pending review.
//!
//! The hint recorded at queue time names the configurable permissions that
//! would let the command run. It is advisory and goes stale: the catalog can
//! change, a permission can be switched off or already on, the authority can
//! be locked down. So each read re-checks it against the catalog the resident
//! admitted and the control authority view the caller holds, and offers
//! nothing that no longer applies. The answer carries catalog identifiers and
//! bounded catalog labels only, never command text. Nothing here mutates
//! authority; enabling a permission still goes through the proof-bound
//! extension-control mutation.
//!
//! A second query names which risk classes call for a caution, so the
//! connector setup card and the extension card share one list.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use guard_command::extension_control::{
    ControlLayerKind, ControlState, ControlTargetKind, ExtensionControlLayer,
};
use guard_command::native_command_catalog::{
    packaged_command_catalog, CatalogPermission, CatalogRule, CommandCatalog,
};
use guard_contracts::{
    ApprovalExtensionRecommendationPayloadV1, ApprovalExtensionRecommendationQueryV1,
    ApprovalExtensionRecommendationRequestV1, ApprovalExtensionRecommendationResultV1,
    ApprovalExtensionRecommendationSnapshotV1, ApprovalExtensionRecommendationV1,
    ApprovalExtensionRecommendedPermissionV1, ExtensionAllowHintV1,
    APPROVAL_EXTENSION_RECOMMENDATION_MAX_BYTES, APPROVAL_EXTENSION_RECOMMENDATION_MAX_HINT_IDS,
    APPROVAL_EXTENSION_RECOMMENDATION_MAX_RISK_CLASSES,
    APPROVAL_EXTENSION_RECOMMENDATION_REQUEST_SCHEMA,
    APPROVAL_EXTENSION_RECOMMENDATION_RESULT_SCHEMA, APPROVAL_EXTENSION_RECOMMENDATION_SCHEMA,
    EXTENSION_ALLOW_HINT_SCHEMA,
};

use crate::context_digest_local_cli::python_whitespace;
use crate::extension_control_op::typed_layers;
use crate::package_authority_op::request_digest_with_limit;
use crate::policy_enforcement::AdmittedPolicySnapshot;

const TOO_LARGE: &str = "native_approval_extension_recommendation_too_large";
const SCHEMA_MISMATCH: &str = "native_approval_extension_recommendation_schema_mismatch";
const HINT_INVALID: &str = "native_approval_extension_recommendation_hint_invalid";
const SNAPSHOT_INVALID: &str = "native_approval_extension_recommendation_snapshot_invalid";
const CATALOG_MISMATCH: &str = "native_approval_extension_recommendation_catalog_mismatch";
const CATALOG_UNAVAILABLE: &str = "native_approval_extension_recommendation_catalog_unavailable";
const TOO_MANY_RISK_CLASSES: &str =
    "native_approval_extension_recommendation_too_many_risk_classes";

/// Longest free-text label, description or example a recommendation carries.
const MAX_TEXT_CHARS: usize = 240;
const MAX_LABEL_CHARS: usize = 120;
const MAX_EXAMPLE_CHARS: usize = 160;

/// Risk classes whose rules call for a caution before an Allow.
const CAUTION_RISK_CLASSES: [&str; 8] = [
    "credential_exfiltration",
    "data_flow_exfiltration",
    "destructive",
    "dynamic_execution",
    "encoded_execution",
    "financial_transaction",
    "local_secret_read",
    "policy_bypass",
];

/// Every authority health the control runtime reports.
const AUTHORITY_HEALTHS: [&str; 6] = [
    "unenrolled",
    "protected",
    "degraded-unacknowledged",
    "degraded-acknowledged",
    "tampered",
    "recovery-required",
];

type States<'a> = HashMap<(ControlTargetKind, &'a str), ControlState>;

/// What the policy store said when asked for its admitted snapshot; `None`
/// when the resident holds no store.
type SnapshotRead = Option<Result<Arc<AdmittedPolicySnapshot>, String>>;

pub(crate) fn evaluate_with_store(
    request: &ApprovalExtensionRecommendationRequestV1,
    store: Option<&crate::policy_store::PolicySnapshotStore>,
) -> Result<Vec<u8>, String> {
    evaluate_with_snapshot(request, || {
        store.map(|store| store.current_admitted_snapshot())
    })
}

fn evaluate_with_snapshot(
    request: &ApprovalExtensionRecommendationRequestV1,
    read_snapshot: impl FnOnce() -> SnapshotRead,
) -> Result<Vec<u8>, String> {
    // Bound and digest the request before any catalog work; an oversized
    // request has no digest to bind.
    let request_sha256 = bounded_digest(request)?;
    // Only a recommend query reads a catalog; the caution list is constant.
    let catalog = match request.query {
        ApprovalExtensionRecommendationQueryV1::Recommend { .. } => {
            admitted_catalog(read_snapshot())
        }
        ApprovalExtensionRecommendationQueryV1::CautionRiskClasses { .. } => None,
    };
    respond(request, request_sha256, catalog.as_deref())
}

/// The catalog of the admitted policy snapshot, else the packaged one. This is a
/// metadata read: it needs no authority lease, which a decision would hold.
/// A snapshot the store refuses to admit (expired, invalid, bound to a changed
/// authority) is an unavailable catalog, never the packaged one, and it is
/// answered as a bound `error` reply: a bare transport error carries no schema,
/// which the client would count against the resident-wide breaker.
fn admitted_catalog(read: SnapshotRead) -> Option<Arc<CommandCatalog>> {
    let snapshot = match read {
        None => None,
        Some(Ok(snapshot)) => Some(snapshot),
        Some(Err(error)) if error == "native_policy_snapshot_missing" => None,
        Some(Err(_)) => return None,
    };
    let catalog = match snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.command_extensions.as_ref())
    {
        Some(controls) => controls.command_catalog(),
        None => packaged_command_catalog(),
    };
    catalog.ok()
}

fn bounded_digest(request: &ApprovalExtensionRecommendationRequestV1) -> Result<String, String> {
    request_digest_with_limit(request, APPROVAL_EXTENSION_RECOMMENDATION_MAX_BYTES)
        .map_err(|_| TOO_LARGE.to_owned())
}

#[cfg(test)]
fn evaluate_with_catalog(
    request: &ApprovalExtensionRecommendationRequestV1,
    catalog: Option<&CommandCatalog>,
) -> Result<Vec<u8>, String> {
    let request_sha256 = bounded_digest(request)?;
    respond(request, request_sha256, catalog)
}

fn respond(
    request: &ApprovalExtensionRecommendationRequestV1,
    request_sha256: String,
    catalog: Option<&CommandCatalog>,
) -> Result<Vec<u8>, String> {
    let (status, code, payload) = match decide(request, catalog) {
        Ok(payload) => ("ok", "ok".to_owned(), Some(payload)),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&ApprovalExtensionRecommendationResultV1 {
        schema: APPROVAL_EXTENSION_RECOMMENDATION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code,
        payload,
    })
}

fn decide(
    request: &ApprovalExtensionRecommendationRequestV1,
    catalog: Option<&CommandCatalog>,
) -> Result<ApprovalExtensionRecommendationPayloadV1, String> {
    if request.schema != APPROVAL_EXTENSION_RECOMMENDATION_REQUEST_SCHEMA {
        return Err(SCHEMA_MISMATCH.to_owned());
    }
    match &request.query {
        ApprovalExtensionRecommendationQueryV1::Recommend {
            hint,
            registry_catalog_digest,
            snapshot,
        } => {
            let catalog = catalog.ok_or_else(|| CATALOG_UNAVAILABLE.to_owned())?;
            Ok(ApprovalExtensionRecommendationPayloadV1::Recommend {
                recommendation: recommend(hint, registry_catalog_digest, snapshot, catalog)?,
            })
        }
        ApprovalExtensionRecommendationQueryV1::CautionRiskClasses { risk_classes } => {
            if risk_classes.len() > APPROVAL_EXTENSION_RECOMMENDATION_MAX_RISK_CLASSES {
                return Err(TOO_MANY_RISK_CLASSES.to_owned());
            }
            let mut cautioned: Vec<String> = risk_classes
                .iter()
                .filter(|class| CAUTION_RISK_CLASSES.contains(&class.as_str()))
                .cloned()
                .collect();
            cautioned.sort();
            cautioned.dedup();
            Ok(
                ApprovalExtensionRecommendationPayloadV1::CautionRiskClasses {
                    risk_classes: cautioned,
                },
            )
        }
    }
}

fn recommend(
    hint: &ExtensionAllowHintV1,
    registry_catalog_digest: &str,
    snapshot: &ApprovalExtensionRecommendationSnapshotV1,
    catalog: &CommandCatalog,
) -> Result<Option<ApprovalExtensionRecommendationV1>, String> {
    validate_hint(hint)?;
    if !AUTHORITY_HEALTHS.contains(&snapshot.health.as_str()) {
        return Err(SNAPSHOT_INVALID.to_owned());
    }
    let layers = typed_layers(&snapshot.layers).map_err(|_| SNAPSHOT_INVALID.to_owned())?;
    // A hint recorded under another catalog names permissions that may no
    // longer mean the same thing.
    if hint.catalog_digest != registry_catalog_digest {
        return Ok(None);
    }
    // The caller's registry may be a prepared one the resident has not admitted;
    // the resident only answers for the catalog it holds.
    if registry_catalog_digest != catalog.catalog_digest {
        return Err(CATALOG_MISMATCH.to_owned());
    }
    if layers.iter().any(|layer| layer.global_lockdown) {
        return Ok(None);
    }
    let local = layer_states(&layers, ControlLayerKind::LocalAdmin);
    let managed = layer_states(&layers, ControlLayerKind::SignedCloud);
    let hinted_rule_ids: HashSet<&str> = hint.rule_ids.iter().map(String::as_str).collect();
    for relied_id in &hint.relied_permission_ids {
        // The queue-time check assumed these were already allowed; if one has
        // since been turned off, allowing the hinted permissions is not enough.
        let key = (ControlTargetKind::Permission, relied_id.as_str());
        let (local_state, managed_state) = (local.get(&key), managed.get(&key));
        if managed_state == Some(&ControlState::Disabled)
            || (local_state != Some(&ControlState::Enabled)
                && managed_state != Some(&ControlState::Enabled))
        {
            return Ok(None);
        }
    }
    let mut permissions = Vec::new();
    for permission_id in &hint.permission_ids {
        let Some(permission) = catalog.permission(permission_id) else {
            return Ok(None);
        };
        let Some(extension) = catalog.get(&permission.extension_id) else {
            return Ok(None);
        };
        if !permission.configurable || permission.deprecated {
            return Ok(None);
        }
        let permission_key = (
            ControlTargetKind::Permission,
            permission.permission_id.as_str(),
        );
        let extension_key = (
            ControlTargetKind::Extension,
            extension.extension_id.as_str(),
        );
        if managed.get(&permission_key) == Some(&ControlState::Disabled)
            || managed.get(&extension_key) == Some(&ControlState::Disabled)
            || local.get(&extension_key) == Some(&ControlState::Disabled)
        {
            return Ok(None);
        }
        if local.get(&permission_key) == Some(&ControlState::Enabled) {
            continue;
        }
        let rules: Vec<&CatalogRule> = permission
            .rule_ids
            .iter()
            .filter_map(|rule_id| catalog.get_rule(rule_id).map(|(_, rule)| rule))
            .collect();
        let primary = rules
            .iter()
            .find(|rule| hinted_rule_ids.contains(rule.rule_id.as_str()))
            .or(rules.first())
            .copied();
        let caution = caution_reason(permission, &rules);
        permissions.push(ApprovalExtensionRecommendedPermissionV1 {
            permission_id: permission.permission_id.clone(),
            label: bounded(&permission.label, MAX_LABEL_CHARS),
            description: bounded(&permission.description, MAX_TEXT_CHARS),
            example_command: permission
                .example_command
                .as_deref()
                .and_then(|example| bounded(example, MAX_EXAMPLE_CHARS)),
            extension_id: extension.extension_id.clone(),
            extension_name: bounded(&extension.name, MAX_LABEL_CHARS),
            rule_id: primary.map(|rule| rule.rule_id.clone()),
            risk_tier: permission.risk_tier.clone(),
            caution: caution.is_some(),
            caution_reason: caution.map(str::to_owned),
            caution_detail: primary
                .filter(|_| caution.is_some())
                .and_then(|rule| bounded(&rule.description, MAX_TEXT_CHARS)),
            cli_command: format!(
                "hol-guard command controls set {} --state allow",
                permission.permission_id
            ),
        });
    }
    if permissions.is_empty() {
        return Ok(None);
    }
    Ok(Some(ApprovalExtensionRecommendationV1 {
        schema: APPROVAL_EXTENSION_RECOMMENDATION_SCHEMA.to_owned(),
        status: if snapshot.health == "protected" {
            "available"
        } else {
            "authority_unavailable"
        }
        .to_owned(),
        caution: permissions.iter().any(|permission| permission.caution),
        permissions,
        revision: snapshot.revision,
        catalog_digest: snapshot.catalog_digest.clone(),
    }))
}

fn validate_hint(hint: &ExtensionAllowHintV1) -> Result<(), String> {
    let bounded_ids = [
        &hint.permission_ids,
        &hint.rule_ids,
        &hint.extension_ids,
        &hint.relied_permission_ids,
    ]
    .iter()
    .all(|ids| ids.len() <= APPROVAL_EXTENSION_RECOMMENDATION_MAX_HINT_IDS);
    if hint.schema != EXTENSION_ALLOW_HINT_SCHEMA || !bounded_ids {
        return Err(HINT_INVALID.to_owned());
    }
    Ok(())
}

/// The explicit state per target in the layers of one kind; a later control
/// for the same target replaces an earlier one.
fn layer_states(layers: &[ExtensionControlLayer], kind: ControlLayerKind) -> States<'_> {
    layers
        .iter()
        .filter(|layer| layer.kind == kind)
        .flat_map(|layer| layer.controls.iter())
        .map(|control| {
            (
                (control.target.kind, control.target.target_id.as_str()),
                control.state,
            )
        })
        .collect()
}

/// Why an Allow deserves a caution, from the permission and the rules it gates.
fn caution_reason(permission: &CatalogPermission, rules: &[&CatalogRule]) -> Option<&'static str> {
    if permission.risk_tier == "critical" || rules.iter().any(|rule| rule.severity == "critical") {
        return Some("critical");
    }
    if permission
        .family
        .as_deref()
        .unwrap_or_default()
        .ends_with("-destructive")
    {
        return Some("destructive");
    }
    let mut action_classes = permission
        .action_classes
        .iter()
        .chain(rules.iter().flat_map(|rule| rule.action_classes.iter()));
    if action_classes.any(|action_class| action_class.contains("destructive")) {
        return Some("destructive");
    }
    let mut risk_classes = rules.iter().flat_map(|rule| rule.risk_classes.iter());
    if risk_classes.any(|risk| CAUTION_RISK_CLASSES.contains(&risk.as_str())) {
        return Some("sensitive");
    }
    None
}

/// Display text with runs of whitespace collapsed (`" ".join(text.split())`,
/// so the ASCII information separators count as whitespace) and cut to
/// `limit` characters; `None` when nothing is left.
fn bounded(text: &str, limit: usize) -> Option<String> {
    let normalized = text
        .split(python_whitespace)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!normalized.is_empty()).then(|| normalized.chars().take(limit).collect())
}

#[cfg(test)]
#[path = "approval_extension_recommendation_op_tests.rs"]
mod tests;
