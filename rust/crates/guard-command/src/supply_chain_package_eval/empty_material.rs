use super::contracts::optional_string;
use super::evaluation::{decision_rank, decision_to_guard_action_variant};
use super::{GuardArtifact, Map, PackageEvalResult, SupplyChainUserCopy, Value};

use crate::package_intent_common::PACKAGE_CWD_UNRESOLVED_NOTE;

fn artifact_note_is(artifact: &GuardArtifact, note: &str) -> bool {
    artifact
        .metadata
        .get("notes")
        .and_then(Value::as_array)
        .is_some_and(|notes| notes.iter().any(|value| value.as_str() == Some(note)))
}

/// `_empty_package_material_result` (:794-827).
///
/// `monitor` becomes allow. An unresolved `--cwd` must stay in review.
// supply_chain_package_eval.py:794-827
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(crate) fn empty_package_material_result(
    artifact: &GuardArtifact,
    workspace_id: Option<&str>,
    bundle_meta: Option<&Map<String, Value>>,
    package_intent_hash: &str,
    workspace_fingerprint: Option<&str>,
) -> PackageEvalResult {
    let unresolved_cwd = artifact_note_is(artifact, PACKAGE_CWD_UNRESOLVED_NOTE);
    let (code, message, decision, title, summary) = if unresolved_cwd {
        (
            "package_cwd_unresolved",
            "The package directory named by --cwd is outside this workspace or could not be resolved, so Guard cannot evaluate its lockfile.",
            "ask",
            "Package directory not in workspace",
            "Guard could not evaluate the package directory named by --cwd inside this workspace.",
        )
    } else {
        (
            "no_package_material",
            "Guard found no package targets, manifests, or lockfiles to evaluate for this request.",
            "monitor",
            "No package material",
            "Guard found no package targets, manifests, or lockfiles to evaluate.",
        )
    };
    let mut reason_map = Map::new();
    reason_map.insert("code".to_string(), Value::String(code.into()));
    reason_map.insert("message".to_string(), Value::String(message.into()));
    reason_map.insert("severity".to_string(), Value::String("unknown".into()));
    reason_map.insert("source".to_string(), Value::String("guard-local".into()));
    let policy_action = decision_to_guard_action_variant(decision);
    let harness_message = if unresolved_cwd {
        summary.to_string()
    } else {
        format!("{summary} No action needed.")
    };
    PackageEvalResult {
        decision: decision.to_string(),
        policy_action: policy_action.as_str().to_string(),
        enforcement: if workspace_id.is_none() {
            "free_local"
        } else {
            "local_fallback"
        }
        .to_string(),
        entitlement_state: if workspace_id.is_none() {
            "free"
        } else {
            "premium"
        }
        .to_string(),
        cache_status: "empty".to_string(),
        package_intent_hash: package_intent_hash.to_string(),
        policy_version: bundle_meta
            .and_then(|meta| optional_string(meta.get("policy_hash")))
            .unwrap_or_else(|| "local:none".to_string()),
        bundle_version: bundle_meta.and_then(|meta| optional_string(meta.get("bundle_version"))),
        workspace_fingerprint: workspace_fingerprint.map(str::to_string),
        reasons: vec![reason_map],
        packages: Vec::new(),
        risk_summary: summary.to_string(),
        user_copy: SupplyChainUserCopy {
            title: title.to_string(),
            summary: summary.to_string(),
            next_step: unresolved_cwd.then(|| "Review this install before running it.".to_string()),
            dashboard_url: None,
            harness_message,
        },
        matched_rule_id: None,
        exception_id: None,
        refresh_required: false,
        record_monitor_evidence: false,
        evidence_ids: Vec::new(),
        external_archive_downloads: Vec::new(),
        external_archive_source_hashes: Vec::new(),
    }
}

/// An unresolved `--cwd` stays in review even when the command also names a
/// package or another segment still has a lockfile.
pub(crate) fn hold_unresolved_package_cwd(
    artifact: &GuardArtifact,
    mut result: PackageEvalResult,
) -> PackageEvalResult {
    if !artifact_note_is(artifact, PACKAGE_CWD_UNRESOLVED_NOTE) {
        return result;
    }
    let noted = result
        .reasons
        .iter()
        .any(|reason| reason.get("code").and_then(Value::as_str) == Some("package_cwd_unresolved"));
    if !noted {
        let mut reason_map = Map::new();
        reason_map.insert(
            "code".to_string(),
            Value::String("package_cwd_unresolved".into()),
        );
        reason_map.insert(
            "message".to_string(),
            Value::String(
                "The package directory named by --cwd is outside this workspace or could not be resolved, so Guard cannot evaluate its lockfile."
                    .into(),
            ),
        );
        reason_map.insert("severity".to_string(), Value::String("unknown".into()));
        reason_map.insert("source".to_string(), Value::String("guard-local".into()));
        result.reasons.push(reason_map);
    }
    for package in &mut result.packages {
        let current = package
            .get("decision")
            .and_then(Value::as_str)
            .unwrap_or("allow");
        if decision_rank(current) < decision_rank("ask") {
            package.insert("decision".to_string(), Value::String("ask".into()));
        }
    }
    if decision_rank(&result.decision) >= decision_rank("ask") {
        return result;
    }
    result.decision = "ask".to_string();
    result.policy_action = decision_to_guard_action_variant("ask").as_str().to_string();
    let summary =
        "Guard could not evaluate the package directory named by --cwd inside this workspace.";
    result.risk_summary = summary.to_string();
    result.user_copy.title = "Package directory not in workspace".to_string();
    result.user_copy.summary = summary.to_string();
    result.user_copy.next_step = Some("Review this install before running it.".to_string());
    result.user_copy.harness_message = summary.to_string();
    result
}
