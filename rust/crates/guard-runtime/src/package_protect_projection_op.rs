//! `protect_projection` query of the `package_audit_projection` op: the
//! package-protect verdict, receipt and every user-facing surface for one
//! authority/evaluation pair. The caller supplies what it assembled (intent,
//! artifact identity, execution context, evaluation) and only persists and
//! executes; it never recomputes the verdict.

use guard_command::action_lattice::normalize_guard_action;
use guard_command::effect_decision::GuardAction;
use guard_command::local_supply_chain::PackageRequestEvaluation;
use guard_command::package_approval::PackageProtectAuthority;
use guard_command::package_execution_context::{
    PackageExecutionContext, PackageExecutionContextComponent,
};
use guard_command::package_intent_common::{GuardArtifact, PackageIntent, PackageIntentTarget};
use guard_command::package_protect_projection::{
    apply_package_protect_projection, install_time_event_payload,
};
use guard_contracts::PackageAuditProtectProjectionQueryV1;
use serde_json::{json, Map, Value};

fn invalid() -> String {
    "native_package_audit_projection_invalid".to_owned()
}

fn text(map: &Map<String, Value>, key: &str) -> Result<String, String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(invalid)
}

fn optional_text(map: &Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(invalid()),
    }
}

fn texts(map: &Map<String, Value>, key: &str) -> Result<Vec<String>, String> {
    map.get(key)
        .and_then(Value::as_array)
        .ok_or_else(invalid)?
        .iter()
        .map(|item| item.as_str().map(str::to_owned).ok_or_else(invalid))
        .collect()
}

fn object(value: &Value) -> Result<&Map<String, Value>, String> {
    value.as_object().ok_or_else(invalid)
}

fn decode_target(value: &Value) -> Result<PackageIntentTarget, String> {
    let map = object(value)?;
    Ok(PackageIntentTarget {
        ecosystem: text(map, "ecosystem")?,
        package_name: optional_text(map, "package_name")?,
        raw_spec: text(map, "raw_spec")?,
        requested_specifier: optional_text(map, "requested_specifier")?,
        source_url: optional_text(map, "source_url")?,
        source_kind: optional_text(map, "source_kind")?,
        source_repository: optional_text(map, "source_repository")?,
        source_revision_kind: optional_text(map, "source_revision_kind")?,
        source_identity: optional_text(map, "source_identity")?,
        source_invalid_reason: optional_text(map, "source_invalid_reason")?,
        alias: optional_text(map, "alias")?,
        dependency_group: optional_text(map, "dependency_group")?,
        extras: texts(map, "extras")?,
        editable: map
            .get("editable")
            .and_then(Value::as_bool)
            .ok_or_else(invalid)?,
    })
}

fn decode_intent(value: &Value) -> Result<PackageIntent, String> {
    let map = object(value)?;
    let intent_kind = match text(map, "intent_kind")?.as_str() {
        "install" => "install",
        "execute" => "execute",
        "sync" => "sync",
        _ => return Err(invalid()),
    };
    Ok(PackageIntent {
        package_manager: text(map, "package_manager")?,
        intent_kind,
        command_tokens: Vec::new(),
        redacted_command: text(map, "redacted_command")?,
        targets: map
            .get("targets")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?
            .iter()
            .map(decode_target)
            .collect::<Result<_, _>>()?,
        manifest_paths: texts(map, "manifest_paths")?,
        lockfile_paths: texts(map, "lockfile_paths")?,
        flags: Vec::new(),
        notes: Vec::new(),
        local_executions: Vec::new(),
        execution_context_hashes: Vec::new(),
        execution_context_cwds: Vec::new(),
        execution_context_reason_codes: Vec::new(),
    })
}

fn decode_artifact(value: &Value) -> Result<GuardArtifact, String> {
    let map = object(value)?;
    Ok(GuardArtifact {
        artifact_id: text(map, "artifact_id")?,
        name: text(map, "name")?,
        harness: String::new(),
        artifact_type: "package_request".to_owned(),
        source_scope: text(map, "source_scope")?,
        config_path: String::new(),
        command: None,
        args: Vec::new(),
        url: None,
        transport: None,
        publisher: None,
        metadata: Value::Null,
        runtime_private_metadata: Value::Null,
    })
}

/// The caller built this context from the workspace; it is evidence only here.
fn decode_context(value: &Value) -> Result<PackageExecutionContext, String> {
    let map = object(value)?;
    let components = map
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?
        .iter()
        .map(|item| {
            let item = object(item)?;
            Ok(PackageExecutionContextComponent {
                name: text(item, "name")?,
                digest: text(item, "digest")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(PackageExecutionContext {
        digest: text(map, "context_digest")?,
        portable: map
            .get("portable")
            .and_then(Value::as_bool)
            .ok_or_else(invalid)?,
        components,
        non_portable_reason: optional_text(map, "non_portable_reason")?,
    })
}

fn permitted(action: &Value) -> bool {
    matches!(action.as_str(), Some("allow" | "warn"))
}

/// Watch-only installs execute on the observed warn/allow; enforcement keeps
/// the observed action.
fn execution_policy_action(observe_mode: bool, policy_action: &Value) -> GuardAction {
    let observed = normalize_guard_action(policy_action, GuardAction::Block);
    match (observe_mode, observed) {
        (false, observed) => observed,
        (true, GuardAction::Warn) => GuardAction::Warn,
        (true, _) => GuardAction::Allow,
    }
}

pub(crate) fn protect_projection(
    query: &PackageAuditProtectProjectionQueryV1,
) -> Result<Value, String> {
    let intent = decode_intent(&query.intent)?;
    let artifact = decode_artifact(&query.artifact)?;
    let context = decode_context(&query.execution_context)?;
    let additional = match &query.additional_policy_context {
        None | Some(Value::Null) => None,
        Some(value) => Some(object(value)?),
    };
    object(&query.evaluation)?;
    let evaluation = PackageRequestEvaluation::new(query.evaluation.clone());
    let policy_action = query
        .evaluation
        .get("policy_action")
        .unwrap_or(&Value::Null);
    let execution_action = execution_policy_action(query.observe_mode, policy_action);
    let execution_permitted = permitted(&json!(execution_action.as_str()));
    let authority = PackageProtectAuthority {
        intent: &intent,
        artifact: &artifact,
        execution_context: &context,
        artifact_hash: &query.artifact_hash,
        additional_policy_context: additional,
        observe_mode: query.observe_mode,
        invoking_harness: &query.invoking_harness,
    };
    let mut fields = Map::new();
    let projection = apply_package_protect_projection(
        &mut fields,
        &authority,
        &evaluation,
        &query.command,
        query.blocking.unwrap_or(!execution_permitted),
        query.executed,
        query.project_execution_action.then_some(execution_action),
    );
    let event_payload = install_time_event_payload(
        &authority,
        &query.command,
        projection.verdict_action,
        &projection.risk_signals,
    );
    Ok(json!({
        "fields": fields,
        "event_payload": event_payload,
        "verdict_action": projection.verdict_action.as_str(),
        "risk_signals": projection.risk_signals,
        "execution_permitted": execution_permitted,
        "execution_exit_code": if execution_permitted { 0 } else { 2 },
        "policy_exit_code": if permitted(policy_action) { 0 } else { 2 },
    }))
}

#[cfg(test)]
#[path = "package_protect_projection_op_tests.rs"]
mod tests;
