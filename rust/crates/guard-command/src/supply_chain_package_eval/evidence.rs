use super::*;

/// `_persist_evidence` (:2124-2164).
// supply_chain_package_eval.py:2124-2164
#[allow(dead_code)]
pub(super) fn persist_evidence(
    deps: &SupplyChainEvalDeps<'_>,
    _store: &dyn SupplyChainStore,
    artifact: &GuardArtifact,
    evaluation: &PackageEvalResult,
    now: &str,
) {
    if evaluation.decision == "allow" {
        return;
    }
    if evaluation.decision == "monitor" && !evaluation.record_monitor_evidence {
        return;
    }
    for package in &evaluation.packages {
        if !should_record_package(package, &evaluation.decision) {
            continue;
        }
        let evidence_id = evidence_id(deps, &evaluation.package_intent_hash, package);
        let mut details = Map::new();
        details.insert(
            "agent_app".to_string(),
            optional_string(artifact.metadata.get("agent_app"))
                .map(Value::String)
                .unwrap_or_else(|| Value::String(artifact.harness.clone())),
        );
        details.insert(
            "command_shape".to_string(),
            optional_string(artifact.metadata.get("redacted_command"))
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert(
            "decision".to_string(),
            Value::String(evaluation.decision.clone()),
        );
        details.insert(
            "enforcement".to_string(),
            Value::String(evaluation.enforcement.clone()),
        );
        details.insert(
            "exception_id".to_string(),
            evaluation
                .exception_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert(
            "harness".to_string(),
            Value::String(artifact.harness.clone()),
        );
        details.insert(
            "matched_rule_id".to_string(),
            evaluation
                .matched_rule_id
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert("package".to_string(), Value::Object(package.clone()));
        details.insert(
            "package_manager".to_string(),
            optional_string(artifact.metadata.get("package_manager"))
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert(
            "repo_fingerprint".to_string(),
            evaluation
                .workspace_fingerprint
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        details.insert(
            "reasons".to_string(),
            Value::Array(
                dict_items(package.get("reasons"))
                    .into_iter()
                    .map(Value::Object)
                    .collect(),
            ),
        );
        details.insert(
            "workspace_fingerprint".to_string(),
            evaluation
                .workspace_fingerprint
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        let mut record = Map::new();
        record.insert("evidence_id".to_string(), Value::String(evidence_id));
        record.insert(
            "action_id".to_string(),
            Value::String(artifact.artifact_id.clone()),
        );
        record.insert(
            "request_id".to_string(),
            Value::String(evaluation.package_intent_hash.clone()),
        );
        record.insert(
            "harness".to_string(),
            Value::String(artifact.harness.clone()),
        );
        record.insert(
            "workspace".to_string(),
            Value::String(artifact.source_scope.clone()),
        );
        record.insert(
            "signal_id".to_string(),
            Value::String(
                optional_string(package.get("decision"))
                    .unwrap_or_else(|| evaluation.decision.clone()),
            ),
        );
        record.insert(
            "category".to_string(),
            Value::String("supply-chain".to_string()),
        );
        record.insert(
            "severity".to_string(),
            Value::String(reason_severity(package)),
        );
        record.insert(
            "confidence".to_string(),
            Value::Number(
                serde_json::Number::from_f64(
                    if matches!(evaluation.decision.as_str(), "block" | "ask") {
                        1.0
                    } else {
                        0.6
                    },
                )
                .unwrap_or_else(|| serde_json::Number::from(0)),
            ),
        );
        record.insert(
            "summary".to_string(),
            Value::String(evaluation.risk_summary.clone()),
        );
        record.insert("details".to_string(), Value::Object(details));
        record.insert(
            "action_identity".to_string(),
            evaluation
                .exception_id
                .clone()
                .or_else(|| evaluation.matched_rule_id.clone())
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        record.insert("created_at".to_string(), Value::String(now.to_string()));
        deps.store_extras.add_evidence(&record);
    }
}
