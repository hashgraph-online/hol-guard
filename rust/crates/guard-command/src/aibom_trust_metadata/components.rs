use super::*;

/// `_trust_components_from_domain(domain)`
pub(super) fn _trust_components_from_domain(domain: &TrustDomainScore) -> Vec<Map<String, Value>> {
    let mut components: Vec<Map<String, Value>> = Vec::new();
    for adapter in &domain.adapters {
        if !adapter.emitted {
            continue;
        }
        components.extend(_trust_components_from_adapter(adapter));
        if components.len() >= 32 {
            break;
        }
    }
    components.truncate(32);
    components
}

/// `_trust_components_from_adapter(adapter)`
pub(super) fn _trust_components_from_adapter(
    adapter: &TrustAdapterScore,
) -> Vec<Map<String, Value>> {
    adapter
        .components
        .iter()
        .map(|component| _trust_component_row(adapter, component))
        .collect()
}

/// `_trust_component_row(adapter, component)`
pub(super) fn _trust_component_row(
    adapter: &TrustAdapterScore,
    component: &TrustComponentScore,
) -> Map<String, Value> {
    let score = py_round(component.score);
    let status = if score < 40 {
        "critical"
    } else if score < 70 {
        "warning"
    } else {
        "positive"
    };
    let mut payload = Map::new();
    payload.insert(
        "componentId".into(),
        json!(format!("{}:{}", adapter.adapter_id, component.key)),
    );
    payload.insert("confidence".into(), json!(85));
    payload.insert("label".into(), json!(adapter.label));
    payload.insert("score".into(), json!(score));
    payload.insert("status".into(), json!(status));
    payload.insert("summary".into(), json!(component.rationale));
    payload.insert("weight".into(), json!(adapter.weight));
    if !component.evidence.is_empty() {
        payload.insert("evidence".into(), json!({ "lines": component.evidence }));
    }
    payload
}

/// `_trust_evidence_hash(payload)`
pub(super) fn _trust_evidence_hash(payload: &Map<String, Value>, deps: &TrustDeps<'_>) -> String {
    deps.evidence_hash.guard_evidence_hash(payload)
}
