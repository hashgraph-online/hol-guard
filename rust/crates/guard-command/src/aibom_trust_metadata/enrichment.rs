use super::*;

// ---------------------------------------------------------------------------
// defmap order
// ---------------------------------------------------------------------------

/// `trust_resolution_from_domain(domain, *, captured_at)`
pub fn trust_resolution_from_domain(
    domain: &TrustDomainScore,
    deps: &TrustDeps<'_>,
    captured_at: &str,
) -> Map<String, Value> {
    let trust_components = _trust_components_from_domain(domain);
    let normalized_captured_at =
        normalize_inventory_datetime(&Value::String(captured_at.to_string()));
    let evidence =
        _local_baseline_evidence_payload(domain, &normalized_captured_at, &trust_components);
    let metadata = json!({
        "profileId": domain.profile_id,
        "profileVersion": domain.profile_version,
        "scorer": "hol-guard-local",
        "specId": domain.spec_id,
        "specVersion": domain.spec_version,
        "trustDomain": domain.domain,
        "attestationStatus": "unsigned",
        "evidenceSchemaVersion": "guard-aibom-local-baseline-evidence.v1",
        "evidenceAuthority": "device_claim",
        "affectsV4Score": false,
        "evidence": evidence,
        "evidenceHash": _trust_evidence_hash(&evidence, deps),
    });
    let mut out = Map::new();
    out.insert("resolutionSource".into(), json!("local"));
    out.insert("status".into(), json!("local"));
    out.insert("evidenceAuthority".into(), json!("device_claim"));
    out.insert("affectsV4Score".into(), json!(false));
    out.insert("trustScore".into(), json!(py_round(domain.score)));
    out.insert(
        "trustComponents".into(),
        Value::Array(trust_components.into_iter().map(Value::Object).collect()),
    );
    out.insert("capturedAt".into(), normalized_captured_at);
    out.insert(
        "provenance".into(),
        Value::Object(_local_claim_provenance("hol-guard-local-baseline")),
    );
    out.insert("metadata".into(), metadata);
    out
}

/// `apply_local_trust_metadata(artifact, *, captured_at, item_kind, metadata, workspace_dir, cisco_runs=())`
pub fn apply_local_trust_metadata(
    artifact: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    captured_at: &str,
    item_kind: &str,
    metadata: Map<String, Value>,
    workspace_dir: Option<&Path>,
    cisco_runs: &[Map<String, Value>],
) -> Map<String, Value> {
    let mut enriched = deps
        .boundary
        .separate_untrusted_adapter_trust_metadata(metadata);
    let mut trust_layers: Vec<Map<String, Value>> = Vec::new();

    if LOCAL_BASELINE_ITEM_KINDS.contains(&item_kind) {
        let domain =
            _local_trust_domain_for_artifact(artifact, deps, item_kind, &enriched, workspace_dir);
        if let Some(domain) = domain {
            enriched.insert(
                "trustResolution".into(),
                Value::Object(trust_resolution_from_domain(&domain, deps, captured_at)),
            );
            trust_layers.push(_trust_layer_from_domain(&domain, deps, captured_at));
        }
    }

    trust_layers.extend(_cisco_trust_layers_for_artifact(
        artifact,
        deps,
        item_kind,
        captured_at,
        cisco_runs,
        workspace_dir,
    ));

    let local_security = _local_security_for_artifact(
        artifact,
        deps,
        item_kind,
        &enriched,
        captured_at,
        cisco_runs,
        workspace_dir,
    );
    if let Some(local_security) = local_security {
        enriched.insert("localSecurity".into(), Value::Object(local_security));
    }

    if !trust_layers.is_empty() {
        enriched.insert(
            "trustLayers".into(),
            Value::Array(_merge_trust_layers(None, trust_layers)),
        );
    }
    enriched
}
