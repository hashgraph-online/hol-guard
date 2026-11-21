use super::*;

// supply_chain_package_eval.py:2257-2300
#[allow(dead_code)]
pub(super) fn private_package_targets_match_public(
    private_targets: &[Value],
    public_targets: &[Value],
) -> bool {
    if private_targets.len() != public_targets.len() {
        return false;
    }
    const STRUCTURAL_FIELDS: &[&str] = &[
        "ecosystem",
        "package_name",
        "requested_specifier",
        "alias",
        "dependency_group",
        "extras",
        "editable",
        "source_kind",
        "source_repository",
        "source_revision_kind",
        "source_identity",
        "source_invalid_reason",
    ];
    for (private_target, public_target) in private_targets.iter().zip(public_targets.iter()) {
        let Some(priv_map) = private_target.as_object() else {
            return false;
        };
        let Some(pub_map) = public_target.as_object() else {
            return false;
        };
        for field in STRUCTURAL_FIELDS {
            if priv_map.get(*field) != pub_map.get(*field) {
                return false;
            }
        }
        let private_raw_spec = optional_string(priv_map.get("raw_spec"));
        let expected_raw_spec_hash = optional_string(pub_map.get("raw_spec_hash"));
        match (&private_raw_spec, &expected_raw_spec_hash) {
            (Some(spec), Some(hash)) => {
                if sha256_hex(spec.as_bytes()) != *hash {
                    return false;
                }
            }
            _ => return false,
        }
        let private_source_url = optional_string(priv_map.get("source_url"));
        let expected_source_hash = optional_string(pub_map.get("source_url_hash"));
        match (&private_source_url, &expected_source_hash) {
            (None, Some(_)) => return false,
            (Some(url), Some(hash)) => {
                if sha256_hex(url.as_bytes()) != *hash {
                    return false;
                }
            }
            (Some(_), None) => return false,
            (None, None) => {}
        }
    }
    true
}

/// `_public_package_targets_are_self_consistent` (:2303-2321).
// supply_chain_package_eval.py:2303-2321
#[allow(dead_code)]
pub(super) fn public_package_targets_are_self_consistent(public_targets: &[Value]) -> bool {
    for target in public_targets {
        let Some(map) = target.as_object() else {
            return false;
        };
        let raw_spec = optional_string(map.get("raw_spec"));
        let raw_spec_hash = optional_string(map.get("raw_spec_hash"));
        if let Some(hash) = raw_spec_hash {
            match &raw_spec {
                Some(spec) if sha256_hex(spec.as_bytes()) == hash => {}
                _ => return false,
            }
        }
        let source_url = optional_string(map.get("source_url"));
        let source_url_hash = optional_string(map.get("source_url_hash"));
        if let Some(hash) = source_url_hash {
            match &source_url {
                Some(url) if sha256_hex(url.as_bytes()) == hash => {}
                _ => return false,
            }
        }
    }
    true
}

/// `_bundle_meta` (:2324-2332).
// supply_chain_package_eval.py:2324-2332
#[allow(dead_code)]
pub(super) fn bundle_meta(bundle_payload: &Map<String, Value>) -> BTreeMap<String, String> {
    let Some(bundle) = bundle_payload.get("bundle").and_then(Value::as_object) else {
        return BTreeMap::new();
    };
    let mut out = BTreeMap::new();
    for (rust_key, py_key) in [
        ("bundle_version", "bundleVersion"),
        ("feed_snapshot_hash", "feedSnapshotHash"),
        ("policy_hash", "policyHash"),
        ("scoring_version", "scoringVersion"),
    ] {
        if let Some(v) = bundle.get(py_key) {
            out.insert(rust_key.to_string(), value_to_plain_string(v));
        }
    }
    out
}
