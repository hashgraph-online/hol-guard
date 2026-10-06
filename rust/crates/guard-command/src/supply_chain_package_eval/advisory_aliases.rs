use super::*;

/// `_primary_bundle_advisory_id` (:1880-1895).
// supply_chain_package_eval.py:1880-1895
#[allow(dead_code)]
pub(super) fn primary_bundle_advisory_id(
    bundle_response: &SupplyChainBundleResponse,
    package: &Map<String, Value>,
) -> Option<String> {
    let related: Vec<String> = package
        .get("relatedAdvisoryIds")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if related.is_empty() {
        return None;
    }
    let mut advisory_lookup: HashMap<String, String> = HashMap::new();
    let advisories = bundle_response
        .signed_bundle
        .get("advisories")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for advisory_val in advisories {
        let Some(advisory) = advisory_val.as_object() else {
            continue;
        };
        let Some(aid) = advisory.get("advisoryId").and_then(Value::as_str) else {
            continue;
        };
        advisory_lookup.insert(aid.to_string(), aid.to_string());
        if let Some(aliases) = advisory.get("aliases").and_then(Value::as_array) {
            for alias in aliases {
                if let Some(a) = alias.as_str() {
                    advisory_lookup
                        .entry(a.to_string())
                        .or_insert_with(|| aid.to_string());
                }
            }
        }
    }
    for advisory_id in &related {
        if let Some(canonical) = advisory_lookup.get(advisory_id) {
            return Some(canonical.clone());
        }
    }
    related.first().cloned()
}

/// `_bundle_advisory_aliases` (:1898-1923).
// supply_chain_package_eval.py:1898-1923
#[allow(dead_code)]
pub(super) fn bundle_advisory_aliases(
    bundle_response: &SupplyChainBundleResponse,
    package: &Map<String, Value>,
) -> Vec<String> {
    let mut advisory_ids: Vec<String> = package
        .get("relatedAdvisoryIds")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if let Some(primary) = primary_bundle_advisory_id(bundle_response, package) {
        if !advisory_ids.contains(&primary) {
            advisory_ids.push(primary);
        }
    }
    if advisory_ids.is_empty() {
        return Vec::new();
    }
    let mut advisory_lookup: HashMap<String, Vec<String>> = HashMap::new();
    let advisories = bundle_response
        .signed_bundle
        .get("advisories")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    for advisory_val in advisories {
        let Some(advisory) = advisory_val.as_object() else {
            continue;
        };
        let Some(aid) = advisory.get("advisoryId").and_then(Value::as_str) else {
            continue;
        };
        let mut tuple = vec![aid.to_string()];
        if let Some(aliases) = advisory.get("aliases").and_then(Value::as_array) {
            for alias in aliases {
                if let Some(a) = alias.as_str() {
                    tuple.push(a.to_string());
                }
            }
        }
        let upper_tuple: Vec<String> = tuple.iter().map(|a| a.to_uppercase()).collect();
        advisory_lookup.insert(aid.to_uppercase(), upper_tuple.clone());
        for alias in &tuple {
            advisory_lookup
                .entry(alias.to_uppercase())
                .or_insert_with(|| upper_tuple.clone());
        }
    }
    let mut aliases: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for advisory_id in &advisory_ids {
        let default = vec![advisory_id.to_uppercase()];
        let list = advisory_lookup
            .get(&advisory_id.to_uppercase())
            .unwrap_or(&default);
        for alias in list {
            if seen.insert(alias.clone()) {
                aliases.push(alias.clone());
            }
        }
    }
    aliases
}
