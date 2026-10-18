use super::*;
use serde_json::json;

fn source() -> Value {
    serde_json::from_slice(packaged_command_program_bytes()).unwrap()
}

fn interfaces(source: &Value) -> (BTreeSet<String>, BTreeSet<String>) {
    let extensions = source["extensions"].as_array().unwrap();
    (
        extensions
            .iter()
            .map(|value| value["extension_id"].as_str().unwrap().to_owned())
            .collect(),
        extensions
            .iter()
            .flat_map(|value| value["permissions"].as_array().unwrap())
            .map(|value| value["permission_id"].as_str().unwrap().to_owned())
            .collect(),
    )
}

fn child_ids(value: &Value, pending: &mut Vec<String>) {
    match value {
        Value::String(id) => pending.push(id.clone()),
        Value::Array(values) => values.iter().for_each(|value| child_ids(value, pending)),
        Value::Object(values) => values.values().for_each(|value| child_ids(value, pending)),
        _ => (),
    }
}

// Split the packaged oracle for composition tests only. Production admission
// will consume per-pack bytes from the authenticated activation snapshot.
fn pack_value(source: &Value, id: &str) -> Value {
    let mut value = source.clone();
    value["extensions"]
        .as_array_mut()
        .unwrap()
        .retain(|extension| extension["extension_id"] == id);
    value["rules"]
        .as_array_mut()
        .unwrap()
        .retain(|rule| rule["extension_id"] == id);
    let rules: BTreeSet<_> = value["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule["rule_id"].as_str().unwrap().to_owned())
        .collect();
    value["coverage"]
        .as_array_mut()
        .unwrap()
        .retain(|row| rules.contains(row["rule_id"].as_str().unwrap()));
    let mut pending = Vec::new();
    for rule in value["rules"].as_array().unwrap() {
        if let Some(id) = rule["matcher"].as_str() {
            pending.push(id.to_owned());
        }
        for variant in rule["safe_variants"].as_array().unwrap() {
            pending.push(variant["matcher"].as_str().unwrap().to_owned());
        }
    }
    let mut nodes = serde_json::Map::new();
    while let Some(id) = pending.pop() {
        if nodes.contains_key(&id) {
            continue;
        }
        let node = &source["nodes"][&id];
        child_ids(&node["children"], &mut pending);
        nodes.insert(id, node.clone());
    }
    let mut families = BTreeMap::<String, usize>::new();
    for node in nodes.values() {
        *families
            .entry(node["op"].as_str().unwrap().to_owned())
            .or_default() += 1;
    }
    value["nodes"] = Value::Object(nodes);
    value["matcher_families"] = serde_json::to_value(families).unwrap();
    value.as_object_mut().unwrap().remove("program_digest");
    value["program_digest"] = json!(digest_value(PROGRAM_DOMAIN, &value).unwrap());
    value
}

fn admit(value: &Value, known: &(BTreeSet<String>, BTreeSet<String>)) -> NativeCommandProgram {
    NativeCommandProgram::from_bytes_observed(
        &serde_json::to_vec(value).unwrap(),
        &mut |_| {},
        Some((&known.0, &known.1)),
    )
    .unwrap()
}

fn selected(source: &Value, ids: &BTreeSet<String>) -> Vec<NativeCommandProgram> {
    let known = interfaces(source);
    ids.iter()
        .map(|id| admit(&pack_value(source, id), &known))
        .collect()
}

fn defaults(source: &Value) -> BTreeSet<String> {
    let mut ids: BTreeSet<_> = source["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|extension| extension["required"] == true || extension["trust_class"] != "external")
        .map(|extension| extension["extension_id"].as_str().unwrap().to_owned())
        .collect();
    loop {
        let before = ids.len();
        let owned: BTreeMap<_, _> = source["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|extension| {
                extension["permissions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(move |permission| {
                        (
                            permission["permission_id"].as_str().unwrap(),
                            extension["extension_id"].as_str().unwrap(),
                        )
                    })
            })
            .collect();
        for extension in source["extensions"].as_array().unwrap() {
            if !ids.contains(extension["extension_id"].as_str().unwrap()) {
                continue;
            }
            for dependency in extension["dependencies"].as_array().unwrap() {
                ids.insert(dependency.as_str().unwrap().to_owned());
            }
            for permission in extension["permissions"].as_array().unwrap() {
                for dependency in permission["dependencies"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .chain(permission["implied_permissions"].as_array().unwrap())
                {
                    ids.insert(owned[dependency.as_str().unwrap()].to_owned());
                }
            }
        }
        if ids.len() == before {
            return ids;
        }
    }
}

#[test]
fn default_collection_excludes_unselected_payload_and_preserves_observations() {
    let source = source();
    let ids = defaults(&source);
    let oracle =
        NativeCommandProgram::from_packaged_bytes(packaged_command_program_bytes()).unwrap();
    let collection = NativeCommandProgram::combine_admitted_packs(selected(&source, &ids)).unwrap();
    assert!(collection.extensions.len() < oracle.extensions.len());
    assert!(collection.nodes.len() < oracle.nodes.len());
    assert!(oracle.node_ids.is_empty());
    eprintln!(
        "collection_inventory: aggregate_extensions={} selected_extensions={} aggregate_rules={} selected_rules={} aggregate_nodes={} selected_nodes={}",
        oracle.extensions.len(), collection.extensions.len(), oracle.rules.len(),
        collection.rules.len(), oracle.nodes.len(), collection.nodes.len(),
    );
    assert_eq!(
        collection
            .extensions
            .iter()
            .map(|extension| extension.extension_id.clone())
            .collect::<BTreeSet<_>>(),
        ids
    );
    for command in [
        "git status",
        "git reset --hard",
        "rm -rf /tmp/demo",
        "find . -name '*.rs'",
        "sh -c 'git status; git clean -fd'",
        "npm install demo",
        "aws s3 rm s3://example/key",
    ] {
        let command =
            crate::parse_command(&serde_json::from_value(json!({"command":command})).unwrap())
                .unwrap();
        assert_eq!(
            serde_json::to_value(collection.observe(&command, &ids, None).unwrap()).unwrap(),
            serde_json::to_value(oracle.observe(&command, &ids, None).unwrap()).unwrap()
        );
    }
    let reversed = NativeCommandProgram::combine_admitted_packs(
        selected(&source, &ids).into_iter().rev().collect(),
    )
    .unwrap();
    assert_eq!(collection.program_digest, reversed.program_digest);
    assert_eq!(collection.catalog_digest, reversed.catalog_digest);
    assert_eq!(collection.trust_digest, reversed.trust_digest);
}

#[test]
fn duplicate_owners_and_incomplete_core_cannot_form_a_collection() {
    let source = source();
    let known = interfaces(&source);
    let value = pack_value(&source, "command.git");
    assert_eq!(
        NativeCommandProgram::combine_admitted_packs(vec![
            admit(&value, &known),
            admit(&value, &known)
        ])
        .unwrap_err(),
        "native_command_extension_duplicate"
    );
    assert!(NativeCommandProgram::combine_admitted_packs(vec![admit(&value, &known)]).is_err());
    assert!(NativeCommandProgram::combine_admitted_packs(Vec::new()).is_err());
}

#[test]
fn selected_collection_exceeds_legacy_aggregate_bounds_without_raising_pack_limits() {
    let source = source();
    let mut parts = selected(&source, &defaults(&source));
    let template = serde_json::to_string(&pack_value(&source, "command.agentbridge")).unwrap();
    for index in 0..1100 {
        let id = format!("command.collection-extra-{index}");
        let mut value: Value =
            serde_json::from_str(&template.replace("command.agentbridge", &id)).unwrap();
        value.as_object_mut().unwrap().remove("program_digest");
        value["program_digest"] = json!(digest_value(PROGRAM_DOMAIN, &value).unwrap());
        parts.push(admit(&value, &(BTreeSet::new(), BTreeSet::new())));
    }
    let collection = NativeCommandProgram::combine_admitted_packs(parts).unwrap();
    assert!(collection.extensions.len() > 512);
    assert!(collection.rules.len() > MAX_RULES);
    assert_eq!(MAX_RULES, 1024);
    let ids = collection
        .extensions
        .iter()
        .map(|extension| extension.extension_id.clone())
        .collect();
    let command =
        crate::parse_command(&serde_json::from_value(json!({"command":"git status"})).unwrap())
            .unwrap();
    assert!(collection.observe(&command, &ids, None).is_ok());
}

#[test]
fn composition_rejects_mutated_rule_ownership_without_panicking() {
    let source = source();
    for invalid_index in [1, usize::MAX] {
        let mut parts = selected(&source, &defaults(&source));
        parts
            .iter_mut()
            .find(|part| !part.rules.is_empty())
            .unwrap()
            .rules[0]
            .extension_index = invalid_index;
        assert_eq!(
            NativeCommandProgram::combine_admitted_packs(parts).unwrap_err(),
            "native_command_pack_rule_owner_invalid"
        );
    }
    let mut parts = selected(&source, &defaults(&source));
    parts
        .iter_mut()
        .find(|part| !part.rules.is_empty())
        .unwrap()
        .rules[0]
        .permission_id = "command.other.permission.read".to_owned();
    assert_eq!(
        NativeCommandProgram::combine_admitted_packs(parts).unwrap_err(),
        "native_command_pack_rule_owner_invalid"
    );
}

#[test]
fn composition_checks_mcp_ownership_without_the_release_reader() {
    let source = source();
    let id = source["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|extension| extension["trust_class"] == "external" && extension["mcp"].is_object())
        .unwrap()["extension_id"]
        .as_str()
        .unwrap();
    let mut parts = selected(&source, &defaults(&source));
    let template = serde_json::to_string(&pack_value(&source, id)).unwrap();
    for suffix in ["one", "two"] {
        let mut value: Value = serde_json::from_str(
            &template.replace(id, &format!("command.collection-mcp-{suffix}")),
        )
        .unwrap();
        value.as_object_mut().unwrap().remove("program_digest");
        value["program_digest"] = json!(digest_value(PROGRAM_DOMAIN, &value).unwrap());
        parts.push(admit(&value, &(BTreeSet::new(), BTreeSet::new())));
    }
    let error = NativeCommandProgram::combine_admitted_packs(parts).unwrap_err();
    assert!(matches!(
        error,
        "command_source_mcp_command_duplicate"
            | "command_source_mcp_package_duplicate"
            | "command_source_mcp_endpoint_duplicate"
    ));
}
