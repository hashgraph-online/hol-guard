//! Offline authoring context, separate from the resident core. Callers obtain
//! catalog metadata and selected dependency packs from their verified bundle.
//! This input grants no installation or activation authority.
use super::*;

pub(super) struct ValidationBase {
    pub catalog: Vec<Value>,
    pub programs: Vec<Value>,
}

impl<'de> Deserialize<'de> for ValidationBase {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged, deny_unknown_fields)]
        enum Input {
            Inline {
                catalog: Vec<Value>,
                programs: Vec<Value>,
            },
            Indexed {
                metadata_index: metadata_index::Handle,
                programs: Vec<Value>,
            },
        }
        match Input::deserialize(decoder)? {
            Input::Inline { catalog, programs } => Ok(Self { catalog, programs }),
            Input::Indexed {
                metadata_index,
                programs,
            } => Ok(Self {
                catalog: metadata_index::read(&metadata_index).map_err(serde::de::Error::custom)?,
                programs,
            }),
        }
    }
}

fn fields(value: &mut Value, schema: &Value) -> Result<(), &'static str> {
    let object = value
        .as_object_mut()
        .ok_or("command_source_interface_invalid")?;
    let keys = schema["properties"].as_object().unwrap();
    object.retain(|key, _| keys.contains_key(key));
    Ok(())
}

// Reconstruct only the compiler's ownership/dependency interface. Predicate
// bodies are deliberately absent: these documents are never lowered/evaluated.
fn document(catalog: &Value) -> Result<contract::SourceDocument, &'static str> {
    let schema = contract::source_schema();
    let extension_schema = &schema["properties"]["extension"];
    let mut extension = catalog.clone();
    fields(&mut extension, extension_schema)?;
    extension["publisher"] = Value::Null;
    let mut owners = BTreeMap::new();
    for permission in extension["permissions"]
        .as_array_mut()
        .ok_or("command_source_interface_invalid")?
    {
        if permission
            .get("extension_id")
            .is_some_and(|owner| owner != &catalog["extension_id"])
        {
            return Err("command_source_interface_owner_invalid");
        }
        let id = permission["permission_id"]
            .as_str()
            .ok_or("command_source_interface_invalid")?
            .to_owned();
        for rule in permission["rule_ids"]
            .as_array()
            .ok_or("command_source_interface_invalid")?
        {
            let rule = rule
                .as_str()
                .ok_or("command_source_interface_invalid")?
                .to_owned();
            if owners.insert(rule, id.clone()).is_some() {
                return Err("command_source_interface_invalid");
            }
        }
        fields(
            permission,
            &extension_schema["properties"]["permissions"]["items"],
        )?;
    }
    for rule in extension["rules"]
        .as_array_mut()
        .ok_or("command_source_interface_invalid")?
    {
        let owner = owners
            .get(
                rule["rule_id"]
                    .as_str()
                    .ok_or("command_source_interface_invalid")?,
            )
            .ok_or("command_source_rule_permission_missing")?;
        fields(rule, &extension_schema["properties"]["rules"]["items"])?;
        rule["permission_id"] = serde_json::json!(owner);
        rule["matcher"] = serde_json::json!({"op":"interface-only", "config":{}});
        rule["native_capability"] = Value::Null;
        for variant in rule["safe_variants"]
            .as_array_mut()
            .ok_or("command_source_interface_invalid")?
        {
            fields(
                variant,
                &extension_schema["properties"]["rules"]["items"]["properties"]["safe_variants"]
                    ["items"],
            )?;
            variant["matcher"] = serde_json::json!({"op":"interface-only", "config":{}});
        }
    }
    serde_json::from_value(
        serde_json::json!({"schema":contract::SOURCE_SCHEMA,"extension":extension}),
    )
    .map_err(|_| "command_source_interface_invalid")
}

impl ValidationBase {
    pub(super) fn prepare(
        &self,
        sources: &[&[u8]],
        mcp_sources: &[&[u8]],
        fixture: bool,
    ) -> Result<Value, &'static str> {
        let embedded: Value =
            serde_json::from_slice(crate::native_command_catalog::embedded_catalog_bytes())
                .map_err(|_| "command_source_packaged_base_invalid")?;
        let mut catalogs = BTreeMap::new();
        for entry in &self.catalog {
            let id = entry["extension_id"]
                .as_str()
                .ok_or("command_source_interface_invalid")?;
            if catalogs.insert(id, entry).is_some() {
                return Err("command_source_extension_duplicate");
            }
        }
        for core in embedded["catalog"].as_array().unwrap() {
            let id = core["extension_id"].as_str().unwrap();
            if catalogs.get(id) != Some(&core) {
                return Err("command_source_core_interface_mismatch");
            }
        }
        let mut documents = self
            .catalog
            .iter()
            .map(document)
            .collect::<Result<Vec<_>, _>>()?;
        let mut mcp_ids: BTreeSet<String> = self
            .catalog
            .iter()
            .filter(|entry| {
                entry.get("mcp_server_id").is_some()
                    || entry["extension_id"]
                        .as_str()
                        .unwrap()
                        .starts_with("command.mcp-")
            })
            .map(|entry| entry["extension_id"].as_str().unwrap().to_owned())
            .collect();
        let mut additions = sources
            .iter()
            .map(|bytes| {
                serde_json::from_value::<contract::SourceDocument>(json::decode(bytes)?)
                    .map_err(|_| "command_source_contract_invalid")
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut candidate_launches = Vec::new();
        let mut candidate_mcp_ids = BTreeSet::new();
        for bytes in mcp_sources {
            let lowered = mcp::lower(bytes)?;
            mcp_ids.insert(lowered.document.extension.extension_id.clone());
            candidate_mcp_ids.insert(lowered.document.extension.extension_id.clone());
            candidate_launches.push(lowered.wire["mcp_launch"].clone());
            additions.push(lowered.document);
        }
        let mut inventory = McpInventory::default();
        for entry in &self.catalog {
            if !fixture || !candidate_mcp_ids.contains(entry["extension_id"].as_str().unwrap()) {
                inventory.insert(&entry["mcp_launch"])?;
            }
        }
        for launch in candidate_launches {
            inventory.insert(&launch)?;
        }
        for addition in additions {
            if let Some(existing) = documents
                .iter()
                .position(|doc| doc.extension.extension_id == addition.extension.extension_id)
            {
                if !fixture {
                    return Err("command_source_addition_cannot_replace_extension");
                }
                documents.remove(existing);
            }
            documents.push(addition);
        }
        validation::validate_pack_relationships(
            &documents,
            &mcp_ids.iter().map(String::as_str).collect(),
        )?;
        let extension_ids = catalogs.keys().map(|id| (*id).to_owned()).collect();
        let permission_ids = self
            .catalog
            .iter()
            .flat_map(|entry| entry["permissions"].as_array().unwrap())
            .map(|permission| permission["permission_id"].as_str().unwrap().to_owned())
            .collect();
        let mut base: Value = serde_json::from_slice(packaged_command_program_bytes())
            .map_err(|_| "command_source_packaged_base_invalid")?;
        for program in &self.programs {
            let bytes =
                serde_json::to_vec(program).map_err(|_| "command_source_encoding_failed")?;
            NativeCommandProgram::validate_compiler_pack_with_interfaces(
                &bytes,
                (&extension_ids, &permission_ids),
            )?;
            let entries = program["extensions"]
                .as_array()
                .ok_or("command_source_interface_invalid")?;
            if entries.len() != 1 {
                return Err("command_source_interface_invalid");
            }
            let id = entries[0]["extension_id"]
                .as_str()
                .ok_or("command_source_interface_invalid")?;
            let catalog = catalogs.get(id).ok_or("command_source_interface_invalid")?;
            let expected = digest_canonical_bytes(
                b"",
                &canonical_json_bytes(&serde_json::json!([catalog]))
                    .map_err(|_| "command_source_encoding_failed")?,
            );
            if program["catalog_digest"] != expected {
                return Err("command_source_interface_program_mismatch");
            }
            merge(&mut base, program)?;
        }
        Ok(base)
    }
}

pub(super) fn merge(base: &mut Value, addition: &Value) -> Result<(), &'static str> {
    let existing: BTreeSet<String> = base["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["extension_id"].as_str().unwrap().to_owned())
        .collect();
    if addition["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| existing.contains(entry["extension_id"].as_str().unwrap()))
    {
        return Err("command_source_addition_cannot_replace_extension");
    }
    for field in ["extensions", "rules", "coverage"] {
        base[field]
            .as_array_mut()
            .unwrap()
            .extend(addition[field].as_array().unwrap().iter().cloned());
    }
    for (id, node) in addition["nodes"].as_object().unwrap() {
        if base["nodes"].get(id).is_some_and(|old| old != node) {
            return Err("command_source_node_digest_conflict");
        }
        base["nodes"][id] = node.clone();
    }
    let mut families = BTreeMap::<String, usize>::new();
    for node in base["nodes"].as_object().unwrap().values() {
        *families
            .entry(node["op"].as_str().unwrap().to_owned())
            .or_default() += 1;
    }
    base["matcher_families"] = serde_json::json!(families);
    base["catalog_digest"] = serde_json::json!(catalog::digest(
        b"hol-guard.authoring-base-catalog.v1\0",
        &serde_json::json!([base["catalog_digest"], addition["catalog_digest"]])
    )?);
    base["authoring_semantics_digest"] = serde_json::json!(catalog::digest(
        b"hol-guard.authoring-base-semantics.v1\0",
        &serde_json::json!([
            base["authoring_semantics_digest"],
            addition["authoring_semantics_digest"]
        ])
    )?);
    let trusts: Vec<_> = base["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|extension| {
            serde_json::json!({
                "extension_id":extension["extension_id"], "trust_class":extension["trust_class"],
                "activation":extension["activation"], "publisher":extension["publisher"],
            })
        })
        .collect();
    base["trust_digest"] = serde_json::json!(catalog::digest(
        b"hol-guard.native-command-trust.v1\0",
        &serde_json::json!(trusts)
    )?);
    base.as_object_mut().unwrap().remove("program_digest");
    base["program_digest"] = serde_json::json!(catalog::digest(PROGRAM_DOMAIN, base)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const EXAMPLE: &[u8] = include_bytes!("../tests/fixtures/command-source-example.v1.json");
    const TRUST: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/trust-class-map.v1.json"));

    fn core_catalog() -> Vec<Value> {
        serde_json::from_slice::<Value>(crate::native_command_catalog::embedded_catalog_bytes())
            .unwrap()["catalog"]
            .as_array()
            .unwrap()
            .clone()
    }

    #[test]
    fn core_metadata_roundtrips_to_complete_relationship_validation() {
        let context = ValidationBase {
            catalog: core_catalog(),
            programs: vec![],
        };
        context.prepare(&[EXAMPLE], &[], false).unwrap();
    }

    #[test]
    fn optional_interfaces_above_legacy_count_do_not_grow_resident_program() {
        let extension_ids = BTreeSet::from(["command.example-cli".to_owned()]);
        let permission_ids = BTreeSet::from(["command.example-cli.permission.destroy".to_owned()]);
        let pack = catalog::compile_pack(&[EXAMPLE], &[], TRUST, (&extension_ids, &permission_ids))
            .unwrap();
        let mut catalog = core_catalog();
        for index in 0..600 {
            let text = serde_json::to_string(&pack.catalog[0])
                .unwrap()
                .replace("command.example-cli", &format!("command.scale{index}"));
            let mut entry: Value = serde_json::from_str(&text).unwrap();
            entry["permissions"][0]["typed_capabilities"] = serde_json::json!([]);
            catalog.push(entry);
        }
        let context = ValidationBase {
            catalog,
            programs: vec![],
        };
        let base = context.prepare(&[EXAMPLE], &[], false).unwrap();
        let packaged: Value = serde_json::from_slice(packaged_command_program_bytes()).unwrap();
        assert_eq!(base, packaged);
    }

    #[test]
    fn packaged_authoring_refuses_missing_global_context() {
        let source: Value = serde_json::from_slice(EXAMPLE).unwrap();
        let trust: Value = serde_json::from_slice(TRUST).unwrap();
        let request = serde_json::json!({"schema":"guard.command-extension-build.v1", "base":"packaged", "sources":[source], "trust":trust});
        assert_eq!(
            compile_build_request(&serde_json::to_vec(&request).unwrap()).unwrap_err(),
            "command_source_global_validation_required"
        );
    }

    #[test]
    fn optional_metadata_collisions_are_not_hidden_by_core_only_residency() {
        let extension_ids = BTreeSet::from(["command.example-cli".to_owned()]);
        let permission_ids = BTreeSet::from(["command.example-cli.permission.destroy".to_owned()]);
        let optional =
            catalog::compile_pack(&[EXAMPLE], &[], TRUST, (&extension_ids, &permission_ids))
                .unwrap();
        let mut catalog = core_catalog();
        catalog.extend(optional.catalog.as_array().unwrap().iter().cloned());
        let context = ValidationBase {
            catalog,
            programs: vec![],
        };
        assert_eq!(
            context.prepare(&[EXAMPLE], &[], false).unwrap_err(),
            "command_source_addition_cannot_replace_extension"
        );
        let mut candidate: Value = serde_json::from_slice(EXAMPLE).unwrap();
        candidate["extension"]["extension_id"] = serde_json::json!("command.another");
        // An alias colliding with an inactive external ID must be diagnosed
        // before any selected payload is needed.
        let text = serde_json::to_string(&candidate)
            .unwrap()
            .replace("command.example-cli.", "command.another.");
        let mut candidate: Value = serde_json::from_str(&text).unwrap();
        candidate["extension"]["aliases"] = serde_json::json!(["command.example-cli"]);
        candidate["extension"]["permissions"][0]["typed_capabilities"] = serde_json::json!([]);
        assert_eq!(
            context
                .prepare(
                    &[serde_json::to_vec(&candidate).unwrap().as_slice()],
                    &[],
                    false
                )
                .unwrap_err(),
            "command_source_alias_collision"
        );
    }

    #[test]
    fn valid_cross_external_dependency_compiles_with_selected_pack() {
        let extension_ids = BTreeSet::from(["command.example-cli".to_owned()]);
        let permission_ids = BTreeSet::from(["command.example-cli.permission.destroy".to_owned()]);
        let optional =
            catalog::compile_pack(&[EXAMPLE], &[], TRUST, (&extension_ids, &permission_ids))
                .unwrap();
        let mut catalog = core_catalog();
        catalog.extend(optional.catalog.as_array().unwrap().iter().cloned());
        let context = ValidationBase {
            catalog,
            programs: vec![optional.program],
        };
        let mut candidate: Value = serde_json::from_str(
            &String::from_utf8(EXAMPLE.to_vec())
                .unwrap()
                .replace("command.example-cli", "command.another"),
        )
        .unwrap();
        candidate["extension"]["dependencies"] = serde_json::json!(["command.example-cli"]);
        candidate["extension"]["permissions"][0]["dependencies"] =
            serde_json::json!(["command.example-cli.permission.destroy"]);
        // Capability identities must remain globally unique.
        candidate["extension"]["permissions"][0]["typed_capabilities"] = serde_json::json!([]);
        let bytes = serde_json::to_vec(&candidate).unwrap();
        let base = context.prepare(&[&bytes], &[], false).unwrap();
        let output =
            catalog::addition::compile_with_base(&[&bytes], &[], TRUST, Some(base)).unwrap();
        assert!(output.program["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["extension_id"] == "command.example-cli"));
    }
}
