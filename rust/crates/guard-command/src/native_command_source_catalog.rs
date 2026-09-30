//! Deterministic catalog/program projections from validated source metadata.

use super::{contract::*, matcher::SourceGraph, *};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustMap {
    #[serde(rename = "schemaVersion")]
    schema: String,
    publishers: BTreeMap<String, Publisher>,
    classes: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Publisher {
    id: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

/// Build output has no activation effect until existing native/control admission.
#[derive(Debug, serde::Serialize)]
pub struct CompiledSourceCatalog {
    pub catalog: Value,
    pub descriptors: Vec<Value>,
    pub program: Value,
    pub source_digest: String,
    pub implementation_digest: String,
    pub catalog_projection_kind: String,
    pub base_program_digest: Option<String>,
}

fn digest(domain: &[u8], value: &Value) -> Result<String, &'static str> {
    let bytes = serde_json::to_vec(value).map_err(|_| "command_source_encoding_failed")?;
    Ok(digest_canonical_bytes(domain, &bytes))
}

fn trust_rows(bytes: &[u8]) -> Result<(TrustMap, BTreeMap<String, String>), &'static str> {
    let map: TrustMap = serde_json::from_value(json::decode(bytes)?)
        .map_err(|_| "command_source_trust_contract_invalid")?;
    if map.schema != "guard.extension-trust-class-map.v1"
        || map.classes.len() != 3
        || map.publishers.len() != 2
        || map
            .publishers
            .get("hol")
            .is_none_or(|publisher| publisher.id != "hol")
        || map
            .publishers
            .get("hol-curated")
            .is_none_or(|publisher| publisher.id != "hol-curated")
    {
        return Err("command_source_trust_contract_invalid");
    }
    let mut classes = BTreeMap::new();
    for (class, extensions) in &map.classes {
        if !matches!(
            class.as_str(),
            "first-party" | "trusted-library" | "external"
        ) {
            return Err("command_source_trust_class_invalid");
        }
        for extension in extensions {
            if classes.insert(extension.clone(), class.clone()).is_some() {
                return Err("command_source_trust_duplicate");
            }
        }
    }
    Ok((map, classes))
}

/// Existing MCP JSON remains canonical and is lowered alongside command sources.
fn lower_catalog(
    sources: &[&[u8]],
    mcp_sources: &[&[u8]],
    trust: &[u8],
) -> Result<CompiledSourceCatalog, &'static str> {
    if (sources.is_empty() && mcp_sources.is_empty())
        || sources.len() + mcp_sources.len() > 512
        || sources
            .iter()
            .chain(mcp_sources.iter())
            .try_fold(0usize, |total, bytes| total.checked_add(bytes.len()))
            .is_none_or(|size| size > MAX_PROGRAM_BYTES)
    {
        return Err("command_source_catalog_bytes_invalid");
    }
    let mut documents: Vec<SourceDocument> = sources
        .iter()
        .map(|bytes| {
            serde_json::from_value(json::decode(bytes)?)
                .map_err(|_| "command_source_contract_invalid")
        })
        .collect::<Result<_, _>>()?;
    let mut mcp_documents = mcp_sources
        .iter()
        .map(|bytes| mcp::lower(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    mcp_documents.sort_by(|a, b| {
        a.document
            .extension
            .extension_id
            .cmp(&b.document.extension.extension_id)
    });
    let mut mcp_wire = BTreeMap::new();
    let mut mcp_canonical = Vec::new();
    for lowered in mcp_documents {
        if mcp_wire
            .insert(
                lowered.document.extension.extension_id.clone(),
                lowered.wire,
            )
            .is_some()
        {
            return Err("command_source_extension_duplicate");
        }
        documents.push(lowered.document);
        mcp_canonical.push(lowered.canonical);
    }
    validation::validate_relationships(&documents, &mcp_wire.keys().map(String::as_str).collect())?;
    documents.sort_by(|a, b| a.extension.extension_id.cmp(&b.extension.extension_id));
    for document in &mut documents {
        document
            .extension
            .permissions
            .sort_by(|a, b| a.permission_id.cmp(&b.permission_id));
    }
    let source_value = serde_json::json!({"documents":documents,"mcp_sources":mcp_canonical});
    let source_digest = digest(b"hol-guard.command-extension-sources.v1\0", &source_value)?;
    let implementation_digest = env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION").to_owned();
    let authoring_digest = digest(
        b"hol-guard.native-authoring-semantics.v1\0",
        &serde_json::json!({
            "source_schema":SOURCE_SCHEMA, "source_digest":source_digest,
            "implementation_digest":implementation_digest,
        }),
    )?;
    let (trust_map, classes) = trust_rows(trust)?;
    let mut graph = SourceGraph::default();
    let mut catalog = Vec::new();
    let mut descriptors = Vec::new();
    let mut extensions = Vec::new();
    let mut rules = Vec::new();
    let mut coverage = Vec::new();
    let mut trusts = Vec::new();
    for document in documents {
        let extension = document.extension;
        let mut public =
            serde_json::to_value(&extension).map_err(|_| "command_source_encoding_failed")?;
        let class = classes
            .get(&extension.extension_id)
            .map(String::as_str)
            .unwrap_or("external");
        if class == "external" && extension.required {
            return Err("command_source_external_required_invalid");
        }
        if class != "external" && extension.publisher.is_some() {
            return Err("command_source_trusted_publisher_is_derived");
        }
        let publisher = match class {
            "first-party" => serde_json::to_value(&trust_map.publishers["hol"]),
            "trusted-library" => serde_json::to_value(&trust_map.publishers["hol-curated"]),
            _ => Ok(extension
                .publisher
                .as_ref()
                .map(SourcePublisher::projection)
                .unwrap_or_else(
                    || serde_json::json!({"id":"community","displayName":"Community"}),
                )),
        }
        .map_err(|_| "command_source_encoding_failed")?;
        let activation = if class == "external" {
            "opt-in"
        } else {
            "default-on"
        };
        let individual_digest = digest(
            b"hol-guard.command-extension-source.v1\0",
            &serde_json::json!({
                "schema":SOURCE_SCHEMA,"extension":public,
            }),
        )?;
        let icon = serde_json::to_value(extension.icon.as_ref().unwrap_or(&SourceIcon::None {}))
            .map_err(|_| "command_source_encoding_failed")?;
        if !mcp_wire.contains_key(&extension.extension_id) {
            descriptors.push(serde_json::json!({
            "schemaVersion":"guard.extension-contribution.v2","generated":true,
            "id":extension.extension_id,"version":extension.version,"name":extension.name,
            "description":extension.description,"icon":icon,"executables":extension.executables,
            "publisher":publisher,"homepage":extension.homepage,"license":extension.license,
            "riskClasses":extension.risk_classes,"actionClasses":extension.action_classes,
            "ecosystemIds":extension.ecosystem_ids,"referenceUrls":extension.reference_urls,
            "saferAlternatives":extension.safer_alternatives,"trustClass":class,"activation":activation,
            "nativeSource":{"schemaVersion":SOURCE_SCHEMA,
                "path":format!("contributions/command-sources/{}.json",extension.extension_id),
                "digest":individual_digest},
            }));
        }
        let trust_record = serde_json::json!({"extension_id":extension.extension_id,
            "trust_class":class, "activation":activation, "publisher":publisher});
        trusts.push(trust_record);
        let mut native_permissions = Vec::new();
        for (index, permission) in extension.permissions.iter().enumerate() {
            let rule_ids: Vec<_> = extension
                .rules
                .iter()
                .filter(|rule| rule.permission_id == permission.permission_id)
                .map(|rule| rule.rule_id.as_str())
                .collect();
            public["permissions"][index]["rule_ids"] = serde_json::json!(rule_ids);
            public["permissions"][index]["extension_id"] =
                serde_json::json!(extension.extension_id);
            public["permissions"][index]["schema_version"] = serde_json::json!(1);
            native_permissions.push(serde_json::json!({
                "permission_id":permission.permission_id,"baseline_floor":permission.baseline_floor,
                "default_enabled":permission.default_enabled,"configurable":permission.configurable,
                "dependencies":permission.dependencies,"implied_permissions":permission.implied_permissions,
                "rule_ids":rule_ids,
            }));
        }
        for (index, rule) in extension.rules.into_iter().enumerate() {
            if rules.len() >= MAX_RULES {
                return Err("command_source_rule_limit_exceeded");
            }
            let permission = extension
                .permissions
                .iter()
                .find(|p| p.permission_id == rule.permission_id)
                .ok_or("command_source_rule_permission_missing")?;
            let hints = rule.matcher.as_ref().map(hints::derive).unwrap_or_default();
            let root = rule.matcher.map(|tree| graph.lower(tree, 0)).transpose()?;
            let matcher_digest = if let Some(root) = &root {
                root.clone()
            } else {
                digest(
                    b"hol-guard.native-capability.v1\0",
                    &serde_json::json!({
                        "capability":rule.native_capability,"rule_id":rule.rule_id,"permission_id":rule.permission_id,
                    }),
                )?
            };
            let mut variants = Vec::new();
            let mut covered_variants = Vec::new();
            for (variant_index, variant) in rule.safe_variants.into_iter().enumerate() {
                let matcher = graph.lower(variant.matcher, 0)?;
                variants
                    .push(serde_json::json!({"variant_id":variant.variant_id,"matcher":matcher}));
                covered_variants.push(serde_json::json!({"variant_id":variant.variant_id,"matcher_contract_digest":matcher}));
                public["rules"][index]["safe_variants"][variant_index]
                    .as_object_mut()
                    .unwrap()
                    .remove("matcher");
                public["rules"][index]["safe_variants"][variant_index]["matcher_kind"] =
                    serde_json::json!("native-matcher.v1");
                public["rules"][index]["safe_variants"][variant_index]["matcher_contract_digest"] =
                    serde_json::json!(matcher);
            }
            let metadata = public["rules"][index].as_object_mut().unwrap();
            for field in ["matcher", "native_capability", "permission_id"] {
                metadata.remove(field);
            }
            metadata.insert(
                "matcher_kind".to_owned(),
                serde_json::json!(if root.is_some() {
                    "native-matcher.v1"
                } else {
                    "native-capability.v1"
                }),
            );
            metadata.insert(
                "matcher_contract_digest".to_owned(),
                serde_json::json!(matcher_digest),
            );
            metadata.insert(
                "compatibility_fallback".to_owned(),
                serde_json::json!(root.is_none()),
            );
            coverage.push(
                serde_json::json!({"rule_id":rule.rule_id,"matcher_contract_digest":matcher_digest,
                "translation":if root.is_some() { "declarative-ir" } else { "compatibility-only" },
                "native_execution":"requires-runtime-admission","safe_variants":covered_variants}),
            );
            rules.push(serde_json::json!({"rule_id":rule.rule_id,"rule_version":rule.rule_version,
                "extension_id":extension.extension_id,"permission_id":rule.permission_id,
                "baseline_floor":permission.baseline_floor,"configurable":permission.configurable,
                "default_mode":rule.default_mode,"severity":rule.severity,"risk_classes":rule.risk_classes,
                "action_classes":rule.action_classes,"matcher":root,"safe_variants":variants,
                "candidate_executables":hints.executables,"candidate_keywords":hints.keywords,
                "candidate_unindexed":hints.unindexed()}));
        }
        public.as_object_mut().unwrap().remove("homepage");
        public.as_object_mut().unwrap().remove("license");
        public["schema_version"] = serde_json::json!(2);
        public["rule_count"] = serde_json::json!(public["rules"].as_array().unwrap().len());
        public["permission_count"] = serde_json::json!(extension.permissions.len());
        public["trust_class"] = serde_json::json!(class);
        public["activation"] = serde_json::json!(activation);
        public["publisher"] = publisher.clone();
        public["enabled"] = serde_json::json!(class != "external");
        public["icon"] = icon;
        if let Some(wire) = mcp_wire.get(&extension.extension_id) {
            public
                .as_object_mut()
                .unwrap()
                .extend(wire.as_object().unwrap().clone());
        }
        catalog.push(public);
        extensions.push(serde_json::json!({"extension_id":extension.extension_id,"version":extension.version,
            "source":extension.source,"required":extension.required,"dependencies":extension.dependencies,
            "executables":extension.executables,"trust_class":class,"activation":activation,"publisher":publisher,
            "delegated_protection":extension.delegated_protection,"mcp":mcp_wire.get(&extension.extension_id),"permissions":native_permissions}));
    }
    let catalog = Value::Array(catalog);
    let catalog_bytes =
        serde_json::to_vec(&catalog).map_err(|_| "command_source_encoding_failed")?;
    if catalog_bytes.len() > 1_000_000 {
        return Err("command_source_catalog_projection_exceeded");
    }
    let nodes = graph.finish()?;
    let mut families = BTreeMap::<String, usize>::new();
    for node in nodes.as_object().unwrap().values() {
        *families
            .entry(node["op"].as_str().unwrap().to_owned())
            .or_default() += 1;
    }
    let mut program = serde_json::json!({"schema":PROGRAM_SCHEMA,"compiler_version":1,
        "semantic_profile":"cpython-3.12-ucd15","authoring_semantics_digest":authoring_digest,
        "catalog_digest":hex::encode(Sha256::digest(&catalog_bytes)),
        "trust_digest":digest(b"hol-guard.native-command-trust.v1\0", &serde_json::json!(trusts))?,
        "extensions":extensions,"rules":rules,"coverage":coverage,"nodes":nodes,"matcher_families":families});
    program["program_digest"] = serde_json::json!(digest(PROGRAM_DOMAIN, &program)?);
    Ok(CompiledSourceCatalog {
        catalog,
        descriptors,
        program,
        source_digest,
        implementation_digest,
        catalog_projection_kind: "complete".to_owned(),
        base_program_digest: None,
    })
}

fn admit(output: CompiledSourceCatalog) -> Result<CompiledSourceCatalog, &'static str> {
    let bytes =
        serde_json::to_vec(&output.program).map_err(|_| "command_source_encoding_failed")?;
    NativeCommandProgram::from_packaged_bytes(&bytes)?;
    mcp::validate_inventory(&output.program)?;
    Ok(output)
}

/// Compile the complete catalog, retaining the mandatory compatibility inventory.
pub fn compile_catalog(
    sources: &[&[u8]],
    trust: &[u8],
) -> Result<CompiledSourceCatalog, &'static str> {
    compile_catalog_with_mcp(sources, &[], trust)
}

pub fn compile_catalog_with_mcp(
    sources: &[&[u8]],
    mcp_sources: &[&[u8]],
    trust: &[u8],
) -> Result<CompiledSourceCatalog, &'static str> {
    admit(lower_catalog(sources, mcp_sources, trust)?)
}

/// Additive onboarding proof against the immutable packaged base. Existing
/// extensions cannot be replaced. The catalog projection contains additions,
/// explicitly distinguished from a complete release catalog.
pub fn compile_addition(
    sources: &[&[u8]],
    trust: &[u8],
) -> Result<CompiledSourceCatalog, &'static str> {
    compile_addition_with_mcp(sources, &[], trust)
}

pub fn compile_addition_with_mcp(
    sources: &[&[u8]],
    mcp_sources: &[&[u8]],
    trust: &[u8],
) -> Result<CompiledSourceCatalog, &'static str> {
    let mut output = lower_catalog(sources, mcp_sources, trust)?;
    NativeCommandProgram::from_packaged_bytes(EMBEDDED_PROGRAM)?;
    let mut base: Value = serde_json::from_slice(EMBEDDED_PROGRAM)
        .map_err(|_| "command_source_packaged_base_invalid")?;
    let base_digest = base["program_digest"].as_str().unwrap().to_owned();
    let existing: BTreeSet<_> = base["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|extension| extension["extension_id"].as_str().unwrap())
        .collect();
    if output.program["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|extension| existing.contains(extension["extension_id"].as_str().unwrap()))
    {
        return Err("command_source_addition_cannot_replace_extension");
    }
    for field in ["extensions", "rules", "coverage"] {
        base[field]
            .as_array_mut()
            .unwrap()
            .extend(output.program[field].as_array().unwrap().iter().cloned());
    }
    for (id, node) in output.program["nodes"].as_object().unwrap() {
        if base["nodes"]
            .get(id)
            .is_some_and(|existing| existing != node)
        {
            return Err("command_source_node_digest_conflict");
        }
        base["nodes"][id] = node.clone();
    }
    for (family, count) in output.program["matcher_families"].as_object().unwrap() {
        let old = base["matcher_families"][family].as_u64().unwrap_or(0);
        base["matcher_families"][family] = serde_json::json!(old + count.as_u64().unwrap());
    }
    base["catalog_digest"] = serde_json::json!(digest(
        b"hol-guard.additive-catalog.v1\0",
        &serde_json::json!({
            "base_catalog_digest":base["catalog_digest"],"additions":output.catalog,
        })
    )?);
    base["authoring_semantics_digest"] = serde_json::json!(digest(
        b"hol-guard.additive-semantics.v1\0",
        &serde_json::json!({
            "base_program_digest":base_digest,"addition_semantics":output.program["authoring_semantics_digest"],
        })
    )?);
    let trusts: Vec<_> = base["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|extension| {
            serde_json::json!({
                "extension_id":extension["extension_id"],"trust_class":extension["trust_class"],
                "activation":extension["activation"],"publisher":extension["publisher"],
            })
        })
        .collect();
    base["trust_digest"] = serde_json::json!(digest(
        b"hol-guard.native-command-trust.v1\0",
        &serde_json::json!(trusts)
    )?);
    base.as_object_mut().unwrap().remove("program_digest");
    base["program_digest"] = serde_json::json!(digest(PROGRAM_DOMAIN, &base)?);
    output.program = base;
    output.catalog_projection_kind = "addition-only-not-release-catalog".to_owned();
    output.base_program_digest = Some(base_digest);
    admit(output)
}
