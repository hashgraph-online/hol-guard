//! Additive contribution proof against the immutable packaged base.
use super::*;

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
    compile_with_base(sources, mcp_sources, trust, None)
}

pub(in super::super) fn compile_with_base(
    sources: &[&[u8]],
    mcp_sources: &[&[u8]],
    trust: &[u8],
    baseline: Option<Value>,
) -> Result<CompiledSourceCatalog, &'static str> {
    let mut output = lower_catalog_inner(sources, mcp_sources, trust, baseline.is_none())?;
    NativeCommandProgram::from_packaged_bytes(packaged_command_program_bytes())?;
    let packaged: Value = serde_json::from_slice(packaged_command_program_bytes())
        .map_err(|_| "command_source_packaged_base_invalid")?;
    let base_digest = packaged["program_digest"].as_str().unwrap().to_owned();
    let mut base = baseline.unwrap_or(packaged);
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
                "activation":extension["activation"],"publisher":super::trust_identity(extension["trust_class"].as_str().unwrap_or(""), &extension["publisher"]),
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
