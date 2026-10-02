//! Validate a portable fixture after its exact extension has entered the build.
//! This path is used only by offline `test`, never by additive compilation or
//! runtime authority. Existing permissions, rules and matchers must agree.

use super::*;

const MISMATCH: &str = "command_source_fixture_packaged_extension_mismatch";

fn rows<'a>(program: &'a Value, field: &str, key: &str) -> BTreeMap<&'a str, &'a Value> {
    program[field]
        .as_array()
        .expect("native compiler array")
        .iter()
        .map(|row| (row[key].as_str().expect("native compiler identity"), row))
        .collect()
}

pub(super) fn compile_fixture_addition(
    sources: &[&[u8]],
    mcp_sources: &[&[u8]],
    trust: &[u8],
) -> Result<CompiledSourceCatalog, &'static str> {
    let mut output = catalog::lower_catalog(sources, mcp_sources, trust)?;
    NativeCommandProgram::from_packaged_bytes(EMBEDDED_PROGRAM)?;
    let base: Value = serde_json::from_slice(EMBEDDED_PROGRAM)
        .map_err(|_| "command_source_packaged_base_invalid")?;
    let supplied: BTreeSet<String> = rows(&output.program, "extensions", "extension_id")
        .keys()
        .map(|id| (*id).to_owned())
        .collect();
    let existing = rows(&base, "extensions", "extension_id");
    if supplied
        .iter()
        .all(|id| !existing.contains_key(id.as_str()))
    {
        return catalog::compile_addition_with_mcp(sources, mcp_sources, trust);
    }
    // Preserve the existing refusal for mixed replacement/addition requests.
    if supplied
        .iter()
        .any(|id| !existing.contains_key(id.as_str()))
    {
        return Err("command_source_addition_cannot_replace_extension");
    }
    let owned_rules: BTreeSet<String> = base["rules"]
        .as_array()
        .expect("admitted rules")
        .iter()
        .filter(|rule| supplied.contains(rule["extension_id"].as_str().unwrap()))
        .map(|rule| rule["rule_id"].as_str().unwrap().to_owned())
        .collect();
    for (field, key, expected_ids) in [
        ("extensions", "extension_id", &supplied),
        ("rules", "rule_id", &owned_rules),
        ("coverage", "rule_id", &owned_rules),
    ] {
        let candidate = rows(&output.program, field, key);
        let expected = rows(&base, field, key);
        let candidate_ids: BTreeSet<_> = candidate.keys().map(|id| (*id).to_owned()).collect();
        if &candidate_ids != expected_ids
            || candidate
                .iter()
                .any(|(id, row)| expected.get(id) != Some(row))
        {
            return Err(MISMATCH);
        }
    }
    if output.program["nodes"]
        .as_object()
        .expect("compiled matcher graph")
        .iter()
        .any(|(id, node)| base["nodes"].get(id) != Some(node))
    {
        return Err(MISMATCH);
    }
    output.base_program_digest = base["program_digest"].as_str().map(str::to_owned);
    output.catalog_projection_kind = "offline-fixture-existing".to_owned();
    output.program = base;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build() -> Value {
        let source: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../contributions/command-sources/command.noodle.json"
        )))
        .unwrap();
        let trust: Value = serde_json::from_slice(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../contracts/extensions/trust-class-map.v1.json"
        )))
        .unwrap();
        serde_json::json!({
            "schema":"guard.command-extension-build.v1", "base":"packaged",
            "sources":[source], "mcp_sources":[], "trust":trust
        })
    }

    #[test]
    fn additive_api_still_rejects_replacing_a_packaged_extension() {
        assert_eq!(
            compile_build_request(&serde_json::to_vec(&build()).unwrap()).unwrap_err(),
            "command_source_addition_cannot_replace_extension"
        );
    }

    #[test]
    fn portable_fixture_accepts_the_exact_already_packaged_behavior() {
        let fixture = serde_json::json!({
            "schema":"guard.command-extension-fixtures.v1", "build":build(),
            "cases":[
                {"id":"review-run", "command":"noodle request run users/get",
                 "enabled_extensions":["command.noodle"], "disabled_permissions":[],
                 "expected_action":"review", "rule_id":"command.noodle.run",
                 "expected_effective_segments":[0]},
                {"id":"help-is-read-only", "command":"noodle request run users/get --help",
                 "enabled_extensions":["command.noodle"], "disabled_permissions":[],
                 "expected_action":"review", "rule_id":"command.noodle.run",
                 "expected_effective_segments":[]}
            ]
        });
        let result = run_fixtures(&serde_json::to_vec(&fixture).unwrap()).unwrap();
        assert_eq!(result["ok"], true, "{result}");
        assert_eq!(result["target_commands_executed"], 0);
    }

    #[test]
    fn changed_packaged_matcher_is_not_treated_as_the_same_fixture() {
        let mut request = build();
        request["sources"][0]["extension"]["rules"][0]["matcher"]["matchers"][0]["config"]
            ["subcommands"] = serde_json::json!(["request", "destroy"]);
        assert_eq!(
            compile_fixture_build_request(&serde_json::to_vec(&request).unwrap()).unwrap_err(),
            MISMATCH
        );
    }
}
