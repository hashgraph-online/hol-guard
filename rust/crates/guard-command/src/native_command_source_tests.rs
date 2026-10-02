use super::*;
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::{parse_command, CommandModelRequestV1};
use guard_contracts::NativeCommandControlBindingV1;

const EXAMPLE: &[u8] = include_bytes!("../tests/fixtures/command-source-example.v1.json");
const TRUST: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../contracts/extensions/trust-class-map.v1.json"
));

#[test]
fn offline_parity_compares_full_native_evidence_and_rejects_real_differences() {
    let mut baseline = compiled().program;
    baseline["authoring_semantics_digest"] = serde_json::json!("a".repeat(64));
    baseline.as_object_mut().unwrap().remove("program_digest");
    baseline["program_digest"] = serde_json::json!(digest_canonical_bytes(
        PROGRAM_DOMAIN,
        &serde_json::to_vec(&baseline).unwrap()
    ));
    let mut request = serde_json::json!({
        "schema":"guard.command-extension-parity.v1",
        "baseline_program":baseline,
        "build":{"schema":"guard.command-extension-build.v1","base":"packaged",
            "sources":[serde_json::from_slice::<Value>(EXAMPLE).unwrap()],
            "trust":serde_json::from_slice::<Value>(TRUST).unwrap()},
        "cases":[{"id":"git-reset","payload":{"tool_name":"Bash","tool_input":{"command":"git reset --hard"}},
            "controls":[],"managed_controls":[]}]
    });
    let result = compare_programs(&serde_json::to_vec(&request).unwrap()).unwrap();
    assert_eq!(result["ok"], true, "{result}");
    for rule in request["baseline_program"]["rules"].as_array_mut().unwrap() {
        rule["rule_version"] = serde_json::json!("9.9.9");
    }
    let baseline = &mut request["baseline_program"];
    baseline.as_object_mut().unwrap().remove("program_digest");
    baseline["program_digest"] = serde_json::json!(digest_canonical_bytes(
        PROGRAM_DOMAIN,
        &serde_json::to_vec(baseline).unwrap()
    ));
    let result = compare_programs(&serde_json::to_vec(&request).unwrap()).unwrap();
    assert_eq!(result["ok"], false);
    assert_ne!(
        result["cases"][0]["baseline"],
        result["cases"][0]["candidate"]
    );
}

fn compiled() -> CompiledSourceCatalog {
    compile_addition(&[EXAMPLE], TRUST).unwrap()
}

fn controls(
    output: &CompiledSourceCatalog,
    enabled: bool,
    blocked: bool,
) -> CompiledNativeCommandControls {
    let program = Arc::new(
        NativeCommandProgram::from_packaged_bytes(&serde_json::to_vec(&output.program).unwrap())
            .unwrap(),
    );
    let mut targets = Vec::new();
    if enabled {
        targets.push(serde_json::json!({"target_kind":"extension", "target_id":"command.example-cli", "state":"enabled"}));
    }
    if blocked {
        targets.push(serde_json::json!({"target_kind":"permission", "target_id":"command.example-cli.permission.destroy", "state":"disabled"}));
    }
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":program.program_digest,"catalog_digest":program.catalog_digest,"trust_digest":program.trust_digest,
        "health":"protected","revision":1,"managed_revision":0,"effective_digest":"",
        "layers":[{"schema_version":"1.0.0","kind":"local-admin","catalog_digest":program.catalog_digest,
                   "global_lockdown":false,"controls":targets}],
    })).unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    CompiledNativeCommandControls::for_program(&binding, program).unwrap()
}

#[test]
fn synthetic_extension_needs_only_data_and_existing_native_operations() {
    let output = compiled();
    let extension = output.program["extensions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|extension| extension["extension_id"] == "command.example-cli")
        .unwrap();
    assert_eq!(extension["trust_class"], "external");
    assert_eq!(extension["activation"], "opt-in");
    assert_eq!(
        output.catalog[0]["permissions"][0]["rule_ids"],
        serde_json::json!(["command.example-cli.destroy"])
    );
    let program =
        NativeCommandProgram::from_packaged_bytes(&serde_json::to_vec(&output.program).unwrap())
            .unwrap();
    for (command, enabled, blocked, action, effective_segments) in [
        ("example-cli destroy", false, false, "review", vec![]),
        ("example-cli destroy", true, false, "review", vec![0]),
        ("example-cli inspect", true, false, "review", vec![]),
        (
            "example-cli destroy --dry-run",
            true,
            false,
            "review",
            vec![],
        ),
        (
            "example-cli destroy --dry-run; example-cli destroy",
            true,
            false,
            "review",
            vec![1],
        ),
        ("example-cli destroy", true, true, "block", vec![0]),
        ("example-cli destroy", false, false, "review", vec![]),
    ] {
        let model = parse_command(&CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "native-source-independent-fixture".to_owned(),
        })
        .unwrap();
        let intrinsic = crate::pretool::evaluate_pre_tool_envelope(
            "claude-code",
            "PreToolUse",
            &serde_json::json!({"tool_name":"Bash","tool_input":{"command":command}}),
        );
        // The existing unknown-command floor is independent of this extension.
        // A dry-run variant may remove its owner's evidence, never that floor.
        assert_eq!(
            intrinsic.minimum_action, "review",
            "{command}: intrinsic policy"
        );
        let active = if enabled {
            BTreeSet::from(["command.example-cli".to_owned()])
        } else {
            BTreeSet::new()
        };
        let observed = program.observe(&model, &active, None).unwrap();
        let segments: Vec<_> = observed
            .observations
            .iter()
            .filter(|observation| observation.rule_id == "command.example-cli.destroy")
            .flat_map(|observation| observation.effective_segment_indexes.iter().copied())
            .collect();
        assert_eq!(
            segments, effective_segments,
            "{command}: extension evidence"
        );
        let result = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
            "claude-code",
            "PreToolUse",
            &serde_json::json!({"tool_name":"Bash","tool_input":{"command":command}}),
            Some(&controls(&output, enabled, blocked)),
            None,
        );
        assert_eq!(
            result.minimum_action, action,
            "{command}; enabled={enabled}; blocked={blocked}"
        );
    }
}

#[test]
fn repeated_and_format_only_builds_have_identical_artifacts() {
    let compact = serde_json::to_vec(&serde_json::from_slice::<Value>(EXAMPLE).unwrap()).unwrap();
    let first = serde_json::to_vec(&compiled()).unwrap();
    let second = serde_json::to_vec(&compile_addition(&[&compact], TRUST).unwrap()).unwrap();
    assert_eq!(first, second);
    assert_eq!(first, serde_json::to_vec(&compiled()).unwrap());
}

#[test]
fn rule_ownership_trust_cycles_and_unknown_fields_fail_before_artifact_creation() {
    for mutation in 0..7 {
        let mut source: Value = serde_json::from_slice(EXAMPLE).unwrap();
        let extension = &mut source["extension"];
        match mutation {
            0 => {
                extension["rules"][0]["permission_id"] =
                    serde_json::json!("command.foreign.permission.destroy")
            }
            1 => extension["trust_class"] = serde_json::json!("first-party"),
            2 => extension["dependencies"] = serde_json::json!(["command.missing"]),
            3 => {
                extension["permissions"][0]["implied_permissions"] =
                    serde_json::json!(["command.example-cli.permission.destroy"])
            }
            4 => extension["required"] = Value::Bool(true),
            5 => {
                extension["rules"][0]["matcher"]["op"] = serde_json::json!("arbitrary-callback.v1")
            }
            _ => {
                extension["rules"][0]["native_capability"] =
                    serde_json::json!("command.git.push.v1")
            }
        }
        assert!(
            compile_addition(&[&serde_json::to_vec(&source).unwrap()], TRUST).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn native_implementation_and_source_identity_both_bind_the_program() {
    let first = compiled();
    assert_eq!(
        first.implementation_digest,
        env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION")
    );
    assert_eq!(first.implementation_digest.len(), 64);
    let mut source: Value = serde_json::from_slice(EXAMPLE).unwrap();
    source["extension"]["rules"][0]["matcher"]["config"]["required_arguments"] =
        serde_json::json!(["remove"]);
    let second = compile_addition(&[&serde_json::to_vec(&source).unwrap()], TRUST).unwrap();
    assert_ne!(first.source_digest, second.source_digest);
    assert_ne!(
        first.program["authoring_semantics_digest"],
        second.program["authoring_semantics_digest"]
    );
    assert_ne!(
        first.program["program_digest"],
        second.program["program_digest"]
    );
}

#[test]
fn changed_semantic_authority_rejects_previously_bound_controls() {
    let original = compiled();
    let mut binding: NativeCommandControlBindingV1 = serde_json::from_value(serde_json::json!({
        "schema":"guard.native-command-control-binding.v1",
        "program_digest":original.program["program_digest"],
        "catalog_digest":original.program["catalog_digest"],
        "trust_digest":original.program["trust_digest"],
        "health":"protected","revision":1,"managed_revision":0,"effective_digest":"",
        "layers":[],
    }))
    .unwrap();
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    let mut candidate = original.program;
    // Model an implementation fingerprint change with identical rule/config
    // data. Recompute a valid program identity; do not rely on hash tampering.
    candidate["authoring_semantics_digest"] = serde_json::json!("a".repeat(64));
    candidate.as_object_mut().unwrap().remove("program_digest");
    candidate["program_digest"] = serde_json::json!(digest_canonical_bytes(
        PROGRAM_DOMAIN,
        &serde_json::to_vec(&candidate).unwrap()
    ));
    let program = Arc::new(
        NativeCommandProgram::from_packaged_bytes(&serde_json::to_vec(&candidate).unwrap())
            .unwrap(),
    );
    assert_eq!(
        CompiledNativeCommandControls::for_program(&binding, program).unwrap_err(),
        "native_command_program_binding_mismatch"
    );
}

#[test]
fn source_icons_are_preserved_and_remain_allowlisted() {
    let mut source: Value = serde_json::from_slice(EXAMPLE).unwrap();
    let icon = serde_json::json!({"kind":"react-icon","name":"HiMiniCube","background":"#1D4ED8"});
    source["extension"]["icon"] = icon.clone();
    let output = compile_addition(&[&serde_json::to_vec(&source).unwrap()], TRUST).unwrap();
    assert_eq!(output.catalog[0]["icon"], icon);
    assert_eq!(output.descriptors[0]["icon"], icon);
    source["extension"]["icon"]["name"] = serde_json::json!("UnreviewedComponent");
    assert!(compile_addition(&[&serde_json::to_vec(&source).unwrap()], TRUST).is_err());
    source["extension"]["icon"] = serde_json::json!({"kind":"none","callback":"execute"});
    assert!(compile_addition(&[&serde_json::to_vec(&source).unwrap()], TRUST).is_err());
}

#[test]
fn external_publisher_attribution_is_preserved_without_granting_trust() {
    let mut source: Value = serde_json::from_slice(EXAMPLE).unwrap();
    source["extension"]["publisher"] = serde_json::json!({
        "id":"community.example","display_name":"Example Contributor","url":"https://example.com"
    });
    source["extension"]["homepage"] = serde_json::json!("https://example.com/project");
    source["extension"]["license"] = serde_json::json!("MIT");
    let output = compile_addition(&[&serde_json::to_vec(&source).unwrap()], TRUST).unwrap();
    assert_eq!(
        output.catalog[0]["publisher"]["displayName"],
        "Example Contributor"
    );
    assert_eq!(output.catalog[0]["trust_class"], "external");
    assert_eq!(output.catalog[0]["activation"], "opt-in");
    assert_eq!(
        output.descriptors[0]["homepage"],
        "https://example.com/project"
    );
    assert_eq!(output.descriptors[0]["license"], "MIT");
    source["extension"]["publisher"]["id"] = serde_json::json!("hol");
    assert!(compile_addition(&[&serde_json::to_vec(&source).unwrap()], TRUST).is_err());
}

const FILESYSTEM_MCP: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../contributions/mcp-servers/mcp.filesystem.json"
));
const REMOTE_MCP: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../contributions/mcp-servers/mcp.instapods.json"
));

#[test]
fn canonical_mcp_inputs_preserve_native_fields_and_remain_opt_in() {
    let baseline: Value = serde_json::from_slice(EMBEDDED_PROGRAM).unwrap();
    for bytes in [FILESYSTEM_MCP, REMOTE_MCP] {
        let lowered = mcp::lower(bytes).unwrap();
        let original = baseline["extensions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["extension_id"] == lowered.document.extension.extension_id)
            .unwrap();
        assert_eq!(lowered.wire, original["mcp"]);
        assert_eq!(
            lowered.document.extension.permissions[0].permission_id,
            original["permissions"][0]["permission_id"]
        );
    }
    let mut source: Value = serde_json::from_slice(FILESYSTEM_MCP).unwrap();
    source["id"] = serde_json::json!("mcp.authoring-fixture");
    source["launch"]["package"] = serde_json::json!("@example/offline-authoring-fixture");
    let output =
        compile_addition_with_mcp(&[], &[&serde_json::to_vec(&source).unwrap()], TRUST).unwrap();
    assert_eq!(output.catalog[0]["activation"], "opt-in");
    assert_eq!(
        output.catalog[0]["permissions"][0]["baseline_floor"],
        "review"
    );
    assert_eq!(output.catalog[0]["permissions"][0]["configurable"], false);
    assert!(output.descriptors.is_empty());
    source["launch"]["package"] = serde_json::json!("@modelcontextprotocol/server-filesystem");
    assert!(matches!(
        compile_addition_with_mcp(&[], &[&serde_json::to_vec(&source).unwrap()], TRUST),
        Err("command_source_mcp_package_duplicate")
    ));
}

#[test]
fn canonical_mcp_sources_reject_remote_allow_and_unknown_fields() {
    let mut source: Value = serde_json::from_slice(REMOTE_MCP).unwrap();
    source["tools"][0]["state"] = serde_json::json!("allow");
    assert!(matches!(
        mcp::lower(&serde_json::to_vec(&source).unwrap()),
        Err("command_source_mcp_tool_invalid")
    ));
    source["tools"][0]["state"] = serde_json::json!("review");
    source["launch"]["execute"] = serde_json::json!("callback");
    assert!(matches!(
        mcp::lower(&serde_json::to_vec(&source).unwrap()),
        Err("command_source_mcp_contract_invalid")
    ));
}
