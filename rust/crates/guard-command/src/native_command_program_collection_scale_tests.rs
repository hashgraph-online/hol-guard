//! Semantic fixtures through production pack compilation/admission, not installed proof.
use super::*;
use crate::native_command_program::authored_test_support::{sources, stream, trust_map};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

fn synthetic(index: usize) -> (Value, Vec<u8>) {
    let id = format!("command.semantic-scale-{index}");
    let text = include_str!("../tests/fixtures/command-source-example.v1.json")
        .replace("command.example-cli", &id)
        .replace("example-cli", &format!("semantic-scale-{index}"));
    let mut document: Value = serde_json::from_str(&text).unwrap();
    let shared = json!({"op":"arguments.v1", "config":{
        "executables":["scale-shared"],"required_arguments":["destroy"]}});
    let unique = json!({"op":"arguments.v1", "config":{
        "executables":[format!("semantic-scale-{index}")],
        "required_arguments":[format!("--target-{index}")]}});
    let global = json!({"op":"any.v1","config":{},"matchers":[
        {"op":"trailing-operand-prefix.v1", "config":{
            "executables":["scale-shared","unrelated"],"minimum_operands":1,
            "operand_prefixes":["danger:"]}},
        {"op":"zero-operand-flags.v1","config":{
            "executables":["scale-shared","unrelated"],"required_flags":["--global"],
            "options_with_values":[]}}
    ]});
    let indexed = json!({"op":"any.v1","config":{},"matchers":[shared.clone(),unique]});
    let template = document["extension"]["rules"][0].clone();
    let mut rules = Vec::new();
    for (suffix, matcher) in [
        ("indexed", indexed),
        ("global", global.clone()),
        (
            "overlap",
            json!({"op":"any.v1","config":{},"matchers":[shared,global]}),
        ),
    ] {
        let mut rule = template.clone();
        rule["rule_id"] = json!(format!("{id}.{suffix}"));
        rule["matcher"] = matcher;
        // Safe variants share a compiler-interned node across different packs.
        rule["safe_variants"][0]["matcher"] = json!({"op":"arguments.v1", "config":{
            "executables":["scale-shared"],"required_arguments":["--dry-run"]}});
        rules.push(rule);
    }
    document["extension"]["rules"] = json!(rules);
    document["extension"]["executables"] =
        json!(["scale-shared", format!("semantic-scale-{index}")]);
    let mut trust = trust_map();
    trust["classes"]["external"] = json!([id]);
    (
        json!({"kind":"command","trust":trust}),
        serde_json::to_vec(&document).unwrap(),
    )
}

struct Release {
    root: Vec<u8>,
    digest: String,
    objects: BTreeMap<String, Vec<u8>>,
}

impl Release {
    fn compile(sources: &[(Value, Vec<u8>)]) -> Self {
        let mut bytes = Vec::new();
        let root = source::compile_pack_stream(stream(sources).as_slice(), &mut bytes).unwrap();
        assert_eq!(root["extensions"], sources.len());
        let objects: BTreeMap<_, _> = bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                let row: Value = serde_json::from_slice(line).unwrap();
                let data = STANDARD.decode(row["data"].as_str().unwrap()).unwrap();
                assert_eq!(row["length"], data.len());
                assert!(data.len() <= 64 * 1024);
                (row["sha256"].as_str().unwrap().to_owned(), data)
            })
            .collect();
        let root = serde_json::to_vec(&root).unwrap();
        Self {
            digest: hex::encode(Sha256::digest(&root)),
            root,
            objects,
        }
    }

    fn selected(&self, ids: &BTreeSet<String>) -> (NativeCommandProgram, usize) {
        // Count actual canonical selected IR bytes, independently of index-page growth.
        let mut reader =
            source::PackReleaseReuse::from_bytes(&self.root, &self.digest, |digest: &str| {
                self.objects.get(digest).cloned().ok_or("missing")
            })
            .unwrap();
        let selected_bytes = ids
            .iter()
            .map(|id| {
                let pack = reader.read(id, None).unwrap().unwrap();
                assert_eq!(pack.program["extensions"].as_array().unwrap().len(), 1);
                canonical_json_bytes(&pack.program).unwrap().len()
            })
            .sum();
        let program = NativeCommandProgram::from_integrity_bound_packs(
            &self.root,
            &self.digest,
            ids,
            PackAdmissionBudget::resident(),
            |digest| self.objects.get(digest).cloned().ok_or("missing"),
        )
        .unwrap();
        assert_eq!(
            program
                .extensions
                .iter()
                .map(|e| e.extension_id.clone())
                .collect::<BTreeSet<_>>(),
            *ids
        );
        (program, selected_bytes)
    }
}

fn command(text: &str) -> CanonicalCommandV1 {
    crate::parse_command(&serde_json::from_value(json!({"command":text})).unwrap()).unwrap()
}

fn replay(program: &NativeCommandProgram, active: &BTreeSet<String>, text: &str) -> Value {
    let model = command(text);
    let dispatch = CommandCandidateIndex::for_active(program, active);
    let candidates = dispatch.candidates(&model);
    // Native observation rejects unsupported models before dispatch. Running only
    // declarative matchers on them invents unrelated matcher-failure observations.
    if let Err(error) = crate::command_compatibility::compatibility_observations(&model, None) {
        let actual = program.observe_in_with_dispatch(
            &model,
            active,
            None,
            crate::pretool::PathContext::default(),
            None,
            Some(&dispatch),
        );
        assert_eq!(actual.unwrap_err(), error, "{text}");
        assert_eq!(error, "native_command_compatibility_model_unsupported");
        return json!({"command":text,"candidates":candidates.len(),
            "active_nodes":dispatch.memo_layout.active_node_count(),
            "observations":0,"error":error});
    }
    // The oracle deliberately visits EVERY rule, bypassing both candidate indexes
    // and the active memo layout. Equality includes evidence, safe variants and segments.
    let expected =
        program.observe_declarative_selected(&model, active, None, 0..program.rules.len());
    let actual = program.observe_declarative_memo(
        &model,
        active,
        None,
        candidates.clone(),
        Some(Arc::clone(&dispatch.memo_layout)),
    );
    assert_eq!(actual, expected, "{text}");
    let observations = actual
        .as_ref()
        .map(|batch| batch.observations.len())
        .unwrap_or(0);
    json!({"command":text,"candidates":candidates.len(),
        "active_nodes":dispatch.memo_layout.active_node_count(),
        "observations":observations,"error":actual.err()})
}

fn binding(
    program: &NativeCommandProgram,
    enabled: bool,
) -> guard_contracts::NativeCommandControlBindingV1 {
    let mut binding = guard_contracts::NativeCommandControlBindingV1 {
        schema: guard_contracts::NATIVE_COMMAND_CONTROL_BINDING_SCHEMA.into(),
        authority: None,
        active_security_digest: None,
        program_digest: program.program_digest.clone(),
        catalog_digest: program.catalog_digest.clone(),
        trust_digest: program.trust_digest.clone(),
        health: "protected".into(),
        revision: 1,
        managed_revision: 0,
        effective_digest: String::new(),
        layers: vec![],
    };
    if enabled {
        binding
            .layers
            .push(guard_contracts::NativeExtensionControlLayerV1 {
                schema_version: "1.0.0".into(),
                kind: "local-admin".into(),
                catalog_digest: program.catalog_digest.clone(),
                global_lockdown: false,
                controls: vec![guard_contracts::NativeExtensionControlV1 {
                    target_kind: "extension".into(),
                    target_id: "command.mcp-filesystem".into(),
                    state: "enabled".into(),
                }],
            });
    }
    binding.effective_digest = binding.compute_effective_digest().unwrap();
    binding
}

fn defaults_and_mcp(program: Arc<NativeCommandProgram>) {
    use crate::native_command_controls::CompiledNativeCommandControls;
    for enabled in [false, true] {
        let controls = CompiledNativeCommandControls::for_program(
            &binding(&program, enabled),
            Arc::clone(&program),
        )
        .unwrap();
        for (tool, expected) in [
            (
                "mcp__filesystem__write_file",
                if enabled { "block" } else { "review" },
            ),
            ("mcp__unowned__write_file", "review"),
        ] {
            let result = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
                "claude-code",
                "PreToolUse",
                &json!({"tool_name":tool,"tool_input":{"path":"fixture.txt","content":"redact-this"}}),
                Some(&controls),
                None,
            );
            assert_eq!(result.minimum_action, expected);
            let batch = result.command_extensions.unwrap();
            assert_eq!(
                !batch.permission_observations.is_empty(),
                enabled && tool.contains("filesystem")
            );
            let encoded = serde_json::to_string(&batch).unwrap();
            assert!(!encoded.contains("fixture.txt") && !encoded.contains("redact-this"));
        }
        let result = crate::pretool::evaluate_pre_tool_envelope_with_extensions(
            "claude-code",
            "PreToolUse",
            &json!({"command":"scale-shared destroy danger:item"}),
            Some(&controls),
            None,
        );
        assert!(result
            .command_extensions
            .unwrap()
            .observations
            .iter()
            .all(|item| !item.extension_id.starts_with("command.semantic-scale-")));
    }
}

#[test]
fn fixed_selection_is_identical_across_1x_10x_100x_unique_catalogs() {
    let mut authored = sources();
    authored.extend((0..3).map(synthetic));
    let baseline = authored.len();
    let source = source();
    let mut ids = defaults(&source);
    ids.insert("command.mcp-filesystem".into());
    ids.extend((0..3).map(|index| format!("command.semantic-scale-{index}")));
    let mut reference = None;
    for multiplier in [1, 10, 100] {
        let mut catalog = authored.clone();
        catalog.extend((3..3 + baseline * (multiplier - 1)).map(synthetic));
        assert_eq!(catalog.len(), baseline * multiplier);
        let release = Release::compile(&catalog);
        let (program, bytes) = release.selected(&ids);
        let program = Arc::new(program);
        let mut metrics = Vec::new();
        for text in [
            "git status",
            "git reset --hard",
            "rm -rf /tmp/fixture",
            "scale-shared destroy danger:item",
            "unrelated danger:item",
            "semantic-scale-1 --target-1",
            "scale-shared destroy --dry-run",
            "scale-shared destroy --dry-run; scale-shared destroy danger:item",
            "timeout 30 scale-shared destroy danger:item",
            "env SAFE=1 sh -c 'scale-shared destroy --dry-run; scale-shared destroy danger:item'",
            "sudo -n scale-shared destroy danger:item && git clean -fd",
            "scale-shared destroy | cat",
        ] {
            let metric = replay(&program, &ids, text);
            if text.starts_with("env SAFE=") {
                assert_eq!(
                    metric["error"],
                    "native_command_compatibility_model_unsupported"
                );
            } else {
                assert!(metric["error"].is_null(), "{metric}");
            }
            metrics.push(metric);
        }
        defaults_and_mcp(Arc::clone(&program));
        let inventory = json!({"program":program.program_digest,"catalog":program.catalog_digest,
            "trust":program.trust_digest,"selected_bytes":bytes,"extensions":program.extensions.len(),
            "rules":program.rules.len(),"nodes":program.nodes.len(),"replay":metrics});
        if let Some(expected) = &reference {
            assert_eq!(&inventory, expected);
        } else {
            reference = Some(inventory.clone());
        }
        eprintln!(
            "semantic_scale_fixed {}",
            json!({"multiplier":multiplier,"catalog_extensions":catalog.len(),
            "objects":release.objects.len(),"object_bytes":release.objects.values().map(Vec::len).sum::<usize>(),
            "root_sha256":release.digest,"selected":inventory})
        );
    }
}

#[test]
fn growing_selection_matches_exhaustive_rules_beyond_legacy_limits() {
    let mut catalog = sources();
    catalog.extend((0..1100).map(synthetic));
    let release = Release::compile(&catalog);
    let base = defaults(&source());
    let mut previous = None;
    for count in [1, 513, 1100] {
        let mut ids = base.clone();
        ids.extend((0..count).map(|index| format!("command.semantic-scale-{index}")));
        let (program, bytes) = release.selected(&ids);
        let shared: BTreeSet<_> = program
            .rules
            .iter()
            .filter(|rule| {
                program.extensions[rule.extension_index]
                    .extension_id
                    .starts_with("command.semantic-scale-")
            })
            .flat_map(|rule| rule.variants.iter().map(|(_, index)| *index))
            .collect();
        assert_eq!(
            shared.len(),
            1,
            "identical safe node must be interned across packs"
        );
        assert!(
            program.unindexed.len() >= 2 * count,
            "global and overlapping unindexed rules were lost"
        );
        if count >= 513 {
            assert!(program.extensions.len() > 512 && program.rules.len() > MAX_RULES);
        }
        let mut metrics = Vec::new();
        for text in [
            "git status".to_owned(),
            format!("semantic-scale-{} --target-{}", count - 1, count - 1),
            "unrelated danger:item".into(),
            "scale-shared destroy".into(),
            "env SAFE=1 sh -c 'scale-shared destroy --dry-run; scale-shared destroy danger:item'"
                .into(),
        ] {
            metrics.push(replay(&program, &ids, &text));
        }
        assert!(metrics[0]["error"].is_null() && metrics[1]["error"].is_null());
        if count < 1100 {
            assert_eq!(metrics[2]["observations"], 2 * count);
        }
        if count == 1100 {
            // Exact operation budgets stay fixed: overlapping matches must fail closed.
            assert_eq!(
                metrics[2]["error"],
                "native_command_evidence_limit_exceeded"
            );
            assert_eq!(
                metrics[3]["error"],
                "native_command_evidence_limit_exceeded"
            );
        }
        let work = metrics[0]["candidates"].as_u64().unwrap();
        if let Some(previous) = previous {
            assert!(work > previous);
        }
        previous = Some(work);
        eprintln!(
            "semantic_scale_active {}",
            json!({"synthetic_active":count,"selected_bytes":bytes,
            "extensions":program.extensions.len(),"rules":program.rules.len(),"nodes":program.nodes.len(),
            "program_digest":program.program_digest,"replay":metrics})
        );
    }
    assert_eq!(
        (MAX_PROGRAM_BYTES, MAX_RULES, MAX_NODES),
        (6 * 1024 * 1024, 1024, 16384)
    );
    assert_eq!(
        (
            MAX_NATIVE_COMMAND_OBSERVATIONS,
            MAX_NATIVE_COMMAND_EVIDENCE_ITEMS
        ),
        (2048, 8192)
    );
}
