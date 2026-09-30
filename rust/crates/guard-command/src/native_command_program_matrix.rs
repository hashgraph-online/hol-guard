//! Explicit test-only catalog/control diagnostics through admitted code paths.
use super::*;
use crate::native_command_controls::CompiledNativeCommandControls;
use crate::pretool::evaluate_pre_tool_envelope_with_extensions;
use guard_contracts::{NativeCommandControlBindingV1, PreToolResultV1};
use std::hint::black_box;
use std::path::Path;

fn distribution(mut values: Vec<f64>) -> Value {
    values.sort_by(f64::total_cmp);
    serde_json::json!({
        "samples": values.len(), "p50_us": values[(values.len() - 1) / 2],
        "p95_us": values[(95 * values.len()).div_ceil(100) - 1],
        "max_us": values[values.len() - 1],
    })
}

fn evaluate(payload: &Value, controls: Option<&CompiledNativeCommandControls>) -> PreToolResultV1 {
    evaluate_pre_tool_envelope_with_extensions("claude-code", "PreToolUse", payload, controls, None)
}

fn rank(action: &str) -> u8 {
    match action {
        "allow" => 0,
        "monitor" => 1,
        "review" => 2,
        "block" => 3,
        _ => panic!("unknown diagnostic action"),
    }
}

#[test]
#[ignore = "component matrix; generate trusted fixtures and run release mode explicitly"]
fn native_command_catalog_control_matrix() {
    let directory =
        std::env::var("HOL_GUARD_COMMAND_MATRIX_DIR").expect("fixture directory required");
    let directory = Path::new(&directory);
    let bytes = std::fs::read(directory.join("manifest.json")).unwrap();
    assert!(bytes.len() <= 16 * 1024 * 1024);
    let manifest: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        manifest["schema"],
        "guard.native-command-component-matrix.v1"
    );
    assert_eq!(manifest["semantic_profile"], "cpython-3.12-ucd15");
    let samples = manifest["warm_samples"].as_u64().unwrap() as usize;
    assert!((1..=1000).contains(&samples));
    let catalogs = manifest["catalogs"].as_array().unwrap();
    assert_eq!(catalogs.len(), 3);
    for catalog in catalogs {
        let filename = catalog["program_file"].as_str().unwrap();
        assert!(filename.ends_with(".program.json") && !filename.contains(['/', '\\']));
        let bytes = std::fs::read(directory.join(filename)).unwrap();
        assert_eq!(
            bytes.len(),
            catalog["program_bytes"].as_u64().unwrap() as usize
        );
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            catalog["program_sha256"]
        );
        let mut cold = Vec::new();
        for _ in 0..10 {
            let started = Instant::now();
            let program = black_box(NativeCommandProgram::from_packaged_bytes(&bytes).unwrap());
            cold.push(started.elapsed().as_secs_f64() * 1_000_000.0);
            assert_eq!(program.program_digest, catalog["program_digest"]);
            drop(program);
        }
        let program = Arc::new(NativeCommandProgram::from_packaged_bytes(&bytes).unwrap());
        println!(
            "{}",
            serde_json::json!({
                "stage":"catalog_admission", "catalog":catalog["name"],
                "program_digest":program.program_digest, "catalog_digest":program.catalog_digest,
                "extensions":program.extensions.len(), "rules":program.rules.len(),
                "nodes":program.nodes.len(), "program_bytes":bytes.len(), "admission":distribution(cold),
            })
        );
        let mut summary = BTreeMap::<&str, usize>::new();
        for state in catalog["states"].as_array().unwrap() {
            let binding: NativeCommandControlBindingV1 =
                serde_json::from_value(state["binding"].clone()).unwrap();
            binding.validate().unwrap();
            // The two layers and all owned targets must fit together, not just
            // their isolated limits. Leave 16 KiB for the surrounding snapshot.
            let binding_bytes = serde_json::to_vec(&binding).unwrap().len();
            assert!(binding_bytes + 16 * 1024 <= 256 * 1024);
            assert_eq!(
                binding_bytes,
                state["binding_bytes"].as_u64().unwrap() as usize
            );
            let mut compile = Vec::new();
            for _ in 0..samples {
                let started = Instant::now();
                let controls = black_box(
                    CompiledNativeCommandControls::for_program(&binding, program.clone()).unwrap(),
                );
                compile.push(started.elapsed().as_secs_f64() * 1_000_000.0);
                drop(controls);
            }
            let controls =
                CompiledNativeCommandControls::for_program(&binding, program.clone()).unwrap();
            println!(
                "{}",
                serde_json::json!({
                    "stage":"control_admission", "catalog":catalog["name"], "state":state["name"],
                    "controls":state["controls"], "binding_bytes":binding_bytes, "admission":distribution(compile),
                })
            );
            for case in state["cases"].as_array().unwrap() {
                let source = case["command"].as_str().unwrap();
                let payload =
                    serde_json::json!({"tool_name":"Bash", "tool_input":{"command":source}});
                let model = crate::parse_command(
                    &serde_json::from_value(serde_json::json!({"command":source})).unwrap(),
                )
                .unwrap();
                let baseline = evaluate(&payload, None);
                let expected = evaluate(&payload, Some(&controls));
                let candidates = program.candidate_rule_indices(&model);
                let declarative_candidates = candidates
                    .iter()
                    .filter(|index| program.rules[**index].matcher.is_some())
                    .count();
                let observations = expected.command_extensions.as_ref().unwrap();
                assert!(observations.evaluation_error.is_none(), "{source}");
                let declarative: Vec<_> = observations
                    .observations
                    .iter()
                    .filter(|item| {
                        program.rules[program.rule_indices[&item.rule_id]]
                            .matcher
                            .is_some()
                    })
                    .collect();
                assert_eq!(
                    serde_json::to_value(declarative).unwrap(),
                    case["python_declarative_observations"],
                    "{} / {} / {source}",
                    catalog["name"],
                    state["name"]
                );
                let mut durations = Vec::new();
                for _ in 0..samples {
                    let started = Instant::now();
                    let actual =
                        black_box(evaluate(black_box(&payload), Some(black_box(&controls))));
                    durations.push(started.elapsed().as_secs_f64() * 1_000_000.0);
                    assert_eq!(actual.minimum_action, expected.minimum_action);
                    assert_eq!(actual.reason_code, expected.reason_code);
                    assert_eq!(
                        actual.command_extensions.as_ref().unwrap().binding,
                        observations.binding
                    );
                }
                let native_rank = rank(&expected.minimum_action);
                let intrinsic_rank = rank(&baseline.minimum_action);
                let python_rank = rank(case["python_minimum_action"].as_str().unwrap());
                let benign = case["intent"] == "benign";
                let ordinary_controls = matches!(
                    state["name"].as_str().unwrap(),
                    "defaults" | "local-opt-in" | "managed-only"
                );
                let false_review = benign && ordinary_controls && native_rank >= rank("review");
                for (key, applies) in [
                    ("rows", true),
                    ("native_above_python_reference", native_rank > python_rank),
                    ("native_below_python_reference", native_rank < python_rank),
                    (
                        "benign_restricted_all_control_states",
                        benign && native_rank >= rank("review"),
                    ),
                    ("benign_ordinary_control_rows", benign && ordinary_controls),
                    ("false_review_or_block_ordinary_controls", false_review),
                    (
                        "benign_extension_strengthened",
                        benign && native_rank > intrinsic_rank,
                    ),
                    (
                        "new_false_review_or_block_from_extensions",
                        false_review && intrinsic_rank < rank("review"),
                    ),
                ] {
                    *summary.entry(key).or_default() += usize::from(applies);
                }
                println!(
                    "{}",
                    serde_json::json!({
                        "stage":"warm_catalog_control", "catalog":catalog["name"], "state":state["name"],
                        "command":source, "intent":case["intent"], "controls":state["controls"],
                    "candidate_rules":candidates.len(), "declarative_candidate_rules":declarative_candidates,
                        "python_candidates":case["python_candidates"], "rules":program.rules.len(),
                        "native_minimum_action":expected.minimum_action, "native_reason":expected.reason_code,
                        "intrinsic_native_minimum_action":baseline.minimum_action,
                        "python_minimum_action":case["python_minimum_action"],
                        "python_reference_scope":case["python_reference_scope"],
                    "false_review_or_block":false_review, "declarative_observation_parity":true,
                    "extension_strengthened_intrinsic":native_rank > intrinsic_rank,
                        "observation_count":observations.binding.observation_count,
                        "uncertainty_count":observations.binding.uncertainty_count,
                        "python_observe":case["python_observe"], "native_pretool_evaluate":distribution(durations),
                    })
                );
            }
        }
        println!(
            "{}",
            serde_json::json!({"stage":"catalog_outcomes", "catalog":catalog["name"], "counts":summary})
        );
    }
}
