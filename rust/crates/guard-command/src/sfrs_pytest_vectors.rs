//! Parity of the pytest target, binary-safety and config helpers against
//! recorded Python output. The fixture holds a directory tree and cases whose
//! paths carry a `{ROOT}` token; the tree is rebuilt below a fresh root.
//! Cases that reach the inline-Python AST oracle are tagged `approx` and
//! compared with `rust >= python` (the port over-approximates, fail-closed).

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::symlink;
use std::path::Path;

use serde_json::{json, Value};

use crate::codex_output_env::Ctx;
use crate::codex_output_py::PyPath;
use crate::sfrs_fs_vectors::Scratch;
use crate::sfrs_pytest_binary as bin;
use crate::sfrs_pytest_config::{
    assess_pytest_configs, assess_selected_pytest_config, combine_pytest_config_assessments,
    parse_pytest_config, PytestConfigAssessment, PytestConfigParseResult,
};
use crate::sfrs_pytest_config_safety as safety;
use crate::sfrs_pytest_config_search as search;
use crate::sfrs_pytest_env as env;
use crate::sfrs_pytest_target as target;
use crate::sfrs_pytest_wrappers as wrappers;
use crate::sfrs_shell_tokens::split_shell_parts;
use crate::sfrs_token_vectors::NoEnvHost;

const TOKEN: &str = "{ROOT}";

fn fixture() -> Value {
    let bytes = include_bytes!("../tests/fixtures/sfrs/pytest_helpers.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    serde_json::from_str(&text).expect("json")
}

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn build_tree(document: &Value) -> Scratch {
    build_tree_in(document, "sfrs-pytest")
}

/// Rebuild the recorded tree under a fresh root named after `prefix`.
pub(crate) fn build_tree_in(document: &Value, prefix: &str) -> Scratch {
    let base = fs::canonicalize(std::env::temp_dir()).expect("temp dir");
    let root = base.join(format!("{prefix}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("root");
    let tree = &document["tree"];
    let put = |name: &str, bytes: Vec<u8>| {
        let path = root.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("parent");
        fs::write(path, bytes).expect("file");
    };
    for name in tree["dirs"].as_array().expect("dirs") {
        fs::create_dir_all(root.join(name.as_str().expect("dir"))).expect("dir");
    }
    for (name, spec) in tree["files"].as_object().expect("files") {
        let bytes = match spec.as_str() {
            Some(text) => text.as_bytes().to_vec(),
            None => spec["repeat"]
                .as_str()
                .expect("repeat")
                .repeat(spec["count"].as_u64().expect("count") as usize)
                .into_bytes(),
        };
        put(name, bytes);
    }
    for (name, hexed) in tree["hexfiles"].as_object().expect("hexfiles") {
        put(name, hex_bytes(hexed.as_str().expect("hex")));
    }
    for (name, link) in tree["links"].as_object().expect("links") {
        let path = root.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("parent");
        symlink(link.as_str().expect("target"), path).expect("link");
    }
    Scratch(root)
}

pub(crate) fn bind(root: &Path, value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace(TOKEN, &root.to_string_lossy())),
        Value::Array(items) => items.iter().map(|item| bind(root, item)).collect(),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), bind(root, item)))
                .collect(),
        ),
        other => other.clone(),
    }
}

pub(crate) fn text(value: &Value) -> &str {
    value.as_str().expect("string argument")
}

pub(crate) fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("list argument")
        .iter()
        .map(|item| text(item).to_owned())
        .collect()
}

fn cwd(value: &Value) -> Option<&Path> {
    value.as_str().map(Path::new)
}

fn optional<T: Into<Value>>(value: Option<T>) -> Value {
    value.map_or(Value::Null, Into::into)
}

fn result_json(result: &PytestConfigParseResult) -> Value {
    let value = result.value.as_ref().map(|value| {
        let mut options: Vec<Value> = value
            .execution_options
            .iter()
            .map(|(key, item)| json!([key, item]))
            .collect();
        options.sort_by_key(Value::to_string);
        json!({
            "addopts": value.addopts,
            "log_file": value.log_file,
            "execution_options": options,
            "unsafe": value.unsafe_options,
        })
    });
    json!({
        "source_path": result.source_path,
        "present": result.present,
        "value": value,
        "complete": result.complete,
        "reason_code": result.reason_code,
        "content_sha256": result.content_sha256,
    })
}

pub(crate) fn assessment_json(assessment: &PytestConfigAssessment) -> Value {
    json!({
        "results": assessment.results.iter().map(result_json).collect::<Vec<_>>(),
        "complete": assessment.complete,
        "unsafe": assessment.unsafe_options,
        "reason_codes": assessment.reason_codes,
        "identity_sha256": assessment.identity_sha256,
    })
}

/// Sort the `execution_options` pair lists of a recorded result the same way.
pub(crate) fn normalize(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                if key == "execution_options" {
                    if let Some(items) = item.as_array_mut() {
                        items.sort_by_key(Value::to_string);
                    }
                }
                normalize(item);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(normalize),
        _ => {}
    }
}

fn combine(spec: &Value) -> Value {
    let workspaces = strings(&spec["workspaces"]);
    let rels = spec["rels"].as_array().expect("rels");
    let modes = strings(&spec["modes"]);
    let picked: Vec<PytestConfigAssessment> = spec["indexes"]
        .as_array()
        .expect("indexes")
        .iter()
        .map(|index| {
            let at = index.as_u64().expect("index") as usize;
            let workspace = Path::new(&workspaces[at]);
            let paths = strings(&rels[at]);
            match modes[at].as_str() {
                "all" => assess_pytest_configs(workspace, &paths, false),
                "require" => assess_pytest_configs(workspace, &paths, true),
                _ => assess_selected_pytest_config(workspace, &paths),
            }
        })
        .collect();
    assessment_json(&combine_pytest_config_assessments(&picked))
}

fn run_config(function: &str, a: &[Value]) -> Option<Value> {
    Some(match function {
        "parse_pytest_config" => {
            result_json(&parse_pytest_config(Path::new(text(&a[0])), text(&a[1])))
        }
        "assess_pytest_configs" => assessment_json(&assess_pytest_configs(
            Path::new(text(&a[0])),
            &strings(&a[1]),
            a[2].as_bool().expect("flag"),
        )),
        "assess_selected_pytest_config" => assessment_json(&assess_selected_pytest_config(
            Path::new(text(&a[0])),
            &strings(&a[1]),
        )),
        "combine_pytest_config_assessments" => combine(&a[0]),
        "pytest_config_assessment" => assessment_json(&search::pytest_config_assessment(
            Path::new(text(&a[0])),
            &strings(&a[1]),
        )),
        "pytest_explicit_config_paths" => optional(search::pytest_explicit_config_paths(
            &strings(&a[0]),
            Path::new(text(&a[1])),
        )),
        "pytest_config_search_dirs" => optional(search::pytest_config_search_dirs(
            &strings(&a[0]),
            Path::new(text(&a[1])),
        )),
        "pytest_selected_relative_path" => optional(search::pytest_selected_relative_path(
            text(&a[0]),
            Path::new(text(&a[1])),
        )),
        "pytest_config_ancestor_dirs" => {
            search::pytest_config_ancestor_dirs(&PyPath::new(text(&a[0]))).into()
        }
        "pytest_positional_args" => search::pytest_positional_args(&strings(&a[0])).into(),
        "pytest_config_may_add_unsafe_options" => {
            safety::pytest_config_may_add_unsafe_options(cwd(&a[0]), &strings(&a[1])).into()
        }
        _ => return None,
    })
}

fn run_safety(function: &str, a: &[Value]) -> Option<Value> {
    Some(match function {
        "python_module_root_from_args" => {
            optional(safety::python_module_root_from_args(&strings(&a[0])))
        }
        "shell_args_without_trailing_redirections" => {
            safety::shell_args_without_trailing_redirections(&strings(&a[0])).into()
        }
        "python_segment_runs_safe_module_nocwd" => {
            safety::python_segment_runs_safe_module(&strings(&a[0]), None).into()
        }
        "python_segment_runs_safe_module" => {
            safety::python_segment_runs_safe_module(&strings(&a[0]), cwd(&a[1])).into()
        }
        "python_module_unsafe_env_keys" => {
            let mut keys = safety::python_module_unsafe_env_keys(a[0].as_str());
            keys.sort_unstable();
            keys.into()
        }
        "is_shell_redirection_token" => safety::is_shell_redirection_token(text(&a[0])).into(),
        "pytest_module_args_are_safe" => {
            safety::pytest_module_args_are_safe(&strings(&a[0])).into()
        }
        "python_module_subcommand" => optional(safety::python_module_subcommand(
            text(&a[0]),
            &strings(&a[1]),
        )),
        "python_module_args_are_safe" => {
            safety::python_module_args_are_safe(text(&a[0]), &strings(&a[1]), cwd(&a[2])).into()
        }
        "ruff_format_target_is_bounded" => {
            safety::ruff_format_target_is_bounded(&strings(&a[0]), cwd(&a[1])).into()
        }
        "python_module_may_be_shadowed" => {
            let path = a[1].as_str().map(PyPath::new);
            env::python_module_may_be_shadowed(text(&a[0]), path.as_ref()).into()
        }
        "python_module_may_be_shadowed_from_execution_context" => {
            safety::python_module_may_be_shadowed_from_execution_context(
                a[0].as_str(),
                cwd(&a[1]),
                &strings(&a[2]),
                a[3].as_u64().expect("index") as usize,
            )
            .into()
        }
        "pythonpath_search_roots" => safety::pythonpath_search_roots_from_segment(
            &strings(&a[1]),
            a[2].as_u64().expect("index") as usize,
            cwd(&a[0]),
        )
        .iter()
        .map(PyPath::to_string)
        .collect::<Vec<_>>()
        .into(),
        "shell_env_assignment_key" => optional(env::shell_env_assignment_key(text(&a[0]))),
        "shell_segment_sets_env_key" => env::shell_segment_sets_env_key(
            &strings(&a[0]),
            a[1].as_u64().expect("index") as usize,
            text(&a[2]),
        )
        .into(),
        "shell_segment_explicit_env_value" => {
            let (set, value, complete) = env::shell_segment_explicit_env_value(
                &strings(&a[0]),
                a[1].as_u64().expect("index") as usize,
                text(&a[2]),
            );
            json!([set, value, complete])
        }
        _ => return None,
    })
}

fn index(value: &Value) -> usize {
    value.as_u64().expect("index") as usize
}

fn run_target(function: &str, a: &[Value], ctx: &Ctx) -> Option<Value> {
    Some(match function {
        "shell_token_has_active_glob" => target::shell_token_has_active_glob(text(&a[0])).into(),
        "shell_command_targets_pytest" => {
            target::shell_command_targets_pytest(text(&a[0]), 0).into()
        }
        "segment_targets_pytest" => {
            target::segment_targets_pytest(&strings(&a[0]), text(&a[1]), index(&a[2]), 0).into()
        }
        "python_inline_script_runs_pytest_parts" | "python_inline_script_runs_pytest" => {
            target::python_inline_script_runs_pytest(&strings(&a[0])).into()
        }
        "pytest_args_from_argument_sequence" => {
            optional(target::pytest_args_from_argument_sequence(&strings(&a[0])))
        }
        "argument_sequence_targets_pytest" => {
            target::argument_sequence_targets_pytest(&strings(&a[0])).into()
        }
        "pytest_args_from_command_position" => optional(target::pytest_args_from_command_position(
            &strings(&a[0]),
            index(&a[1]),
        )),
        "pytest_args_from_runner_argument_sequence" => optional(
            target::pytest_args_from_runner_argument_sequence(text(&a[0]), &strings(&a[1])),
        ),
        "pytest_args_from_argument_sequence_ignoring" => {
            let ignored: Vec<usize> = a[1]
                .as_array()
                .expect("ignored")
                .iter()
                .map(index)
                .collect();
            optional(target::pytest_args_from_argument_sequence_ignoring(
                &strings(&a[0]),
                &ignored,
            ))
        }
        "inline_python_payload_runs_pytest" => {
            target::inline_python_payload_runs_pytest(text(&a[0]), 0).into()
        }
        _ => return run_binary(function, a, ctx),
    })
}

fn run_binary(function: &str, a: &[Value], ctx: &Ctx) -> Option<Value> {
    let parts = || split_shell_parts(text(&a[0]));
    Some(match function {
        "is_literal_cat_heredoc_to_stdout" => {
            bin::is_literal_cat_heredoc_to_stdout(text(&a[0])).into()
        }
        "contains_pytest_process_substitution" => {
            bin::contains_pytest_process_substitution(text(&a[0]), &parts()).into()
        }
        "contains_prior_pytest_state_mutation" => {
            bin::contains_prior_pytest_state_mutation(&parts()).into()
        }
        "contains_unsafe_pytest_environment_wrapper" => {
            bin::contains_unsafe_pytest_environment_wrapper(&parts()).into()
        }
        "looks_like_safe_python_module_invocation" => {
            bin::looks_like_safe_python_module_invocation(&parts(), cwd(&a[1]), ctx).into()
        }
        "looks_like_bounded_python_script_invocation" => {
            bin::looks_like_bounded_python_script_invocation(&parts(), cwd(&a[1]), ctx).into()
        }
        "looks_like_supported_python_invocation" => {
            bin::looks_like_supported_python_invocation(&parts(), cwd(&a[1]), ctx).into()
        }
        "looks_like_safe_pytest_binary_invocation" => {
            bin::looks_like_safe_pytest_binary_invocation(&parts(), cwd(&a[1]), ctx).into()
        }
        "bounded_python_script_path" => optional(
            bin::bounded_python_script_path(&strings(&a[0]), Path::new(text(&a[1])), ctx)
                .map(|path| path.to_string_lossy().into_owned()),
        ),
        "pytest_binary_segment_is_safe" => {
            bin::pytest_binary_segment_is_safe(text(&a[0]), &strings(&a[1]), cwd(&a[2])).into()
        }
        "shell_declared_env_key" => bin::shell_declared_env_key(text(&a[0])).into(),
        "shell_declaration_exports_env" => {
            bin::shell_declaration_exports_env(&strings(&a[0])).into()
        }
        "shell_set_exports_assignments" => {
            bin::shell_set_exports_assignments(&strings(&a[0])).into()
        }
        "shell_directory_setup_segment_is_safe" => {
            wrappers::shell_directory_setup_segment_is_safe(text(&a[0]), &strings(&a[1])).into()
        }
        "shell_segment_uses_env_split_string_wrapper" => {
            wrappers::shell_segment_uses_env_split_string_wrapper(&strings(&a[0]), index(&a[1]))
                .into()
        }
        "shell_segment_uses_env_chdir" => {
            wrappers::shell_segment_uses_env_chdir(&strings(&a[0]), index(&a[1])).into()
        }
        "shell_segment_uses_sudo_chdir" => {
            wrappers::shell_segment_uses_sudo_chdir(&strings(&a[0]), index(&a[1])).into()
        }
        "shell_segment_uses_cwd_changing_wrapper" => {
            wrappers::shell_segment_uses_cwd_changing_wrapper(&strings(&a[0]), index(&a[1])).into()
        }
        _ => return None,
    })
}

fn run(function: &str, args: &[Value], ctx: &Ctx) -> Option<Value> {
    run_config(function, args)
        .or_else(|| run_safety(function, args))
        .or_else(|| run_target(function, args, ctx))
}

/// An approximate case passes when Rust is at least as cautious as Python:
/// wherever Python found pytest (true or a value) Rust must too, and agree.
fn approx_ok(actual: &Value, expected: &Value) -> bool {
    match expected {
        Value::Bool(false) | Value::Null => true,
        _ => actual == expected,
    }
}

#[test]
fn pytest_helpers_match_recorded_python() {
    let document = fixture();
    let scratch = build_tree(&document);
    let root = scratch.0.clone();
    let host = NoEnvHost;
    let ctx = Ctx::new(&host, "/", &root.to_string_lossy());
    let mut failures = Vec::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for case in document["cases"].as_array().expect("cases") {
        let function = case["fn"].as_str().expect("fn");
        let args = bind(&root, &case["args"]);
        let mut expected = bind(&root, &case["result"]);
        normalize(&mut expected);
        let Some(mut actual) = run(function, args.as_array().expect("args"), &ctx) else {
            failures.push(format!("unhandled function {function}"));
            continue;
        };
        normalize(&mut actual);
        *counts.entry(function.to_owned()).or_default() += 1;
        let approx = case["approx"].as_bool().unwrap_or(false);
        let same = if approx {
            approx_ok(&actual, &expected)
        } else {
            actual == expected
        };
        if !same {
            failures.push(format!("{function} {args}: {actual} vs {expected}"));
        }
    }
    assert!(counts.len() >= 50, "too few functions: {counts:?}");
    let failures =
        crate::sfrs_host_divergence::portable_failures(failures, &[("/cfg/py_upper_suffix\"", 9)]);
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(12)]
    );
}
