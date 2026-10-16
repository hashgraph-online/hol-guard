//! Parity of the interpreter launch, identity, trust and observer helpers
//! against recorded Python output. The fixture holds a directory tree plus the
//! host facts the Python run depended on: the deterministic executable
//! identities each case requested, `sys.executable`, the environment and the
//! reuse nonce. Paths carry a `{ROOT}` token bound to a fresh tree.
//!
//! Cases tagged `approx` reached the inline-Python oracle, which the port
//! over-approximates; they pass when equal or when Rust is stricter.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::Path;

use serde_json::{json, Value};

use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};
use crate::codex_output_py::PyPath;
use crate::sfrs_interpreter_heredoc as heredoc;
use crate::sfrs_interpreter_identity::{python_interpreter_executable_identities, IdentityInputs};
use crate::sfrs_interpreter_launch::{self as launch, Environment, ShellLaunchCandidate};
use crate::sfrs_interpreter_observers as obs;
use crate::sfrs_interpreter_trust as trust;
use crate::sfrs_pytest_vectors::{assessment_json, bind, build_tree_in, normalize, strings, text};
use crate::shell_execution_context::model_shell_execution_context;

type CallKey = (String, Option<String>, String);

/// Replays the host facts of one recorded case.
struct CaseHost {
    environment: Vec<(String, String)>,
    guard: String,
    nonce: String,
    calls: HashMap<CallKey, Value>,
}

impl InspectionHost for CaseHost {
    fn env(&self, name: &str) -> Option<String> {
        self.environment
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }
    fn environment(&self) -> Vec<(String, String)> {
        self.environment.clone()
    }
    fn runtime_executable_identity(
        &self,
        command: &str,
        search_path: Option<&str>,
        cwd: &str,
    ) -> Option<Value> {
        self.calls
            .get(&(
                command.to_owned(),
                search_path.map(str::to_owned),
                cwd.to_owned(),
            ))
            .cloned()
    }
    fn reuse_nonce(&self) -> Option<String> {
        Some(self.nonce.clone())
    }
    fn guard_executable(&self) -> Option<String> {
        Some(self.guard.clone())
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        false
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("vector host does not run git")
    }
}

fn fixture() -> Value {
    let bytes = include_bytes!("../tests/fixtures/sfrs/interpreter.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    serde_json::from_str(&text).expect("json")
}

fn case_host(document: &Value, root: &Path, case: &Value) -> CaseHost {
    let environment = bind(root, &document["env"])
        .as_object()
        .expect("env")
        .iter()
        .map(|(key, value)| (key.clone(), text(value).to_owned()))
        .collect();
    let mut calls = HashMap::new();
    for call in case["calls"].as_array().into_iter().flatten() {
        let call = bind(root, call);
        let key = (
            text(&call[0]).to_owned(),
            call[1].as_str().map(str::to_owned),
            text(&call[2]).to_owned(),
        );
        calls.insert(key, call[3].clone());
    }
    CaseHost {
        environment,
        guard: text(&bind(root, &document["guard"])).to_owned(),
        nonce: text(&document["nonce"]).to_owned(),
        calls,
    }
}

fn index(value: &Value) -> usize {
    value.as_u64().expect("index") as usize
}

fn path(value: &Value) -> Option<PyPath> {
    value.as_str().map(PyPath::new)
}

fn env_map(value: &Value) -> Environment {
    value
        .as_object()
        .expect("environment")
        .iter()
        .map(|(key, item)| (key.clone(), text(item).to_owned()))
        .collect::<BTreeMap<_, _>>()
}

fn optional<T: Into<Value>>(value: Option<T>) -> Value {
    value.map_or(Value::Null, Into::into)
}

fn candidate_json(candidate: Option<ShellLaunchCandidate>) -> Value {
    candidate.map_or(Value::Null, |item| {
        json!({
            "tokens": item.tokens,
            "command_index": item.command_index,
            "effective_cwd": item.effective_cwd.to_string(),
            "environment": item.environment,
            "resolution_reason": item.resolution_reason,
        })
    })
}

fn run_observers(function: &str, a: &[Value], ctx: &Ctx) -> Option<Value> {
    let home = || a.last().and_then(Value::as_str).map(Path::new);
    Some(match function {
        "looks_like_safe_read_only_lookup_command" => {
            obs::looks_like_safe_read_only_lookup_command(text(&a[0]), &strings(&a[1]), home(), ctx)
                .into()
        }
        "looks_like_read_only_interpreter_compound" => {
            obs::looks_like_read_only_interpreter_compound(
                text(&a[0]),
                &strings(&a[1]),
                home(),
                ctx,
            )
            .into()
        }
        "read_only_lookup_segments" => obs::read_only_lookup_segments(&strings(&a[0])).into(),
        "read_only_lookup_token_is_safe_stderr_discard" => {
            obs::read_only_lookup_token_is_safe_stderr_discard(text(&a[0])).into()
        }
        "contains_pytest_env_shell_script_wrapper" => {
            obs::contains_pytest_env_shell_script_wrapper(&strings(&a[0])).into()
        }
        "parts_use_python_module_mode" => obs::parts_use_python_module_mode(&strings(&a[0])).into(),
        "python_args_use_module_mode" => obs::python_args_use_module_mode(&strings(&a[0])).into(),
        "looks_like_benign_interpreter_wait_chain" => {
            obs::looks_like_benign_interpreter_wait_chain(text(&a[0]), &strings(&a[1])).into()
        }
        "looks_like_benign_interpreter_wait" => {
            obs::looks_like_benign_interpreter_wait(text(&a[0]), &strings(&a[1]), &strings(&a[2]))
                .into()
        }
        "looks_like_read_only_interpreter_command" => {
            obs::looks_like_read_only_interpreter_command(
                text(&a[0]),
                &strings(&a[1]),
                &strings(&a[2]),
            )
            .into()
        }
        "single_interpreter_heredoc_script" => {
            optional(heredoc::single_interpreter_heredoc_script(text(&a[0])))
        }
        "single_interpreter_heredoc_interpreter" => {
            optional(heredoc::single_interpreter_heredoc_interpreter(text(&a[0])))
        }
        "single_interpreter_heredoc_args" => {
            optional(heredoc::single_interpreter_heredoc_args(text(&a[0])))
        }
        "shell_heredoc_payloads" => heredoc::shell_heredoc_payloads(text(&a[0])).into(),
        "shell_script_targets_pytest" => heredoc::shell_script_targets_pytest(text(&a[0])).into(),
        "normalized_redirect_target" => heredoc::normalized_redirect_target(text(&a[0])).into(),
        "is_read_only_observer_interpreter_command" => {
            heredoc::is_read_only_observer_interpreter_command(text(&a[0])).into()
        }
        _ => return None,
    })
}

fn run_trust(function: &str, a: &[Value], ctx: &Ctx) -> Option<Value> {
    Some(match function {
        "interpreter_token_has_path" => trust::interpreter_token_has_path(text(&a[0])).into(),
        "interpreter_identity_path_chain_is_stable" => {
            trust::interpreter_identity_path_chain_is_stable(&a[0]).into()
        }
        "interpreter_path_is_within" => trust::interpreter_path_is_within(
            &PyPath::new(text(&a[0])),
            &PyPath::new(text(&a[1])),
            ctx,
        )
        .into(),
        "python_interpreter_trust" => trust::python_interpreter_trust(
            text(&a[0]),
            &a[1],
            &PyPath::new(text(&a[2])),
            path(&a[3]).as_ref(),
            a[4].as_str(),
            ctx,
        )
        .into(),
        "pytest_args_from_segment" => optional(trust::pytest_args_from_segment(
            &strings(&a[0]),
            index(&a[1]),
        )),
        "pytest_config_assessment_for_command" => {
            let cwd = a[1].as_str().map(Path::new);
            let context = model_shell_execution_context(text(&a[0]), cwd, cwd, None);
            assessment_json(&trust::pytest_config_assessment_for_command(
                text(&a[0]),
                cwd,
                &context,
            ))
        }
        _ => return None,
    })
}

fn run_launch(function: &str, a: &[Value], ctx: &Ctx) -> Option<Value> {
    Some(match function {
        "normalized_interpreter_cwd" => {
            launch::normalized_interpreter_cwd(path(&a[0]).as_ref(), ctx)
                .to_string()
                .into()
        }
        "consume_sudo_wrapper_for_interpreter" => {
            let (at, cwd, reason) = launch::consume_sudo_wrapper_for_interpreter(
                &strings(&a[0]),
                index(&a[1]),
                &PyPath::new(text(&a[2])),
                ctx,
            );
            json!([at, cwd.to_string(), reason])
        }
        "shell_launch_candidate" => candidate_json(launch::shell_launch_candidate(
            &strings(&a[0]),
            &PyPath::new(text(&a[1])),
            &env_map(&a[2]),
            index(&a[3]),
            a[4].as_str(),
            ctx,
        )),
        "ambiguous_python_evidence_from_tokens" => launch::ambiguous_python_evidence_from_tokens(
            &strings(&a[0]),
            &PyPath::new(text(&a[1])),
            &env_map(&a[2]),
            &PyPath::new(text(&a[3])),
            path(&a[4]).as_ref(),
            text(&a[5]),
            ctx,
        )
        .into(),
        "python_interpreter_executable_identity" => launch::python_interpreter_executable_identity(
            text(&a[0]),
            &PyPath::new(text(&a[1])),
            &env_map(&a[2]),
            &PyPath::new(text(&a[3])),
            path(&a[4]).as_ref(),
            a[5].as_str(),
            ctx,
        ),
        "without_interpreter_reuse_nonces" => launch::without_interpreter_reuse_nonces(&a[0]),
        "python_interpreter_executable_identities" => {
            let cwd = path(&a[1]);
            let home = path(&a[2]);
            let environment = a[3].as_object().map(|_| env_map(&a[3]));
            let workspace = path(&a[4]);
            let inputs = IdentityInputs {
                cwd: cwd.as_ref(),
                home_dir: home.as_ref(),
                environment: environment.as_ref(),
                workspace_root: workspace.as_ref(),
                execution_context: None,
            };
            python_interpreter_executable_identities(text(&a[0]), &inputs, index(&a[5]), ctx).into()
        }
        _ => return None,
    })
}

fn run(function: &str, args: &[Value], ctx: &Ctx) -> Option<Value> {
    run_observers(function, args, ctx)
        .or_else(|| run_trust(function, args, ctx))
        .or_else(|| run_launch(function, args, ctx))
}

/// Rust may only be stricter than Python.
fn stricter(function: &str, actual: &Value, expected: &Value) -> bool {
    match function {
        // An integer mode of 2**64 or more is unrepresentable here: refused.
        "interpreter_identity_path_chain_is_stable" => {
            actual == &Value::Bool(false) && expected == &Value::Bool(true)
        }
        // The inline-Python oracle is a lexical over-approximation.
        "shell_script_targets_pytest" => {
            actual == &Value::Bool(true) && expected == &Value::Bool(false)
        }
        "pytest_config_assessment_for_command" => {
            actual["unsafe"] == json!(true) || actual["complete"] == json!(false)
        }
        // Past the shell-nesting depth cap Rust also keeps the user-controlled
        // candidate Python drops: a strict superset of the recorded identities.
        "python_interpreter_executable_identities" => {
            match (actual.as_array(), expected.as_array()) {
                (Some(a), Some(e)) => a.len() > e.len() && e.iter().all(|item| a.contains(item)),
                _ => false,
            }
        }
        _ => false,
    }
}

#[test]
fn interpreter_helpers_match_recorded_python() {
    let document = fixture();
    let scratch = build_tree_in(&document, "sfrs-interp");
    let root = scratch.0.clone();
    let mut failures = Vec::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut divergent: BTreeMap<String, usize> = BTreeMap::new();
    for case in document["cases"].as_array().expect("cases") {
        let function = case["fn"].as_str().expect("fn");
        let host = case_host(&document, &root, case);
        let ctx = Ctx::new(
            &host,
            &root.to_string_lossy(),
            &root.join("home").to_string_lossy(),
        );
        let args = bind(&root, &case["args"]);
        let mut expected = bind(&root, &case["result"]);
        normalize(&mut expected);
        let Some(mut actual) = run(function, args.as_array().expect("args"), &ctx) else {
            failures.push(format!("unhandled function {function}"));
            continue;
        };
        normalize(&mut actual);
        *counts.entry(function.to_owned()).or_default() += 1;
        if actual == expected {
            continue;
        }
        let approx = case["approx"].as_bool().unwrap_or(false);
        let known = approx
            || matches!(
                function,
                "interpreter_identity_path_chain_is_stable"
                    | "shell_script_targets_pytest"
                    | "python_interpreter_executable_identities"
            );
        if known && stricter(function, &actual, &expected) {
            *divergent.entry(function.to_owned()).or_default() += 1;
            continue;
        }
        let clip = |v: &dyn std::fmt::Display| v.to_string().chars().take(600).collect::<String>();
        failures.push(format!(
            "{function} {}: {} vs {}",
            clip(&args),
            clip(&actual),
            clip(&expected)
        ));
    }
    eprintln!("cases {counts:?}\nstricter divergences {divergent:?}");
    assert!(counts.len() >= 28, "too few functions: {counts:?}");
    let failures = crate::sfrs_host_divergence::portable_failures(
        failures,
        &[
            ("python_interpreter_executable_identities ", 20),
            ("shell_launch_candidate ", 28),
        ],
    );
    let mut by_function: BTreeMap<&str, (usize, &String)> = BTreeMap::new();
    for failure in &failures {
        let name = failure.split(' ').next().unwrap_or("");
        by_function.entry(name).or_insert((0, failure)).0 += 1;
    }
    let summary: Vec<String> = by_function
        .iter()
        .map(|(name, (count, first))| format!("{name} x{count}: {first}"))
        .collect();
    assert!(
        failures.is_empty(),
        "{} differ:\n{}",
        failures.len(),
        summary.join("\n")
    );
}
