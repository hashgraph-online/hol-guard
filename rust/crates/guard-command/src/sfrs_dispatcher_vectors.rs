//! Parity of `extract_sensitive_tool_action_request` against recorded Python
//! output. The fixture holds a directory tree plus the host facts each case
//! depended on: the executable identities it requested, `sys.executable`, the
//! environment and the reuse nonce. A case names the tool, the arguments, the
//! declared cwd and home, the text its canonical command was parsed from, and
//! the kind of synthetic native evaluation it carried. Paths carry a `{ROOT}`
//! token bound to a fresh tree.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::Path;

use serde_json::Value;

use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};
use crate::command_evaluation::CommandDecisionFloor;
use crate::command_model::parse_shell_command;
use crate::hook_adapter_value::OValue;
use crate::sfrs_dispatcher::{extract_sensitive_tool_action_request, ExtractInputs};
use crate::sfrs_dispatcher_request::NativeEvaluationView;
use crate::sfrs_pytest_vectors::{bind, build_tree_in, text};

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
    let bytes = include_bytes!("../tests/fixtures/sfrs/sfrs_dispatcher.json.gz");
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

/// The synthetic native evaluation the recorder built for `kind`.
fn native_view(kind: &str, identity: &str, other: &str) -> NativeEvaluationView {
    let strings = |items: &[&str]| items.iter().map(|item| (*item).to_owned()).collect();
    let mut view = NativeEvaluationView {
        security_identity: identity.to_owned(),
        minimum_action: CommandDecisionFloor::Allow,
        match_default_modes: Vec::new(),
        reason_codes: Vec::new(),
        explicitly_enabled_permission_ids: Vec::new(),
        controlling_action_class: None,
        controlling_reason: None,
    };
    match kind {
        "benign" => view.reason_codes = strings(&["native.explicit-benign"]),
        "disabled_only" => view.match_default_modes = strings(&["disabled", "disabled"]),
        "interaction" => {
            view.minimum_action = CommandDecisionFloor::Review;
            view.match_default_modes = strings(&["review"]);
            view.controlling_action_class = Some("package install command".to_owned());
            view.controlling_reason = Some("A command extension requires review.".to_owned());
        }
        "enabled_allow" => {
            view.match_default_modes = strings(&["review"]);
            view.explicitly_enabled_permission_ids = strings(&["perm.x"]);
            view.controlling_action_class = Some("enabled extension action".to_owned());
            view.controlling_reason = Some("An enabled extension needs composition.".to_owned());
        }
        "monitor_no_class" => {
            view.minimum_action = CommandDecisionFloor::Monitor;
            view.match_default_modes = strings(&["review"]);
        }
        "classification_block" => {
            view.minimum_action = CommandDecisionFloor::Block;
            view.reason_codes = strings(&["native.classification-block"]);
        }
        "block_with_matches" => {
            view.minimum_action = CommandDecisionFloor::Block;
            view.match_default_modes = strings(&["block"]);
            view.reason_codes = strings(&["native.classification-block"]);
            view.controlling_action_class = Some("blocked extension action".to_owned());
            view.controlling_reason = Some("A command extension blocks this command.".to_owned());
        }
        "mismatch" => view.security_identity = other.to_owned(),
        other_kind => panic!("unknown native kind {other_kind}"),
    }
    view
}

fn declared(root: &Path, value: &Value) -> Option<std::path::PathBuf> {
    value.as_str().map(|relative| root.join(relative))
}

fn run_case(document: &Value, root: &Path, case: &Value) -> Value {
    let host = case_host(document, root, case);
    let ctx = Ctx::new(
        &host,
        &root.join("proj").to_string_lossy(),
        &root.join("home").to_string_lossy(),
    );
    let (cwd, home) = (declared(root, &case["cwd"]), declared(root, &case["home"]));
    let canonical = case["canonical"].as_str().map(|command| {
        parse_shell_command(
            command,
            cwd.as_deref(),
            home.as_deref(),
            "posix",
            "shell_string",
            "guard-shell",
            true,
        )
    });
    let native = match (&canonical, case["native"].as_str()) {
        (Some(command), Some(kind)) => {
            let other = parse_shell_command(
                "echo different",
                cwd.as_deref(),
                home.as_deref(),
                "posix",
                "shell_string",
                "guard-shell",
                true,
            );
            Some(native_view(
                kind,
                &command.security_identity(),
                &other.security_identity(),
            ))
        }
        _ => None,
    };
    let inputs = ExtractInputs {
        cwd: cwd.as_deref(),
        home_dir: home.as_deref(),
        canonical_command: canonical.as_ref(),
        native_evaluation: native.as_ref(),
        controls: None,
        ctx: &ctx,
    };
    let tool = OValue::from_wire(&tagged_wire(&case["tool"])).expect("tool");
    let arguments = bind(root, &case["arguments"]);
    match extract_sensitive_tool_action_request(&tool, &arguments, &inputs) {
        Ok(None) => Value::Null,
        Ok(Some(mut request)) => {
            if request.shell_execution_context_hash.is_some() {
                request.shell_execution_context_hash = Some("<hash>".to_owned());
            }
            // Both hash absolute paths under a per-run scratch root.
            if request.script_read_identity_sha256.is_some() {
                request.script_read_identity_sha256 = Some("<hash>".to_owned());
            }
            serde_json::to_value(&request).expect("serialize")
        }
        Err(error) => serde_json::json!({ "error": error.0 }),
    }
}

/// The recorder writes plain JSON; the resident wire tags each list with `"l"`.
fn tagged_wire(value: &Value) -> Value {
    match value {
        Value::Array(items) => {
            let mut tagged = vec![Value::String("l".to_owned())];
            tagged.extend(items.iter().map(tagged_wire));
            Value::Array(tagged)
        }
        other => other.clone(),
    }
}

fn shown(value: Option<&Value>) -> String {
    let text = value.map_or("<absent>".to_owned(), Value::to_string);
    if text.chars().count() > 160 {
        format!("{}…", text.chars().take(160).collect::<String>())
    } else {
        text
    }
}

/// Follows a difference down to its first differing leaf and shows both values.
fn first_difference(path: &str, want: Option<&Value>, got: Option<&Value>) -> String {
    match (want, got) {
        (Some(Value::Object(left)), Some(Value::Object(right))) => {
            let mut keys: Vec<&String> = left.keys().chain(right.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                if left.get(key) != right.get(key) {
                    return first_difference(
                        &format!("{path}.{key}"),
                        left.get(key),
                        right.get(key),
                    );
                }
            }
            path.to_owned()
        }
        (Some(Value::Array(left)), Some(Value::Array(right))) if left.len() == right.len() => {
            for (index, (one, two)) in left.iter().zip(right).enumerate() {
                if one != two {
                    return first_difference(&format!("{path}[{index}]"), Some(one), Some(two));
                }
            }
            path.to_owned()
        }
        _ => format!("{path}: {} != {}", shown(want), shown(got)),
    }
}

/// Names each top-level field whose value differs, down to its first differing leaf.
fn differing_fields(expected: &Value, actual: &Value) -> String {
    let (Some(left), Some(right)) = (expected.as_object(), actual.as_object()) else {
        return format!(
            "whole value: expected {} actual {}",
            shown(Some(expected)),
            shown(Some(actual))
        );
    };
    let mut keys: Vec<&String> = left.keys().chain(right.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut parts = Vec::new();
    for key in keys {
        let (want, got) = (left.get(key), right.get(key));
        if want != got {
            parts.push(first_difference(key, want, got));
        }
    }
    parts.join("; ")
}

/// The Rust inline `python -c` pytest check is lexical where Python parses the
/// payload, so it may also route a payload that only might reach pytest into
/// the restricted pytest profile. That divergence is accepted only one way:
/// Python found no pytest route and Rust requires the sandbox. Only the fields
/// the pytest route rewrites may differ; every other field must still match.
fn stricter_inline_pytest(case: &Value, expected: &Value, actual: &Value) -> bool {
    const PYTEST_ROUTE_FIELDS: [&str; 7] = [
        "action_class",
        "guard_default_action",
        "pytest_config_identity_sha256",
        "pytest_config_reason_codes",
        "reason",
        "reason_code",
        "restricted_profile_version",
    ];
    let command = case["arguments"]["command"].as_str().unwrap_or_default();
    let (Some(mut want), Some(mut got)) =
        (expected.as_object().cloned(), actual.as_object().cloned())
    else {
        return false;
    };
    let python_inline = command.contains("python") && command.contains(" -c");
    let python_had_no_pytest_route = want.get("guard_default_action").is_none_or(Value::is_null)
        && want
            .get("pytest_config_reason_codes")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty);
    let rust_requires_sandbox =
        got.get("guard_default_action").and_then(Value::as_str) == Some("sandbox-required");
    if !(python_inline && python_had_no_pytest_route && rust_requires_sandbox) {
        return false;
    }
    for key in PYTEST_ROUTE_FIELDS {
        want.remove(key);
        got.remove(key);
    }
    want == got
}

/// A Linux mismatch is host-sensitive only when every differing leaf is one of
/// the two facts the macOS recording cannot reproduce: interpreter trust for a
/// missing `/bin/python3`, or an upload operand's security identity.
fn host_only_difference(fields: &str) -> bool {
    !fields.is_empty()
        && fields.split("; ").all(|part| {
            let name = part.split(':').next().unwrap_or_default().trim();
            name == "canonical_command.security_identity"
                || name == "interpreter_executable_identities[0].trust"
        })
}

/// The recorded security identity of an upload operand hashes the absolute
/// scratch path the recorder happened to use. A per-user temp directory
/// (macOS `/var/folders/<hash>/T`) differs on every machine, so those four
/// vectors can match only on the recording host. On macOS a mismatch is
/// tolerated only when it names `marker`, differs in nothing but the security
/// identity, and stays within `limit` vectors.
fn root_dependent_identities(failures: Vec<String>, marker: &str, limit: usize) -> Vec<String> {
    let mut tolerated = 0usize;
    failures
        .into_iter()
        .filter(|failure| {
            let only_identity = failure.contains(marker)
                && failure.lines().any(|line| {
                    line.trim_start().starts_with("differ ")
                        && host_only_difference(line.trim_start().trim_start_matches("differ "))
                        && !line.contains("interpreter_executable_identities")
                });
            if only_identity && tolerated < limit {
                tolerated += 1;
                return false;
            }
            true
        })
        .collect()
}

/// Set in the child process that replays the vectors from `proj`.
const REPLAY_CHILD_ENV: &str = "HOL_GUARD_SFRS_DISPATCHER_REPLAY_CHILD";

/// The recorder ran from `proj`, and a shell model without a declared cwd
/// starts at the process cwd. Changing the cwd is process-wide, so the replay
/// runs in its own child process of this test binary; `cargo test` threads that
/// read the cwd never observe the scratch tree, and a failed replay cannot leave
/// the cwd changed for them.
#[test]
fn dispatcher_matches_recorded_python() {
    if std::env::var_os(REPLAY_CHILD_ENV).is_some() {
        replay_from_proj();
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
        .args([
            "--exact",
            "sfrs_dispatcher_vectors::dispatcher_matches_recorded_python",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(REPLAY_CHILD_ENV, "1")
        .output()
        .expect("spawn dispatcher replay");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "dispatcher replay failed\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn replay_from_proj() {
    let document = fixture();
    let scratch = build_tree_in(&document, "sfrs-dispatch");
    let root = scratch.0.clone();
    std::env::set_current_dir(root.join("proj")).expect("enter proj");
    let mut host_failures = Vec::new();
    let mut other_failures = Vec::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    let cases = document["cases"].as_array().expect("cases");
    for (position, case) in cases.iter().enumerate() {
        let expected = match case.get("error") {
            Some(error) => serde_json::json!({ "error": error }),
            None => {
                let mut result = bind(&root, &case["result"]);
                if let Some(hash) = result.get_mut("script_read_identity_sha256") {
                    if !hash.is_null() {
                        *hash = Value::String("<hash>".to_owned());
                    }
                }
                result
            }
        };
        let actual = run_case(&document, &root, case);
        let bucket = if actual == expected {
            "pass"
        } else if stricter_inline_pytest(case, &expected, &actual) {
            "stricter"
        } else {
            "fail"
        };
        *counts.entry(bucket).or_default() += 1;
        if bucket == "fail" {
            let fields = differing_fields(&expected, &actual);
            let names = fields
                .split("; ")
                .map(|part| part.split(':').next().unwrap_or_default())
                .collect::<Vec<_>>()
                .join(",");
            *kinds.entry(names).or_default() += 1;
            let failure = format!(
                "case {position}: tool {} args {} cwd {} home {} canonical {} native {}\n  differ {fields}",
                case["tool"], case["arguments"], case["cwd"], case["home"], case["canonical"], case["native"],
            );
            if host_only_difference(&fields) {
                host_failures.push(failure);
            } else {
                other_failures.push(failure);
            }
        }
    }
    assert!(cases.len() >= 800, "recorded {} cases", cases.len());
    // Recorded on macOS: `command -p` and `command -pv` find no `/bin/python3` there, so `command -p` and
    // `command -pv` observe a different interpreter trust on Linux CI. The
    // upload operand's security identity observes host path facts of the scratch
    // tree. Any other differing field stays a failure.
    let host_failures = crate::sfrs_host_divergence::portable_failures(
        host_failures,
        &[
            ("command -p python3", 4),
            ("command -pv python3", 2),
            ("curl -F f=@", 4),
        ],
    );
    other_failures.extend(host_failures);
    // Off macOS `portable_failures` already spent the four-vector budget for
    // the upload identities; only macOS needs this separate allowance.
    let other_failures = if cfg!(target_os = "macos") {
        root_dependent_identities(other_failures, "curl -F f=@", 4)
    } else {
        other_failures
    };
    assert!(
        other_failures.is_empty(),
        "{counts:?}\n{kinds:#?}\n{}",
        other_failures
            .iter()
            .take(120)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
