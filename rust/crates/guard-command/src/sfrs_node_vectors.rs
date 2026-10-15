//! Parity of the Node heredoc, generated-workflow, TypeScript/GraphQL and
//! GitHub PR-body leaves against recorded Python output. The fixture holds a
//! small tree and cases whose paths carry a `{ROOT}` token; the tree is rebuilt
//! below a fresh root. Secret-content classification (the marker `SECRET`) is
//! the recorder's stand-in; the GitHub CLI classifier is the real Rust one.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};
use crate::sfrs_gh_body_safety as gbs;
use crate::sfrs_interpreter_heredoc::shell_heredoc_payloads;
use crate::sfrs_node_heredoc as heredoc;
use crate::sfrs_node_redaction as redaction;
use crate::sfrs_node_templates::{self as templates, Assignments};
use crate::sfrs_node_workflows as workflows;
use crate::sfrs_typescript_graphql as graphql;

const TOKEN: &str = "{ROOT}";
const SECRET_MARKER: &str = "SECRET";

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> Value {
    let bytes = include_bytes!("../tests/fixtures/sfrs/sfrs_node.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    serde_json::from_str(&text).expect("json")
}

fn build_tree(document: &Value) -> Scratch {
    let base = fs::canonicalize(std::env::temp_dir()).expect("temp dir");
    let root = base.join(format!("sfrs-node-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("root");
    let tree = &document["tree"];
    let dirs = tree["dirs"].as_object().expect("dirs");
    for name in dirs.keys() {
        fs::create_dir_all(root.join(name)).expect("dir");
    }
    for (name, text) in tree["files"].as_object().expect("files") {
        let path = root.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("parent");
        fs::write(&path, text.as_str().expect("text")).expect("file");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    for (name, mode) in dirs {
        let mode = u32::try_from(mode.as_u64().expect("mode")).expect("mode");
        fs::set_permissions(root.join(name), fs::Permissions::from_mode(mode)).expect("chmod");
    }
    Scratch(root)
}

fn bind(root: &Path, value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace(TOKEN, &root.to_string_lossy())),
        Value::Array(items) => items.iter().map(|item| bind(root, item)).collect(),
        other => other.clone(),
    }
}

fn unbind(root: &Path, value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace(&*root.to_string_lossy(), TOKEN)),
        Value::Array(items) => items.into_iter().map(|item| unbind(root, item)).collect(),
        other => other,
    }
}

/// The replay host: recorded environment, the real uid of the tree owner, the
/// secret stub of the recorder and the real filesystem for path facts.
struct Host {
    env: Vec<(String, String)>,
    uid: u32,
}

/// `os.path.realpath`: resolve the longest existing prefix and re-append the rest.
fn realpath(path: &str) -> Option<String> {
    let mut rest: Vec<String> = Vec::new();
    let mut current = PathBuf::from(path);
    loop {
        if let Ok(resolved) = fs::canonicalize(&current) {
            let mut result = resolved;
            for part in rest.iter().rev() {
                result.push(part);
            }
            return Some(result.to_string_lossy().into_owned());
        }
        let name = current.file_name()?.to_string_lossy().into_owned();
        rest.push(name);
        if !current.pop() {
            return None;
        }
    }
}

impl InspectionHost for Host {
    fn env(&self, name: &str) -> Option<String> {
        self.env
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }
    fn environment(&self) -> Vec<(String, String)> {
        self.env.clone()
    }
    fn current_uid(&self) -> Option<u32> {
        Some(self.uid)
    }
    fn secret_content_found(&self, text: &str, _is_path: bool) -> bool {
        text.contains(SECRET_MARKER)
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
        GitRun::Failed("replay host does not run git")
    }
    fn path_exists(&self, path: &str) -> bool {
        fs::symlink_metadata(path).is_ok() || Path::new(path).exists()
    }
    fn real_path(&self, path: &str) -> Option<String> {
        realpath(path)
    }
}

fn text(value: &Value) -> &str {
    value.as_str().expect("string argument")
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("list argument")
        .iter()
        .map(|item| text(item).to_owned())
        .collect()
}

fn optional_path(value: &Value) -> Option<PathBuf> {
    value.as_str().map(PathBuf::from)
}

fn pairs(value: &Value) -> Vec<(String, String)> {
    value
        .as_array()
        .expect("pairs")
        .iter()
        .map(|pair| (text(&pair[0]).to_owned(), text(&pair[1]).to_owned()))
        .collect()
}

fn pairs_json(assignments: &Assignments) -> Value {
    json!(assignments
        .items()
        .iter()
        .map(|(name, value)| json!([name, value]))
        .collect::<Vec<_>>())
}

fn char_to_byte(script: &str, index: usize) -> usize {
    script
        .char_indices()
        .nth(index)
        .map_or(script.len(), |(offset, _)| offset)
}

fn sorted(items: impl IntoIterator<Item = String>) -> Value {
    let mut items: Vec<String> = items.into_iter().collect();
    items.sort();
    json!(items)
}

fn replay(function: &str, args: &[Value], ctx: &Ctx) -> Value {
    let one = || text(&args[0]);
    let flag = |index: usize| args[index].as_bool().expect("bool argument");
    let cwd = || args.get(1).and_then(optional_path);
    let home = || args.get(2).and_then(optional_path);
    match function {
        "single_node_heredoc_script" => json!(templates::single_node_heredoc_script(one())),
        "single_node_heredoc_delimiter_is_quoted" => {
            json!(templates::single_node_heredoc_delimiter_is_quoted(one()))
        }
        "node_string_assignments" => pairs_json(&templates::node_string_assignments(one())),
        "node_string_assignment_from_line" => {
            json!(templates::node_string_assignment_from_line(one()))
        }
        "read_js_quoted_literal" => {
            let quote = text(&args[1]).chars().next().expect("quote");
            json!(templates::read_js_quoted_literal(one(), quote))
        }
        "node_expand_template_value" => json!(templates::node_expand_template_value(
            one(),
            &Assignments::from_pairs(&pairs(&args[1]))
        )),
        "js_string_literal_text" => json!(templates::js_string_literal_text(one())),
        "node_generated_path_has_safe_root" => {
            json!(templates::node_generated_path_has_safe_root(one()))
        }
        "node_template_placeholders_are_safe_filename_fragments" => {
            json!(templates::node_template_placeholders_are_safe_filename_fragments(one()))
        }
        "node_template_placeholder_is_safe_filename_fragment" => {
            json!(templates::node_template_placeholder_is_safe_filename_fragment(one()))
        }
        "node_path_without_template_placeholders" => {
            json!(templates::node_path_without_template_placeholders(one()))
        }
        "looks_like_safe_node_generated_file_heredoc" => json!(
            heredoc::looks_like_safe_node_generated_file_heredoc(one(), text(&args[1]))
        ),
        "looks_like_safe_node_read_only_http_heredoc" => json!(
            heredoc::looks_like_safe_node_read_only_http_heredoc(one(), text(&args[1]))
        ),
        "node_script_contains_disallowed_destructive_file_call" => {
            json!(heredoc::node_script_contains_disallowed_destructive_file_call(one()))
        }
        "node_write_file_targets" => json!(heredoc::node_write_file_targets(one())),
        "first_js_call_argument" => {
            let start = char_to_byte(
                one(),
                usize::try_from(args[1].as_u64().expect("index")).expect("index"),
            );
            json!(heredoc::first_js_call_argument(one(), start))
        }
        "node_write_target_is_safe_generated_file" => {
            json!(heredoc::node_write_target_is_safe_generated_file(
                one(),
                &Assignments::from_pairs(&pairs(&args[1]))
            ))
        }
        "node_generated_path_contains_shell_expansion" => {
            json!(heredoc::node_generated_path_contains_shell_expansion(one()))
        }
        "node_generated_path_has_safe_extension" => {
            json!(heredoc::node_generated_path_has_safe_extension(one()))
        }
        "looks_like_safe_graphql_query_file_workflow" => {
            json!(workflows::looks_like_safe_graphql_query_file_workflow(
                one(),
                ctx
            ))
        }
        "graphql_workflow_rest_args_are_safe" => {
            json!(workflows::graphql_workflow_rest_args_are_safe(
                one(),
                text(&args[1])
            ))
        }
        "looks_like_temporary_pr_threads_query_path" => {
            json!(workflows::looks_like_temporary_pr_threads_query_path(
                one(),
                ctx
            ))
        }
        "contains_destructive_node_inline_eval" => {
            json!(workflows::contains_destructive_node_inline_eval(&strings(
                &args[0]
            )))
        }
        "find_or_fd_uses_write_or_exec_action" => {
            json!(workflows::find_or_fd_uses_write_or_exec_action(
                &strings(&args[0]),
                optional_path(&args[1]).as_deref()
            ))
        }
        "is_combined_node_inline_eval_flag" => {
            json!(workflows::is_combined_node_inline_eval_flag(one()))
        }
        "segment_contains_destructive_node_inline_eval" => {
            json!(workflows::segment_contains_destructive_node_inline_eval(
                &strings(&args[0])
            ))
        }
        "last_non_whitespace_character" => {
            json!(redaction::last_non_whitespace_character(&strings(&args[0])).map(String::from))
        }
        "js_slash_starts_regex" => json!(redaction::js_slash_starts_regex(&strings(&args[0]))),
        "redacted_node_inline_string_literals" => {
            json!(redaction::redacted_node_inline_string_literals(
                one(),
                flag(1)
            ))
        }
        "script_references_destructive_file_call" => {
            let allowed = strings(&args[1]);
            let allowed: Vec<&str> = allowed.iter().map(String::as_str).collect();
            json!(redaction::script_references_destructive_file_call(
                one(),
                &allowed
            ))
        }
        "contains_destructive_node_inline_script" => {
            json!(redaction::contains_destructive_node_inline_script(one()))
        }
        "node_script_contains_non_file_generation_risk" => {
            json!(redaction::node_script_contains_non_file_generation_risk(
                one()
            ))
        }
        "node_script_contains_sensitive_runtime_behavior" => {
            json!(redaction::node_script_contains_sensitive_runtime_behavior(
                one()
            ))
        }
        "looks_like_contained_temporary_typescript_workflow" => {
            json!(graphql::looks_like_contained_temporary_typescript_workflow(
                one()
            ))
        }
        "strip_shell_quotes" => json!(graphql::strip_shell_quotes(one())),
        "contains_shell_expansion" => json!(graphql::contains_shell_expansion(one())),
        "graphql_query_file_substitution_refs" => {
            sorted(graphql::graphql_query_file_substitution_refs(one()))
        }
        "graphql_query_file_argument_values" => {
            sorted(graphql::graphql_query_file_argument_values(one()))
        }
        "graphql_workflow_field_arg_is_safe" => {
            json!(graphql::graphql_workflow_field_arg_is_safe(
                one(),
                text(&args[1])
            ))
        }
        "contains_unsafe_pytest_binary_invocation" => {
            json!(graphql::contains_unsafe_pytest_binary_invocation(
                &strings(&args[0]),
                optional_path(&args[1]).as_deref()
            ))
        }
        "contains_unmodeled_inline_interpreter_eval" => {
            json!(graphql::contains_unmodeled_inline_interpreter_eval(
                one(),
                &strings(&args[1]),
                &strings(&args[2])
            ))
        }
        "is_unmodeled_inline_interpreter_command" => {
            json!(graphql::is_unmodeled_inline_interpreter_command(one()))
        }
        "path_text_looks_sensitive" => json!(gbs::path_text_looks_sensitive(one())),
        "text_contains_credential_exfiltration" => {
            json!(gbs::text_contains_credential_exfiltration(one()))
        }
        "bounded_output_consumer" => json!(gbs::bounded_output_consumer(&strings(&args[0]))),
        "gh_pr_create_segment_with_bounded_output" => json!(
            gbs::gh_pr_create_segment_with_bounded_output(one()).map(|tokens| tokens
                .into_iter()
                .map(|token| json!([token.raw, token.plain]))
                .collect::<Vec<_>>())
        ),
        "gh_pr_create_uses_safe_static_body_file" => {
            json!(gbs::gh_pr_create_uses_safe_static_body_file(
                one(),
                cwd().as_deref(),
                home().as_deref(),
                ctx
            ))
        }
        "gh_pr_edit_uses_safe_static_body_file" => {
            json!(gbs::gh_pr_edit_uses_safe_static_body_file(
                one(),
                cwd().as_deref(),
                home().as_deref(),
                ctx
            ))
        }
        "shell_heredoc_payloads" => json!(shell_heredoc_payloads(one())),
        "shell_read_segment_can_emit_stdout" => {
            json!(gbs::shell_read_segment_can_emit_stdout(&strings(&args[0])))
        }
        "search_args_use_quiet_mode" => json!(gbs::search_args_use_quiet_mode(&strings(&args[0]))),
        "find_exec_reads_file_content" => {
            json!(gbs::find_exec_reads_file_content(&strings(&args[0])))
        }
        "find_target_candidates" => json!(gbs::find_target_candidates(&strings(&args[0]))),
        "find_target_candidate_is_sensitive" => json!(gbs::find_target_candidate_is_sensitive(
            one(),
            cwd().as_deref(),
            home().as_deref()
        )),
        "shell_segment_reads_sensitive_path" => json!(gbs::shell_segment_reads_sensitive_path(
            &strings(&args[0]),
            cwd().as_deref(),
            home().as_deref()
        )),
        "find_segment_reads_sensitive_path" => json!(gbs::find_segment_reads_sensitive_path(
            &strings(&args[0]),
            cwd().as_deref(),
            home().as_deref()
        )),
        other => panic!("unknown recorded function {other}"),
    }
}

#[test]
fn node_leaves_match_recorded_python() {
    let document = fixture();
    let scratch = build_tree(&document);
    let root = scratch.0.as_path();
    let uid = fs::metadata(root).expect("root metadata").uid();
    let root_text = root.to_string_lossy().into_owned();
    let host = Host {
        env: vec![
            ("PATH".to_owned(), format!("{root_text}/bin")),
            ("TMPDIR".to_owned(), format!("{root_text}/tmp")),
            ("HOME".to_owned(), format!("{root_text}/home")),
        ],
        uid,
    };
    let proj = format!("{root_text}/home/proj");
    let ctx = Ctx::new(&host, &proj, &format!("{root_text}/home"));
    let mut failures = Vec::new();
    let cases = document["cases"].as_array().expect("cases");
    for case in cases {
        let function = text(&case["fn"]);
        let args: Vec<Value> = case["args"]
            .as_array()
            .expect("args")
            .iter()
            .map(|item| bind(root, item))
            .collect();
        let actual = unbind(root, replay(function, &args, &ctx));
        if actual != case["result"] {
            failures.push(format!(
                "{function} {} => {actual}, expected {}",
                case["args"], case["result"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases diverge:\n{}",
        failures.len(),
        cases.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
