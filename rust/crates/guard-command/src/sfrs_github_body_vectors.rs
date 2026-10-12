//! Parity of the PR body-file, ephemeral-body and Actions read checks against
//! recorded Python output. The fixture holds a directory tree (with modes and
//! ages) plus cases whose paths carry a `{ROOT}` token and whose environment is
//! recorded per case; the tree is rebuilt below a fresh root before replay.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use base64::Engine;
use serde_json::Value;

use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};
use crate::codex_output_py::PyPath;
use crate::sfrs_gh_actions_env as env_checks;
use crate::sfrs_gh_actions_filters::{self as filters, ValueKind};
use crate::sfrs_gh_actions_read as actions;
use crate::sfrs_gh_body_file as body;
use crate::sfrs_gh_body_file_check as body_check;
use crate::sfrs_gh_ephemeral_body as eph;
use crate::sfrs_quote_tokens::{
    shell_token_segments, shell_tokens_preserving_quote_context, QuotedToken,
};
use crate::shell_structure::{extract_heredocs, mask_complete_heredocs};

const TOKEN: &str = "{ROOT}";
const SECRET_MARKER: &str = "SECRET";

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> Value {
    let bytes = include_bytes!("../tests/fixtures/sfrs/github_body.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    serde_json::from_str(&text).expect("json")
}

fn set_mode(path: &Path, mode: u64) {
    let mode = u32::try_from(mode).expect("mode");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
}

fn build_tree(document: &Value) -> Scratch {
    let base = fs::canonicalize(std::env::temp_dir()).expect("temp dir");
    let root = base.join(format!("sfrs-ghb-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("root");
    let tree = &document["tree"];
    let dirs = tree["dirs"].as_object().expect("dirs");
    for name in dirs.keys() {
        fs::create_dir_all(root.join(name)).expect("dir");
    }
    let now = SystemTime::now();
    for (name, spec) in tree["files"].as_object().expect("files") {
        let path = root.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("parent");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(spec["b64"].as_str().expect("b64"))
            .expect("base64");
        fs::write(&path, bytes).expect("file");
        set_mode(&path, spec["mode"].as_u64().expect("mode"));
        let age = spec["age"].as_f64().expect("age");
        let stamp = if age >= 0.0 {
            now - Duration::from_secs_f64(age)
        } else {
            now + Duration::from_secs_f64(-age)
        };
        fs::File::options()
            .write(true)
            .open(&path)
            .or_else(|_| {
                set_mode(&path, 0o600);
                fs::File::options().write(true).open(&path)
            })
            .expect("open")
            .set_modified(stamp)
            .expect("mtime");
        set_mode(&path, spec["mode"].as_u64().expect("mode"));
    }
    for (name, target) in tree["links"].as_object().expect("links") {
        symlink(target.as_str().expect("target"), root.join(name)).expect("link");
    }
    for (name, target) in tree["hardlinks"].as_object().expect("hardlinks") {
        fs::hard_link(root.join(target.as_str().expect("target")), root.join(name)).expect("hard");
    }
    for (name, mode) in dirs {
        set_mode(&root.join(name), mode.as_u64().expect("mode"));
    }
    Scratch(root)
}

fn bind(root: &Path, value: &Value) -> Value {
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

/// The replay host: recorded environment, the real uid of the tree owner, the
/// fixed secret stub and the executable-trust stub of the recorder.
struct Host {
    env: Vec<(String, String)>,
    root: String,
    uid: u32,
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
    fn git_binary_trusted(&self, git: &str, _: &str) -> bool {
        let bin = format!("{}/bin", self.root);
        git == bin || git.starts_with(&format!("{bin}/"))
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("replay host does not run git")
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

fn string_lists(value: &Value) -> Vec<Vec<String>> {
    value
        .as_array()
        .expect("lists")
        .iter()
        .map(strings)
        .collect()
}

fn values(value: &Value) -> HashMap<String, ValueKind> {
    value
        .as_object()
        .expect("values")
        .iter()
        .map(|(name, kind)| {
            let kind = if text(kind) == "number" {
                ValueKind::Number
            } else {
                ValueKind::Text
            };
            (name.clone(), kind)
        })
        .collect()
}

fn optional_text(value: &Value) -> Option<&str> {
    value.as_str()
}

fn path_text(path: Option<PyPath>) -> Value {
    path.map_or(Value::Null, |path| Value::from(path.to_string()))
}

fn kind_value(kind: Option<ValueKind>) -> Value {
    match kind {
        Some(ValueKind::Number) => "number".into(),
        Some(ValueKind::Text) => "text".into(),
        None => Value::Null,
    }
}

fn segments_of(source: &str, position: usize) -> Vec<QuotedToken> {
    let masked = mask_complete_heredocs(source, &extract_heredocs(source));
    shell_token_segments(&shell_tokens_preserving_quote_context(&masked))
        .into_iter()
        .nth(position)
        .expect("segment")
}

fn run_ephemeral(function: &str, args: &[Value]) -> Option<Value> {
    Some(match function {
        "eph_safe" => unreachable!("handled with a context"),
        "eph_quoted_word" => eph::is_one_fully_quoted_word(text(&args[0])).into(),
        "eph_static_argument" => {
            eph::static_shell_argument(text(&args[0]), args[1].as_bool().expect("flag")).into()
        }
        "eph_assignment" | "eph_writer" | "eph_cat" | "eph_grep" | "eph_echo" | "eph_pr_create" => {
            let segment = segments_of(text(&args[0]), position(&args[1]));
            let variable = args.get(2).map(text).unwrap_or_default();
            match function {
                "eph_assignment" => {
                    eph::assignment_variable(&segment).map_or(Value::Null, Value::from)
                }
                "eph_writer" => eph::heredoc_writer_is_safe(&segment, variable).into(),
                "eph_cat" => eph::body_cat_is_safe(&segment, variable).into(),
                "eph_grep" => eph::body_grep_is_safe(&segment, variable).into(),
                "eph_echo" => eph::echo_is_safe(&segment, variable).into(),
                _ => eph::pr_create_is_safe(&segment, variable).into(),
            }
        }
        _ => return None,
    })
}

fn position(value: &Value) -> usize {
    usize::try_from(value.as_u64().expect("index")).expect("index")
}

fn run_body_file(function: &str, args: &[Value], ctx: &Ctx, uid: u32) -> Option<Value> {
    Some(match function {
        "bf_edit_operand" => body::static_markdown_pr_edit_body_file_operand(&strings(&args[0]))
            .map_or(Value::Null, Value::from),
        "bf_markdown_name" => body::is_pr_body_markdown_name(text(&args[0])).into(),
        "bf_looks_sensitive" => body::path_looks_sensitive(&PyPath::new(text(&args[0]))).into(),
        "bf_cascade_root" => path_text(
            body::cascade_projects_authored_root(
                &PyPath::new(text(&args[0])),
                &PyPath::new(text(&args[1])),
                ctx,
            )
            .flatten(),
        ),
        "bf_omp_root" => path_text(
            body::omp_session_authored_root(
                &PyPath::new(text(&args[0])),
                &PyPath::new(text(&args[1])),
                ctx,
            )
            .flatten(),
        ),
        "bf_resolve" => path_text(body::resolve_operand(
            text(&args[0]),
            &PyPath::new(text(&args[1])),
            &PyPath::new(text(&args[2])),
        )),
        "bf_authored_root" => path_text(body::authored_location_root(
            &PyPath::new(text(&args[0])),
            &PyPath::new(text(&args[1])),
            &PyPath::new(text(&args[2])),
            ctx,
        )),
        "bf_chain" => body_check::ancestor_chain_is_controlled(
            &PyPath::new(text(&args[0])),
            &PyPath::new(text(&args[1])),
            ctx,
        )
        .into(),
        "bf_private_dir" => {
            let wanted = if args.len() > 1 {
                uid.wrapping_add(1)
            } else {
                uid
            };
            body_check::private_directory_owned_by_current_user(
                &PyPath::new(text(&args[0])),
                wanted,
                None,
            )
            .into()
        }
        "bf_is_safe" => {
            let cwd = optional_text(&args[1]).map(PathBuf::from);
            let home = optional_text(&args[2]).map(PathBuf::from);
            body_check::github_pr_body_file_is_safe(
                text(&args[0]),
                cwd.as_deref(),
                home.as_deref(),
                ctx,
            )
            .into()
        }
        _ => return None,
    })
}

fn run_actions(function: &str, args: &[Value], ctx: &Ctx) -> Option<Value> {
    let cwd = || PyPath::new(text(&args[1]));
    Some(match function {
        "aw_workflow" => {
            let cwd = optional_text(&args[1]).map(PyPath::new);
            actions::is_nonexecuting_github_actions_read_workflow(text(&args[0]), cwd.as_ref(), ctx)
                .into()
        }
        "aw_pipeline" => {
            let cwd = args.get(2).and_then(optional_text).map(PyPath::new);
            kind_value(actions::safe_github_read_pipeline(
                text(&args[0]),
                &values(&args[1]),
                cwd.as_ref(),
                ctx,
            ))
        }
        "aw_env_safe" => {
            env_checks::shell_read_execution_environment_is_safe(&PyPath::new(text(&args[0])), ctx)
                .into()
        }
        "aw_loader_paths" => {
            env_checks::trusted_loader_paths(text(&args[0]), &cwd_at(&args[1]), ctx).into()
        }
        "aw_within" => {
            env_checks::path_is_within(&PyPath::new(text(&args[0])), &PyPath::new(text(&args[1])))
                .into()
        }
        "aw_trusted_exec" => {
            let names = strings(&args[0]);
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            env_checks::trusted_pipeline_executables(&names, &cwd(), ctx).into()
        }
        "aw_path_command" => env_checks::path_command_for_cwd(text(&args[0]), &cwd(), ctx)
            .map_or(Value::Null, Value::from),
        "aw_metadata_pipeline" => {
            actions::safe_actions_log_metadata_pipeline(&string_lists(&args[0]), &cwd(), ctx).into()
        }
        "aw_failed_pipeline" => {
            actions::safe_failed_log_filter_pipeline(&string_lists(&args[0]), &cwd(), ctx).into()
        }
        _ => return run_filters(function, args),
    })
}

fn cwd_at(value: &Value) -> PyPath {
    PyPath::new(text(value))
}

fn run_filters(function: &str, args: &[Value]) -> Option<Value> {
    Some(match function {
        "aw_segments" => filters::pipeline_segments(text(&args[0])).into(),
        "aw_substitute" => {
            filters::substitute_number_variables(&strings(&args[0]), &values(&args[1]))
                .map_or(Value::Null, Value::from)
        }
        "aw_stderr" => filters::without_safe_stderr_redirect(&strings(&args[0]))
            .map_or(Value::Null, Value::from),
        "aw_github_cmd" => filters::safe_actions_github_command(&strings(&args[0])).into(),
        "aw_run_view" => filters::safe_run_view_args(&strings(&args[0])).into(),
        "aw_api_options" => filters::safe_api_options(&strings(&args[0])).into(),
        "aw_output_kind" => kind_value(Some(filters::github_output_kind(&strings(&args[0])))),
        "aw_filter" => filters::safe_emitted_output_filter(&strings(&args[0])).into(),
        "aw_bound_matches" => {
            filters::filters_bound_emitted_matches(&string_lists(&args[0])).into()
        }
        "aw_bounded_count" => {
            filters::bounded_count(text(&args[0]), args[1].as_u64().expect("maximum")).into()
        }
        "aw_text_pipeline" => {
            filters::safe_text_filter_pipeline(text(&args[0]), &values(&args[1])).into()
        }
        "aw_echo" => filters::safe_echo(text(&args[0]), &values(&args[1])).into(),
        "aw_echo_tokens" => filters::safe_echo_tokens(&strings(&args[0]), &values(&args[1])).into(),
        "aw_log_args" => filters::safe_run_log_metadata_args(&strings(&args[0])).into(),
        "aw_log_grep" => filters::safe_log_metadata_grep(&strings(&args[0])).into(),
        _ => return None,
    })
}

fn run(function: &str, args: &[Value], ctx: &Ctx, uid: u32) -> Option<Value> {
    if function == "eph_safe" {
        return Some(eph::gh_pr_create_uses_safe_ephemeral_body(text(&args[0]), ctx).into());
    }
    run_ephemeral(function, args)
        .or_else(|| run_body_file(function, args, ctx, uid))
        .or_else(|| run_actions(function, args, ctx))
}

#[test]
fn github_body_checks_match_recorded_python() {
    let document = fixture();
    let scratch = build_tree(&document);
    let root = scratch.0.clone();
    let root_text = root.to_string_lossy().into_owned();
    let uid = fs::metadata(&root).expect("root").uid();
    let home = format!("{root_text}/home");
    let mut failures = Vec::new();
    let mut compared = 0usize;
    let mut functions = std::collections::BTreeSet::new();
    for case in document["cases"].as_array().expect("cases") {
        let function = case["fn"].as_str().expect("fn");
        let expected = bind(&root, &case["result"]);
        if expected.get("$raises").is_some() {
            // Python crashes on these inputs (for example `int("\u{b2}")`).
            continue;
        }
        let args = bind(&root, &case["args"]);
        let environment = bind(&root, &case["env"]);
        let host = Host {
            env: environment
                .as_object()
                .expect("env")
                .iter()
                .map(|(key, value)| (key.clone(), text(value).to_owned()))
                .collect(),
            root: root_text.clone(),
            uid,
        };
        let ctx = Ctx::new(&host, &root_text, &home);
        let Some(actual) = run(function, args.as_array().expect("args"), &ctx, uid) else {
            failures.push(format!("{function}: no replay entry"));
            continue;
        };
        compared += 1;
        functions.insert(function.to_owned());
        if actual != expected {
            failures.push(format!("{function} {args}: {actual} vs {expected}"));
        }
    }
    let failures = crate::sfrs_host_divergence::portable_failures(
        failures,
        &[
            ("bf_is_safe [\"PR-BODY.MD\"", 1),
            ("bf_is_safe [\"~/.omp/agent/sessions/s1/pr-body.md\"", 1),
            ("bf_authored_root ", 2),
            ("aw_path_command [\"gh\"", 1),
        ],
    );
    assert!(
        failures.is_empty(),
        "{} of {compared} github body vectors differ:\n{}",
        failures.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(compared > 10_000, "only {compared} vectors replayed");
    assert!(
        functions.len() >= 43,
        "only {} functions covered",
        functions.len()
    );
}
