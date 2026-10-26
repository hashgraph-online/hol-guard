//! Parity of the leaf secret-file-request checks (read-only Git audit, origin
//! fetch, Guard self-approval, routine move, environment dump, read-only Perl)
//! against recorded Python output. The fixture holds a directory tree and cases
//! whose paths carry a `{ROOT}` token; the tree is rebuilt below a fresh root.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::codex_output_env::{Ctx, GitCheck, GitRun, InspectionHost};
use crate::codex_output_py::PyPath;
use crate::sfrs_git_audit::is_read_only_git_ancestry_audit;
use crate::sfrs_git_fetch::{
    command_is_origin_shaped_git_fetch, git_fetch_operands, origin_shaped_git_fetch_args,
};
use crate::sfrs_perl_read_only::{
    looks_like_read_only_perl_filter, perl_execution_environment_is_safe, perl_print_if_pattern,
    trusted_perl_command,
};
use crate::sfrs_routine_move::looks_like_safe_routine_move;
use crate::sfrs_self_approval as approval;
use crate::sfrs_shell_tokens::{iter_shell_command_segments, split_shell_parts};

const TOKEN: &str = "{ROOT}";

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Mirrors the recorder stand-ins for the resident's Git trust answers.
struct Host {
    env: BTreeMap<String, String>,
}

impl InspectionHost for Host {
    fn env(&self, name: &str) -> Option<String> {
        self.env.get(name).cloned()
    }
    fn git_executable(&self) -> Option<String> {
        None
    }
    fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
        false
    }
    fn git_binary_trusted(&self, _git: &str, cwd: &str) -> bool {
        !cwd.contains("untrusted")
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("unavailable")
    }
    fn git_log_execution_free_config(&self, cwd: &str, _git: &str) -> bool {
        !cwd.contains("badconfig")
    }
}

fn fixture() -> Value {
    let bytes = include_bytes!("../tests/fixtures/sfrs/sfrs_leaf.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    serde_json::from_str(&text).expect("json")
}

fn build_tree(document: &Value) -> Scratch {
    let base = fs::canonicalize(std::env::temp_dir()).expect("temp dir");
    let root = base.join(format!("sfrs-leaf-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("root");
    let tree = &document["tree"];
    for name in tree["dirs"].as_array().expect("dirs") {
        fs::create_dir_all(root.join(name.as_str().expect("dir"))).expect("dir");
    }
    for (name, text) in tree["files"].as_object().expect("files") {
        let path = root.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("parent");
        fs::write(path, text.as_str().expect("text")).expect("file");
    }
    for name in tree["executables"].as_array().expect("executables") {
        let path = root.join(name.as_str().expect("exe"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    for (name, target) in tree["links"].as_object().expect("links") {
        symlink(target.as_str().expect("target"), root.join(name)).expect("link");
    }
    let bin = root.join("home/proj/bin");
    fs::create_dir_all(&bin).expect("bin");
    fs::write(bin.join("perl"), "#!/bin/sh\n").expect("perl");
    fs::set_permissions(bin.join("perl"), fs::Permissions::from_mode(0o700)).expect("mode");
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

fn name_list(items: &[String]) -> Vec<&str> {
    items.iter().map(String::as_str).collect()
}

fn segments_of(source: &str) -> Vec<Vec<String>> {
    iter_shell_command_segments(&split_shell_parts(source))
}

fn merge_env(env: &mut BTreeMap<String, String>, value: &Value) {
    for (key, item) in value.as_object().expect("env") {
        env.insert(key.clone(), text(item).to_owned());
    }
}

fn run(function: &str, args: &[Value], root: &Path) -> Option<Value> {
    let proj = root.join("home/proj").to_string_lossy().into_owned();
    let home = root.join("home").to_string_lossy().into_owned();
    let mut env = BTreeMap::new();
    env.insert(
        "PATH".to_owned(),
        root.join("home/bin").to_string_lossy().into_owned(),
    );
    env.insert(
        "TMPDIR".to_owned(),
        root.join("tmp").to_string_lossy().into_owned(),
    );
    match function {
        "perl_read_only" => merge_env(&mut env, &args[3]),
        "perl_trusted_command" => merge_env(&mut env, &args[2]),
        "perl_environment_safe" => merge_env(&mut env, &args[0]),
        _ => {}
    }
    let host = Host { env };
    let ctx = Ctx::new(&host, &proj, &home);
    Some(match function {
        "read_only_git_audit" => is_read_only_git_ancestry_audit(
            text(&args[0]),
            optional_path(&args[1]).as_deref(),
            Path::new(text(&args[2])),
            &ctx,
        )
        .into(),
        "origin_shaped_git_fetch_args" => origin_shaped_git_fetch_args(&strings(&args[0])).into(),
        "git_fetch_operands_text" => Value::Array(
            segments_of(text(&args[0]))
                .iter()
                .map(|segment| git_fetch_operands(segment).map_or(Value::Null, Value::from))
                .collect(),
        ),
        "git_fetch_operands" => {
            git_fetch_operands(&strings(&args[0])).map_or(Value::Null, Value::from)
        }
        "command_is_origin_shaped_git_fetch" => {
            command_is_origin_shaped_git_fetch(&segments_of(text(&args[0]))).into()
        }
        "is_guard_approval_mutation_command" => {
            approval::is_guard_approval_mutation_command(text(&args[0])).into()
        }
        "approval_from_agent" => {
            let map = args[0].as_object().expect("env");
            approval::approval_resolution_invoked_from_agent(&|name| {
                map.get(name).map(|value| text(value).to_owned())
            })
            .into()
        }
        "approval_split_shell_parts" => approval::split_shell_parts(text(&args[0])).into(),
        "approval_shell_segments" => approval::shell_segments(&strings(&args[0])).into(),
        "approval_segment" => approval::segment_is_guard_approval_mutation(
            &strings(&args[0]),
            usize::try_from(args[1].as_u64().expect("depth")).expect("depth"),
        )
        .into(),
        "approval_first_executable_index" => {
            approval::first_executable_index(&strings(&args[0])).map_or(Value::Null, Value::from)
        }
        "approval_python_args" => {
            approval::python_module_args_mutate_approvals(&strings(&args[0])).into()
        }
        "approval_guard_args" => approval::guard_args_mutate_approvals(&strings(&args[0])).into(),
        "approval_tail_mutation" => approval::approval_tail_has_mutation(&strings(&args[0])).into(),
        "approval_runner_tail" => approval::runner_wrapper_tail(text(&args[0]), &strings(&args[1]))
            .map_or(Value::Null, Value::from),
        "approval_tail_after_subcommand" => {
            let names = strings(&args[1]);
            approval::tail_after_subcommand(&strings(&args[0]), &name_list(&names))
                .map_or(Value::Null, Value::from)
        }
        "approval_tail_after_flag" => approval::tail_after_flag(&strings(&args[0]), text(&args[1]))
            .map_or(Value::Null, Value::from),
        "approval_looks_env_assignment" => approval::looks_env_assignment(text(&args[0])).into(),
        "approval_is_python" => approval::is_python_interpreter(text(&args[0])).into(),
        "routine_move" => looks_like_safe_routine_move(
            &split_shell_parts(text(&args[0])),
            optional_path(&args[1]).as_deref(),
            optional_path(&args[2]).as_deref(),
            &ctx,
        )
        .into(),
        "perl_read_only" => looks_like_read_only_perl_filter(
            text(&args[0]),
            optional_path(&args[1]).as_deref(),
            optional_path(&args[2]).as_deref(),
            &ctx,
        )
        .into(),
        "perl_environment_safe" => perl_execution_environment_is_safe(&ctx).into(),
        "perl_trusted_command" => {
            trusted_perl_command(text(&args[0]), &PyPath::new(text(&args[1])), &ctx).into()
        }
        "perl_print_if_pattern" => {
            perl_print_if_pattern(text(&args[0])).map_or(Value::Null, Value::from)
        }
        _ => return None,
    })
}

#[test]
fn leaf_checks_match_recorded_python() {
    let document = fixture();
    let scratch = build_tree(&document);
    let root = scratch.0.clone();
    let mut failures = Vec::new();
    let mut compared = 0usize;
    for case in document["cases"].as_array().expect("cases") {
        let function = case["fn"].as_str().expect("fn");
        let args = bind(&root, &case["args"]);
        let expected = bind(&root, &case["result"]);
        let actual = run(function, args.as_array().expect("args"), &root)
            .unwrap_or_else(|| panic!("unknown function {function}"));
        compared += 1;
        if actual != expected {
            failures.push(format!("{function} {args}: {actual} vs {expected}"));
        }
    }
    assert!(compared > 6000, "too few cases: {compared}");
    let failures = crate::sfrs_host_divergence::portable_failures(
        failures,
        &[("routine_move [\"mv BUILD build3\"", 2)],
    );
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(8)]
    );
}
