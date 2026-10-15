//! Parity of the routine git, setup and developer recognizers against recorded
//! Python output. Each case carries a scenario that drives the stand-in host
//! (git, trust and PATH services); the recorder applies the same scenario to
//! Python. The fixture holds a tree whose paths carry a `{ROOT}` token.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::codex_output_env::{Ctx, GitCheck, GitProbe, GitRun, InspectionHost};
use crate::codex_output_py::PyPath;
use crate::sfrs_developer_graph::GraphInputs;
use crate::sfrs_developer_routines as dev;
use crate::sfrs_fs_vectors::Scratch;
use crate::sfrs_git_routines as git;
use crate::sfrs_routine_setup as setup;
use crate::sfrs_shell_tokens::split_shell_parts;
use guard_contracts::CompoundGitSegmentV1;

const TOKEN: &str = "{ROOT}";
const SAFE_STATUS: [&str; 8] = [
    "--short",
    "-s",
    "-sb",
    "-b",
    "--branch",
    "--porcelain",
    "--porcelain=v1",
    "--ignored",
];

fn fixture() -> Value {
    let bytes = include_bytes!("../tests/fixtures/sfrs/routines.json.gz");
    let mut text = String::new();
    flate2::read::GzDecoder::new(&bytes[..])
        .read_to_string(&mut text)
        .expect("gzip");
    serde_json::from_str(&text).expect("json")
}

fn build_tree(document: &Value) -> Scratch {
    let base = fs::canonicalize(std::env::temp_dir()).expect("temp dir");
    let root = base.join(format!("sfrs-routines-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("root");
    let tree = &document["tree"];
    for name in tree["dirs"].as_array().expect("dirs") {
        fs::create_dir_all(root.join(name.as_str().expect("dir"))).expect("dir");
    }
    for (name, spec) in tree["files"].as_object().expect("files") {
        let path = root.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("parent");
        let bytes = match spec.as_str() {
            Some(text) => text.to_owned(),
            None => spec["repeat"]
                .as_str()
                .expect("repeat")
                .repeat(spec["count"].as_u64().expect("count") as usize),
        };
        fs::write(path, bytes).expect("file");
    }
    for name in tree["exec"].as_array().expect("exec") {
        let path = root.join(name.as_str().expect("exec"));
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("mode");
    }
    for (name, target) in tree["links"].as_object().expect("links") {
        let path = root.join(name);
        fs::create_dir_all(path.parent().expect("parent")).expect("parent");
        symlink(target.as_str().expect("target"), path).expect("link");
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

fn opt_path(value: &Value) -> Option<&Path> {
    value.as_str().map(Path::new)
}

/// Mirrors the recorder's stand-ins, driven by the case scenario.
struct Host {
    sc: Value,
    root: PathBuf,
}

impl Host {
    fn flag(&self, key: &str) -> bool {
        self.sc[key].as_bool().expect("flag")
    }
    fn trusted(&self, name: &str) -> bool {
        self.sc["trusted"][name].as_bool().unwrap_or(false)
    }
    fn which(&self, name: &str) -> Option<String> {
        self.sc["which"][name].as_str().map(str::to_owned)
    }
    fn probe_row(row: &Value) -> Option<GitProbe> {
        if row.is_null() {
            return None;
        }
        let cell = |at: usize| row.get(at).and_then(Value::as_str).unwrap_or("").to_owned();
        Some(GitProbe {
            code: row[0].as_i64().expect("code") as i32,
            stdout: cell(1),
            stderr: cell(2),
        })
    }
}

impl InspectionHost for Host {
    fn env(&self, name: &str) -> Option<String> {
        match name {
            "PATH" => Some("/usr/bin:/bin".to_owned()),
            "HOME" => Some(self.root.join("home").to_string_lossy().into_owned()),
            _ => self.sc["env"][name].as_str().map(str::to_owned),
        }
    }
    fn git_executable(&self) -> Option<String> {
        self.which("git")
    }
    fn git_safety(&self, check: GitCheck, cwd: Option<&str>, args: &[String]) -> bool {
        match check {
            GitCheck::ConfigEnvironmentClean => self.flag("env_clean"),
            GitCheck::StatusArguments => {
                args.first().is_some_and(|first| first == "status")
                    && args[1..]
                        .iter()
                        .all(|arg| SAFE_STATUS.contains(&arg.as_str()))
            }
            GitCheck::StatusConfig => {
                self.flag("status_cfg") && !cwd.unwrap_or("").contains("unsafe-cfg")
            }
            GitCheck::ResolveBinary => false,
        }
    }
    fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
        self.trusted("git")
    }
    fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
        GitRun::Failed("unavailable")
    }
    fn cached_diff_pathspecs(&self, values: &[String]) -> bool {
        !values.is_empty()
            && values
                .iter()
                .all(|value| !value.is_empty() && !value.starts_with('-') && !value.contains("bad"))
    }
    fn git_inspection_segment(&self, segment: &CompoundGitSegmentV1, _: Option<&str>) -> bool {
        !segment
            .tokens
            .iter()
            .any(|token| token.contains("unsafe-seg"))
    }
    fn git_show_config(&self, _: &CompoundGitSegmentV1, repository_path: Option<&str>) -> bool {
        repository_path.is_none_or(|path| !path.contains("unsafe-repo"))
    }
    fn standalone_git_routine(
        &self,
        segments: &[CompoundGitSegmentV1],
        complete: bool,
        home_dir: Option<&str>,
    ) -> bool {
        let mut tokens = segments.iter().flat_map(|segment| &segment.tokens);
        complete
            && segments
                .iter()
                .flat_map(|segment| &segment.tokens)
                .any(|token| token.contains("standalone-ok"))
            && (home_dir.is_some() || !tokens.any(|token| token.contains("home-ok")))
    }
    fn trusted_path_command(&self, command: &str, _: &str, _: &str) -> bool {
        self.trusted(command)
    }
    fn trusted_git_binary(&self, _: &str) -> Option<String> {
        self.flag("git_binary").then(|| "/usr/bin/git".to_owned())
    }
    fn git_probe(&self, _: &str, args: &[String], _: &str) -> Option<GitProbe> {
        probe(&self.sc, args)
    }
    fn git_worktree_add_config(&self, _: &str, _: &str, _: &str) -> bool {
        self.flag("wt_config")
    }
    fn git_lfs_trusted(&self, _: &str) -> bool {
        self.which("git-lfs").is_some() && self.trusted("git-lfs")
    }
    fn home_git_c_path(&self, command: &str) -> Option<String> {
        command.contains("homec").then(|| "/h".to_owned())
    }
    fn git_object_existence_query(&self, command: &str, _: &str) -> bool {
        command.contains("objexist")
    }
}

/// Mirrors the recorder's deterministic `git` subprocess stand-in.
fn probe(sc: &Value, argv: &[String]) -> Option<GitProbe> {
    let key = argv.join(" ");
    if let Some(row) = sc["probes"].get(&key) {
        return Host::probe_row(row);
    }
    let word = |at: usize| argv.get(at).map(String::as_str);
    let listed = |list: &str, name: &str| {
        sc[list]
            .as_array()
            .expect("list")
            .iter()
            .any(|item| item.as_str() == Some(name))
    };
    let rows = |code: i32, stdout: &str, stderr: &str| {
        Some(GitProbe {
            code,
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
        })
    };
    let pair = |row: &Value| {
        (
            row[0].as_i64().expect("code") as i32,
            text(&row[1]).to_owned(),
        )
    };
    match (word(0), word(1), word(2)) {
        (Some("rev-parse"), Some("--verify"), Some("--quiet")) => {
            let target = word(3).unwrap_or("");
            let reference = target.strip_suffix("^{commit}").unwrap_or(target);
            let known = match reference.strip_prefix("refs/heads/") {
                Some(branch) => listed("branches", branch),
                None => listed("refs", reference),
            };
            if known {
                rows(0, &format!("{}\n", text(&sc["sha"])), "")
            } else {
                rows(1, "", "")
            }
        }
        (Some("show-ref"), Some("--verify"), Some("--quiet")) => {
            let mode = text(&sc["branch_probe"]);
            if mode == "fail" {
                return None;
            }
            let target = word(3).unwrap_or("");
            if listed(
                "branches",
                target.strip_prefix("refs/heads/").unwrap_or(target),
            ) {
                rows(0, "", "")
            } else {
                rows(1, "", if mode == "noise" { "warn" } else { "" })
            }
        }
        (Some("config"), Some("--null"), Some("--get-regexp")) => {
            let (code, out) = pair(&sc["config_regexp"]);
            rows(code, &out, "")
        }
        (Some("config"), Some("--null"), Some("--get-all")) => {
            let found = sc["pager_cfg"].get(word(3).unwrap_or(""));
            let (code, out) = found.map_or((1, String::new()), pair);
            rows(code, &out, "")
        }
        (Some("rev-parse"), Some("--git-path"), _) => {
            let (code, out) = pair(&sc["hook"]);
            rows(code, &format!("{out}\n"), "")
        }
        (Some("rev-parse"), Some("--absolute-git-dir"), _) => {
            let (code, out) = pair(&sc["git_dir"]);
            rows(code, &format!("{out}\n"), "")
        }
        _ => rows(128, "", "fatal"),
    }
}

fn run(function: &str, args: &[Value], root: &Path) -> Option<Value> {
    let sc = args.last().expect("scenario").clone();
    let host = Host {
        sc,
        root: root.to_path_buf(),
    };
    let home = root.join("home");
    let ctx = Ctx::new(
        &host,
        &home.join("proj").to_string_lossy(),
        &home.to_string_lossy(),
    );
    let py = |value: &Value| PyPath::new(text(value));
    let owned = strings;
    Some(match function {
        "git_standalone_routine" => git::looks_like_safe_standalone_git_routine(
            text(&args[0]),
            opt_path(&args[1]),
            opt_path(&args[2]),
            &ctx,
        )
        .into(),
        "git_status_command" => git::looks_like_safe_git_status_command(
            text(&args[0]),
            &split_shell_parts(text(&args[0])),
            opt_path(&args[1]),
            &ctx,
        )
        .into(),
        "git_branch_switch_command" => git::looks_like_safe_git_branch_switch_command(
            text(&args[0]),
            &split_shell_parts(text(&args[0])),
            opt_path(&args[1]),
            &ctx,
        )
        .into(),
        "git_local_branch_switch_is_safe" => {
            git::git_local_branch_switch_is_safe(&owned(&args[0]), Path::new(text(&args[1])), &ctx)
                .into()
        }
        "git_checkout_config_safe" => git::git_checkout_execution_config_is_safe(
            text(&args[0]),
            Path::new(text(&args[1])),
            &ctx,
        )
        .into(),
        "read_only_git_invocation" => {
            match git::read_only_git_invocation(&owned(&args[0]), Path::new(text(&args[1])), &ctx) {
                None => Value::Null,
                Some((operation, cwd)) => json!([operation, cwd.to_string_lossy()]),
            }
        }
        "git_log_config" => git::git_log_has_execution_free_config(
            Path::new(text(&args[0])),
            args[1].as_str(),
            &ctx,
        )
        .into(),
        "git_worktree_add" => setup::is_safe_git_worktree_add(
            text(&args[0]),
            opt_path(&args[1]),
            Path::new(text(&args[2])),
            &ctx,
        )
        .into(),
        "memory_registry_search" => setup::is_safe_codex_memory_registry_search(
            text(&args[0]),
            opt_path(&args[1]),
            Path::new(text(&args[2])),
            &ctx,
        )
        .into(),
        "safe_path_operand" => setup::safe_path_operand(text(&args[0])).into(),
        "safe_git_name" => {
            let pattern = if text(&args[0]) == "branch" {
                &*setup::BRANCH
            } else {
                &*setup::REF
            };
            setup::safe_git_name(text(&args[1]), pattern).into()
        }
        "literal_tokens" => setup::literal_tokens(text(&args[0])).map_or(Value::Null, Value::from),
        "expand_path" => Value::from(
            setup::expand_path(text(&args[0]), &py(&args[1]), Path::new(text(&args[2])))
                .to_string(),
        ),
        "absolute_destination" => Value::from(
            setup::absolute_destination(
                text(&args[0]),
                &py(&args[1]),
                Path::new(text(&args[2])),
                &ctx,
            )
            .to_string(),
        ),
        "safe_worktree_parent" => {
            setup::safe_worktree_parent(&py(&args[0]), Path::new(text(&args[1])), &ctx).into()
        }
        "path_has_symlink_below_home" => {
            setup::path_has_symlink_below_home(&py(&args[0]), &py(&args[1]), &ctx).into()
        }
        "git_ref_exists" => {
            setup::git_ref_exists("/usr/bin/git", text(&args[0]), text(&args[1]), &ctx).into()
        }
        "git_branch_exists" => {
            setup::git_branch_exists("/usr/bin/git", text(&args[0]), text(&args[1]), &ctx).into()
        }
        "kubernetes_inventory_command" => dev::looks_like_safe_kubernetes_inventory_command(
            text(&args[0]),
            &split_shell_parts(text(&args[0])),
            opt_path(&args[1]),
            &ctx,
        )
        .into(),
        "compound_developer_inspection" => {
            let graph = GraphInputs {
                cwd: opt_path(&args[1]),
                home_dir: Path::new(text(&args[2])),
                ctx: &ctx,
                managed_bin_dirs: &[],
                classify_github: crate::sfrs_developer_graph_vectors::stand_in,
            };
            dev::looks_like_safe_compound_developer_inspection(text(&args[0]), &graph).into()
        }
        "cli_metadata_command" => dev::looks_like_safe_cli_metadata_command(
            text(&args[0]),
            &split_shell_parts(text(&args[0])),
            opt_path(&args[1]),
            &ctx,
            &[],
        )
        .into(),
        "dependency_symlink_context" => {
            match dev::safe_dependency_symlink_execution_context(
                text(&args[0]),
                opt_path(&args[1]),
                Path::new(text(&args[2])),
                &ctx,
            ) {
                None => Value::Null,
                Some(context) => json!({
                    "complete": context.complete,
                    "segments": context.segments.len(),
                    "command_text": context.command_text,
                    "workspace_root": context
                        .workspace_root
                        .as_ref()
                        .map(|path| path.to_string_lossy().into_owned()),
                }),
            }
        }
        _ => return None,
    })
}

#[test]
fn routines_match_recorded_python() {
    let document = fixture();
    let scratch = build_tree(&document);
    let root = scratch.0.clone();
    let mut failures = Vec::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for case in document["cases"].as_array().expect("cases") {
        let function = case["fn"].as_str().expect("fn");
        let args = bind(&root, &case["args"]);
        let expected = bind(&root, &case["result"]);
        let Some(actual) = run(function, args.as_array().expect("args"), &root) else {
            failures.push(format!("unhandled function {function}"));
            continue;
        };
        *counts.entry(function.to_owned()).or_default() += 1;
        if actual != expected {
            let shown = &args.as_array().expect("args")[..args.as_array().expect("args").len() - 1];
            let scenario = args
                .as_array()
                .and_then(|items| items.last())
                .map_or(String::new(), |sc| format!("{}", sc["env"]));
            failures.push(format!(
                "{function} {} sc-env={scenario}: rust {actual} vs python {expected}",
                Value::from(shown.to_vec())
            ));
        }
    }
    assert!(counts.len() >= 22, "too few functions: {counts:?}");
    let failures = crate::sfrs_host_divergence::portable_failures(
        failures,
        &[("git_worktree_add ", 11), ("safe_worktree_parent ", 3)],
    );
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(12)]
    );
}
