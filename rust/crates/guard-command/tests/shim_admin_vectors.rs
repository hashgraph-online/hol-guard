//! Replays the package-shim admin parity vectors recorded from the Python
//! implementation that preceded the resident `shim_admin` op
//! (`scripts/ci/shim_admin_vector_recorder.py`).
//!
//! Each scenario builds a scratch tree, runs the same calls against
//! `guard_command::shims`, and compares every call's JSON result, the whole-tree
//! digest after each call, and the final tree. Scratch-directory-dependent text
//! and content digests are normalised exactly as the recorder does.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::Engine;
use guard_command::shims::{self, ProbeOptions, ShimContext, ShimFacts};
use serde_json::{json, Value};

#[path = "shim_admin_vectors/normalise.rs"]
mod normalise;

use normalise::{
    collect_hashes, remap_value, snapshot, substitute, tokenise, tree_digest, tree_files,
    ROOT_TOKEN,
};

// The POSIX fixture is recorded on a POSIX host and the Windows one on Windows:
// pathlib's `WindowsPath` cannot be built elsewhere, so each replays only on its
// own platform.
#[cfg(unix)]
const FIXTURE: &[u8] = include_bytes!("fixtures/shim_admin_vectors.v1.json.gz");
#[cfg(windows)]
const FIXTURE: &[u8] = include_bytes!("fixtures/shim_admin_vectors_windows.v1.json.gz");
const TRANSIENT_FRAGMENTS: [&str; 6] = [
    "/var/folders/",
    "/private/var/folders/",
    "/tmp/",
    "/private/tmp/",
    "/temp/",
    "pytest-of-",
];
#[cfg(unix)]
const MIN_SCENARIOS_RUN: usize = 300;
#[cfg(windows)]
const MIN_SCENARIOS_RUN: usize = 150;

fn apply_step(root: &Path, step: &Value) {
    let path = root.join(step["path"].as_str().expect("step path"));
    match step["op"].as_str().expect("step op") {
        "write" => {
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir parent");
            let data = match step.get("b64").and_then(Value::as_str) {
                Some(encoded) => base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .expect("b64"),
                None => step["text"].as_str().expect("text").as_bytes().to_vec(),
            };
            fs::write(&path, data).expect("write");
            #[cfg(unix)]
            {
                let mode = if step.get("exec").and_then(Value::as_bool) == Some(true) {
                    0o755
                } else {
                    0o644
                };
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
            }
        }
        "append" => {
            use std::io::Write;
            let mut handle = fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open");
            handle
                .write_all(step["text"].as_str().expect("text").as_bytes())
                .expect("append");
        }
        "mkdir" => fs::create_dir_all(&path).expect("mkdir"),
        #[cfg(unix)]
        "symlink" => {
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir parent");
            symlink(step["target"].as_str().expect("target"), &path).expect("symlink");
        }
        "remove" => {
            let meta = fs::symlink_metadata(&path);
            match meta {
                Ok(meta) if meta.is_dir() => fs::remove_dir_all(&path).expect("rmdir"),
                Ok(_) => fs::remove_file(&path).expect("unlink"),
                Err(_) => {}
            }
        }
        other => panic!("unknown step op {other}"),
    }
}

fn string_of(value: &Value) -> String {
    value.as_str().expect("string").to_owned()
}

fn facts_from(value: &Value) -> ShimFacts {
    ShimFacts {
        environ: value["environ"]
            .as_object()
            .expect("environ")
            .iter()
            .map(|(key, item)| (key.clone(), string_of(item)))
            .collect(),
        home: string_of(&value["home"]),
        cwd: string_of(&value["cwd"]),
        executable: string_of(&value["executable"]),
        frozen: value["frozen"].as_bool().expect("frozen"),
        frozen_cli: string_of(&value["frozen_cli"]),
        trusted_frozen_cli_paths: value["trusted_frozen_cli_paths"]
            .as_array()
            .expect("trusted")
            .iter()
            .map(string_of)
            .collect(),
        python_version: (
            value["python_version"][0].as_u64().expect("major") as u32,
            value["python_version"][1].as_u64().expect("minor") as u32,
        ),
        import_root: string_of(&value["import_root"]),
        argv0: value["argv0"].as_str().map(str::to_owned),
        windows: value["windows"].as_bool().expect("windows"),
        sqlite_connect_timeout_seconds: value["sqlite_connect_timeout_seconds"]
            .as_f64()
            .expect("timeout"),
        now: string_of(&value["now"]),
        shim_dir_transient: value.get("shim_dir_transient").and_then(Value::as_bool),
    }
}

fn to_value<T: serde::Serialize>(result: Result<T, String>) -> Result<Value, String> {
    result.map(|item| serde_json::to_value(item).expect("serialise"))
}

fn run_call(context: &ShimContext, subop: &str, args: &Value) -> Result<Value, String> {
    let managers: Option<Vec<String>> = args
        .get("managers")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(string_of).collect());
    let managers = managers.as_deref();
    let path_env = args.get("path_env").and_then(Value::as_str);
    let flag = |name: &str| args.get(name).and_then(Value::as_bool).unwrap_or(false);
    match subop {
        "status" => to_value(shims::package_shim_status(context, path_env)),
        "dashboard_status" => to_value(shims::package_shim_dashboard_status(context)),
        "cloud_coverage" => shims::package_shim_cloud_coverage(
            context,
            args.get("generated_at").and_then(Value::as_str),
        ),
        "path_order" => to_value(shims::get_path_order_status(
            context,
            args["manager"].as_str().expect("manager"),
            path_env,
        )),
        "install" => to_value(shims::install_package_shims(context, managers, path_env)),
        "activate" => to_value(shims::activate_package_shims(
            context,
            managers,
            flag("repair"),
        )),
        "repair" => to_value(shims::repair_package_shims(context, managers, path_env)),
        "uninstall" => to_value(shims::uninstall_package_shims(context, managers)),
        "probe_intercepts" => to_value(shims::probe_package_shim_intercepts(
            context,
            &ProbeOptions {
                managers: managers.map(<[String]>::to_vec),
                workspace_dir: args
                    .get("workspace_dir")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                allow_inactive_path: flag("allow_inactive_path"),
                project_shell_profile: flag("project_shell_profile"),
                timeout_seconds: args["timeout_seconds"].as_u64().expect("timeout"),
            },
        )),
        "supported_managers" => Ok(json!(shims::package_shim_supported_managers())),
        "ensure_package_shim_profile" => shims::ensure_package_shim_path_in_shell_profile(context),
        "remove_guard_profile_blocks" => shims::remove_guard_profile_blocks(context),
        other => panic!("unknown subop {other}"),
    }
}

fn is_transient(root: &str) -> bool {
    TRANSIENT_FRAGMENTS
        .iter()
        .any(|fragment| root.contains(fragment))
}

fn root_base() -> PathBuf {
    // `target/tmp` itself reads as transient (`/tmp/`), so default to a sibling.
    let default = Path::new(env!("CARGO_TARGET_TMPDIR")).with_file_name("shim-vectors");
    let base = std::env::var_os("SHIM_VECTOR_ROOT_BASE").map_or(default, PathBuf::from);
    fs::create_dir_all(&base).expect("root base");
    let base = plain_path(fs::canonicalize(base).expect("canonical base"));
    assert!(
        base.to_string_lossy()
            .chars()
            .all(|c| c.is_ascii_alphanumeric()
                || matches!(c, '.' | '_' | '/' | '-')
                || (cfg!(windows) && matches!(c, '\\' | ':'))),
        "root base {} has characters the vectors do not model",
        base.display()
    );
    base
}

/// `canonicalize` yields `\\?\C:\...` on Windows; Python's `realpath` does not.
fn plain_path(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix("\\\\?\\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path,
    }
}

fn first_difference(left: &Value, right: &Value) -> String {
    if let (Value::Object(a), Value::Object(b)) = (left, right) {
        for key in a.keys().chain(b.keys()) {
            if a.get(key) != b.get(key) {
                return format!(
                    "{key}: got {} expected {}",
                    shorten(a.get(key)),
                    shorten(b.get(key))
                );
            }
        }
    }
    format!(
        "got {} expected {}",
        shorten(Some(left)),
        shorten(Some(right))
    )
}

fn shorten(value: Option<&Value>) -> String {
    let text = value.map_or_else(|| "<absent>".to_owned(), Value::to_string);
    if text.len() > 600 {
        format!(
            "{}...",
            &text[..text.char_indices().nth(600).map_or(text.len(), |(i, _)| i)]
        )
    } else {
        text
    }
}

fn run_scenario(scenario: &Value, base: &Path, index: usize) -> Vec<String> {
    let name = string_of(&scenario["name"]);
    let root = base.join(format!("v{}-{index}", std::process::id()));
    fs::create_dir_all(&root).expect("scenario root");
    let root_text = root.to_string_lossy().into_owned();
    let expand = |value: &Value| substitute(value, ROOT_TOKEN, &root_text);
    let facts = expand(&scenario["facts"]);
    let context_spec = expand(&scenario["context"]);
    let context = ShimContext::new(
        context_spec["guard_home"].as_str().expect("guard_home"),
        context_spec["home_dir"].as_str(),
        context_spec["workspace_dir"]
            .as_str()
            .filter(|text| !text.is_empty()),
        facts_from(&facts),
    );
    let expected_calls = scenario["expected"]["calls"].as_array().expect("calls");
    let mut failures = Vec::new();
    let mut hashes = BTreeMap::new();
    let mut call_index = 0;
    for step in scenario["steps"].as_array().expect("steps") {
        let step = expand(step);
        if step["op"] != "call" {
            apply_step(&root, &step);
            continue;
        }
        collect_hashes(&snapshot(&root), &root_text, &mut hashes);
        let outcome = run_call(
            &context,
            step["subop"].as_str().expect("subop"),
            &step["args"],
        );
        let after = snapshot(&root);
        collect_hashes(&after, &root_text, &mut hashes);
        let expected = &expected_calls[call_index];
        match (&outcome, expected["ok"].as_bool().expect("ok")) {
            (Ok(result), true) => {
                let got = remap_value(&tokenise(result, &root_text), &hashes);
                if got != expected["result"] {
                    failures.push(format!(
                        "{name} call {call_index} ({}): result {}",
                        step["subop"],
                        first_difference(&got, &expected["result"])
                    ));
                }
            }
            (Err(_), false) => {}
            (Ok(_), false) => failures.push(format!(
                "{name} call {call_index}: expected failure, got success"
            )),
            (Err(error), true) => failures.push(format!(
                "{name} call {call_index} ({}): unexpected error {error}",
                step["subop"]
            )),
        }
        collect_hashes(&after, &root_text, &mut hashes);
        let digest = tree_digest(&after, &root_text, &hashes);
        if digest != expected["tree"] {
            failures.push(format!(
                "{name} call {call_index} ({}): tree {}",
                step["subop"],
                first_difference(&digest, &expected["tree"])
            ));
        }
        call_index += 1;
    }
    let final_tree = snapshot(&root);
    collect_hashes(&final_tree, &root_text, &mut hashes);
    let files = tree_files(&final_tree, &root_text, &hashes);
    if files != scenario["expected"]["files"] {
        failures.push(format!(
            "{name} final tree: {}",
            first_difference(&files, &scenario["expected"]["files"])
        ));
    }
    let _ = fs::remove_dir_all(&root);
    failures
}

#[test]
fn shim_admin_matches_recorded_python_vectors() {
    let mut json_text = String::new();
    flate2::read::GzDecoder::new(FIXTURE)
        .read_to_string(&mut json_text)
        .expect("gunzip fixture");
    let document: Value = serde_json::from_str(&json_text).expect("fixture json");
    assert_eq!(document["schema"], "guard-shim-admin-vectors.v1");
    let base = root_base();
    let base_text = format!("{}/", base.display());
    let ci = std::env::var_os("CI").is_some();
    let mut failures = Vec::new();
    let mut ran = 0;
    for (index, scenario) in document["scenarios"]
        .as_array()
        .expect("scenarios")
        .iter()
        .enumerate()
    {
        if scenario["durable_root"] == true && is_transient(&base_text) {
            assert!(
                !ci,
                "durable-root scenarios need a non-transient root base in CI"
            );
            continue;
        }
        failures.extend(run_scenario(scenario, &base, index));
        ran += 1;
    }
    assert!(
        failures.is_empty(),
        "{} mismatches:\n{}",
        failures.len(),
        failures
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(ran >= MIN_SCENARIOS_RUN || !ci, "only {ran} scenarios ran");
}
