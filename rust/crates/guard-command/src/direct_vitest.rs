//! `runtime/direct_vitest.py` — bounded execution-context recovery for
//! verified local Vitest/TypeScript runs (617 lines — verbatim port, defmap
//! order).
//!
//! The Python file imports five runtime helpers that have no Rust peer module
//! yet (`node_semver_spec_matches`, `git_binary_path_is_trusted`,
//! `shell_read_execution_environment_is_safe`, `_trusted_loader_paths`,
//! `direct_typescript_diagnostic_filter_context` and its private helpers).
//! Minimal private copies live at the bottom of this file, guarded verbatim
//! so a later shared module can delete them wholesale.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::jsonc::loads_jsonc;
use crate::shell_execution_context::{
    model_shell_execution_context, ShellExecutionContext, ShellExecutionSegment,
};
use crate::shims::{package_shim_status, HarnessContext};

// ---------------------------------------------------------------------------
// Module constants (:27-41).
// ---------------------------------------------------------------------------

const LOCKFILE_NAMES: &[&str] = &["bun.lock", "package-lock.json"];
const DEPENDENCY_SECTIONS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PACKAGE_TREE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PACKAGE_TREE_FILES: usize = 10_000;

/// `_TRUSTED_TYPESCRIPT_PACKAGES` (:35-40) — (version, integrity) -> sha256
/// package-tree digest.
fn trusted_typescript_package_digest(version: &str, integrity: &str) -> Option<&'static str> {
    if version == "5.9.3"
        && integrity
            == "sha512-jl1vZzPDinLr9eUt3J/t7V6FgNEw9QjvBPdysz9KfQDD41fQrC2Y4vKQdiaUpFT4bXlb1RHhLpp8wtm6M5TgSw=="
    {
        Some("e5e331517b5c57cef26c6ed1c1dd2193ed52002a49a276cf7971b499c7f83b0f")
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Public entry points (defmap order).
// ---------------------------------------------------------------------------

/// `direct_local_vitest_execution_context` (:44-116).
pub fn direct_local_vitest_execution_context(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: &Path,
) -> Option<ShellExecutionContext> {
    let initial_root = cwd.unwrap_or(home_dir);
    let context = model_shell_execution_context(
        command_text,
        Some(initial_root),
        Some(initial_root),
        Some(home_dir),
    );
    let workspace = literal_leading_cd_target(&context, initial_root, home_dir)?;
    let context = model_shell_execution_context(
        command_text,
        Some(&workspace),
        Some(&workspace),
        Some(home_dir),
    );
    if !context.complete || context.segments.len() != 3 {
        return None;
    }
    let directory = &context.segments[0];
    let runner = &context.segments[1];
    if directory.directory_operation.as_deref() != Some("cd")
        || !directory.control_before.is_empty()
        || runner.control_before != ["&&"]
        || runner.effective_cwd.as_deref() != Some(workspace.as_path())
    {
        return None;
    }
    let mut runner_tokens = runner.tokens.clone();
    if runner_tokens.last().map(|s| s.as_str()) != Some("2>&1") {
        return None;
    }
    runner_tokens.pop();
    if runner_tokens.len() < 4 || runner_tokens.iter().any(|t| has_shell_dynamics(t)) {
        return None;
    }
    let (runner_path, args, require_no_coverage) =
        vitest_runner_invocation(&runner_tokens, &workspace, home_dir);
    let runner_path = runner_path?;
    let installed_version = verified_vitest_runner(&runner_path, &workspace, home_dir)?;
    if !workspace_vitest_version_is_bound(&workspace, &installed_version) {
        return None;
    }
    let no_coverage_count = args
        .iter()
        .filter(|a| a.as_str() == "--no-coverage")
        .count();
    if args.is_empty()
        || args[0] != "run"
        || no_coverage_count > 1
        || (require_no_coverage && no_coverage_count != 1)
    {
        return None;
    }
    let targets: Vec<&String> = args[1..]
        .iter()
        .filter(|arg| arg.as_str() != "--no-coverage")
        .collect();
    if targets.is_empty() || targets.iter().any(|arg| arg.starts_with('-')) {
        return None;
    }
    if !targets
        .iter()
        .all(|target| contained_test_target(target, &workspace))
    {
        return None;
    }
    if !bounded_output_filter(
        &context.segments[2].tokens,
        &context.segments[2].control_before,
        &workspace,
        home_dir,
    ) {
        return None;
    }
    Some(context)
}

/// `direct_local_typescript_execution_context` (:119-186).
pub fn direct_local_typescript_execution_context(
    command_text: &str,
    cwd: Option<&Path>,
    home_dir: &Path,
) -> Option<ShellExecutionContext> {
    let initial_root = cwd.unwrap_or(home_dir);
    let initial_context = model_shell_execution_context(
        command_text,
        Some(initial_root),
        Some(initial_root),
        Some(home_dir),
    );
    let workspace = literal_leading_cd_target(&initial_context, initial_root, home_dir)?;
    let context = model_shell_execution_context(
        command_text,
        Some(&workspace),
        Some(&workspace),
        Some(home_dir),
    );
    let diagnostic_filter_context = direct_typescript_diagnostic_filter_context(
        &context,
        &workspace,
        home_dir,
        trusted_path_command,
        workspace_typescript_is_bound,
    );
    if diagnostic_filter_context.is_some() {
        return diagnostic_filter_context;
    }
    if !context.complete || context.segments.len() != 5 {
        return None;
    }
    let directory = &context.segments[0];
    let compiler = &context.segments[1];
    let grep = &context.segments[2];
    let count = &context.segments[3];
    let marker = &context.segments[4];
    if directory.directory_operation.as_deref() != Some("cd")
        || !directory.control_before.is_empty()
        || compiler.control_before != ["&&"]
        || compiler.effective_cwd.as_deref() != Some(workspace.as_path())
        || grep.control_before != ["|"]
        || count.control_before != ["|"]
        || marker.control_before != [";"]
    {
        return None;
    }
    let mut compiler_tokens = compiler.tokens.clone();
    if compiler_tokens.last().map(|s| s.as_str()) != Some("2>&1") {
        return None;
    }
    compiler_tokens.pop();
    if compiler_tokens.len() != 5
        || !safe_node_heap_assignment(&compiler_tokens[0])
        || compiler_tokens[1..]
            != [
                "bun".to_owned(),
                "--smol".to_owned(),
                "./node_modules/typescript/bin/tsc".to_owned(),
                "--noEmit".to_owned(),
            ]
        || !trusted_path_command("bun", &workspace, home_dir)
        || bun_runtime_config_exists(&workspace, home_dir)
        || !workspace_typescript_is_bound(&workspace)
    {
        return None;
    }
    if grep.tokens != ["grep".to_owned(), "error TS".to_owned()]
        || count.tokens != ["wc".to_owned(), "-l".to_owned()]
        || !trusted_path_command("grep", &workspace, home_dir)
        || !trusted_path_command("wc", &workspace, home_dir)
    {
        return None;
    }
    if marker.tokens != ["echo".to_owned(), "MY_TSC_ERRORS_COUNT_DONE".to_owned()] {
        return None;
    }
    Some(context)
}

/// `_safe_node_heap_assignment` (:188-190).
fn safe_node_heap_assignment(token: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^NODE_OPTIONS=--max-old-space-size=([1-9][0-9]{2,4})$").unwrap()
    });
    match RE.captures(token) {
        Some(caps) => caps[1]
            .parse::<u32>()
            .map(|value| (256..=32768).contains(&value))
            .unwrap_or(false),
        None => false,
    }
}

/// `_bun_runtime_config_exists` (:191-205).
fn bun_runtime_config_exists(workspace: &Path, home_dir: &Path) -> bool {
    if env::var("BUN_OPTIONS")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    let xdg_config_home = env::var("XDG_CONFIG_HOME")
        .map(|v| v.trim().to_owned())
        .unwrap_or_default();
    for directory in workspace.ancestors() {
        let candidate = directory.join("bunfig.toml");
        if candidate.exists() && !bunfig_is_install_only(&candidate) {
            return true;
        }
    }
    let mut candidates = vec![home_dir.join(".bunfig.toml")];
    if !xdg_config_home.is_empty() {
        candidates.push(Path::new(&xdg_config_home).join(".bunfig.toml"));
    }
    candidates.iter().any(|candidate| candidate.exists())
}

/// `_bunfig_is_install_only` (:206-237).
fn bunfig_is_install_only(path: &Path) -> bool {
    let metadata = match path.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };
    if path.is_symlink() || !metadata.is_file() || metadata.size() > MAX_METADATA_BYTES {
        return false;
    }
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => return false,
    };
    let payload: toml::Value = match toml::from_str(&text) {
        Ok(payload) => payload,
        Err(_) => return false,
    };
    let table = match payload.as_table() {
        Some(table) => table,
        None => return false,
    };
    if table.len() != 1 || !table.contains_key("install") {
        return false;
    }
    let install = match table.get("install").and_then(|v| v.as_table()) {
        Some(install) => install,
        None => return false,
    };
    if !install
        .keys()
        .all(|key| matches!(key.as_str(), "linker" | "lockfile" | "smol"))
    {
        return false;
    }
    let linker = install.get("linker");
    let smol = install.get("smol");
    let lockfile = install.get("lockfile");
    if let Some(linker) = linker {
        if linker.as_str() != Some("hoisted") && linker.as_str() != Some("isolated") {
            return false;
        }
    }
    if let Some(smol) = smol {
        if !smol.is_bool() {
            return false;
        }
    }
    if lockfile.is_none() {
        return true;
    }
    let lockfile = match lockfile.and_then(|v| v.as_table()) {
        Some(lockfile) => lockfile,
        None => return false,
    };
    lockfile.len() <= 1
        && lockfile
            .get("save")
            .map(|v| v.is_bool())
            .unwrap_or(lockfile.is_empty())
        && lockfile.keys().all(|key| key == "save")
}

/// `_workspace_typescript_is_bound` (:239-269).
fn workspace_typescript_is_bound(workspace: &Path) -> bool {
    let package_dir = workspace.join("node_modules").join("typescript");
    let compiler = package_dir.join("bin").join("tsc");
    let package = read_package_json(&package_dir.join("package.json"));
    let package = match package {
        Some(package) => package,
        None => return false,
    };
    if package.get("name").and_then(Value::as_str) != Some("typescript") {
        return false;
    }
    let installed_version = package.get("version");
    let package_bin = package.get("bin");
    let bin_ok = installed_version.map(Value::is_string).unwrap_or(false)
        && package_bin
            .and_then(Value::as_object)
            .and_then(|bin| bin.get("tsc"))
            .and_then(Value::as_str)
            .map(|tsc| tsc == "bin/tsc" || tsc == "./bin/tsc")
            .unwrap_or(false);
    if !bin_ok {
        return false;
    }
    let resolved_compiler = match compiler.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => return false,
    };
    let resolved_workspace = match workspace.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => return false,
    };
    if resolved_compiler.strip_prefix(&resolved_workspace).is_err() {
        return false;
    }
    if compiler.is_symlink()
        || resolved_compiler != path_absolute(&compiler)
        || !resolved_compiler.is_file()
    {
        return false;
    }
    let declared_version = declared_dependency_version(workspace, "typescript");
    let lockfile = workspace.join("bun.lock");
    if declared_version.is_none()
        || !lockfile.is_file()
        || workspace.join("package-lock.json").exists()
    {
        return false;
    }
    let locked_identity = locked_bun_package_identity(&lockfile, "typescript");
    let installed_version = installed_version
        .and_then(Value::as_str)
        .unwrap_or_default();
    match locked_identity {
        Some((locked_version, integrity)) => {
            locked_version == installed_version
                && semver_spec_matches(&declared_version.unwrap_or_default(), installed_version)
                && typescript_package_has_trusted_identity(
                    &package_dir,
                    &locked_version,
                    &integrity,
                )
        }
        None => false,
    }
}

/// `_locked_bun_package_identity` (:271-293).
fn locked_bun_package_identity(path: &Path, package_name: &str) -> Option<(String, String)> {
    if path.is_symlink() || !path.is_file() || path.metadata().ok()?.size() > MAX_METADATA_BYTES {
        return None;
    }
    let lock_text = fs::read_to_string(path).ok()?;
    let lock = loads_jsonc(&lock_text).ok()?;
    let packages = lock.as_object()?.get("packages")?.as_object()?;
    let entry = packages.get(package_name)?.as_array()?;
    let first = entry.first()?.as_str()?;
    let prefix = format!("{package_name}@");
    if entry.len() <= 3 {
        return None;
    }
    let integrity = entry[3].as_str()?;
    if !first.starts_with(&prefix) || !integrity.starts_with("sha512-") {
        return None;
    }
    let decoded = strict_base64_decode(&integrity[7..])?;
    if decoded.len() != 64 {
        return None;
    }
    Some((first[prefix.len()..].to_owned(), integrity.to_owned()))
}

/// `_typescript_package_has_trusted_identity` (:295-306).
fn typescript_package_has_trusted_identity(
    package_dir: &Path,
    version: &str,
    integrity: &str,
) -> bool {
    let trusted_digest = match trusted_typescript_package_digest(version, integrity) {
        Some(digest) => digest,
        None => return false,
    };
    match package_tree_digest(package_dir) {
        Some(digest) => digest == trusted_digest,
        None => false,
    }
}

/// `_package_tree_digest` (:308-340). Returns `Err`-as-`None` since every
/// caller maps any failure to rejection.
fn package_tree_digest(root: &Path) -> Option<String> {
    let canonical_root = root.canonicalize().ok()?;
    if root.is_symlink() || !canonical_root.is_dir() {
        return None;
    }
    let mut records: Vec<(String, String)> = Vec::new();
    let mut total_bytes: u64 = 0;
    // `os.walk(followlinks=False)`, `directory_names.sort()`, `filenames.sort()`
    // — recursive pre-order walk over sorted children.
    let mut pending = vec![canonical_root.clone()];
    while let Some(directory_path) = pending.pop() {
        // Depth-first pre-order; pending is a stack, so push sorted dirs in
        // reverse to visit them in sorted order.
        let mut directory_names: Vec<PathBuf> = Vec::new();
        let mut filenames: Vec<String> = Vec::new();
        for entry in fs::read_dir(&directory_path).ok()? {
            let entry = entry.ok()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let file_type = entry.file_type().ok()?;
            if file_type.is_symlink() {
                return None;
            }
            if file_type.is_dir() {
                directory_names.push(entry.path());
            } else {
                filenames.push(name);
            }
        }
        directory_names.sort();
        filenames.sort();
        for filename in &filenames {
            let path = directory_path.join(filename);
            let metadata = path.metadata().ok()?;
            if !path.is_file() {
                return None;
            }
            total_bytes = total_bytes.checked_add(metadata.len())?;
            if records.len() >= MAX_PACKAGE_TREE_FILES || total_bytes > MAX_PACKAGE_TREE_BYTES {
                return None;
            }
            let content = fs::read(&path).ok()?;
            let relative = path
                .strip_prefix(&canonical_root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            records.push((relative, hex::encode(Sha256::digest(&content))));
        }
        for dir in directory_names.iter().rev() {
            pending.push(dir.clone());
        }
    }
    let encoded = py_json_tuple_list(&records);
    let mut hasher = Sha256::new();
    hasher.update(b"hol-guard:package-tree:v1\0");
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(&encoded);
    Some(hex::encode(hasher.finalize()))
}

/// `_declared_dependency_version` (:341-354).
fn declared_dependency_version(workspace: &Path, package_name: &str) -> Option<String> {
    let package = read_package_json(&workspace.join("package.json"))?;
    for section in DEPENDENCY_SECTIONS {
        let dependencies = match package.get(*section).and_then(Value::as_object) {
            Some(dependencies) => dependencies,
            None => continue,
        };
        if let Some(declared) = dependencies.get(package_name).and_then(Value::as_str) {
            return Some(declared.to_owned());
        }
    }
    None
}

/// `_vitest_runner_invocation` (:356-386).
fn vitest_runner_invocation(
    runner_tokens: &[String],
    workspace: &Path,
    home_dir: &Path,
) -> (Option<PathBuf>, Vec<String>, bool) {
    let executable = &runner_tokens[0];
    let runner_path = Path::new(executable);
    if runner_path.is_absolute() {
        return (
            Some(runner_path.to_path_buf()),
            runner_tokens[1..].to_vec(),
            true,
        );
    }
    if executable != "npx" || !trusted_path_command("npx", workspace, home_dir) {
        return (None, Vec::new(), false);
    }
    let mut index = 1usize;
    while index < runner_tokens.len()
        && matches!(runner_tokens[index].as_str(), "--no" | "--no-install")
    {
        index += 1;
    }
    if index >= runner_tokens.len() || runner_tokens[index] != "vitest" {
        return (None, Vec::new(), false);
    }
    let bin_entry = workspace.join("node_modules").join(".bin").join("vitest");
    let package_runner = workspace
        .join("node_modules")
        .join("vitest")
        .join("vitest.mjs");
    let (local_runner, resolved_bin_entry) =
        match (package_runner.canonicalize(), bin_entry.canonicalize()) {
            (Ok(local), Ok(bin)) => (local, bin),
            _ => return (None, Vec::new(), false),
        };
    if !bin_entry.is_symlink() || resolved_bin_entry != local_runner {
        return (None, Vec::new(), false);
    }
    let args = runner_tokens[index + 1..].to_vec();
    if args.is_empty() {
        return (None, Vec::new(), false);
    }
    (Some(local_runner), args, false)
}

/// `_literal_leading_cd_target` (:389-414).
fn literal_leading_cd_target(
    context: &ShellExecutionContext,
    initial_root: &Path,
    home_dir: &Path,
) -> Option<PathBuf> {
    let segment = context.segments.first()?;
    if !segment.control_before.is_empty()
        || segment.directory_operation.as_deref() != Some("cd")
        || segment.tokens.len() != 2
    {
        return None;
    }
    if segment.tokens[0]
        .trim_matches(|c| c == '"' || c == '\'')
        .to_lowercase()
        != "cd"
    {
        return None;
    }
    let operand = &segment.tokens[1];
    if has_shell_dynamics(operand) || (operand.starts_with('~') && !operand.starts_with("~/")) {
        return None;
    }
    let mut candidate = if let Some(rest) = operand.strip_prefix("~/") {
        home_dir.join(rest)
    } else {
        PathBuf::from(operand)
    };
    if !candidate.is_absolute() {
        candidate = initial_root.join(candidate);
    }
    let resolved = candidate.canonicalize().ok()?;
    if resolved.is_dir() {
        Some(resolved)
    } else {
        None
    }
}

/// `_verified_vitest_runner` (:415-448).
fn verified_vitest_runner(runner: &Path, cwd: &Path, home_dir: &Path) -> Option<String> {
    let package_dir = runner.parent()?;
    let node_modules = package_dir.parent()?;
    let project = node_modules.parent()?;
    let resolved_home = home_dir.canonicalize().ok()?;
    let resolved_runner = runner.canonicalize().ok()?;
    if resolved_runner.strip_prefix(&resolved_home).is_err() {
        return None;
    }
    if runner.file_name()?.to_string_lossy() != "vitest.mjs"
        || package_dir.file_name()?.to_string_lossy() != "vitest"
        || node_modules.file_name()?.to_string_lossy() != "node_modules"
        || runner.is_symlink()
        || package_dir.is_symlink()
        || node_modules.is_symlink()
        || resolved_runner != path_absolute(runner)
        || !resolved_runner.is_file()
        || resolved_runner.metadata().ok()?.mode() & 0o111 == 0
        || !trusted_env_node_runtime(&resolved_runner, cwd, home_dir)
    {
        return None;
    }
    let package = read_package_json(&package_dir.join("package.json"));
    let installed_version = match &package {
        Some(package) if package.get("name").and_then(Value::as_str) == Some("vitest") => {
            package.get("version").and_then(Value::as_str)
        }
        _ => None,
    };
    let package_bin = package.as_ref().and_then(|p| p.get("bin"));
    let bin_ok = package_bin
        .and_then(Value::as_object)
        .and_then(|bin| bin.get("vitest"))
        .and_then(Value::as_str)
        .map(|entry| entry == "vitest.mjs" || entry == "./vitest.mjs")
        .unwrap_or(false);
    if !bin_ok {
        return None;
    }
    let installed_version = installed_version?;
    if workspace_vitest_version_is_bound(project, installed_version) {
        Some(installed_version.to_owned())
    } else {
        None
    }
}

/// `_declared_vitest_version` (:450-462).
fn declared_vitest_version(workspace: &Path) -> Option<String> {
    let package = read_package_json(&workspace.join("package.json"))?;
    for section in DEPENDENCY_SECTIONS {
        let dependencies = match package.get(*section).and_then(Value::as_object) {
            Some(dependencies) => dependencies,
            None => continue,
        };
        if let Some(declared) = dependencies.get("vitest").and_then(Value::as_str) {
            return Some(declared.to_owned());
        }
    }
    None
}

/// `_workspace_vitest_version_is_bound` (:464-471).
fn workspace_vitest_version_is_bound(workspace: &Path, installed_version: &str) -> bool {
    let declared_version = declared_vitest_version(workspace);
    let lockfiles: Vec<PathBuf> = LOCKFILE_NAMES
        .iter()
        .map(|name| workspace.join(name))
        .filter(|path| path.exists())
        .collect();
    if declared_version.is_none() || lockfiles.len() != 1 {
        return false;
    }
    let locked_version = locked_vitest_version(&lockfiles[0]);
    locked_version.as_deref() == Some(installed_version)
        && semver_spec_matches(&declared_version.unwrap_or_default(), installed_version)
}

/// `_read_package_json` (:473-490).
fn read_package_json(path: &Path) -> Option<Map<String, Value>> {
    let metadata = path.metadata().ok()?;
    if path.is_symlink() || !metadata.is_file() || metadata.size() > MAX_METADATA_BYTES {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    let payload: Value = serde_json::from_str(&text).ok()?;
    payload.as_object().cloned()
}

/// `_locked_vitest_version` (:492-494).
fn locked_vitest_version(path: &Path) -> Option<String> {
    locked_package_version(path, "vitest")
}

/// `_locked_package_version` (:496-525).
fn locked_package_version(path: &Path, package_name: &str) -> Option<String> {
    let metadata = path.metadata().ok()?;
    if path.is_symlink() || !metadata.is_file() || metadata.size() > MAX_METADATA_BYTES {
        return None;
    }
    let lock_text = fs::read_to_string(path).ok()?;
    let lock: Value = if path.file_name()?.to_string_lossy() == "bun.lock" {
        loads_jsonc(&lock_text).ok()?
    } else {
        serde_json::from_str(&lock_text).ok()?
    };
    let packages = lock.as_object()?.get("packages")?.as_object()?;
    if path.file_name()?.to_string_lossy() == "bun.lock" {
        let entry = packages.get(package_name)?.as_array()?;
        let first = entry.first()?.as_str()?;
        let prefix = format!("{package_name}@");
        if !first.starts_with(&prefix) {
            return None;
        }
        return Some(first[prefix.len()..].to_owned());
    }
    let entry = packages
        .get(&format!("node_modules/{package_name}"))?
        .as_object()?;
    entry
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// `_contained_test_target` (:527-539).
fn contained_test_target(target: &str, workspace: &Path) -> bool {
    if has_shell_dynamics(target) || target.starts_with('/') || target.starts_with('~') {
        return false;
    }
    let candidate = workspace.join(target);
    let absolute = path_absolute(&candidate);
    let resolved = match candidate.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => return false,
    };
    if resolved.strip_prefix(workspace).is_err() {
        return false;
    }
    if absolute != resolved || !resolved.is_file() {
        return false;
    }
    let name = resolved
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    name.contains(".test.") || name.contains(".spec.")
}

/// `_bounded_output_filter` (:541-558).
fn bounded_output_filter(
    tokens: &[String],
    control_before: &[String],
    cwd: &Path,
    home_dir: &Path,
) -> bool {
    if control_before != ["|"] || tokens.len() != 2 || (tokens[0] != "head" && tokens[0] != "tail")
    {
        return false;
    }
    if !trusted_path_command(&tokens[0], cwd, home_dir) {
        return false;
    }
    let count = &tokens[1];
    count.starts_with('-')
        && count[1..].chars().all(|c| c.is_ascii_digit())
        && !count[1..].is_empty()
        && count[1..]
            .parse::<u32>()
            .map(|value| (1..=1000).contains(&value))
            .unwrap_or(false)
}

/// `_trusted_env_node_runtime` (:560-566).
fn trusted_env_node_runtime(runner: &Path, cwd: &Path, home_dir: &Path) -> bool {
    let shebang = {
        let mut handle = match fs::File::open(runner) {
            Ok(handle) => handle,
            Err(_) => return false,
        };
        use std::io::{BufRead, BufReader};
        let mut line = Vec::new();
        match BufReader::new(&mut handle).read_until(b'\n', &mut line) {
            Ok(_) => line,
            Err(_) => return false,
        }
    };
    shebang == b"#!/usr/bin/env node\n" && trusted_path_command("node", cwd, home_dir)
}

/// `_trusted_path_command` (:568-613).
fn trusted_path_command(command: &str, cwd: &Path, home_dir: &Path) -> bool {
    let mut path_entries: Vec<String> = Vec::new();
    let path_env_value = env::var("PATH").unwrap_or_else(|_| os_defpath());
    for entry in path_env_value.split(':') {
        let raw = if entry.is_empty() { "." } else { entry };
        let mut candidate = expand_user(Path::new(raw));
        if !candidate.is_absolute() {
            candidate = cwd.join(&candidate);
        }
        path_entries.push(candidate.to_string_lossy().into_owned());
    }
    let located = match shutil_which(command, Some(&path_entries.join(":"))) {
        Some(located) => located,
        None => return false,
    };
    let resolved = match located.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => return false,
    };
    if git_binary_path_is_trusted(&resolved, cwd) {
        return true;
    }
    if command != "bun" {
        return false;
    }
    let status = package_shim_status(
        &HarnessContext {
            guard_home: home_dir.join(".hol-guard"),
            home_dir: Some(home_dir.to_path_buf()),
            workspace_dir: Some(cwd.to_path_buf()),
            home_override_explicit: false,
        },
        env::var("PATH").ok().as_deref(),
    );
    let details = match status.get("manager_details").and_then(Value::as_array) {
        Some(details) => details,
        None => return false,
    };
    details.iter().any(|raw_detail| {
        let detail = match raw_detail.as_object() {
            Some(detail) => detail,
            None => return false,
        };
        detail.get("manager").and_then(Value::as_str) == Some("bun")
            && detail.get("integrity").and_then(Value::as_str) == Some("ok")
            && detail.get("path_active").and_then(Value::as_bool) == Some(true)
            && detail.get("shim_path").and_then(Value::as_str)
                == Some(resolved.to_string_lossy().as_ref())
    })
}

/// `_has_shell_dynamics` (:615-617).
fn has_shell_dynamics(token: &str) -> bool {
    token
        .chars()
        .any(|ch| matches!(ch, '$' | '`' | '\0' | '>' | '<'))
}

// ---------------------------------------------------------------------------
// Local primitives shared by the duplicated dependency ports below.
// ---------------------------------------------------------------------------

/// `os.defpath` — `':/bin:/usr/bin'` on POSIX.
fn os_defpath() -> String {
    #[cfg(unix)]
    {
        ":/bin:/usr/bin".to_owned()
    }
    #[cfg(windows)]
    {
        ".;C:\\bin".to_owned()
    }
}

/// `Path.expanduser` — POSIX `~`/`~/` expansion against `$HOME`.
fn expand_user(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home);
        }
        return path.to_path_buf();
    }
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME") {
            return Path::new(&home).join(rest);
        }
    }
    path.to_path_buf()
}

/// `Path.absolute()` — lexical absolutization against the process CWD with
/// POSIX `normpath` semantics.
fn path_absolute(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    normpath(&joined)
}

/// `Path.resolve(strict=True)` — canonicalize only when every component
/// exists.
fn resolve_strict(path: &Path) -> Option<PathBuf> {
    path.canonicalize().ok()
}

/// POSIX `os.path.normpath`.
fn normpath(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    let rooted = text.starts_with('/');
    let mut stack: Vec<String> = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                if stack.last().map(|p| p.as_str() != "..").unwrap_or(false) {
                    stack.pop();
                } else if !rooted {
                    stack.push("..".to_owned());
                }
            }
            other => stack.push(other.to_owned()),
        }
    }
    let body = stack.join("/");
    if rooted {
        PathBuf::from(format!("/{body}"))
    } else if body.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(body)
    }
}

/// `shutil.which(command, path=...)` — POSIX executable lookup honoring an
/// explicit path string.
fn shutil_which(command: &str, path_env: Option<&str>) -> Option<PathBuf> {
    if command.contains('/') || command.contains('\\') {
        let candidate = Path::new(command);
        return executable_file(candidate).then(|| candidate.to_path_buf());
    }
    let path = path_env
        .map(|p| p.to_owned())
        .or_else(|| env::var("PATH").ok())
        .unwrap_or_else(|| "/bin:/usr/bin".to_owned());
    for entry in path.split(':') {
        let directory = if entry.is_empty() { "." } else { entry };
        let candidate = Path::new(directory).join(command);
        if executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn executable_file(candidate: &Path) -> bool {
    match candidate.metadata() {
        Ok(metadata) => metadata.is_file() && metadata.mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// `base64.b64decode(value, validate=True)` — strict alphabet, correct
/// padding; any deviation returns `None` (Python raises `binascii.Error`).
fn strict_base64_decode(value: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut decode = [0xFFu8; 256];
    for (index, byte) in TABLE.iter().enumerate() {
        decode[*byte as usize] = index as u8;
    }
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunks = bytes.len() / 4;
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let last = index == chunks - 1;
        let pad = chunk.iter().filter(|b| **b == b'=').count();
        if pad > 2 || (!last && pad > 0) {
            return None;
        }
        if pad > 0 && chunk.iter().position(|b| *b == b'=') != Some(4 - pad) {
            return None;
        }
        let mut acc: u32 = 0;
        let mut bits = 0u32;
        for byte in chunk {
            if *byte == b'=' {
                continue;
            }
            let digit = decode[*byte as usize];
            if digit == 0xFF {
                return None;
            }
            acc = (acc << 6) | digit as u32;
            bits += 6;
        }
        let _ = bits;
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

/// Python `json.dumps(records, separators=(",", ":"), ensure_ascii=True)` for
/// `[(str, str)]` — verbatim byte output for the digest preimage.
fn py_json_tuple_list(records: &[(String, String)]) -> Vec<u8> {
    let mut out = String::with_capacity(records.len() * 64 + 2);
    out.push('[');
    for (index, (key, value)) in records.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('[');
        push_py_json_str(&mut out, key);
        out.push(',');
        push_py_json_str(&mut out, value);
        out.push(']');
    }
    out.push(']');
    out.into_bytes()
}

/// Python `json.dumps` string escape (`ensure_ascii=True`): control escapes,
/// `"`, `\\`, and `\uXXXX` for every non-ASCII code point.
fn push_py_json_str(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) < 0x7f => out.push(c),
            c => {
                let code = c as u32;
                if code > 0xffff {
                    // Surrogate pair encoding to match CPython ensure_ascii.
                    let adjusted = code - 0x1_0000;
                    let high = 0xd800 + (adjusted >> 10);
                    let low = 0xdc00 + (adjusted & 0x3ff);
                    out.push_str(&format!("\\u{high:04x}\\u{low:04x}"));
                } else {
                    out.push_str(&format!("\\u{code:04x}"));
                }
            }
        }
    }
    out.push('"');
}

/// `tempfile.gettempdir()` — `TMPDIR`-honored POSIX temp root.
fn temp_dir() -> PathBuf {
    env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

// ===========================================================================
// `runtime/node_semver.py` private copy (verbatim; delete on shared port).
// ===========================================================================

fn semver_parse_version(text: &str) -> Option<(u64, u64, u64)> {
    let text = text.strip_prefix('v').unwrap_or(text);
    let core = text.split(['-', '+']).next().unwrap_or_default();
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let mut out = [0u64; 3];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
        out[index] = part.parse::<u64>().ok()?;
    }
    Some((out[0], out[1], out[2]))
}

fn semver_wildcard(text: &str) -> bool {
    matches!(text, "*" | "x" | "X")
}

#[allow(dead_code)]
fn semver_partial_bounds(text: &str) -> Option<(u64, u64, u64, usize)> {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?").unwrap()
    });
    let caps = RE.captures(text)?;
    let mut parts: Vec<u64> = Vec::new();
    let mut seen = 0usize;
    for group in 1..=3 {
        match caps.get(group) {
            Some(part) => {
                let p = part.as_str();
                if semver_wildcard(p) {
                    break;
                }
                parts.push(p.parse::<u64>().ok()?);
                seen += 1;
            }
            None => break,
        }
    }
    if parts.is_empty() || seen == 0 {
        return None;
    }
    parts.resize(3, 0);
    Some((
        parts[0],
        parts[1],
        parts[2],
        parts.len() - parts.iter().skip(seen.max(3)).count(),
    ))
}

fn semver_tuple_cmp(a: (u64, u64, u64), b: (u64, u64, u64)) -> std::cmp::Ordering {
    a.cmp(&b)
}

fn semver_spec_matches(specifier: &str, version_text: &str) -> bool {
    static SPEC_RANGE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^\s*(>=|<=|>|<|\^|~|=)?\s*v?(\d+|\*|[xX])(?:\.(\d+|\*|[xX]))?(?:\.(\d+|\*|[xX]))?(?:-[^\s]*)?(?:\+[^\s]*)?\s*$",
        )
        .unwrap()
    });
    let version = match semver_parse_version(version_text) {
        Some(v) => v,
        None => return false,
    };
    let specifiers: Vec<&str> = specifier.split(',').map(str::trim).collect();
    if specifier.trim().is_empty() || specifiers.iter().any(|s| s.is_empty()) {
        return false;
    }
    for specifier in specifiers {
        if specifier
            .chars()
            .any(|ch| matches!(ch, ' ' | '\t' | '|' | '-'))
            && !specifier
                .chars()
                .next()
                .map(|c| matches!(c, '>' | '<' | '=' | '^' | '~'))
                .unwrap_or(false)
        {
            return false;
        }
        if specifier.contains('-') && !specifier.starts_with("v") {
            let hyphen_index = specifier.find('-').unwrap();
            let version_part = &specifier[..hyphen_index];
            if version_part
                .chars()
                .any(|ch| matches!(ch, '>' | '<' | '=' | '^' | '~' | ' '))
            {
                return false;
            }
        }
        let caps = match SPEC_RANGE.captures(specifier) {
            Some(caps) => caps,
            None => return false,
        };
        let operator = caps.get(1).map(|m| m.as_str()).unwrap_or("=");
        let major = caps.get(2).unwrap().as_str();
        let minor = caps.get(3).map(|m| m.as_str()).unwrap_or("0");
        let patch = caps.get(4).map(|m| m.as_str()).unwrap_or("0");
        let resolved = match (
            semver_wildcard(major),
            semver_wildcard(minor),
            semver_wildcard(patch),
        ) {
            (true, _, _) => {
                if !matches!(operator, "=" | "^" | "~" | ">=" | ">") {
                    return false;
                }
                continue;
            }
            _ => None::<()>,
        };
        let _ = resolved;
        let major = match major.parse::<u64>() {
            Ok(v) => v,
            Err(_) => return false,
        };
        if semver_wildcard(minor) || (caps.get(3).is_none() && matches!(operator, "^" | "~")) {
            let lower = (major, 0, 0);
            let upper = (major + 1, 0, 0);
            let in_range = match operator {
                "^" | "~" | ">=" => {
                    semver_tuple_cmp(version, lower) != std::cmp::Ordering::Less
                        && semver_tuple_cmp(version, upper) == std::cmp::Ordering::Less
                }
                "=" => {
                    semver_tuple_cmp(version, lower) != std::cmp::Ordering::Less
                        && semver_tuple_cmp(version, upper) == std::cmp::Ordering::Less
                }
                ">" => semver_tuple_cmp(version, upper) != std::cmp::Ordering::Less,
                "<=" => semver_tuple_cmp(version, upper) == std::cmp::Ordering::Less,
                "<" => semver_tuple_cmp(version, lower) == std::cmp::Ordering::Less,
                _ => return false,
            };
            if !in_range {
                return false;
            }
            continue;
        }
        let minor = match minor.parse::<u64>() {
            Ok(v) => v,
            Err(_) => return false,
        };
        if semver_wildcard(patch) || (caps.get(4).is_none() && matches!(operator, "^" | "~")) {
            let lower = (major, minor, 0);
            let upper = match operator {
                "^" => (major + 1, 0, 0),
                _ => (major, minor + 1, 0),
            };
            let in_range = match operator {
                "^" | "~" | ">=" | "=" => {
                    semver_tuple_cmp(version, lower) != std::cmp::Ordering::Less
                        && semver_tuple_cmp(version, upper) == std::cmp::Ordering::Less
                }
                ">" => semver_tuple_cmp(version, upper) != std::cmp::Ordering::Less,
                "<=" => semver_tuple_cmp(version, upper) == std::cmp::Ordering::Less,
                "<" => semver_tuple_cmp(version, lower) == std::cmp::Ordering::Less,
                _ => return false,
            };
            if !in_range {
                return false;
            }
            continue;
        }
        let patch = match patch.parse::<u64>() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let base = (major, minor, patch);
        let in_range = match operator {
            "=" => semver_tuple_cmp(version, base) == std::cmp::Ordering::Equal,
            ">=" => semver_tuple_cmp(version, base) != std::cmp::Ordering::Less,
            "<=" => semver_tuple_cmp(version, base) != std::cmp::Ordering::Greater,
            ">" => semver_tuple_cmp(version, base) == std::cmp::Ordering::Greater,
            "<" => semver_tuple_cmp(version, base) == std::cmp::Ordering::Less,
            "^" => {
                semver_tuple_cmp(version, base) != std::cmp::Ordering::Less
                    && semver_tuple_cmp(version, (major + 1, 0, 0)) == std::cmp::Ordering::Less
            }
            "~" => {
                semver_tuple_cmp(version, base) != std::cmp::Ordering::Less
                    && semver_tuple_cmp(version, (major, minor + 1, 0)) == std::cmp::Ordering::Less
            }
            _ => return false,
        };
        if !in_range {
            return false;
        }
    }
    true
}

// ===========================================================================
// `runtime/git_execution_safety.py` private copy (verbatim; delete on
// shared port).
// ===========================================================================

fn git_binary_path_is_trusted(resolved: &Path, cwd: &Path) -> bool {
    let resolved = match resolved.canonicalize() {
        Ok(r) => r,
        Err(_) => resolved.to_path_buf(),
    };
    let resolved = resolve_strict(&resolved).unwrap_or(resolved);
    if cwd.join(".git").is_dir() {
        let _ = resolved; // workspace-local git absent: resolved exe check below
    }
    let text = resolved.to_string_lossy();
    const TRUSTED: &[&str] = &[
        "/usr/bin",
        "/bin",
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/opt/homebrew/sbin",
        "/usr/local/sbin",
    ];
    let trusted = TRUSTED
        .iter()
        .any(|root| resolved.strip_prefix(Path::new(root)).is_ok());
    if !trusted {
        return false;
    }
    let metadata = match resolved.metadata() {
        Ok(m) => m,
        Err(_) => return false,
    };
    metadata.is_file() && metadata.mode() & 0o111 != 0 && metadata.mode() & 0o022 == 0
        || text.contains("/usr/bin/")
}

// ===========================================================================
// `runtime/github_actions_read_workflow.py` private copy (verbatim).
// ===========================================================================

static EXECUTION_ROUTING_ENVIRONMENT: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "RUBYLIB",
    "RUBYOPT",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_SSH_VARIANT",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_PROXY_COMMAND",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_SYSTEM",
];

static LOADER_PATH_ENVIRONMENT: &[&str] = &[
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "LD_LIBRARY_PATH",
];

fn shell_read_execution_environment_is_safe(cwd: &Path) -> bool {
    if EXECUTION_ROUTING_ENVIRONMENT
        .iter()
        .any(|key| env::var(key).map(|v| !v.trim().is_empty()).unwrap_or(false))
    {
        return false;
    }
    for (key, value) in env::vars() {
        if value.is_empty()
            || !(key.starts_with("BASH_FUNC_")
                || key.starts_with("DYLD_")
                || key.starts_with("LD_"))
        {
            continue;
        }
        if !LOADER_PATH_ENVIRONMENT.contains(&key.as_str()) || !trusted_loader_paths(&value, cwd) {
            return false;
        }
    }
    true
}

fn trusted_loader_paths(value: &str, cwd: &Path) -> bool {
    let paths: Vec<&str> = value.split(':').collect();
    if paths.is_empty() || paths.iter().any(|item| item.is_empty()) {
        return false;
    }
    for item in paths {
        let mut candidate = PathBuf::from(item);
        if !candidate.is_absolute() {
            candidate = cwd.join(candidate);
        }
        let resolved = match candidate.canonicalize() {
            Ok(resolved) => resolved,
            Err(_) => return false,
        };
        if resolved.strip_prefix(temp_dir()).is_ok() || !git_binary_path_is_trusted(&resolved, cwd)
        {
            return false;
        }
    }
    true
}

// ===========================================================================
// `runtime/direct_typescript_diagnostics.py` private copy (verbatim).
// Only `direct_typescript_diagnostic_filter_context` and its private helpers
// are duplicated here.
// ===========================================================================

const TSC_DIAGNOSTIC_SUMMARY_FLAGS: &[&str] = &[
    "--pretty",
    "--noErrorTruncation",
    "--listFiles",
    "--listFilesOnly",
    "--extendedDiagnostics",
    "--diagnostics",
    "--generateTrace",
    "--generateCpuProfile",
    "--incremental",
    "--tsBuildInfoFile",
    "--declaration",
    "--emitDeclarationOnly",
    "--outDir",
    "--outFile",
    "--declarationDir",
    "--rootDir",
    "--rootDirs",
    "--baseUrl",
    "--paths",
    "--typeRoots",
    "--types",
    "--plugins",
    "--preserveWatchOutput",
    "--watch",
    "--watchFile",
    "--watchDirectory",
    "--fallbackPolling",
    "--synchronousWatchDirectory",
    "--build",
    "--dry",
    "--force",
    "--verbose",
];

static TSC_NO_VALUE_FLAGS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "--pretty",
        "--noPretty",
        "--strict",
        "--noImplicitAny",
        "--strictNullChecks",
        "--strictFunctionTypes",
        "--strictBindCallApply",
        "--strictPropertyInitialization",
        "--strictBuiltinIteratorReturn",
        "--noImplicitThis",
        "--useUnknownInCatchVariables",
        "--alwaysStrict",
        "--noUnusedLocals",
        "--noUnusedParameters",
        "--exactOptionalPropertyTypes",
        "--noImplicitReturns",
        "--noFallthroughCasesInSwitch",
        "--noUncheckedIndexedAccess",
        "--noImplicitOverride",
        "--noPropertyAccessFromIndexSignature",
        "--allowUnusedLabels",
        "--allowUnreachableCode",
        "--allowJs",
        "--checkJs",
        "--skipLibCheck",
        "--skipDefaultLibCheck",
        "--esModuleInterop",
        "--allowSyntheticDefaultImports",
        "--forceConsistentCasingInFileNames",
        "--resolveJsonModule",
        "--isolatedModules",
        "--verbatimModuleSyntax",
        "--preserveConstEnums",
        "--declaration",
        "--declarationMap",
        "--emitDeclarationOnly",
        "--sourceMap",
        "--inlineSourceMap",
        "--inlineSources",
        "--removeComments",
        "--noEmit",
        "--noEmitOnError",
        "--noErrorTruncation",
        "--preserveWatchOutput",
        "--listEmittedFiles",
        "--listFiles",
        "--explainFiles",
        "--extendedDiagnostics",
        "--diagnostics",
        "--generateCpuProfile",
        "--incremental",
        "--composite",
        "--disableSourceOfProjectReferenceRedirect",
        "--disableSolutionSearching",
        "--disableReferencedProjectLoad",
        "--assumeChangesOnlyAffectDirectDependencies",
        "--experimentalDecorators",
        "--emitDecoratorMetadata",
        "--jsxFragmentFactory",
        "--jsxFactory",
        "--jsxImportSource",
        "--allowArbitraryExtensions",
        "--allowImportingTsExtensions",
        "--allowUmdGlobalAccess",
        "--moduleDetection",
        "--noLib",
        "--noResolve",
        "--preserveSymlinks",
        "--useDefineForClassFields",
        "--isolatedDeclarations",
        "--erasableSyntaxOnly",
        "--noCheck",
        "--rewriteRelativeImportExtensions",
        "--verbatim",
    ])
});

static TSC_VALUE_FLAGS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "--target",
        "-t",
        "--module",
        "-m",
        "--lib",
        "--moduleResolution",
        "--moduleSuffixes",
        "--jsx",
        "-j",
        "--outDir",
        "--outFile",
        "--rootDir",
        "--declarationDir",
        "--tsBuildInfoFile",
        "--project",
        "-p",
        "--generateTrace",
        "--types",
        "--typeRoots",
        "--baseUrl",
        "--paths",
        "--customConditions",
        "--preserveSymlinks",
        "--watchFile",
        "--watchDirectory",
        "--fallbackPolling",
    ])
});

static TSC_PACKAGE_VALUE_FLAGS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from(["--lib", "--types"]));

static TSC_PATH_VALUE_FLAGS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "--outDir",
        "--outFile",
        "--declarationDir",
        "--tsBuildInfoFile",
        "--project",
        "-p",
        "--generateTrace",
        "--typeRoots",
        "--baseUrl",
        "--rootDir",
    ])
});

type TrustedPathCommand = fn(&str, &Path, &Path) -> bool;
type WorkspaceTypeScriptBinding = fn(&Path) -> bool;

/// `direct_typescript_diagnostic_filter_context` (:44-137).
fn direct_typescript_diagnostic_filter_context(
    context: &ShellExecutionContext,
    workspace: &Path,
    home_dir: &Path,
    trusted_path_command: TrustedPathCommand,
    workspace_typescript_is_bound: WorkspaceTypeScriptBinding,
) -> Option<ShellExecutionContext> {
    if !context.complete || context.segments.len() != 4 {
        return None;
    }
    let directory = &context.segments[0];
    let compiler = &context.segments[1];
    let filter = &context.segments[2];
    let summary = &context.segments[3];
    if directory.directory_operation.as_deref() != Some("cd")
        || !directory.control_before.is_empty()
        || compiler.control_before != ["&&"]
        || compiler.effective_cwd.as_deref() != Some(workspace)
        || filter.control_before != ["|"]
        || summary.control_before != [";"]
    {
        return None;
    }
    let mut compiler_tokens = compiler.tokens.clone();
    if compiler_tokens.last().map(|s| s.as_str()) != Some("2>&1") {
        return None;
    }
    compiler_tokens.pop();
    let node_options = compiler_tokens
        .first()
        .filter(|token| token.starts_with("NODE_OPTIONS="))
        .cloned();
    if let Some(ref node_options) = node_options {
        if !safe_typecheck_node_options(node_options) {
            return None;
        }
        compiler_tokens.remove(0);
    }
    if compiler_tokens.len() < 2
        || compiler_tokens[0] != "npx"
        || compiler_tokens[1] != "tsc"
        || !typescript_no_emit_args_are_safe(&compiler_tokens[2..], workspace)
        || !shell_read_execution_environment_is_safe(workspace)
        || node_execution_environment_is_configurable(workspace, home_dir)
        || !trusted_path_command("npx", workspace, home_dir)
        || !trusted_path_command("node", workspace, home_dir)
        || !workspace_typescript_is_bound(workspace)
    {
        return None;
    }
    if !typescript_stream_observer_is_safe(filter, workspace, home_dir, trusted_path_command) {
        return None;
    }
    if summary.tokens != ["echo".to_owned(), "TSC_DONE".to_owned()]
        && !(summary.tokens.len() == 2
            && summary.tokens[0] == "echo"
            && summary.tokens[1]
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
            && !summary.tokens[1].is_empty()
            && summary.tokens[1].len() <= 64)
    {
        return None;
    }
    Some(context.clone())
}

/// `_safe_typecheck_node_options` (:139-149).
fn safe_typecheck_node_options(token: &str) -> bool {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^NODE_OPTIONS=([a-zA-Z0-9_\-./ :;=]*)$").unwrap());
    let caps = match RE.captures(token) {
        Some(caps) => caps,
        None => return false,
    };
    let options = &caps[1];
    let allowed: HashSet<&str> = [
        "--max-old-space-size=256",
        "--max-old-space-size=512",
        "--max-old-space-size=1024",
        "--max-old-space-size=2048",
        "--max-old-space-size=4096",
        "--max-old-space-size=8192",
        "--max-semi-space-size=2",
        "--max-semi-space-size=4",
        "--max-semi-space-size=8",
        "--max-semi-space-size=16",
        "--max-semi-space-size=32",
        "--max-semi-space-size=64",
        "--stack-size=984",
        "--stack-size=1968",
        "--stack-size=3936",
        "--stack-size=7872",
    ]
    .into_iter()
    .collect();
    let flags: Vec<&str> = options.split_whitespace().collect();
    !flags.is_empty() && flags.len() <= 4 && flags.iter().all(|flag| allowed.contains(flag))
}

/// `_typescript_no_emit_args_are_safe` (:151-226).
fn typescript_no_emit_args_are_safe(args: &[String], workspace: &Path) -> bool {
    if args.iter().any(|arg| arg == "--") {
        return false;
    }
    let mut index = 0usize;
    while index < args.len() {
        let arg = &args[index];
        if TSC_DIAGNOSTIC_SUMMARY_FLAGS.contains(&arg.as_str()) {
            return false;
        }
        if arg == "-v" || arg == "--version" || arg == "-h" || arg == "--help" {
            return false;
        }
        if TSC_NO_VALUE_FLAGS.contains(arg.as_str())
            || (arg.starts_with("--")
                && arg.contains('=')
                && !TSC_VALUE_FLAGS.contains(arg.split('=').next().unwrap_or_default()))
        {
            if arg.contains('=') && TSC_NO_VALUE_FLAGS.contains(arg.as_str()) {
                return false;
            }
            index += 1;
            continue;
        }
        if TSC_VALUE_FLAGS.contains(arg.as_str()) {
            if index + 1 >= args.len() {
                return false;
            }
            let value = &args[index + 1];
            if TSC_PACKAGE_VALUE_FLAGS.contains(arg.as_str())
                && !typescript_package_list_is_safe(value)
            {
                return false;
            }
            if TSC_PATH_VALUE_FLAGS.contains(arg.as_str())
                && !typescript_path_is_contained(value, workspace)
            {
                return false;
            }
            index += 2;
            continue;
        }
        if arg.starts_with('-') {
            return false;
        }
        if !typescript_path_is_contained(arg, workspace) {
            return false;
        }
        index += 1;
    }
    true
}

/// `_typescript_path_is_contained` (:228-236).
fn typescript_path_is_contained(value: &str, workspace: &Path) -> bool {
    let mut candidate = PathBuf::from(value);
    if !candidate.is_absolute() {
        candidate = workspace.join(candidate);
    }
    match candidate.canonicalize() {
        Ok(resolved) => resolved
            .strip_prefix(
                workspace
                    .canonicalize()
                    .unwrap_or_else(|_| workspace.to_path_buf()),
            )
            .is_ok(),
        Err(_) => false,
    }
}

/// `_typescript_package_list_is_safe` (:238-241).
fn typescript_package_list_is_safe(value: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$").unwrap()
    });
    !value.is_empty() && value.split(',').all(|item| RE.is_match(item))
}

/// `_typescript_stream_observer_is_safe` (:243-269).
fn typescript_stream_observer_is_safe(
    segment: &ShellExecutionSegment,
    workspace: &Path,
    home_dir: &Path,
    trusted_path_command: TrustedPathCommand,
) -> bool {
    let tokens = &segment.tokens;
    if segment.control_before != ["|"] || tokens.is_empty() {
        return false;
    }
    if tokens.iter().any(|token| has_shell_dynamics(token)) {
        return false;
    }
    if !trusted_path_command(&tokens[0], workspace, home_dir) {
        return false;
    }
    if tokens[0] == "grep" {
        let flags = &tokens[1..tokens.len() - 1];
        return !tokens.last().map(|s| s.is_empty()).unwrap_or(true)
            && !tokens.last().unwrap().starts_with('-')
            && tokens.last().unwrap().len() <= 512
            && flags.iter().all(|flag| {
                matches!(
                    flag.as_str(),
                    "-a" | "-E" | "-i" | "-v" | "-aE" | "-ai" | "-iv"
                )
            });
    }
    if (tokens[0] == "head" || tokens[0] == "tail") && tokens.len() == 2 {
        let count = tokens[1].trim_start_matches('-');
        return count.chars().all(|c| c.is_ascii_digit())
            && !count.is_empty()
            && count
                .parse::<u32>()
                .map(|value| (1..=200).contains(&value))
                .unwrap_or(false);
    }
    false
}

/// `_node_execution_environment_is_configurable` (:271-285).
fn node_execution_environment_is_configurable(workspace: &Path, home_dir: &Path) -> bool {
    if env::var("NODE_OPTIONS")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    for directory in workspace.ancestors() {
        for name in [".nvmrc", ".node-version", ".npmrc"] {
            if directory.join(name).exists() {
                return true;
            }
        }
    }
    for name in [".nvmrc", ".node-version", ".npmrc"] {
        if home_dir.join(name).exists() {
            return true;
        }
    }
    false
}
