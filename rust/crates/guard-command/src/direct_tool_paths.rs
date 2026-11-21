//! Native direct-tool validation helpers.
use super::*;

/// `_vitest_runner_invocation` (:356-386).
pub(super) fn vitest_runner_invocation(
    runner_tokens: &[String],
    workspace: &Path,
    home_dir: &Path,
    authority: &dyn DirectToolAuthority,
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
    if executable != "npx" || !trusted_path_command("npx", workspace, home_dir, authority) {
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
pub(super) fn literal_leading_cd_target(
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
pub(super) fn verified_vitest_runner(
    runner: &Path,
    cwd: &Path,
    home_dir: &Path,
    authority: &dyn DirectToolAuthority,
) -> Option<String> {
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
        || !authority.executable_file(&resolved_runner)
        || !trusted_env_node_runtime(&resolved_runner, cwd, home_dir, authority)
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
pub(super) fn declared_vitest_version(workspace: &Path) -> Option<String> {
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
pub(super) fn workspace_vitest_version_is_bound(workspace: &Path, installed_version: &str) -> bool {
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
pub(super) fn read_package_json(path: &Path) -> Option<Map<String, Value>> {
    let metadata = path.metadata().ok()?;
    if path.is_symlink() || !metadata.is_file() || metadata.len() > MAX_METADATA_BYTES {
        return None;
    }
    let text = read_bounded_text(path, MAX_METADATA_BYTES).ok()?;
    let payload: Value = serde_json::from_str(&text).ok()?;
    payload.as_object().cloned()
}

/// `_locked_vitest_version` (:492-494).
pub(super) fn locked_vitest_version(path: &Path) -> Option<String> {
    locked_package_version(path, "vitest")
}

/// `_locked_package_version` (:496-525).
pub(super) fn locked_package_version(path: &Path, package_name: &str) -> Option<String> {
    let metadata = path.metadata().ok()?;
    if path.is_symlink() || !metadata.is_file() || metadata.len() > MAX_METADATA_BYTES {
        return None;
    }
    let lock_text = read_bounded_text(path, MAX_METADATA_BYTES).ok()?;
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
pub(super) fn contained_test_target(target: &str, workspace: &Path) -> bool {
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
    if !lexical_target_has_no_symlinks(&absolute) || !resolved.is_file() {
        return false;
    }
    let name = resolved
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    name.contains(".test.") || name.contains(".spec.")
}

// Python's POSIX realpath preserves the requested spelling on case-insensitive
// filesystems. Rust canonicalize may return the stored case. Prove the absence
// of symlinks and parent traversal without rejecting a case-equivalent name.
pub(super) fn lexical_target_has_no_symlinks(path: &Path) -> bool {
    let mut prefix = PathBuf::new();
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return false;
        }
        prefix.push(component);
        match fs::symlink_metadata(&prefix) {
            Ok(metadata) if !metadata.file_type().is_symlink() => {}
            _ => return false,
        }
    }
    true
}

/// `_bounded_output_filter` (:541-558).
pub(super) fn bounded_output_filter(
    tokens: &[String],
    control_before: &[String],
    cwd: &Path,
    home_dir: &Path,
    authority: &dyn DirectToolAuthority,
) -> bool {
    if control_before != ["|"] || tokens.len() != 2 || (tokens[0] != "head" && tokens[0] != "tail")
    {
        return false;
    }
    if !trusted_path_command(&tokens[0], cwd, home_dir, authority) {
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
pub(super) fn trusted_env_node_runtime(
    runner: &Path,
    cwd: &Path,
    home_dir: &Path,
    authority: &dyn DirectToolAuthority,
) -> bool {
    let shebang = {
        let mut handle = match fs::File::open(runner) {
            Ok(handle) => handle,
            Err(_) => return false,
        };
        use std::io::{BufRead, BufReader};
        let mut line = Vec::new();
        match BufReader::new(std::io::Read::take(&mut handle, 64)).read_until(b'\n', &mut line) {
            Ok(_) => line,
            Err(_) => return false,
        }
    };
    shebang == b"#!/usr/bin/env node\n" && trusted_path_command("node", cwd, home_dir, authority)
}

/// Tool resolution uses the resident's existing binary and managed-shim authority.
pub(super) fn trusted_path_command(
    command: &str,
    cwd: &Path,
    home_dir: &Path,
    authority: &dyn DirectToolAuthority,
) -> bool {
    authority.within_budget() && authority.trusted_command(command, cwd, home_dir)
}

/// `_has_shell_dynamics` (:615-617).
pub(super) fn has_shell_dynamics(token: &str) -> bool {
    token
        .chars()
        .any(|ch| matches!(ch, '$' | '`' | '\0' | '>' | '<'))
}

// ---------------------------------------------------------------------------
// Local primitives shared by the duplicated dependency ports below.
// ---------------------------------------------------------------------------

/// Every production caller supplies admitted absolute paths.
pub(super) fn path_absolute(path: &Path) -> PathBuf {
    path.to_path_buf()
}
