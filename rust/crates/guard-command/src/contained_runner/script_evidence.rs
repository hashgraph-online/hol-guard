//! Exact launch evidence for bounded local Bun package scripts.
//!
//! Faithful port of `runtime/local_package_script_evidence.py`.

use std::collections::HashSet;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::common::{file_sha256, framed_digest};
use super::node_evidence::require;
use super::pkg_json::{
    canonical_registry_resolution, object_of, package_bin_target, read_json_with_integrity,
    resolved_package_bin_target, stripped, valid_sha512_integrity, version_spec_matches,
};

const OPERATIONS: [&str; 4] = ["test", "lint", "build", "typecheck"];
const ALTERNATE_LOCKS: [&str; 5] = [
    "bun.lock",
    "bun.lockb",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
];
const TEST_SUFFIXES: [&str; 8] = [
    ".test.js",
    ".test.jsx",
    ".test.ts",
    ".test.tsx",
    ".spec.js",
    ".spec.jsx",
    ".spec.ts",
    ".spec.tsx",
];
const LINT_SUFFIXES: [&str; 8] = [".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"];

/// Exact launch evidence; never authorizes execution by itself.
#[derive(Debug, Clone)]
pub(crate) struct ScriptEvidence {
    pub(crate) complete: bool,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) reasons: Vec<String>,
    pub(crate) binding_digest: String,
    pub(crate) operation_id: String,
    pub(crate) runner: String,
    pub(crate) runner_args: Vec<String>,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) input_files: Vec<String>,
    pub(crate) executable_path: Option<String>,
    pub(crate) executable_hash: Option<String>,
    pub(crate) root_manifest_hash: Option<String>,
    pub(crate) lockfile_hash: Option<String>,
    pub(crate) package_manifest_hash: Option<String>,
}

/// Python `shlex.split(text, posix=True)`; `None` is its `ValueError`.
fn py_shlex_split(text: &str) -> Option<Vec<String>> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens: Vec<String> = Vec::new();
    let mut token = String::new();
    let mut in_token = false;
    let mut index = 0;
    while index < chars.len() {
        let current = chars[index];
        index += 1;
        match current {
            ' ' | '\t' | '\r' | '\n' => {
                if in_token {
                    tokens.push(std::mem::take(&mut token));
                    in_token = false;
                }
            }
            '\\' => {
                token.push(*chars.get(index)?);
                index += 1;
                in_token = true;
            }
            '\'' => {
                in_token = true;
                loop {
                    let value = *chars.get(index)?;
                    index += 1;
                    if value == '\'' {
                        break;
                    }
                    token.push(value);
                }
            }
            '"' => {
                in_token = true;
                loop {
                    let value = *chars.get(index)?;
                    index += 1;
                    if value == '"' {
                        break;
                    }
                    if value == '\\' {
                        let escaped = *chars.get(index)?;
                        index += 1;
                        if escaped != '"' && escaped != '\\' {
                            token.push('\\');
                        }
                        token.push(escaped);
                    } else {
                        token.push(value);
                    }
                }
            }
            other => {
                token.push(other);
                in_token = true;
            }
        }
    }
    if in_token {
        tokens.push(token);
    }
    Some(tokens)
}

fn expected_runner(operation: &str) -> &'static str {
    match operation {
        "test" => "vitest",
        "lint" => "eslint",
        "build" => "vite",
        _ => "tsc",
    }
}

fn runner_package(runner: &str) -> Option<&'static str> {
    match runner {
        "vitest" => Some("vitest"),
        "eslint" => Some("eslint"),
        "vite" => Some("vite"),
        "tsc" => Some("typescript"),
        _ => None,
    }
}

/// Bind one exact Bun script to package, lock, executable and inputs.
pub(crate) fn build_local_package_script_evidence(
    manager: &str,
    argv: &[String],
    workspace: &Path,
) -> Result<Option<ScriptEvidence>, String> {
    if manager != "bun"
        || argv.len() != 2
        || argv[0] != "run"
        || !OPERATIONS.contains(&argv[1].as_str())
    {
        return Ok(None);
    }
    let operation = argv[1].as_str();
    let (root_payload, root_hash) =
        read_json_with_integrity(&workspace.join("package.json"), false);
    let (lock_payload, lock_hash) =
        read_json_with_integrity(&workspace.join("package-lock.json"), false);
    let mut reasons: Vec<String> = Vec::new();
    let script = package_script(root_payload.as_ref(), operation);
    let launch = script_launch(operation, script.as_deref(), workspace, &mut reasons);
    let (runner, runner_args, input_files) =
        launch.unwrap_or_else(|| ("invalid".to_owned(), Vec::new(), Vec::new()));
    let package = runner_package(&runner);
    let package_root = workspace
        .join("node_modules")
        .join(package.unwrap_or("invalid"));
    let (package_payload, package_hash) =
        read_json_with_integrity(&package_root.join("package.json"), false);

    require(
        root_payload.is_some() && root_hash.is_some(),
        "manifest_identity_incomplete",
        &mut reasons,
    );
    require(
        lock_payload.is_some() && lock_hash.is_some(),
        "lock_identity_incomplete",
        &mut reasons,
    );
    require(
        !ALTERNATE_LOCKS
            .iter()
            .any(|name| workspace.join(name).exists()),
        "lock_source_ambiguous",
        &mut reasons,
    );
    require(package.is_some(), "script_runner_unsupported", &mut reasons);
    require(
        !has_lifecycle_script(root_payload.as_ref(), operation),
        "lifecycle_script_present",
        &mut reasons,
    );

    let declared = dependency_version(root_payload.as_ref(), package);
    let (locked, source_ok) = locked_version(lock_payload.as_ref(), package);
    let installed_name = string_value(package_payload.as_ref(), "name");
    let installed_version = string_value(package_payload.as_ref(), "version");
    require(
        declared.is_some(),
        "manifest_dependency_missing",
        &mut reasons,
    );
    require(locked.is_some(), "lock_dependency_missing", &mut reasons);
    require(source_ok, "lock_source_drift", &mut reasons);
    require(
        installed_name.as_deref() == package,
        "installed_package_name_mismatch",
        &mut reasons,
    );
    require(
        installed_version.is_some(),
        "installed_package_missing",
        &mut reasons,
    );
    require(
        version_spec_matches(declared.as_deref(), locked.as_deref(), true),
        "manifest_lock_version_drift",
        &mut reasons,
    );
    require(
        locked == installed_version,
        "lock_install_version_drift",
        &mut reasons,
    );

    let bin_target = package_bin_target(package_payload.as_ref(), &runner);
    let executable = resolved_package_bin_target(&package_root, bin_target.as_deref());
    let mut executable_path: Option<String> = None;
    let mut executable_hash: Option<String> = None;
    if let Some(executable) = executable {
        let regular = std::fs::symlink_metadata(&executable)
            .is_ok_and(|meta| !meta.file_type().is_symlink() && meta.is_file());
        if let (true, Ok(canonical)) = (regular, std::fs::canonicalize(&executable)) {
            if canonical.is_file() {
                let path = canonical.to_string_lossy().into_owned();
                if let Ok(digest) = file_sha256(Path::new(&path)) {
                    executable_hash = Some(format!("sha256:{digest}"));
                    executable_path = Some(path);
                }
            }
        }
    }
    require(bin_target.is_some(), "package_bin_missing", &mut reasons);
    require(
        executable_path.is_some() && executable_hash.is_some(),
        "executable_identity_incomplete",
        &mut reasons,
    );

    let mut seen = HashSet::new();
    reasons.retain(|reason| seen.insert(reason.clone()));
    let binding_digest = framed_digest(&json!({
        "schema_version": 1,
        "manager": manager,
        "operation": operation,
        "script": script,
        "runner": runner,
        "runner_args": runner_args,
        "input_files": input_files,
        "manifest_hash": root_hash,
        "lock_hash": lock_hash,
        "package_manifest_hash": package_hash,
        "declared_version": declared,
        "locked_version": locked,
        "installed_name": installed_name,
        "installed_version": installed_version,
        "executable_path": executable_path,
        "executable_hash": executable_hash,
        "reasons": reasons,
    }))?;
    Ok(Some(ScriptEvidence {
        complete: reasons.is_empty(),
        reasons,
        binding_digest,
        operation_id: operation.to_owned(),
        runner,
        runner_args,
        input_files,
        executable_path,
        executable_hash,
        root_manifest_hash: root_hash,
        lockfile_hash: lock_hash,
        package_manifest_hash: package_hash,
    }))
}

type Launch = (String, Vec<String>, Vec<String>);

fn script_launch(
    operation: &str,
    script: Option<&str>,
    workspace: &Path,
    reasons: &mut Vec<String>,
) -> Option<Launch> {
    let markers = ['\n', '\r', ';', '&', '|', '>', '<', '$', '`'];
    let Some(script) = script.filter(|text| !text.contains(markers)) else {
        reasons.push("script_not_exact".to_owned());
        return None;
    };
    let Some(tokens) = py_shlex_split(script) else {
        reasons.push("script_not_exact".to_owned());
        return None;
    };
    let runner = expected_runner(operation);
    if tokens.first().map(String::as_str) != Some(runner) {
        reasons.push("script_runner_mismatch".to_owned());
        return None;
    }
    let args: Vec<String> = tokens.iter().skip(1).cloned().collect();
    let mut raw_files: Vec<String> = Vec::new();
    match operation {
        "test" => {
            if args.first().map(String::as_str) != Some("run")
                || args.iter().skip(1).any(|value| value.starts_with('-'))
            {
                reasons.push("script_arguments_not_result_only".to_owned());
            }
            raw_files = args.iter().skip(1).cloned().collect();
        }
        "lint" => {
            let no_cache = args.iter().filter(|value| *value == "--no-cache").count();
            if no_cache != 1
                || args
                    .iter()
                    .any(|value| value.starts_with('-') && value != "--no-cache")
            {
                reasons.push("script_arguments_not_result_only".to_owned());
            }
            raw_files = args
                .iter()
                .filter(|value| *value != "--no-cache")
                .cloned()
                .collect();
        }
        "build" if args != ["build"] => reasons.push("script_arguments_not_result_only".to_owned()),
        "typecheck" if args != ["--noEmit"] && args != ["--noEmit", "--pretty"] => {
            reasons.push("script_arguments_not_result_only".to_owned());
        }
        _ => {}
    }
    let input_files = validated_inputs(workspace, operation, &raw_files, reasons);
    Some((runner.to_owned(), args, input_files))
}

fn validated_inputs(
    workspace: &Path,
    operation: &str,
    raw_files: &[String],
    reasons: &mut Vec<String>,
) -> Vec<String> {
    if !matches!(operation, "test" | "lint") {
        return Vec::new();
    }
    if raw_files.is_empty() {
        reasons.push("explicit_inputs_missing".to_owned());
        return Vec::new();
    }
    let suffixes: &[&str] = if operation == "test" {
        &TEST_SUFFIXES
    } else {
        &LINT_SUFFIXES
    };
    let mut result: Vec<String> = Vec::new();
    for raw_file in raw_files {
        let candidate = workspace.join(raw_file);
        let canonical = std::fs::canonicalize(&candidate).ok();
        let relative = canonical
            .as_ref()
            .and_then(|path| path.strip_prefix(workspace).ok().map(Path::to_path_buf));
        let (Some(canonical), Some(relative)) = (canonical, relative) else {
            reasons.push("input_outside_workspace".to_owned());
            continue;
        };
        let portable = relative.to_string_lossy().into_owned();
        let symlink =
            std::fs::symlink_metadata(&candidate).is_ok_and(|meta| meta.file_type().is_symlink());
        if symlink
            || !canonical.is_file()
            || !suffixes.iter().any(|suffix| portable.ends_with(suffix))
        {
            reasons.push("input_not_exact_regular_source".to_owned());
        } else if raw_file.replace('\\', "/") != portable
            || relative.components().any(|part| {
                let name = part.as_os_str().to_string_lossy().to_lowercase();
                name.starts_with(".env") || name == ".git" || name == ".guard"
            })
        {
            reasons.push("input_alias_or_protected".to_owned());
        } else {
            result.push(portable);
        }
    }
    let unique: HashSet<&String> = result.iter().collect();
    if unique.len() != result.len() {
        reasons.push("input_alias_or_duplicate".to_owned());
    }
    result
}

fn package_script(payload: Option<&Map<String, Value>>, operation: &str) -> Option<String> {
    stripped(object_of(payload?.get("scripts"))?.get(operation))
}

fn has_lifecycle_script(payload: Option<&Map<String, Value>>, operation: &str) -> bool {
    package_script(payload, &format!("pre{operation}")).is_some()
        || package_script(payload, &format!("post{operation}")).is_some()
}

fn dependency_version(
    payload: Option<&Map<String, Value>>,
    package: Option<&str>,
) -> Option<String> {
    let (payload, package) = (payload?, package?);
    for group in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(version) =
            object_of(payload.get(group)).and_then(|values| stripped(values.get(package)))
        {
            return Some(version);
        }
    }
    None
}

fn locked_version(
    payload: Option<&Map<String, Value>>,
    package: Option<&str>,
) -> (Option<String>, bool) {
    let item = package.and_then(|name| {
        payload
            .and_then(|map| object_of(map.get("packages")))
            .and_then(|packages| object_of(packages.get(&format!("node_modules/{name}"))))
    });
    let (Some(item), Some(package)) = (item, package) else {
        return (None, false);
    };
    let version = stripped(item.get("version"));
    let ok = item.get("link") != Some(&Value::Bool(true))
        && version.as_deref().is_some_and(|version| {
            canonical_registry_resolution(package, version, item.get("resolved"))
        })
        && valid_sha512_integrity(item.get("integrity"));
    (version, ok)
}

fn string_value(payload: Option<&Map<String, Value>>, key: &str) -> Option<String> {
    stripped(payload?.get(key))
}
