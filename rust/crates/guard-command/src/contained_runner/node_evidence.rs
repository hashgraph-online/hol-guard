//! Typed launch evidence for exact result-only local Node runners.
//!
//! Faithful port of `runtime/local_node_runner_evidence.py`. The
//! `LocalPackageExecutionEvidence` fields arrive as the caller's JSON and are
//! re-validated here against the workspace before anything is executed.

use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::common::{canonical_bytes, file_sha256};
use super::pkg_json::{
    canonical_registry_resolution, object_of, package_bin_target, read_json_with_integrity,
    resolved_package_bin_target, stripped, valid_sha512_integrity, version_spec_matches,
    weak_resolve,
};
use super::runner_options::{bun_locked_version, vitest_result_arguments};

const SOURCE_PREFIXES: [&str; 8] = [
    "file:",
    "git+",
    "git://",
    "github:",
    "http://",
    "https://",
    "npm:",
    "workspace:",
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
pub(crate) struct NodeRunnerEvidence {
    pub(crate) complete: bool,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) reasons: Vec<String>,
    pub(crate) binding_digest: String,
    pub(crate) runner: String,
    pub(crate) operation_id: &'static str,
    pub(crate) runner_args: Vec<String>,
    pub(crate) input_files: Vec<String>,
    pub(crate) executable_path: Option<String>,
    pub(crate) executable_hash: Option<String>,
    pub(crate) root_manifest_hash: Option<String>,
    pub(crate) lockfile_hash: Option<String>,
    pub(crate) package_manifest_hash: Option<String>,
    pub(crate) lockfile_name: String,
}

fn runner_operation(runner: &str) -> Option<&'static str> {
    match runner {
        "vitest" => Some("test"),
        "eslint" => Some("lint"),
        "tsx" => Some("diagnostic"),
        _ => None,
    }
}

pub(crate) fn require(condition: bool, reason: &str, reasons: &mut Vec<String>) {
    if !condition {
        reasons.push(reason.to_owned());
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn available(item: &Value) -> bool {
    text(item, "status") == Some("available")
}

/// Build exact launch evidence without authorizing execution.
pub(crate) fn build_local_node_runner_evidence(
    manager: &str,
    argv: &[String],
    execution: &Value,
    workspace: &Path,
) -> Result<Option<NodeRunnerEvidence>, String> {
    let Some((runner, runner_args, input_files, argument_reasons)) =
        runner_arguments(manager, argv, workspace)
    else {
        return Ok(None);
    };
    let mut reasons = argument_reasons;
    require(
        matches!(manager, "npx" | "bunx"),
        "manager_mismatch",
        &mut reasons,
    );
    require(
        text(execution, "manager_name") == Some(manager),
        "manager_evidence_mismatch",
        &mut reasons,
    );
    let local_only = execution.get("local_only_requested") == Some(&Value::Bool(true));
    require(
        local_only || manager == "bunx" || runner == "tsx",
        "remote_install_not_disabled",
        &mut reasons,
    );
    require(
        text(execution, "package_name") == Some(&runner),
        "package_mismatch",
        &mut reasons,
    );
    require(
        text(execution, "executable_name") == Some(&runner),
        "executable_mismatch",
        &mut reasons,
    );
    let manager_identity = execution.get("manager").filter(|value| !value.is_null());
    require(
        manager_identity.is_some_and(available),
        "manager_identity_incomplete",
        &mut reasons,
    );

    let executable = execution
        .get("local_executable")
        .filter(|value| !value.is_null());
    let executable_path = executable
        .and_then(|item| text(item, "resolved_path"))
        .map(str::to_owned);
    let executable_hash = executable
        .and_then(|item| text(item, "content_hash"))
        .map(str::to_owned);
    require(
        executable.is_some_and(available) && executable_path.is_some() && executable_hash.is_some(),
        "executable_identity_incomplete",
        &mut reasons,
    );

    let root_manifest = workspace.join("package.json");
    let lockfile_name = if workspace.join("bun.lock").exists() {
        "bun.lock"
    } else {
        "package-lock.json"
    };
    let lockfile = workspace.join(lockfile_name);
    let package_root = workspace.join("node_modules").join(&runner);
    let package_manifest = package_root.join("package.json");
    let (root_payload, root_hash) = read_json_with_integrity(&root_manifest, false);
    let (lock_payload, lock_hash) =
        read_json_with_integrity(&lockfile, lockfile_name == "bun.lock");
    let (package_payload, package_hash) = read_json_with_integrity(&package_manifest, false);
    require(
        evidence_contains(
            execution.get("manifests"),
            &root_manifest,
            root_hash.as_deref(),
        ),
        "manifest_identity_drift",
        &mut reasons,
    );
    require(
        evidence_contains(execution.get("lockfiles"), &lockfile, lock_hash.as_deref()),
        "lock_identity_drift",
        &mut reasons,
    );
    require(
        has_only_supported_lock(execution, lockfile_name),
        "lock_source_ambiguous",
        &mut reasons,
    );

    let declared_version = dependency_version(root_payload.as_ref(), &runner);
    let (locked_version, lock_source_ok) = if lockfile_name == "bun.lock" {
        bun_locked_version(lock_payload.as_ref(), &runner)
    } else {
        locked_version(lock_payload.as_ref(), &runner)
    };
    let installed_name = string_value(package_payload.as_ref(), "name");
    let installed_version = string_value(package_payload.as_ref(), "version");
    require(
        declared_version.is_some(),
        "manifest_dependency_missing",
        &mut reasons,
    );
    require(
        declared_version.as_ref().is_some_and(|value| {
            !SOURCE_PREFIXES
                .iter()
                .any(|prefix| value.to_lowercase().starts_with(prefix))
        }),
        "manifest_source_drift",
        &mut reasons,
    );
    require(
        locked_version.is_some(),
        "lock_dependency_missing",
        &mut reasons,
    );
    require(lock_source_ok, "lock_source_drift", &mut reasons);
    require(
        installed_name.as_deref() == Some(&runner),
        "installed_package_name_mismatch",
        &mut reasons,
    );
    require(
        installed_version.is_some(),
        "installed_package_missing",
        &mut reasons,
    );
    require(
        version_spec_matches(declared_version.as_deref(), locked_version.as_deref(), true),
        "manifest_lock_version_drift",
        &mut reasons,
    );
    require(
        locked_version == installed_version,
        "lock_install_version_drift",
        &mut reasons,
    );
    require(
        text(execution, "declared_version").map(str::to_owned) == declared_version,
        "declared_dependency_mismatch",
        &mut reasons,
    );

    let bin_target = package_bin_target(package_payload.as_ref(), &runner);
    let expected_executable = resolved_package_bin_target(&package_root, bin_target.as_deref());
    require(bin_target.is_some(), "package_bin_missing", &mut reasons);
    require(
        matches!((&executable_path, &expected_executable),
            (Some(path), Some(expected)) if Path::new(path) == expected.as_path()),
        "wrong_local_executable",
        &mut reasons,
    );
    if let (Some(path), Some(hash)) = (&executable_path, &executable_hash) {
        let observed = file_sha256(Path::new(path))
            .ok()
            .map(|digest| format!("sha256:{digest}"));
        require(
            observed.as_deref() == Some(hash.as_str()),
            "executable_identity_drift",
            &mut reasons,
        );
    }

    let mut seen = std::collections::HashSet::new();
    reasons.retain(|reason| seen.insert(reason.clone()));
    let binding_payload = json!({
        "schema_version": 1,
        "manager": manager,
        "manager_identity": manager_identity.cloned().unwrap_or(Value::Null),
        "runner": runner,
        "runner_args": runner_args,
        "input_files": input_files,
        "context_hash": execution.get("context_hash").cloned().unwrap_or(Value::Null),
        "manifest_hash": root_hash,
        "lock_hash": lock_hash,
        "lockfile_name": lockfile_name,
        "package_manifest_hash": package_hash,
        "declared_version": declared_version,
        "locked_version": locked_version,
        "installed_name": installed_name,
        "installed_version": installed_version,
        "executable_path": executable_path,
        "executable_hash": executable_hash,
        "reasons": reasons,
    });
    let encoded = canonical_bytes(&binding_payload)?;
    let mut framed = b"hol-guard:local-node-runner-evidence:v1\0".to_vec();
    framed.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    framed.extend_from_slice(&encoded);
    let operation_id = runner_operation(&runner).ok_or_else(|| "unsupported runner".to_owned())?;
    Ok(Some(NodeRunnerEvidence {
        complete: reasons.is_empty(),
        reasons,
        binding_digest: hex::encode(Sha256::digest(&framed)),
        runner,
        operation_id,
        runner_args,
        input_files,
        executable_path,
        executable_hash,
        root_manifest_hash: root_hash,
        lockfile_hash: lock_hash,
        package_manifest_hash: package_hash,
        lockfile_name: lockfile_name.to_owned(),
    }))
}

type ParsedArguments = (String, Vec<String>, Vec<String>, Vec<String>);

fn runner_arguments(manager: &str, argv: &[String], workspace: &Path) -> Option<ParsedArguments> {
    if !matches!(manager, "npx" | "bunx") {
        return None;
    }
    let mut index = 0;
    while index < argv.len() && matches!(argv[index].as_str(), "--no" | "--no-install") {
        index += 1;
    }
    let runner = argv.get(index)?;
    runner_operation(runner)?;
    let tail: Vec<String> = argv[index + 1..].to_vec();
    let mut reasons: Vec<String> = Vec::new();
    if argv
        .iter()
        .any(|token| token == "--package" || token.starts_with("--package="))
    {
        reasons.push("explicit_package_source".to_owned());
    }
    let raw_files: Vec<String> = match runner.as_str() {
        "vitest" => {
            let (files, valid) = vitest_result_arguments(&tail);
            if !valid {
                reasons.push("runner_arguments_not_result_only".to_owned());
            }
            files
        }
        "eslint" => {
            let no_cache = tail.iter().filter(|token| *token == "--no-cache").count();
            if no_cache != 1
                || tail
                    .iter()
                    .any(|token| token.starts_with('-') && token != "--no-cache")
            {
                reasons.push("runner_arguments_not_result_only".to_owned());
            }
            tail.iter()
                .filter(|token| *token != "--no-cache")
                .cloned()
                .collect()
        }
        _ => {
            if tail.len() != 1 || tail[0].starts_with('-') {
                reasons.push("runner_arguments_not_result_only".to_owned());
            }
            if tail.len() == 1 {
                tail.clone()
            } else {
                Vec::new()
            }
        }
    };
    let input_files = validated_input_files(workspace, runner, &raw_files, &mut reasons);
    Some((runner.clone(), tail, input_files, reasons))
}

fn validated_input_files(
    workspace: &Path,
    runner: &str,
    raw_files: &[String],
    reasons: &mut Vec<String>,
) -> Vec<String> {
    if raw_files.is_empty() {
        reasons.push("explicit_inputs_missing".to_owned());
        return Vec::new();
    }
    let suffixes: &[&str] = if runner == "vitest" {
        &TEST_SUFFIXES
    } else {
        &LINT_SUFFIXES
    };
    let mut result: Vec<String> = Vec::new();
    for raw_file in raw_files {
        let candidate = workspace.join(raw_file);
        let relative = std::fs::canonicalize(&candidate)
            .ok()
            .and_then(|canonical| {
                canonical
                    .strip_prefix(workspace)
                    .ok()
                    .map(Path::to_path_buf)
            });
        let Some(relative) = relative else {
            reasons.push("input_outside_workspace".to_owned());
            continue;
        };
        let portable = relative.to_string_lossy().into_owned();
        let symlink =
            std::fs::symlink_metadata(&candidate).is_ok_and(|meta| meta.file_type().is_symlink());
        if symlink
            || !candidate.is_file()
            || !suffixes.iter().any(|suffix| portable.ends_with(suffix))
        {
            reasons.push("input_not_exact_regular_source".to_owned());
            continue;
        }
        let protected = relative.components().any(|part| {
            let name = part.as_os_str().to_string_lossy().to_lowercase();
            name.starts_with(".env") || name == ".git" || name == ".guard"
        });
        if protected {
            reasons.push("input_protected".to_owned());
            continue;
        }
        if raw_file.replace('\\', "/") != portable {
            reasons.push("input_alias_or_duplicate".to_owned());
            continue;
        }
        result.push(portable);
    }
    let unique: std::collections::HashSet<&String> = result.iter().collect();
    if unique.len() != result.len() {
        reasons.push("input_alias_or_duplicate".to_owned());
    }
    result
}

fn evidence_contains(values: Option<&Value>, path: &Path, content_hash: Option<&str>) -> bool {
    let canonical = weak_resolve(path).to_string_lossy().into_owned();
    values.and_then(Value::as_array).is_some_and(|items| {
        items.iter().any(|item| {
            available(item)
                && text(item, "resolved_path") == Some(canonical.as_str())
                && text(item, "content_hash") == content_hash
        })
    })
}

fn has_only_supported_lock(execution: &Value, name: &str) -> bool {
    let lockfiles: Vec<&Value> = execution
        .get("lockfiles")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter(|item| available(item)).collect())
        .unwrap_or_default();
    lockfiles.len() == 1
        && matches!(name, "package-lock.json" | "bun.lock")
        && PathBuf::from(text(lockfiles[0], "resolved_path").unwrap_or(""))
            .file_name()
            .is_some_and(|file| file == name)
}

fn dependency_version(payload: Option<&Map<String, Value>>, package: &str) -> Option<String> {
    let payload = payload?;
    for group in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(version) =
            object_of(payload.get(group)).and_then(|values| stripped(values.get(package)))
        {
            return Some(version);
        }
    }
    None
}

fn locked_version(payload: Option<&Map<String, Value>>, package: &str) -> (Option<String>, bool) {
    let item = payload
        .and_then(|map| object_of(map.get("packages")))
        .and_then(|packages| object_of(packages.get(&format!("node_modules/{package}"))));
    let Some(item) = item else {
        return (None, false);
    };
    let version = item.get("version").and_then(Value::as_str);
    let source_ok = item.get("link") != Some(&Value::Bool(true))
        && version.is_some_and(|version| {
            canonical_registry_resolution(package, version, item.get("resolved"))
        })
        && valid_sha512_integrity(item.get("integrity"));
    (stripped(item.get("version")), source_ok)
}

fn string_value(payload: Option<&Map<String, Value>>, key: &str) -> Option<String> {
    stripped(payload?.get(key))
}
