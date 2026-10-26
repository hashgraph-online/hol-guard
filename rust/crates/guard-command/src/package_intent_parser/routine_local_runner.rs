//! The decision that a routine JS runner invocation is already bound to local
//! project state. It was ported from the Python helpers
//! `_routine_local_runner_has_complete_evidence` and
//! `_routine_local_runner_versions_match`, which this port replaced.
//!
//! The caller uses that verdict to suppress a package review artifact
//! entirely, so it is authority, and it depends on reading `package.json`,
//! the installed package's own manifest and every lockfile. The
//! parser already resolves and digests those files for the execution
//! evidence, so the verdict is computed here, beside the reads it depends on,
//! and travels with the intent instead of over a second round trip.
//!
//! The containment checks stay strict: each of the workspace, `node_modules`,
//! the package root and the executable must canonicalize, and the two
//! `strip_prefix` checks reject a package directory or a runner binary that a
//! symlink moved outside the tree the evidence claims it is in.
//!
//! Every manifest and lockfile read is capped at `MAX_VERDICT_FILE_BYTES`; a
//! larger file gives no verdict, so the review artifact stays.

use std::collections::BTreeSet;
use std::path::Path;

use super::*;
use crate::direct_vitest::semver_spec_matches;
use crate::jsonc::loads_jsonc;

/// The runners whose local identity is worth establishing.
const ROUTINE_RUNNERS: [&str; 4] = ["eslint", "jest", "tsc", "vitest"];

/// Declared-version prefixes that name a source outside the registry, where a
/// version string proves nothing about what is installed.
const REMOTE_VERSION_PREFIXES: [&str; 6] =
    ["file:", "git+", "git://", "github:", "http:", "https:"];

/// Whether this evidence row resolved to a readable file with a stable
/// identity and content digest.
fn complete(evidence: &PackageExecutionFileEvidence) -> bool {
    evidence.status == "available"
        && evidence.resolved_path.is_some()
        && evidence.file_identity.is_some()
        && evidence.content_hash.is_some()
}

/// Whether a routine runner invocation is bound to the local project state
/// its evidence names.
pub(super) fn routine_local_runner(intent: &PackageIntent) -> bool {
    if !matches!(intent.package_manager.as_str(), "bunx" | "npx")
        || intent.local_executions.len() != 1
    {
        return false;
    }
    let execution = &intent.local_executions[0];
    let Some(package_name) = execution.package_name.as_deref() else {
        return false;
    };
    if !ROUTINE_RUNNERS.contains(&package_name) || intent.targets.len() != 1 {
        return false;
    }

    let target = &intent.targets[0];
    if target.raw_spec != package_name || target.requested_specifier.is_some() {
        return false;
    }
    if target.source_kind.is_some() || target.source_url.is_some() {
        return false;
    }
    if intent
        .command_tokens
        .iter()
        .any(|token| token == "--package" || token.starts_with("--package="))
    {
        return false;
    }

    if execution.executable_name.as_deref() != Some(package_name) {
        return false;
    }
    let Some(declared_version) = execution.declared_version.as_deref() else {
        return false;
    };
    let lowered = declared_version.to_lowercase();
    if REMOTE_VERSION_PREFIXES
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
    {
        return false;
    }

    if execution.manifests.is_empty() || execution.lockfiles.is_empty() {
        return false;
    }
    let (Some(manager), Some(executable)) = (
        execution.manager.as_ref(),
        execution.local_executable.as_ref(),
    ) else {
        return false;
    };
    if ![manager, executable]
        .into_iter()
        .chain(execution.manifests.iter())
        .chain(execution.lockfiles.iter())
        .all(complete)
    {
        return false;
    }
    let Some(executable_path) = executable.resolved_path.as_deref() else {
        return false;
    };

    let (Ok(workspace), Ok(executable_path)) = (
        std::fs::canonicalize(&execution.effective_cwd),
        std::fs::canonicalize(executable_path),
    ) else {
        return false;
    };
    let Ok(node_modules) = std::fs::canonicalize(workspace.join("node_modules")) else {
        return false;
    };
    let Ok(package_root) = std::fs::canonicalize(node_modules.join(package_name)) else {
        return false;
    };
    if package_root.strip_prefix(&node_modules).is_err()
        || executable_path.strip_prefix(&package_root).is_err()
    {
        return false;
    }

    intent.execution_context_reason_codes.is_empty()
        && versions_match(
            &workspace,
            package_name,
            declared_version,
            &execution.lockfiles,
        )
}

/// The largest manifest or lockfile the verdict reads. The parser runs in
/// the shared resident, so a file past this gets no verdict rather than a
/// second unbounded read and parse.
const MAX_VERDICT_FILE_BYTES: u64 = 32 * 1024 * 1024;

/// `path` as UTF-8 text, or `None` when it cannot be read or is larger than
/// `limit` bytes.
pub(super) fn read_bounded(path: &Path, limit: u64) -> Option<String> {
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(limit.saturating_add(1))
        .read_to_string(&mut text)
        .ok()?;
    u64::try_from(text.len())
        .is_ok_and(|length| length <= limit)
        .then_some(text)
}

/// A JSON object read from `path`, or `None` for any read, decode, size or
/// shape failure. A read error, invalid UTF-8, invalid JSON and a non-mapping
/// document are all treated the same way.
fn read_json_object(path: &Path) -> Option<Map<String, Value>> {
    let text = read_bounded(path, MAX_VERDICT_FILE_BYTES)?;
    match serde_json::from_str::<Value>(&text).ok()? {
        Value::Object(object) => Some(object),
        _ => None,
    }
}

/// The declared dependency pin, the installed manifest and every lockfile
/// must name one version, and that version must satisfy the pin.
fn versions_match(
    workspace: &Path,
    package_name: &str,
    declared_version: &str,
    lockfiles: &[PackageExecutionFileEvidence],
) -> bool {
    let (Some(manifest), Some(installed)) = (
        read_json_object(&workspace.join("package.json")),
        read_json_object(
            &workspace
                .join("node_modules")
                .join(package_name)
                .join("package.json"),
        ),
    ) else {
        return false;
    };

    let declared = ["dependencies", "devDependencies"].iter().any(|group| {
        manifest
            .get(*group)
            .and_then(Value::as_object)
            .and_then(|group| group.get(package_name))
            .and_then(Value::as_str)
            == Some(declared_version)
    });
    if !declared || installed.get("name").and_then(Value::as_str) != Some(package_name) {
        return false;
    }
    let Some(installed_version) = installed.get("version").and_then(Value::as_str) else {
        return false;
    };

    let mut locked_versions: BTreeSet<String> = BTreeSet::new();
    let npm_key = format!("node_modules/{package_name}");
    let bun_prefix = format!("{package_name}@");
    for evidence in lockfiles {
        let Some(resolved) = evidence.resolved_path.as_deref() else {
            continue;
        };
        let path = Path::new(resolved);
        let Some(text) = read_bounded(path, MAX_VERDICT_FILE_BYTES) else {
            return false;
        };
        let parsed = if path.file_name().and_then(|name| name.to_str()) == Some("bun.lock") {
            loads_jsonc(&text).ok()
        } else {
            serde_json::from_str::<Value>(&text).ok()
        };
        // A document that does not parse, is not a mapping, or carries no
        // `packages` mapping is a lockfile Guard cannot read — fail closed
        // rather than letting the remaining lockfiles decide alone.
        let Some(packages) = parsed
            .as_ref()
            .and_then(|lock| lock.get("packages"))
            .and_then(Value::as_object)
        else {
            return false;
        };
        if let Some(version) = packages
            .get(&npm_key)
            .and_then(Value::as_object)
            .and_then(|entry| entry.get("version"))
            .and_then(Value::as_str)
        {
            locked_versions.insert(version.to_owned());
        }
        if let Some(version) = packages
            .get(package_name)
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(Value::as_str)
            .and_then(|entry| entry.strip_prefix(&bun_prefix))
        {
            locked_versions.insert(version.to_owned());
        }
    }

    locked_versions.len() == 1
        && locked_versions.contains(installed_version)
        && semver_spec_matches(declared_version, installed_version)
}
