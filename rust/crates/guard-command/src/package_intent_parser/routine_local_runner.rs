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

#[path = "routine_local_runner_lockfiles.rs"]
mod lockfiles;

use lockfiles::locked_versions;

/// The runners whose local identity is worth establishing: the lint, test,
/// commit-hook and TypeScript entry points a project pins in its own manifest
/// and runs through `bunx` or `npx` on every change.
const ROUTINE_RUNNERS: [&str; 18] = [
    "ava",
    "borp",
    "cucumber-js",
    "eslint",
    "jasmine",
    "jest",
    "lab",
    "lint-staged",
    "mocha",
    "poku",
    "qunit",
    "tap",
    "tape",
    "tsc",
    "tsd",
    "tsx",
    "uvu",
    "vitest",
];

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
    // The runner list names the executables a project runs, and two of them
    // are published under another name: `tsc` ships inside `typescript` and
    // `lab` inside `@hapi/lab`. The declared pin was already read under the
    // dependency name, so the installed tree, the manifest key and every
    // lockfile entry have to be read under it too, or the verdict looks for a
    // `node_modules/tsc` that npm never creates.
    let dependency_name = local_executable_package_alias(package_name);
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

    let local_only = install_refused(&intent.package_manager, &intent.command_tokens);
    if execution.manifests.is_empty() || (execution.lockfiles.is_empty() && !local_only) {
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
    let Ok(package_root) = std::fs::canonicalize(node_modules.join(dependency_name)) else {
        return false;
    };
    if package_root.strip_prefix(&node_modules).is_err()
        || executable_path.strip_prefix(&package_root).is_err()
    {
        return false;
    }

    if !intent.execution_context_reason_codes.is_empty() {
        return false;
    }
    let Some(installed_version) =
        declared_release_installed(&workspace, dependency_name, declared_version)
    else {
        return false;
    };
    // A run that cannot fetch starts the bin checked above or nothing, so a
    // lockfile another manager left behind has nothing to say about it.
    local_only
        || lockfiles_pin(
            &workspace,
            dependency_name,
            declared_version,
            &installed_version,
            &execution.lockfiles,
        )
}

/// Whether the runner's own options forbid a registry fetch. `npx` reads
/// `--no-install` as `--no`, and the last of `--yes`, `-y` and `--no` wins;
/// `bunx` has only `--no-install`. Words after the executable are the tool's.
fn install_refused(manager: &str, tokens: &[String]) -> bool {
    let mut refused = false;
    for token in tokens.iter().skip(1) {
        match (manager, token.as_str()) {
            (_, "--") => break,
            ("npx" | "bunx", "--no-install") | ("npx", "--no") => refused = true,
            ("npx", "--yes" | "-y") => refused = false,
            (_, option) if option.starts_with('-') => {}
            _ => break,
        }
    }
    refused
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

/// Whether an npm lockfile entry describes a package the registry served.
///
/// A `link` entry points at another directory in the tree and a `resolved`
/// value outside `http(s)` names a checkout or a tarball on disk, neither of
/// which the declared version says anything about.
fn registry_entry(entry: &Map<String, Value>) -> bool {
    if entry.get("link").and_then(Value::as_bool) == Some(true) {
        return false;
    }
    match entry.get("resolved").map(|value| value.as_str()) {
        None => true,
        Some(Some(resolved)) => resolved.starts_with("https://") || resolved.starts_with("http://"),
        Some(None) => false,
    }
}

/// The installed release, when `package.json` declares the pin the evidence
/// read and the package installed under that name satisfies it.
fn declared_release_installed(
    workspace: &Path,
    dependency_name: &str,
    declared_version: &str,
) -> Option<String> {
    let (Some(manifest), Some(installed)) = (
        read_json_object(&workspace.join("package.json")),
        read_json_object(
            &workspace
                .join("node_modules")
                .join(dependency_name)
                .join("package.json"),
        ),
    ) else {
        return None;
    };

    let declared = ["dependencies", "devDependencies"].iter().any(|group| {
        manifest
            .get(*group)
            .and_then(Value::as_object)
            .and_then(|group| group.get(dependency_name))
            .and_then(Value::as_str)
            == Some(declared_version)
    });
    if !declared || installed.get("name").and_then(Value::as_str) != Some(dependency_name) {
        return None;
    }
    let installed_version = installed.get("version").and_then(Value::as_str)?;
    semver_spec_matches(declared_version, installed_version).then(|| installed_version.to_owned())
}

/// Every lockfile that still describes the declared dependency must name one
/// version, the installed one.
fn lockfiles_pin(
    workspace: &Path,
    dependency_name: &str,
    declared_version: &str,
    installed_version: &str,
    lockfiles: &[PackageExecutionFileEvidence],
) -> bool {
    let mut locked: BTreeSet<String> = BTreeSet::new();
    for evidence in lockfiles {
        let Some(resolved) = evidence.resolved_path.as_deref() else {
            continue;
        };
        // Every lockfile in the workspace has to bind this runner itself, to
        // a release the registry served. A file Guard cannot read, cannot
        // recognise, or that parses but never names the package would
        // otherwise let the remaining lockfiles answer for it.
        let Some(versions) = locked_versions(Path::new(resolved), workspace, dependency_name)
        else {
            return false;
        };
        // A lockfile whose every entry for this dependency falls outside the
        // range the manifest declares was written against an older manifest.
        // Projects keep an abandoned manager's lockfile in the tree long after
        // they stop running it, and a pin the manifest no longer admits cannot
        // describe the installed tree: the installed release has to satisfy
        // that range to get this far. Such a file neither pins the runner nor
        // contradicts the lockfiles that do, so it is passed over rather than
        // read as a conflict.
        if versions
            .iter()
            .all(|version| !semver_spec_matches(declared_version, version))
        {
            continue;
        }
        locked.extend(versions);
    }
    locked.len() == 1 && locked.contains(installed_version)
}
