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

/// The runners whose local identity is worth establishing: the lint, test,
/// commit-hook and TypeScript entry points a project pins in its own manifest
/// and runs through `bunx` or `npx` on every change.
const ROUTINE_RUNNERS: [&str; 7] = [
    "eslint",
    "jest",
    "lint-staged",
    "mocha",
    "tsc",
    "tsx",
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
    // The runner list names the executables a project runs, and one of them is
    // published under another name: `tsc` ships inside `typescript`. The
    // declared pin was already read under the dependency name, so the
    // installed tree, the manifest key and every lockfile entry have to be
    // read under it too, or the verdict looks for a `node_modules/tsc` that
    // npm never creates.
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
    let Ok(package_root) = std::fs::canonicalize(node_modules.join(dependency_name)) else {
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
            dependency_name,
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

/// The declared dependency pin, the installed manifest and every lockfile
/// must name one version, and that version must satisfy the pin.
fn versions_match(
    workspace: &Path,
    dependency_name: &str,
    declared_version: &str,
    lockfiles: &[PackageExecutionFileEvidence],
) -> bool {
    let (Some(manifest), Some(installed)) = (
        read_json_object(&workspace.join("package.json")),
        read_json_object(
            &workspace
                .join("node_modules")
                .join(dependency_name)
                .join("package.json"),
        ),
    ) else {
        return false;
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
        return false;
    }
    let Some(installed_version) = installed.get("version").and_then(Value::as_str) else {
        return false;
    };

    let mut locked: BTreeSet<String> = BTreeSet::new();
    for evidence in lockfiles {
        let Some(resolved) = evidence.resolved_path.as_deref() else {
            continue;
        };
        // Every lockfile in the workspace has to bind this runner itself, to
        // a release the registry served. A file Guard cannot read, cannot
        // recognise, or that parses but never names the package would
        // otherwise let the remaining lockfiles answer for it.
        let Some(versions) = locked_versions(Path::new(resolved), dependency_name) else {
            return false;
        };
        locked.extend(versions);
    }

    locked.len() == 1
        && locked.contains(installed_version)
        && semver_spec_matches(declared_version, installed_version)
}

/// The versions one lockfile pins for `dependency_name`, or `None` when it is
/// a file Guard cannot read, is written in a dialect it does not recognise,
/// names a source outside the registry, or never names the package at all.
fn locked_versions(path: &Path, dependency_name: &str) -> Option<BTreeSet<String>> {
    let text = read_bounded(path, MAX_VERDICT_FILE_BYTES)?;
    let versions = match path.file_name().and_then(|name| name.to_str())? {
        "pnpm-lock.yaml" => pnpm_locked_versions(&text, dependency_name)?,
        "yarn.lock" => yarn_locked_versions(&text, dependency_name)?,
        "bun.lock" => json_locked_versions(&loads_jsonc(&text).ok()?, dependency_name)?,
        // `bun.lockb` is Bun's binary lockfile, which carries no text form to
        // read, so a workspace holding one gets no verdict.
        "bun.lockb" => return None,
        // Everything else npm writes is JSON: `package-lock.json` and the
        // `npm-shrinkwrap.json` it publishes beside it.
        _ => json_locked_versions(&serde_json::from_str::<Value>(&text).ok()?, dependency_name)?,
    };
    (!versions.is_empty()).then_some(versions)
}

/// `spec` as a released version, or `None` when it names a source instead.
/// Every lockfile dialect writes the source inside the spec it pins, so a
/// scheme or a path there means the installed copy is a checkout or a
/// directory rather than something the registry served.
fn registry_version(spec: &str) -> Option<&str> {
    (!spec.is_empty() && !spec.contains([':', '/'])).then_some(spec)
}

/// The versions a JSON lockfile pins for `dependency_name`. npm keys its
/// `packages` mapping by install path and Bun by package name, and either
/// spelling can appear, so both are read from every JSON lockfile.
fn json_locked_versions(lock: &Value, dependency_name: &str) -> Option<BTreeSet<String>> {
    let packages = lock.get("packages").and_then(Value::as_object)?;
    let mut versions = BTreeSet::new();
    if let Some(entry) = packages
        .get(&format!("node_modules/{dependency_name}"))
        .and_then(Value::as_object)
    {
        if !registry_entry(entry) {
            return None;
        }
        if let Some(version) = entry.get("version").and_then(Value::as_str) {
            versions.insert(version.to_owned());
        }
    }
    if let Some(spec) = packages
        .get(dependency_name)
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .and_then(|entry| entry.strip_prefix(&format!("{dependency_name}@")))
    {
        versions.insert(registry_version(spec)?.to_owned());
    }
    Some(versions)
}

/// What one `pnpm-lock.yaml` entry has said so far about the release it pins.
struct PnpmEntry {
    version: String,
    resolution: Option<String>,
}

impl PnpmEntry {
    /// The release the entry pins, or `None` when it named a source outside
    /// the registry or never finished saying what it resolved to.
    ///
    /// Every release the registry served carries an integrity digest, while a
    /// checkout, a local directory or a linked package names its source in
    /// the same mapping and says nothing about what the declared range would
    /// have installed. The key alone cannot be trusted for this: lockfile 5
    /// and 6 wrote a plain `name/version` key for a git dependency and left
    /// the git remote to the entry body.
    fn finish(self) -> Option<String> {
        let resolution = self.resolution?;
        let names_a_source = ["type:", "repo:", "directory:", "path:"]
            .iter()
            .any(|field| resolution.contains(field));
        (resolution.contains("integrity:") && !names_a_source).then_some(self.version)
    }
}

/// The versions `pnpm-lock.yaml` pins for `dependency_name`.
///
/// pnpm writes one key per resolved package under a top-level `packages`
/// mapping, two spaces in, with the entry's own body four spaces in. Three
/// key spellings have shipped: `name@version` in lockfile 9, `/name@version`
/// in lockfile 6 and `/name/version` in lockfile 5. A key may also carry the
/// peers it was resolved against in parentheses, which still names that
/// release.
fn pnpm_locked_versions(text: &str, dependency_name: &str) -> Option<BTreeSet<String>> {
    let mut versions = BTreeSet::new();
    let mut inside_packages = false;
    let mut entry: Option<PnpmEntry> = None;
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let Some(indented) = line.strip_prefix("  ") else {
            // Anything else at column zero opens the next top-level block.
            if let Some(entry) = entry.take() {
                versions.insert(entry.finish()?);
            }
            inside_packages = line == "packages:";
            continue;
        };
        if !inside_packages {
            continue;
        }
        if let Some(body) = indented.strip_prefix(' ') {
            if let (Some(entry), Some(value)) = (
                entry.as_mut(),
                body.trim_start().strip_prefix("resolution:"),
            ) {
                entry.resolution = Some(value.trim().to_owned());
            }
            continue;
        }
        if let Some(entry) = entry.take() {
            versions.insert(entry.finish()?);
        }
        let Some(key) = indented.strip_suffix(':') else {
            continue;
        };
        let key = key.trim_matches(['\'', '"']);
        let key = key.strip_prefix('/').unwrap_or(key);
        let Some(rest) = key.strip_prefix(dependency_name) else {
            continue;
        };
        let Some(spec) = rest.strip_prefix('@').or_else(|| rest.strip_prefix('/')) else {
            continue;
        };
        // A patch rewrites the package's own files after the registry served
        // them, so the version it carries no longer describes what is on
        // disk. pnpm marks that in the key, in parentheses since lockfile 9
        // and after an underscore before it.
        if spec.contains("patch_hash=") {
            return None;
        }
        let spec = spec.split('(').next().unwrap_or(spec);
        entry = Some(PnpmEntry {
            version: registry_version(spec)?.to_owned(),
            resolution: None,
        });
    }
    if let Some(entry) = entry {
        versions.insert(entry.finish()?);
    }
    Some(versions)
}

/// What one `yarn.lock` block has said so far about the release it pins.
#[derive(Default)]
struct YarnBlock {
    version: Option<String>,
    from_registry: bool,
}

impl YarnBlock {
    /// Read one body line of the block.
    fn read(&mut self, line: &str) {
        if let Some(value) = line
            .strip_prefix("version ")
            .or_else(|| line.strip_prefix("version: "))
        {
            self.version = Some(unquote(value).to_owned());
        } else if let Some(value) = line.strip_prefix("resolved ") {
            let value = unquote(value);
            self.from_registry = value.starts_with("https://") || value.starts_with("http://");
        } else if let Some(value) = line.strip_prefix("resolution: ") {
            self.from_registry = unquote(value).contains("@npm:");
        }
    }

    /// The release the block pins, or `None` when it never named one or named
    /// a source outside the registry.
    fn finish(self) -> Option<String> {
        let version = self.version?;
        (self.from_registry && registry_version(&version).is_some()).then_some(version)
    }
}

/// `value` without the quotes a lockfile may wrap it in.
fn unquote(value: &str) -> &str {
    value.trim().trim_matches(['"', '\''])
}

/// What a `yarn.lock` block header says about the package being looked for.
enum YarnHeader {
    /// The block answers for some other package.
    Other,
    /// The block answers for this package, resolved from the npm registry.
    Registry,
    /// The block answers for this package from somewhere else: a patch, a
    /// tarball URL, a checkout, a workspace or a local directory.
    Foreign,
}

/// The package name a `yarn.lock` specifier opens with, or `None` when it
/// carries no range at all. A scoped name opens with its own `@`, so the
/// separator is the next one rather than the last: a Berry `patch:` range
/// holds further `@`s of its own.
fn yarn_specifier_name(spec: &str) -> Option<&str> {
    let index = spec.get(1..)?.find('@')? + 1;
    Some(&spec[..index])
}

/// What a `yarn.lock` block header, the column-zero line opening a block,
/// says about `dependency_name`, or `None` when the line is not a header at
/// all and the file is therefore one Guard cannot read.
///
/// A header lists the specifiers the block resolves, each a package name
/// followed by the range it was requested at, and either dialect may quote
/// them. Yarn 1 writes a bare range and Berry prefixes it with the protocol
/// it resolved through, so a range naming anything but `npm:` is a copy the
/// registry never served.
fn yarn_header(header: &str, dependency_name: &str) -> Option<YarnHeader> {
    let header = header.strip_suffix(':')?;
    let mut answer = YarnHeader::Other;
    for spec in header.split(',') {
        let spec = unquote(spec);
        let Some(name) = yarn_specifier_name(spec) else {
            continue;
        };
        if name != dependency_name {
            continue;
        }
        let range = &spec[name.len() + 1..];
        if range.starts_with("npm:") || !range.contains([':', '/']) {
            answer = YarnHeader::Registry;
            continue;
        }
        return Some(YarnHeader::Foreign);
    }
    Some(answer)
}

/// The versions `yarn.lock` pins for `dependency_name`.
///
/// Both dialects write one block per resolved package: a column-zero header
/// listing the specifiers it answers for, then an indented body. Yarn 1
/// writes `version "4.22.4"` and the registry URL on a `resolved` line; Yarn
/// 2 and later write `version: 4.22.4` and name the source in `resolution`.
fn yarn_locked_versions(text: &str, dependency_name: &str) -> Option<BTreeSet<String>> {
    let mut versions = BTreeSet::new();
    let mut block: Option<YarnBlock> = None;
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') {
            if let Some(block) = block.take() {
                versions.insert(block.finish()?);
            }
            block = match yarn_header(line, dependency_name)? {
                YarnHeader::Registry => Some(YarnBlock::default()),
                // Skipping the block would not withdraw the verdict: a
                // sibling block resolving the same package from the registry
                // would still answer, for a copy nobody installed from it.
                YarnHeader::Foreign => return None,
                YarnHeader::Other => None,
            };
            continue;
        }
        let Some(block) = block.as_mut() else {
            continue;
        };
        block.read(line.trim_start());
    }
    if let Some(block) = block {
        versions.insert(block.finish()?);
    }
    Some(versions)
}
