//! The lockfile dialects the routine-runner verdict reads.
//!
//! Four package managers write the same fact — which release of a dependency
//! this workspace resolved — in four shapes: npm's JSON, Bun's JSONC, pnpm's
//! YAML and yarn's own text. Each reader answers with every release the file
//! pins for one package, and with `None` when the file says something the
//! verdict must not act on: a source outside the registry, a patched package,
//! or a dialect it does not recognise.

use std::collections::BTreeSet;
use std::path::{Component, Path};

use serde_json::Value;

use super::{read_bounded, registry_entry, MAX_VERDICT_FILE_BYTES, REMOTE_VERSION_PREFIXES};
use crate::jsonc::loads_jsonc;

/// The versions one lockfile pins for `dependency_name`, or `None` when it is
/// a file Guard cannot read, is written in a dialect it does not recognise,
/// names a source outside the registry, or never names the package at all.
pub(super) fn locked_versions(
    path: &Path,
    workspace: &Path,
    dependency_name: &str,
) -> Option<BTreeSet<String>> {
    let text = read_bounded(path, MAX_VERDICT_FILE_BYTES)?;
    let versions = match path.file_name().and_then(|name| name.to_str())? {
        "pnpm-lock.yaml" => pnpm_locked_versions(
            &text,
            dependency_name,
            importer_key(path, workspace).as_deref(),
        )?,
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

/// The key `pnpm-lock.yaml` writes for the workspace the run is in.
///
/// pnpm roots its `importers` block at the lockfile's own directory and names
/// every workspace under it by a relative path, with the root itself spelled
/// `.`. A workspace that does not sit under the lockfile, or whose path
/// cannot be spelled the way pnpm spells it, has no key there.
///
/// The lockfile's own directory is resolved before the two paths are
/// compared, because the workspace reached the verdict resolved and a link
/// anywhere above either of them would otherwise read as a different tree.
fn importer_key(lockfile: &Path, workspace: &Path) -> Option<String> {
    let root = std::fs::canonicalize(lockfile.parent()?).ok()?;
    let relative = workspace.strip_prefix(&root).ok()?;
    let mut key = String::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return None;
        };
        if !key.is_empty() {
            key.push('/');
        }
        key.push_str(name.to_str()?);
    }
    Some(if key.is_empty() { ".".to_owned() } else { key })
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
///
/// A patched runner gives no versions at all. The top-level
/// `patchedDependencies` block names every patch in every lockfile version,
/// which the `patch_hash=` key suffix does not: lockfile 9 moved that suffix
/// onto the `snapshots` keys, leaving the `packages` key spelled like an
/// ordinary release.
///
/// One lockfile serves every workspace in a monorepo, so `packages` lists
/// each release any of them resolved: two workspaces on different releases of
/// the same runner leave two versions there and no verdict. The `importers`
/// block says which one *this* workspace resolved, so when `importer` names a
/// workspace whose entry pins a release `packages` also carries, that release
/// is the answer. Everything `packages` refuses — a patch, a checkout, a
/// directory — is still read first and still refuses the whole file.
fn pnpm_locked_versions(
    text: &str,
    dependency_name: &str,
    importer: Option<&str>,
) -> Option<BTreeSet<String>> {
    let mut versions = BTreeSet::new();
    let mut inside_packages = false;
    let mut inside_patched = false;
    let mut inside_importers = false;
    let mut this_importer = false;
    let mut this_dependency = false;
    let mut importer_version: Option<String> = None;
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
            inside_patched = line == "patchedDependencies:";
            inside_importers = line == "importers:";
            continue;
        };
        if inside_patched {
            // Only the block's own keys name a patch; its body lines, which
            // carry the hash and the patch file, are indented further.
            if indented.starts_with(' ') {
                continue;
            }
            let key = indented.strip_suffix(':').unwrap_or(indented);
            let key = key.trim_matches(['\'', '"']);
            if key == dependency_name
                || key
                    .strip_prefix(dependency_name)
                    .is_some_and(|rest| rest.starts_with('@'))
            {
                return None;
            }
            continue;
        }
        if inside_importers {
            read_importer_line(
                indented,
                dependency_name,
                importer,
                &mut this_importer,
                &mut this_dependency,
                &mut importer_version,
            );
            continue;
        }
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
        // disk. Lockfile 6 and older mark that in this key; lockfile 9 marks
        // it in `patchedDependencies` and on the `snapshots` key instead.
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
    if let Some(version) = importer_version {
        if versions.contains(&version) {
            return Some(BTreeSet::from([version]));
        }
    }
    Some(versions)
}

/// Read one line of the `importers` block, tracking whether it belongs to the
/// workspace the run is in and to the dependency being asked about.
///
/// The block nests the workspace key two spaces in, its dependency groups
/// four, each dependency six and the `specifier`/`version` pair eight. A
/// version there may carry the peers it was resolved against in parentheses,
/// and a workspace link or a local directory names its source the way every
/// other dialect does, which leaves no release to narrow to.
fn read_importer_line(
    indented: &str,
    dependency_name: &str,
    importer: Option<&str>,
    this_importer: &mut bool,
    this_dependency: &mut bool,
    importer_version: &mut Option<String>,
) {
    let trimmed = indented.trim_start();
    let key = || {
        trimmed
            .strip_suffix(':')
            .unwrap_or(trimmed)
            .trim_matches(['\'', '"'])
    };
    match indented.len() - trimmed.len() {
        0 => {
            *this_importer = Some(key()) == importer;
            *this_dependency = false;
        }
        2 => *this_dependency = false,
        4 => *this_dependency = *this_importer && key() == dependency_name,
        _ => {
            if !*this_dependency {
                return;
            }
            if let Some(value) = trimmed.strip_prefix("version:") {
                let value = value.trim().trim_matches(['\'', '"']);
                let value = value.split('(').next().unwrap_or(value);
                *importer_version = registry_version(value).map(str::to_owned);
            }
        }
    }
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
