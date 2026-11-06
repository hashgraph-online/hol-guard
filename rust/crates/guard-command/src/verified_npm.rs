//! Prove which `npm` an agent's `PATH` will actually run.
//!
//! Port of the npm-proving helpers in
//! `daemon/hook_native_package_review.py`: `verified_npm_version`,
//! `_changes_npm`, `_loader_paths_outside`, `_npmrc_redirects_fetch` and
//! `_resolve_executable`. A script-free registry install may continue without
//! review only when the install really is the standard npm the agent's `PATH`
//! resolves, so every uncertainty here fails closed by answering "unknown".

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// Largest `npm/package.json` this will read before refusing to prove a version.
pub const MAX_PACKAGE_JSON_BYTES: u64 = 256 * 1024;
/// Largest npm config file this will read before treating it as a redirect.
pub const MAX_NPMRC_BYTES: u64 = 64 * 1024;

/// Loader variables whose stamped value must stay outside the workspace.
pub const LIBRARY_SEARCH_PATH_NAMES: [&str; 5] = [
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
];

/// npm settings that change nothing about where packages come from.
const INERT_NPM_SETTINGS: [&str; 7] = [
    "cache",
    "update-notifier",
    "fund",
    "audit",
    "loglevel",
    "progress",
    "color",
];

/// Settings that change what npm or node load before the command line is read.
const ENVIRONMENT_OVERRIDES: [&str; 3] = ["npm_config_", "node_options", "node_path"];
const ENVIRONMENT_NAMES: [&str; 3] = ["prefix", "destdir", "node_tls_reject_unauthorized"];

/// npm config keys that move where packages come from or how transport is
/// trusted. `prefix` is left out: outside the command line it only moves
/// global installs.
const FETCH_REDIRECTING_KEYS: [&str; 14] = [
    "registry",
    "replace-registry-host",
    "strict-ssl",
    "ca",
    "cafile",
    "proxy",
    "https-proxy",
    "http-proxy",
    "noproxy",
    "no-proxy",
    "global",
    "location",
    "globalconfig",
    "userconfig",
];

/// The execution environment a hook stamped alongside the command.
#[derive(Debug, Default)]
pub struct ExecutionEnvironment {
    /// `environment_names`: the variable names the agent exported.
    pub names: Vec<String>,
    /// `path`: the search path the agent's shell will use.
    pub search_path: Option<String>,
    /// `home`: the agent's home directory.
    pub home: Option<String>,
    /// `library_search_paths`: stamped values for the loader variables.
    pub library_search_paths: BTreeMap<String, String>,
    /// Whether the stamped environment was a well-formed object at all.
    pub well_formed: bool,
}

impl ExecutionEnvironment {
    /// Read the stamped environment, keeping Python's `isinstance` checks.
    ///
    /// A field of the wrong shape is dropped rather than coerced, so a
    /// malformed stamp proves nothing and the caller fails closed.
    pub fn from_value(value: Option<&Value>) -> Self {
        let Some(Value::Object(object)) = value else {
            return Self::default();
        };
        let mut environment = Self {
            well_formed: true,
            ..Self::default()
        };
        // Python requires `environment_names` to be a list of strings; a
        // single non-string entry rejects the whole environment, which the
        // caller sees as an unprovable name.
        match object.get("environment_names") {
            Some(Value::Array(items)) => {
                for item in items {
                    match item.as_str() {
                        Some(name) => environment.names.push(name.to_owned()),
                        // A single non-string entry rejects the whole stamp.
                        None => environment.well_formed = false,
                    }
                }
            }
            _ => environment.well_formed = false,
        }
        if let Some(Value::String(path)) = object.get("path") {
            environment.search_path = Some(path.clone());
        }
        if let Some(Value::String(home)) = object.get("home") {
            environment.home = Some(home.clone());
        }
        if let Some(Value::Object(stamped)) = object.get("library_search_paths") {
            for (name, item) in stamped {
                match item {
                    Value::String(text) => {
                        environment
                            .library_search_paths
                            .insert(name.clone(), text.clone());
                    }
                    _ => {
                        // Present but not a string: Python keeps the key and
                        // rejects it when read, so record it as empty.
                        environment
                            .library_search_paths
                            .insert(name.clone(), String::new());
                    }
                }
            }
        }
        environment
    }
}

/// Whether an environment variable may change what npm or node load or fetch.
pub fn changes_npm(name: &str) -> bool {
    let lowered = name.to_lowercase();
    if let Some(setting) = lowered.strip_prefix("npm_config_") {
        // npm reads `npm_config_update_notifier` as `update-notifier`.
        let setting = setting.replace('_', "-");
        return !INERT_NPM_SETTINGS.contains(&setting.as_str());
    }
    ENVIRONMENT_OVERRIDES
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
        || ENVIRONMENT_NAMES.contains(&lowered.as_str())
}

/// Symlink hops `realpath` follows before it gives up, as the kernel does.
const MAX_SYMLINK_HOPS: usize = 40;

/// `os.path.realpath`: resolve every symlink component, dangling ones included.
///
/// A link whose target does not exist yet is still followed, so a path that
/// leads through it into the workspace is seen as inside even before the
/// directory is created. A symlink loop answers `None`, which callers treat as
/// unprovable.
fn realpath(path: &Path) -> Option<PathBuf> {
    let mut pending: Vec<std::ffi::OsString> = Vec::new();
    let mut resolved = PathBuf::new();
    let mut hops = 0;
    push_components(&mut pending, &mut resolved, path);
    while let Some(part) = pending.pop() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        let candidate = resolved.join(&part);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                hops += 1;
                if hops > MAX_SYMLINK_HOPS {
                    return None;
                }
                let target = fs::read_link(&candidate).ok()?;
                push_components(&mut pending, &mut resolved, &target);
            }
            _ => resolved = candidate,
        }
    }
    Some(resolved)
}

/// Queue `path`'s components for `realpath`, restarting at the root when it is
/// absolute.
fn push_components(pending: &mut Vec<std::ffi::OsString>, resolved: &mut PathBuf, path: &Path) {
    use std::path::Component;
    let mut parts = Vec::new();
    let mut rooted = false;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                if !rooted {
                    resolved.clear();
                    rooted = true;
                }
                resolved.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => parts.push(std::ffi::OsString::from("..")),
            Component::Normal(name) => parts.push(name.to_os_string()),
        }
    }
    pending.extend(parts.into_iter().rev());
}

/// Whether every exported loader search path stays out of the workspace.
///
/// The same search path reaches `npm test` and every other process the agent
/// starts without review, so refusing it only for the install adds an approval
/// without keeping a planted library out. A relative or empty entry searches
/// the working directory, and an entry inside the workspace names a directory
/// the agent writes, so those still fail closed. A loader variable exported
/// without its stamped value cannot be checked and fails closed too.
pub fn loader_paths_outside(environment: &ExecutionEnvironment, root: &Path) -> bool {
    for name in LIBRARY_SEARCH_PATH_NAMES {
        let exported = environment.names.iter().any(|item| item == name);
        let stamped = environment.library_search_paths.get(name);
        if !exported && stamped.is_none() {
            continue;
        }
        let Some(value) = stamped else {
            return false;
        };
        if value.is_empty() {
            return false;
        }
        for entry in value.split(':') {
            let candidate = Path::new(entry);
            if !candidate.is_absolute() {
                return false;
            }
            match realpath(candidate) {
                Some(resolved) if !resolved.starts_with(root) => {}
                _ => return false,
            }
        }
    }
    true
}

/// Whether an npm config file may change the fetch; unreadable counts.
pub fn npmrc_redirects_fetch(path: &Path) -> bool {
    // `Path.exists()` answers false for a missing path and for one that
    // cannot be stat'd at all, and neither leaves a config to change the fetch.
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() > MAX_NPMRC_BYTES {
        return true;
    }
    let Ok(text) = fs::read_to_string(path) else {
        return true;
    };
    // Python's `splitlines` also ends a line at a bare `\r`, and npm's ini
    // parser does too, so a key after one still counts.
    for line in text.split(['\n', '\r']) {
        let key = line.split_once('=').map_or(line, |(head, _)| head).trim();
        if key.starts_with('#') || key.starts_with(';') {
            continue;
        }
        let key = key.trim_matches(['"', '\'']).to_lowercase();
        // npm's ini parser reads `ca[]=` as an entry of the `ca` array.
        let key = key.strip_suffix("[]").unwrap_or(&key);
        if key.ends_with(":registry") || FETCH_REDIRECTING_KEYS.contains(&key) {
            return true;
        }
    }
    false
}

#[cfg(unix)]
fn is_executable_file(path: &Path, metadata: &fs::Metadata) -> bool {
    use nix::unistd::{access, AccessFlags};
    // `shutil.which` asks whether this user may run the file, not whether any
    // execute bit is set, so an npm only another user can run is passed over.
    metadata.is_file() && access(path, AccessFlags::X_OK).is_ok()
}

#[cfg(not(unix))]
fn is_executable_file(_path: &Path, metadata: &fs::Metadata) -> bool {
    // Windows never reaches this path: the caller settles npm reviews only on
    // POSIX. Keeping the check compiled everywhere avoids a platform-shaped
    // hole in the port that CI could not see.
    metadata.is_file()
}

/// Resolve `name` the way a shell would, refusing relative entries.
///
/// A relative or empty `PATH` entry is searched from the working directory, so
/// one ahead of the match could pick a different executable per cwd.
pub fn resolve_executable(name: &str, search_path: &str) -> Option<PathBuf> {
    let separator = if cfg!(windows) { ';' } else { ':' };
    for entry in search_path.split(separator) {
        if entry.is_empty() || !Path::new(entry).is_absolute() {
            return None;
        }
        let candidate = Path::new(entry).join(name);
        let Ok(metadata) = fs::metadata(&candidate) else {
            continue;
        };
        if is_executable_file(&candidate, &metadata) {
            // `Path.resolve(strict=True)`: a candidate that vanished between
            // the probe and the resolve proves nothing.
            return fs::canonicalize(&candidate).ok();
        }
    }
    None
}

/// Whether each output filter resolves to a program outside the workspace.
///
/// A workspace could otherwise put its own `tail` on `PATH` ahead of the real
/// one and run code through an install that never runs package code.
pub fn filters_outside_workspace(
    programs: &[String],
    environment: &ExecutionEnvironment,
    workspace: &Path,
) -> bool {
    if programs.is_empty() {
        return true;
    }
    let Some(search_path) = environment.search_path.as_deref().filter(|p| !p.is_empty()) else {
        return false;
    };
    let Ok(root) = fs::canonicalize(workspace) else {
        return false;
    };
    programs.iter().all(|name| {
        resolve_executable(name, search_path).is_some_and(|program| !program.starts_with(&root))
    })
}

/// The version of the npm the agent's `PATH` runs, or `None`.
///
/// Only a standard npm install qualifies: `npm` resolves through absolute
/// `PATH` entries to `npm/bin/npm-cli.js` inside a package named npm, neither
/// npm nor node comes from the workspace, and no environment setting changes
/// what npm or node load. Shims and wrappers fail closed because their version
/// cannot be read without running them.
pub fn verified_npm_version(
    environment: &ExecutionEnvironment,
    workspace: &Path,
) -> Option<String> {
    if !environment.well_formed {
        return None;
    }
    if environment.names.iter().any(|name| changes_npm(name)) {
        return None;
    }
    let search_path = environment
        .search_path
        .as_deref()
        .filter(|p| !p.is_empty())?;
    let root = fs::canonicalize(workspace).ok()?;
    if !loader_paths_outside(environment, &root) {
        return None;
    }
    let npm = resolve_executable("npm", search_path)?;
    let node = resolve_executable("node", search_path)?;
    if npm.starts_with(&root) || node.starts_with(&root) {
        return None;
    }
    if npm.file_name()?.to_str()? != "npm-cli.js" {
        return None;
    }
    let bin = npm.parent()?;
    if bin.file_name()?.to_str()? != "bin" {
        return None;
    }
    let package_root = bin.parent()?;
    let package_json = package_root.join("package.json");
    if fs::metadata(&package_json).ok()?.len() > MAX_PACKAGE_JSON_BYTES {
        return None;
    }
    let manifest: Value = serde_json::from_str(&fs::read_to_string(&package_json).ok()?).ok()?;
    let manifest = manifest.as_object()?;
    if manifest.get("name").and_then(Value::as_str) != Some("npm") {
        return None;
    }
    // Without an absolute HOME the user config cannot be located, so it cannot
    // be shown not to move the fetch.
    let home = environment.home.as_deref()?;
    if !Path::new(home).is_absolute() {
        return None;
    }
    let node_root = node.parent()?.parent()?;
    let config_files = [
        package_root.join("npmrc"),
        node_root.join("etc").join("npmrc"),
        Path::new(home).join(".npmrc"),
    ];
    if config_files.iter().any(|path| npmrc_redirects_fetch(path)) {
        return None;
    }
    manifest
        .get("version")
        .and_then(Value::as_str)
        .filter(|version| !version.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
#[path = "verified_npm_tests.rs"]
mod tests;
