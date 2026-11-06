//! The files a frozen install reads: the lockfile, the manager's project and
//! user configuration, and any workspace root above the project that could
//! make the manager install somewhere else.

use super::Manager;
use crate::jsonc::{loads_jsonc_pairs_checked, JsoncError, JsoncPairs};
use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Instant;

const MAX_LOCKFILE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const DEFAULT_REGISTRY: &str = "https://registry.npmjs.org/";

/// pnpm-workspace.yaml settings that only choose packages, versions or which
/// build scripts may run (none do under `--ignore-scripts`). Anything else,
/// such as a pnpmfile or a registry, is refused.
const PNPM_WORKSPACE_KEYS: &[&str] = &[
    "packages",
    "catalog",
    "catalogs",
    "onlyBuiltDependencies",
    "ignoredBuiltDependencies",
    "neverBuiltDependencies",
    "overrides",
    "patchedDependencies",
    "peerDependencyRules",
    "packageExtensions",
];

/// bunfig.toml `[install]` settings that do not move the registry, the
/// credentials or the lockfile.
const BUNFIG_INSTALL_KEYS: &[&str] = &[
    "exact",
    "frozenLockfile",
    "production",
    "optional",
    "dev",
    "peer",
    "saveTextLockfile",
    "linker",
    "auto",
    "minimumReleaseAge",
    "linkWorkspacePackages",
    "dryRun",
    "smol",
];

pub(super) fn directory_ready(
    manager: Manager,
    context: super::super::PathContext<'_>,
    xdg_config_home: Option<&str>,
    deadline: Option<Instant>,
) -> bool {
    let (Some(directory), Some(home)) =
        (context.cwd.map(Path::new), context.home_dir.map(Path::new))
    else {
        return false;
    };
    if !directory.is_absolute()
        || !home.is_absolute()
        || !super::super::npm_reads::configuration_inert(context)
        || !manifest_inert(&directory.join("package.json"), deadline)
        || !no_workspace_root_above(directory)
    {
        return false;
    }
    let lockfile = directory.join(lockfile_name(manager));
    if !companions_absent(manager, directory) || !regular(&lockfile, MAX_LOCKFILE_BYTES) {
        return false;
    }
    let Ok(text) = fs::read_to_string(&lockfile) else {
        return false;
    };
    // Both managers read user settings from the XDG configuration directory,
    // `~/.config` when it is unset.
    let mut config_dirs = vec![home.join(".config")];
    match xdg_config_home.map(Path::new) {
        Some(xdg) if xdg.is_absolute() => config_dirs.push(xdg.to_path_buf()),
        Some(_) => return false,
        None => {}
    }
    match manager {
        Manager::Bun => {
            let mut bunfigs = vec![directory.join("bunfig.toml"), home.join(".bunfig.toml")];
            bunfigs.extend(config_dirs.iter().map(|dir| dir.join(".bunfig.toml")));
            bunfigs.iter().all(|path| bunfig_inert(path)) && bun_lock_registry_only(&text, deadline)
        }
        Manager::Pnpm => {
            // pnpm's own global rc uses the npmrc format.
            let mut rcs = vec![home.join("Library/Preferences/pnpm/rc")];
            rcs.extend(config_dirs.iter().map(|dir| dir.join("pnpm/rc")));
            rcs.iter()
                .all(|path| super::super::npm_reads::npmrc_inert(path))
                && pnpm_workspace_inert(&directory.join("pnpm-workspace.yaml"))
                && pnpm_lock_registry_only(&text)
        }
        Manager::Npm => package_lock_registry_only(&text, deadline),
    }
}

/// The lockfile each manager installs from.
fn lockfile_name(manager: Manager) -> &'static str {
    match manager {
        Manager::Bun => "bun.lock",
        Manager::Pnpm => "pnpm-lock.yaml",
        Manager::Npm => "package-lock.json",
    }
}

/// Whether `directory` lacks every file that would change what `manager`
/// installs from its lockfile: Bun's binary lockfile, a pnpmfile, or npm's
/// shrinkwrap.
fn companions_absent(manager: Manager, directory: &Path) -> bool {
    let absent: &[&str] = match manager {
        Manager::Bun => &["bun.lockb"],
        Manager::Pnpm => &[".pnpmfile.cjs", ".pnpmfile.mjs"],
        Manager::Npm => &["npm-shrinkwrap.json"],
    };
    absent.iter().all(|name| missing(&directory.join(name)))
}

/// When `directory` has no lockfile for `manager` but holds exactly one
/// other manager's lockfile, a sentence naming the no-script install that
/// fits it. An agent that guessed the wrong package manager can then restore
/// dependencies instead of stopping on the review.
pub(super) fn present_lockfile_hint(manager: Manager, directory: &Path) -> Option<String> {
    if !missing(&directory.join(lockfile_name(manager))) {
        return None;
    }
    let present: Vec<Manager> = [Manager::Bun, Manager::Pnpm, Manager::Npm]
        .into_iter()
        .filter(|other| {
            *other != manager && regular(&directory.join(lockfile_name(*other)), MAX_LOCKFILE_BYTES)
        })
        .collect();
    let [other] = present.as_slice() else {
        return None;
    };
    // A companion file sends the named install to review too, so naming it
    // would only lead to a second hold.
    if !companions_absent(*other, directory) {
        return None;
    }
    let form = match other {
        Manager::Bun => "bun install --frozen-lockfile --ignore-scripts",
        Manager::Pnpm => "pnpm install --frozen-lockfile --ignore-scripts --ignore-pnpmfile",
        Manager::Npm => "npm ci --ignore-scripts",
    };
    Some(format!(
        "This folder has no `{}`. It has `{}`, so the install that fits it is `{form}`.",
        lockfile_name(manager),
        lockfile_name(*other),
    ))
}

fn missing(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|error| error.kind() == ErrorKind::NotFound)
}

/// A regular file, not a link, no larger than `limit`.
fn regular(path: &Path, limit: u64) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.len() <= limit)
}

/// `path` is missing, or a regular file whose text passes `inert`.
fn optional_text(path: &Path, inert: impl FnOnce(&str) -> bool) -> bool {
    missing(path)
        || (regular(path, MAX_CONFIG_BYTES) && fs::read_to_string(path).is_ok_and(|t| inert(&t)))
}

/// Bun and npm look upward for a `package.json` whose `workspaces` include the
/// project, and pnpm for a `pnpm-workspace.yaml`. Either would install for
/// that root, with its lockfile and configuration, instead of this one.
fn no_workspace_root_above(directory: &Path) -> bool {
    let Ok(physical) = fs::canonicalize(directory) else {
        return false;
    };
    directory
        .ancestors()
        .skip(1)
        .chain(physical.ancestors().skip(1))
        .all(|ancestor| {
            missing(&ancestor.join("pnpm-workspace.yaml"))
                && optional_text(&ancestor.join("package.json"), |text| {
                    // Parsed, so an escaped key still reads as `workspaces`.
                    matches!(parse(text, None), Some(JsoncPairs::Object(root))
                        if field(&root, "workspaces").is_none())
                })
        })
}

/// The project's `package.json`. Corepack reads `packageManager` before the
/// manager starts, and a URL there makes it download and run that archive, so
/// only a plain `name@version` with an optional `+sha…` hash is accepted.
fn manifest_inert(path: &Path, deadline: Option<Instant>) -> bool {
    if !regular(path, MAX_CONFIG_BYTES) {
        return false;
    }
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    let Some(JsoncPairs::Object(root)) = parse(&text, deadline) else {
        return false;
    };
    match field(&root, "packageManager") {
        None => true,
        Some(JsoncPairs::String(pin)) => pin.split_once('@').is_some_and(|(name, version)| {
            ["npm", "pnpm", "yarn", "bun"].contains(&name)
                && !version.is_empty()
                && version
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
        }),
        Some(_) => false,
    }
}

fn bunfig_inert(path: &Path) -> bool {
    optional_text(path, |text| {
        let Ok(table) = toml::from_str::<toml::Table>(text) else {
            return false;
        };
        if bunfig_preloads_code(&table) {
            return false;
        }
        match table.get("install") {
            None => true,
            Some(toml::Value::Table(install)) => install.iter().all(|(key, value)| {
                BUNFIG_INSTALL_KEYS.contains(&key.as_str())
                    || (key == "lockfile" && bunfig_lockfile_inert(value))
                    || (key == "cache" && bunfig_cache_inert(value))
            }),
            Some(_) => false,
        }
    })
}

/// `preload` names scripts Bun runs before a file, at the top level or under
/// `[run]` or `[test]`. An install does not read it, but a project that
/// configures code to run at startup is not one to wave through unseen.
fn bunfig_preloads_code(table: &toml::Table) -> bool {
    table.contains_key("preload")
        || ["run", "test"].iter().any(|section| {
            matches!(table.get(*section), Some(toml::Value::Table(inner)) if inner.contains_key("preload"))
        })
}

/// `[install.cache]` may only switch the cache off. A `dir` moves where the
/// install writes.
fn bunfig_cache_inert(value: &toml::Value) -> bool {
    let toml::Value::Table(cache) = value else {
        return false;
    };
    cache.iter().all(|(key, value)| {
        matches!(key.as_str(), "disable" | "disableManifest") && value.is_bool()
    })
}

/// `[install.lockfile]` only says whether Bun writes `bun.lock` and whether it
/// also prints a `yarn.lock`. A frozen install writes neither, and neither key
/// names a registry, a credential or a script.
fn bunfig_lockfile_inert(value: &toml::Value) -> bool {
    let toml::Value::Table(lockfile) = value else {
        return false;
    };
    lockfile
        .iter()
        .all(|(key, value)| match (key.as_str(), value) {
            ("save", toml::Value::Boolean(_)) => true,
            ("print", toml::Value::String(format)) => format == "yarn",
            _ => false,
        })
}

/// Top-level keys only: the file is YAML, and a nested value cannot name a
/// pnpmfile or a registry under the keys allowed here.
fn pnpm_workspace_inert(path: &Path) -> bool {
    optional_text(path, |text| {
        text.lines().all(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || line.starts_with([' ', '-']) {
                return !line.starts_with('\t');
            }
            if trimmed == "---" {
                return true;
            }
            line.split_once(':').is_some_and(|(key, _)| {
                let key = key.trim().trim_matches(['"', '\'']);
                PNPM_WORKSPACE_KEYS.contains(&key)
            })
        })
    })
}

/// Every resolution is a registry integrity hash: pnpm fetches those from the
/// configured registry, which the npmrc checks keep at the default. A git
/// commit, tarball URL or local directory resolution is refused, and so is
/// anything this line scan could misread (block style, escapes, explicit keys,
/// a flow-style entry carrying its own resolution). A `file:` dependency is
/// refused, and a `link:` version only follows a `workspace:` specifier.
fn pnpm_lock_registry_only(text: &str) -> bool {
    let mut workspace_specifier = false;
    text.lines().all(|line| {
        let trimmed = line.trim();
        if trimmed.contains(['\\', '\t']) || trimmed.starts_with(['?', '&', '*', '!']) {
            return false;
        }
        if trimmed.contains("tarball") || trimmed.contains("file:") {
            return false;
        }
        let (key, value) = match trimmed.split_once(':') {
            Some((key, value)) => (
                Some(key.trim().trim_matches(['"', '\''])),
                value.trim().trim_matches(['"', '\'']),
            ),
            None => (None, ""),
        };
        let specifier = std::mem::replace(&mut workspace_specifier, false);
        match key {
            Some("specifier") => {
                workspace_specifier = value.starts_with("workspace:");
                return true;
            }
            Some("version") if value.starts_with("link:") => return specifier,
            _ if trimmed.contains("link:") => return false,
            Some("resolution") => {}
            _ => return !trimmed.contains("resolution"),
        }
        trimmed
            .strip_prefix("resolution: {integrity: ")
            .and_then(|rest| rest.strip_suffix('}'))
            .is_some_and(|hash| {
                !hash.is_empty()
                    && hash
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-'))
            })
    })
}

fn parse(text: &str, deadline: Option<Instant>) -> Option<JsoncPairs> {
    let mut check = || match deadline {
        Some(deadline) if Instant::now() >= deadline => {
            Err(JsoncError::Decode("deadline exceeded".into()))
        }
        _ => Ok(()),
    };
    let parsed = loads_jsonc_pairs_checked(text, &mut check).ok()?;
    unique_keys(&parsed).then_some(parsed)
}

/// A repeated key lets two readers disagree about which value counts.
fn unique_keys(value: &JsoncPairs) -> bool {
    match value {
        JsoncPairs::Object(pairs) => {
            let mut seen = HashSet::new();
            pairs
                .iter()
                .all(|(key, value)| seen.insert(key.as_str()) && unique_keys(value))
        }
        JsoncPairs::Array(items) => items.iter().all(unique_keys),
        _ => true,
    }
}

fn field<'a>(pairs: &'a [(String, JsoncPairs)], name: &str) -> Option<&'a JsoncPairs> {
    pairs
        .iter()
        .find_map(|(key, value)| (key == name).then_some(value))
}

/// `package-lock.json` v2 or v3, where every package resolves from the
/// default registry or links a workspace folder.
fn package_lock_registry_only(text: &str, deadline: Option<Instant>) -> bool {
    let Some(JsoncPairs::Object(root)) = parse(text, deadline) else {
        return false;
    };
    let version = matches!(field(&root, "lockfileVersion"),
        Some(JsoncPairs::Number(version)) if [2.0, 3.0].contains(version));
    let Some(JsoncPairs::Object(packages)) = field(&root, "packages") else {
        return false;
    };
    version
        && packages.iter().all(|(key, entry)| {
            let JsoncPairs::Object(entry) = entry else {
                return false;
            };
            let link = matches!(field(entry, "link"), Some(JsoncPairs::Bool(true)));
            // An installed package needs a hash, or npm fetches it unpinned.
            // Folders (the root and workspace members) and bundled copies
            // are not fetched.
            let installed = key.starts_with("node_modules/") || key.contains("/node_modules/");
            let bundled = matches!(field(entry, "inBundle"), Some(JsoncPairs::Bool(true)));
            let pinned = matches!(field(entry, "integrity"),
                Some(JsoncPairs::String(hash)) if !hash.is_empty());
            if installed && !link && !bundled && !pinned {
                return false;
            }
            let resolved = match field(entry, "resolved") {
                None => true,
                Some(JsoncPairs::String(url)) if link => !url.contains(':'),
                Some(JsoncPairs::String(url)) => {
                    url.starts_with(DEFAULT_REGISTRY) && !url.contains(['?', '#', '\\'])
                }
                Some(_) => false,
            };
            let version = match field(entry, "version") {
                None => true,
                Some(JsoncPairs::String(version)) => !version.contains(':'),
                Some(_) => false,
            };
            resolved && version
        })
}

/// `bun.lock`, where every package is `name@version` from the default
/// registry (an empty registry field) or a workspace member.
fn bun_lock_registry_only(text: &str, deadline: Option<Instant>) -> bool {
    let Some(JsoncPairs::Object(root)) = parse(text, deadline) else {
        return false;
    };
    let Some(JsoncPairs::Object(packages)) = field(&root, "packages") else {
        return false;
    };
    packages.iter().all(|(_, entry)| {
        let JsoncPairs::Array(entry) = entry else {
            return false;
        };
        let Some(JsoncPairs::String(identity)) = entry.first() else {
            return false;
        };
        let Some(spec) = identity
            .rfind('@')
            .filter(|at| *at > 0)
            .map(|at| &identity[at + 1..])
        else {
            return false;
        };
        if let Some(member) = spec.strip_prefix("workspace:") {
            return !member.contains(':');
        }
        !spec.is_empty()
            && spec
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
            && matches!(entry.get(1), Some(JsoncPairs::String(registry)) if registry.is_empty())
    })
}
