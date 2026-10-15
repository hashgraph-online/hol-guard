//! Registry installs that run no package code.
//!
//! Lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`) are
//! how a malicious npm release runs code at install time. `--ignore-scripts`
//! alone does not stop all of it: before npm 12, a git dependency anywhere in
//! the tree is cloned and prepared with a nested `npm install` that reads the
//! clone's own `.npmrc`, so a `git=` setting there runs attacker code. npm
//! 11.9 added `--allow-git=none`, which refuses every git dependency. With
//! both flags on a verified npm 11.9 or later, the install only writes
//! registry package files. A registry name that resolves on the public
//! registry is then identified well enough to continue without review;
//! anything that later executes those files is reviewed on its own. Any
//! npm from 7 on, including 11.9 and later without `--allow-git=none`, also
//! qualifies with `--ignore-scripts` alone once the tree is proven to hold no
//! git dependency (`registry_install_tree`).

use super::*;

/// A project `.npmrc` larger than this is treated as redirecting the registry.
const MAX_NPMRC_BYTES: u64 = 64 * 1024;

/// The first npm release with `--allow-git`. Older releases ignore the option.
const MIN_ALLOW_GIT_NPM: (u64, u64, u64) = (11, 9, 0);
/// The first npm release that installs peer dependencies and writes the
/// `packages` lock layout the git-free tree proof reads.
const MIN_TREE_PROOF_NPM: (u64, u64, u64) = (7, 0, 0);

/// Metadata the hook stamps after resolving the agent's `npm` executable. Other
/// callers never set it, so the rule below stays off for them.
pub(super) const VERIFIED_NPM_VERSION_KEY: &str = "verified_npm_version";

/// Options that move the install out of the project: a global install links
/// package binaries onto `PATH`, and a prefix or directory can point anywhere.
const RELOCATING_OPTIONS: [&str; 7] = [
    "-g",
    "--global",
    "--location",
    "--prefix",
    "--dir",
    "-C",
    "--global-dir",
];

pub(super) const LIFECYCLE_SCRIPTS_ENABLED_CODE: &str = "package_lifecycle_scripts_enabled";

/// Whether this request installs registry packages with no package code able
/// to run, from the public registry, with nothing on the command line or in
/// the project's npm configuration pointing the install somewhere else.
pub(super) fn script_free_registry_install(
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> bool {
    let tokens = command_tokens(artifact);
    registry_install_candidate(artifact, workspace_dir)
        && verified_npm_supports_allow_git(artifact)
        && lifecycle_scripts_disabled(&tokens)
        && git_dependencies_refused(&tokens)
}

/// The same outcome without `--allow-git=none`: scripts are off and registry
/// metadata proves no git dependency can enter the tree. npm 11.9 and later
/// clone git dependencies exactly like older releases unless the flag is set,
/// so the tree proof covers them too.
pub(super) fn script_free_git_free_tree_install(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
    targets: &[Map<String, Value>],
) -> bool {
    let tokens = command_tokens(artifact);
    if !registry_install_candidate(artifact, workspace_dir) || !lifecycle_scripts_disabled(&tokens)
    {
        return false;
    }
    let Some(root) = optional_string(artifact.metadata.get("effective_cwd"))
        .map(PathBuf::from)
        .or_else(|| workspace_dir.map(Path::to_path_buf))
    else {
        return false;
    };
    let requested: Option<Vec<(String, String)>> = targets
        .iter()
        .map(|target| Some((target_package_name(target)?, registry_selector(target)?)))
        .collect();
    requested.is_some_and(|requested| {
        !requested.is_empty() && git_free_install_tree(deps, &root, requested)
    })
}

/// Whether the agent should be told which flags let this install continue:
/// it is a candidate and lacks a flag the proof for its npm requires.
pub(super) fn registry_install_needs_flags(
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> bool {
    let tokens = command_tokens(artifact);
    registry_install_candidate(artifact, workspace_dir)
        && (!lifecycle_scripts_disabled(&tokens)
            || verified_npm_supports_allow_git(artifact) && !git_dependencies_refused(&tokens))
}

fn target_package_name(target: &Map<String, Value>) -> Option<String> {
    let name = optional_string(target.get("name"))?;
    Some(match optional_string(target.get("namespace")) {
        Some(namespace) => format!("{namespace}/{name}"),
        None => name,
    })
}

/// Whether the same request could qualify once the flags its npm needs are
/// added: `--ignore-scripts` plus either a git-free tree or, on npm 11.9 or
/// later, `--allow-git=none`.
pub(super) fn registry_install_candidate(
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> bool {
    let tokens = command_tokens(artifact);
    optional_string(artifact.metadata.get("intent_kind")).as_deref() == Some("install")
        && optional_string(artifact.metadata.get("package_manager")).as_deref() == Some("npm")
        && verified_npm_release(artifact).is_some_and(|version| version >= MIN_TREE_PROOF_NPM)
        && only_recording_options(&tokens)
        && !command_uses_alternate_package_index(artifact)
        && !command_overrides_registry(&tokens)
        && !command_relocates_install(&tokens)
        && !project_npmrc_overrides_registry(artifact, workspace_dir)
}

fn verified_npm_supports_allow_git(artifact: &GuardArtifact) -> bool {
    verified_npm_release(artifact).is_some_and(|version| version >= MIN_ALLOW_GIT_NPM)
}

fn verified_npm_release(artifact: &GuardArtifact) -> Option<(u64, u64, u64)> {
    optional_string(artifact.metadata.get(VERIFIED_NPM_VERSION_KEY))
        .and_then(|version| release_triple(&version))
}

/// `major.minor.patch`; a prerelease or build suffix on the patch is ignored.
fn release_triple(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.splitn(3, '.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?;
    let digits = patch.split(|c: char| !c.is_ascii_digit()).next()?;
    Some((major, minor, digits.parse().ok()?))
}

/// The registry selector to resolve: the requested range, the exact version
/// when the request pinned one, or `latest` for a bare name. Only a plain `name[@selector]` spec
/// qualifies; aliases (`npm:`), paths, URLs and git shorthands do not.
pub(super) fn registry_selector(target: &Map<String, Value>) -> Option<String> {
    if optional_string(target.get("source_url")).is_some()
        || !optional_string(target.get("raw_spec")).is_some_and(|spec| plain_registry_spec(&spec))
    {
        return None;
    }
    // A bare name installs the `latest` dist-tag, which the resolver binds
    // to the version that tag names.
    Some(
        optional_string(target.get("range"))
            .or_else(|| optional_string(target.get("version")))
            .unwrap_or_else(|| "latest".to_owned()),
    )
}

/// `name`, `@scope/name`, either followed by `@selector`, where the selector
/// is a version, range or dist-tag with no source syntax in it.
pub(super) fn plain_registry_spec(spec: &str) -> bool {
    let (scope, rest) = match spec.strip_prefix('@') {
        Some(scoped) => match scoped.split_once('/') {
            Some((scope, rest)) => (Some(scope), rest),
            None => return false,
        },
        None => (None, spec),
    };
    let (name, selector) = match rest.split_once('@') {
        Some((name, selector)) => (name, Some(selector)),
        None => (rest, None),
    };
    let name_part = |part: &str| {
        part.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
            && part
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._~-".contains(c))
    };
    scope.is_none_or(name_part)
        && name_part(name)
        && selector.is_none_or(|selector| {
            !selector.is_empty()
                && selector
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || " ^~<>=.*|+-_".contains(c))
        })
}

/// Agent-facing reason attached to an install that would continue without
/// review if it disabled lifecycle scripts.
pub(super) fn lifecycle_scripts_enabled_reason(artifact: &GuardArtifact) -> Map<String, Value> {
    let manager = optional_string(artifact.metadata.get("package_manager"))
        .unwrap_or_else(|| "npm".to_string());
    let mut reason = Map::new();
    reason.insert(
        "code".to_string(),
        Value::String(LIFECYCLE_SCRIPTS_ENABLED_CODE.to_string()),
    );
    reason.insert(
        "message".to_string(),
        Value::String(format!(
            "This install could run package code. Rerun the same {manager} command with \
             {flags}",
            flags = if verified_npm_supports_allow_git(artifact) {
                "--ignore-scripts --allow-git=none and HOL Guard will let it continue without review."
            } else {
                "--ignore-scripts and HOL Guard will let it continue without review when every \
                 dependency it can install comes from the npm registry. npm 11.9 or later also \
                 takes --allow-git=none, which removes that condition."
            }
        )),
    );
    reason.insert("severity".to_string(), Value::String("medium".to_string()));
    reason.insert(
        "source".to_string(),
        Value::String("guard-local".to_string()),
    );
    reason
}

fn command_tokens(artifact: &GuardArtifact) -> Vec<String> {
    let redacted = optional_string(artifact.metadata.get("redacted_command")).unwrap_or_default();
    crate::command_launcher_floors::shlex_split(&redacted).unwrap_or_default()
}

/// Mirrors how npm's option parser settles a boolean flag: the last spelling
/// wins, and a bare `true`/`false` after the flag is its value. Any other
/// `=` value, or `--no-ignore-scripts`, leaves scripts enabled.
fn lifecycle_scripts_disabled(tokens: &[String]) -> bool {
    let mut disabled = false;
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if token == "--" {
            break;
        }
        if token == "--ignore-scripts" {
            match tokens.get(index + 1).map(String::as_str) {
                Some("false") => {
                    disabled = false;
                    index += 1;
                }
                Some("true") => {
                    disabled = true;
                    index += 1;
                }
                _ => disabled = true,
            }
        } else if token == "--ignore-scripts=true" {
            disabled = true;
        } else if token.starts_with("--ignore-scripts=") || token.starts_with("--no-ignore-scripts")
        {
            disabled = false;
        }
        index += 1;
    }
    disabled
}

/// npm settles `--allow-git` like any option: the last spelling wins, and the
/// value may follow as the next token.
fn git_dependencies_refused(tokens: &[String]) -> bool {
    let mut value: Option<&str> = None;
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if token == "--" {
            break;
        }
        if token == "--allow-git" {
            value = tokens.get(index + 1).map(String::as_str);
            index += 1;
        } else if let Some(inline) = token.strip_prefix("--allow-git=") {
            value = Some(inline);
        }
        index += 1;
    }
    value == Some("none")
}

/// Options that only shape how the project records or reports the install.
const RECORDING_OPTIONS: [&str; 27] = [
    "-D",
    "--save-dev",
    "-E",
    "--save-exact",
    "-O",
    "--save-optional",
    "-P",
    "--save-prod",
    "--save-peer",
    "-S",
    "--save",
    "--no-save",
    "--no-audit",
    "--no-fund",
    "--no-package-lock",
    "--package-lock-only",
    "--legacy-peer-deps",
    "--strict-peer-deps",
    "--prefer-offline",
    "--prefer-online",
    "--offline",
    "--dry-run",
    "--silent",
    "-s",
    "--quiet",
    "-q",
    "--no-progress",
];

/// `npm install` and the aliases npm documents for it.
const INSTALL_SUBCOMMANDS: &[&str] = &[
    "install", "i", "add", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
    "isntall",
];

/// npm expands any unambiguous prefix of a long option (`--reg=` is
/// `--registry=`) and has multi-letter shorthands, so a denylist of risky
/// options cannot be complete. Every option must be one of the recording
/// options above or an exact spelling of the two safety flags. The command
/// shape is redacted, and redaction swaps a URL-bearing token such as
/// `--reg=https://...` for a placeholder with no leading dash, so every operand
/// after the subcommand must also be a plain registry spec.
fn only_recording_options(tokens: &[String]) -> bool {
    let mut index = 1;
    let mut subcommand_seen = false;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        let next = tokens.get(index + 1).map(String::as_str);
        if token == "--" {
            return false;
        }
        if token == "--ignore-scripts" && next == Some("true")
            || token == "--allow-git" && next == Some("none")
        {
            index += 2;
            continue;
        }
        let operand = if token.starts_with('-') {
            false
        } else if subcommand_seen {
            plain_registry_spec(token)
        } else {
            subcommand_seen = true;
            INSTALL_SUBCOMMANDS.contains(&token)
        };
        let known = operand
            || RECORDING_OPTIONS.contains(&token)
            || matches!(
                token,
                "--ignore-scripts" | "--ignore-scripts=true" | "--allow-git=none"
            );
        if !known {
            return false;
        }
        index += 1;
    }
    true
}

fn command_overrides_registry(tokens: &[String]) -> bool {
    tokens.iter().any(|token| {
        let option = token.split('=').next().unwrap_or_default();
        option.starts_with("--") && (option == "--registry" || option.ends_with(":registry"))
    })
}

fn command_relocates_install(tokens: &[String]) -> bool {
    tokens
        .iter()
        .take_while(|token| token.as_str() != "--")
        .any(|token| {
            let option = token.split('=').next().unwrap_or_default();
            let short_cluster = option.len() > 2
                && option.starts_with('-')
                && !option.starts_with("--")
                && option[1..].chars().any(|c| c == 'g' || c == 'C');
            RELOCATING_OPTIONS.contains(&option) || short_cluster
        })
}

/// A project `.npmrc` that sets `registry` or a scoped `@scope:registry` makes
/// the install fetch from somewhere other than the registry Guard resolved
/// against. An unreadable or oversized file counts as an override.
fn project_npmrc_overrides_registry(
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> bool {
    let mut roots: Vec<PathBuf> = workspace_dir.map(Path::to_path_buf).into_iter().collect();
    if let Some(cwd) = optional_string(artifact.metadata.get("effective_cwd")) {
        roots.push(PathBuf::from(cwd));
    }
    roots.iter().any(|root| {
        let path = root.join(".npmrc");
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            return false;
        };
        if !metadata.is_file() || metadata.len() > MAX_NPMRC_BYTES {
            return true;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            return true;
        };
        text.lines().any(npmrc_redirects_fetch)
    })
}

/// npm settings that change where packages come from, how their transport is
/// trusted, or where they are installed. Command-line flags outrank a project
/// `.npmrc`, but none of these is checked on the command line by the rule.
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
    "prefix",
    "global",
    "location",
    "globalconfig",
];

fn npmrc_redirects_fetch(line: &str) -> bool {
    let key = line.split('=').next().unwrap_or_default().trim();
    if key.starts_with(['#', ';']) {
        return false;
    }
    let key = key.trim_matches(['"', '\'']).to_ascii_lowercase();
    key.ends_with(":registry") || FETCH_REDIRECTING_KEYS.contains(&key.as_str())
}

#[cfg(test)]
#[path = "registry_install_identity_tests.rs"]
mod tests;
