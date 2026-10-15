//! Read-only npm queries: `npm view`, `npm ls` and `npm cache ls`.
//!
//! None runs package code. `npm view` fetches public metadata for one
//! registry package, `npm ls` reads the installed tree and `npm cache ls`
//! lists entries already in the local cache. The risk is npm's
//! configuration: a `.npmrc` that moves the registry can pair it with an
//! `${ENV}` auth line and send that secret to another host. So the proof also
//! needs every `.npmrc` npm could read to leave the fetch, its trust and npm's
//! own paths alone, and no inherited npm or Node override.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

const MAX_NPMRC_BYTES: u64 = 64 * 1024;

pub(super) fn safe_npm_read(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let Some((subcommand, rest)) = arguments.split_first() else {
        return false;
    };
    let shape = match subcommand.as_str() {
        "view" | "v" | "info" | "show" => view_arguments(rest),
        "ls" | "list" => list_arguments(rest),
        "cache" => cache_list_arguments(rest),
        _ => false,
    };
    // npm finds the user config through its own HOME, so the one checked
    // below must be that HOME.
    shape && context.npm_config_inert && context.shell_home_matches && configuration_inert(context)
}

/// The configuration check reads files before the command runs, so nothing
/// else in the command may write. Every other segment must be another npm
/// segment, which gets its own proof, or a tool that only reads or filters.
pub(super) fn read_only_neighbors(model: &crate::CanonicalCommandV1) -> bool {
    model.segments.iter().all(|segment| {
        segment.executable.as_deref().is_some_and(|executable| {
            matches!(
                super::executable_basename(executable),
                "npm"
                    | "cd"
                    | "pwd"
                    | "echo"
                    | "printf"
                    | "true"
                    | "ls"
                    | "cat"
                    | "head"
                    | "tail"
                    | "grep"
                    | "rg"
                    | "jq"
                    | "wc"
                    | "sort"
                    | "uniq"
                    | "cut"
                    | "which"
            )
        })
    })
}

/// One package spec, then any number of field paths, with `--json` anywhere.
fn view_arguments(arguments: &[String]) -> bool {
    let mut operands = arguments
        .iter()
        .filter(|argument| argument.as_str() != "--json");
    operands
        .next()
        .is_some_and(|spec| plain_registry_spec(spec))
        && operands.all(|field| field_path(field))
}

fn list_arguments(arguments: &[String]) -> bool {
    arguments.iter().all(|argument| {
        matches!(
            argument.as_str(),
            "--all" | "-a" | "--json" | "--parseable" | "-p" | "--long" | "-l"
        ) || argument.strip_prefix("--depth=").is_some_and(|depth| {
            (1..=2).contains(&depth.len()) && depth.bytes().all(|byte| byte.is_ascii_digit())
        }) || matches!(
            argument.strip_prefix("--omit="),
            Some("dev" | "optional" | "peer")
        ) || plain_registry_spec(argument)
    })
}

/// `cache ls` and any package names. The other cache subcommands fetch into,
/// prune or rewrite the cache, so they stay with the package review.
fn cache_list_arguments(arguments: &[String]) -> bool {
    arguments.split_first().is_some_and(|(subcommand, specs)| {
        subcommand == "ls" && specs.iter().all(|spec| plain_registry_spec(spec))
    })
}

/// `name`, `@scope/name`, either followed by `@selector`, where the selector
/// is a version, range or dist-tag with no source syntax in it. Aliases,
/// paths, URLs and Git shorthands all need a `:` or an unscoped `/`.
fn plain_registry_spec(spec: &str) -> bool {
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
            .is_some_and(|character| character.is_ascii_alphanumeric())
            && part.chars().all(|character| {
                character.is_ascii_lowercase()
                    || character.is_ascii_digit()
                    || "._~-".contains(character)
            })
    };
    scope.is_none_or(name_part)
        && name_part(name)
        && selector.is_none_or(|selector| {
            !selector.is_empty()
                && selector.chars().all(|character| {
                    character.is_ascii_alphanumeric() || " ^~<>=.*|+-_".contains(character)
                })
        })
}

/// `version`, `dist-tags.latest`, `dependencies[zod]` and the like.
fn field_path(field: &str) -> bool {
    field
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic())
        && field
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-[]@/".contains(character))
}

/// npm reads one project `.npmrc`, from the nearest ancestor holding a
/// `package.json` or `node_modules`, plus the user's `~/.npmrc`. Checking every
/// ancestor of both the logical and physical cwd covers whichever one npm
/// picks, without reproducing its search.
pub(in crate::pretool) fn configuration_inert(context: super::PathContext<'_>) -> bool {
    let (Some(cwd), Some(home)) = (context.cwd.map(Path::new), context.home_dir.map(Path::new))
    else {
        return false;
    };
    if !cwd.is_absolute() || !home.is_absolute() {
        return false;
    }
    let Ok(physical) = fs::canonicalize(cwd) else {
        return false;
    };
    cwd.ancestors()
        .chain(physical.ancestors())
        .chain(std::iter::once(home))
        .all(|directory| npmrc_inert(&directory.join(".npmrc")))
}

/// A missing file is inert. Anything unreadable, oversized or not a regular
/// file is not.
pub(in crate::pretool) fn npmrc_inert(path: &Path) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return error.kind() == ErrorKind::NotFound,
    };
    if !metadata.is_file() || metadata.len() > MAX_NPMRC_BYTES {
        return false;
    }
    fs::read_to_string(path).is_ok_and(|text| text.lines().all(inert_line))
}

/// Settings that move where npm fetches from, how it trusts that transport,
/// which other config it loads, where it writes, which pnpm hook file it
/// loads, or that send credentials to any registry. Underscores and hyphens are compared alike.
const UNSAFE_KEYS: [&str; 28] = [
    "registry",
    "replace-registry-host",
    "strict-ssl",
    "ca",
    "cafile",
    "cert",
    "key",
    "proxy",
    "https-proxy",
    "http-proxy",
    "noproxy",
    "no-proxy",
    "prefix",
    "global",
    "location",
    "userconfig",
    "globalconfig",
    "cache",
    "logs-dir",
    "onload-script",
    "node-options",
    "-auth",
    "-authtoken",
    "-password",
    "username",
    "always-auth",
    "pnpmfile",
    "global-pnpmfile",
];

fn inert_line(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with(['#', ';']) {
        return true;
    }
    // An ini section nests its keys where this check would not see them.
    if line.starts_with('[') {
        return false;
    }
    let key = line
        .split('=')
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches(['"', '\''])
        .trim_end_matches("[]")
        .to_ascii_lowercase()
        .replace('_', "-");
    // npm expands `${VAR}` in keys too, so `${X?}registry` reads as `registry`.
    !key.contains("${") && !key.ends_with(":registry") && !UNSAFE_KEYS.contains(&key.as_str())
}

#[cfg(test)]
#[path = "npm_reads_tests.rs"]
mod tests;
