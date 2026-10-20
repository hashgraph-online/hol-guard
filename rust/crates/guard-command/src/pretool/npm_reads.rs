//! Read-only npm queries: `npm view`, `npm ls` and `npm cache ls`.
//!
//! None runs package code. `npm view` fetches public metadata for one
//! registry package, `npm ls` reads the installed tree and `npm cache ls`
//! lists entries already in the local cache. The risk is npm's
//! configuration: a `.npmrc` that moves the registry can pair it with an
//! `${ENV}` auth line and send that secret to another host. So the proof also
//! needs every `.npmrc` npm could read to leave the fetch, its trust and npm's
//! own paths alone, and no inherited npm or Node override.

use super::npmrc_keys;
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

/// `-g` reads the globally installed tree instead of the project one. It is
/// the same offline read of installed package metadata, at npm's own prefix:
/// a `prefix`, `global` or `location` line in any `.npmrc` this proof reads
/// already keeps its review, so the tree it prints is the installed one.
fn list_arguments(arguments: &[String]) -> bool {
    arguments.iter().all(|argument| {
        matches!(
            argument.as_str(),
            "--all"
                | "-a"
                | "--json"
                | "--parseable"
                | "-p"
                | "--long"
                | "-l"
                | "-g"
                | "--global"
                | "--location=global"
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
        && global_configuration_inert(home)
}

/// Prefixes a Node installation is placed in, holding `etc/npmrc` when an
/// administrator wrote one.
const SYSTEM_PREFIXES: [&str; 5] = [
    "/usr/local",
    "/usr",
    "/opt/homebrew",
    "/opt/local",
    "/home/linuxbrew/.linuxbrew",
];

/// The same below home, where a user installs without root.
const HOME_PREFIXES: [&str; 4] = [".npm-global", ".local", "n", ".nodebrew/current"];

/// Directories holding one prefix per installed Node version, and the
/// component between a version and its prefix where a manager adds one.
///
/// A manager that follows the XDG layout keeps its versions below
/// `~/.local/share`, and on macOS fnm uses the application-support directory
/// instead, so both spellings are read beside the manager's older home
/// directory. A relocation a variable asks for (`NVM_DIR`, `FNM_DIR`,
/// `XDG_DATA_HOME`) is not read: those are exported by the manager's own
/// shell setup on every machine that uses one, so refusing them would review
/// an ordinary `npm ls` for every developer who installed Node that way,
/// while the file they move is one only someone who can already write the
/// home directory can write.
const HOME_VERSION_ROOTS: [(&str, &str); 10] = [
    (".nvm/versions/node", ""),
    (".fnm/node-versions", "installation"),
    (".local/share/fnm/node-versions", "installation"),
    (
        "Library/Application Support/fnm/node-versions",
        "installation",
    ),
    (".local/share/mise/installs/node", ""),
    (".local/share/rtx/installs/node", ""),
    (".asdf/installs/nodejs", ""),
    (".nodenv/versions", ""),
    (".proto/tools/node", ""),
    (".volta/tools/image/node", ""),
];

/// A version directory holding more entries than any machine installs is not
/// a Node version root, and walking it is not this proof's work.
const MAX_VERSION_PREFIXES: usize = 64;

/// Whether npm's global configuration file leaves the fetch and npm's paths
/// alone, wherever npm is installed.
///
/// `npm ls` reads `<prefix>/etc/npmrc` as well as the project and user files,
/// and npm resolves that prefix from its own installation rather than from
/// the working directory, which this hook cannot ask it for. So every prefix
/// a Node installation is actually placed in is read instead: the system ones
/// and the per-user ones, including the directories a version manager keeps
/// one prefix per version in. A `prefix` line in the user's own `.npmrc`
/// would move the global file somewhere else, and that line already keeps its
/// review.
///
/// The builtin file that ships beside the npm binary is not read here. It is
/// part of the installation — Homebrew writes the prefix it installed into —
/// and whoever can write it can write the program it sits next to.
fn global_configuration_inert(home: &Path) -> bool {
    if !SYSTEM_PREFIXES
        .iter()
        .all(|prefix| npmrc_inert(&Path::new(prefix).join("etc/npmrc")))
    {
        return false;
    }
    if !HOME_PREFIXES
        .iter()
        .all(|name| npmrc_inert(&home.join(name).join("etc/npmrc")))
    {
        return false;
    }
    HOME_VERSION_ROOTS.iter().all(|(root, nested)| {
        let entries = match fs::read_dir(home.join(root)) {
            Ok(entries) => entries,
            Err(error) => return absent(&error),
        };
        let mut seen = 0usize;
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            seen += 1;
            if seen > MAX_VERSION_PREFIXES {
                return false;
            }
            let prefix = entry.path().join(nested);
            if !npmrc_inert(&prefix.join("etc/npmrc")) {
                return false;
            }
        }
        true
    })
}

/// Whether a path holds no file at all.
///
/// A path whose parent is not a directory reports `ENOTDIR` rather than "no
/// such file", and macOS writes a `.DS_Store` file beside the version
/// directories a Node version manager keeps, so the configuration path built
/// from that entry lands below a regular file. npm reads nothing there
/// either, so it is as absent as a missing one.
fn absent(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

/// A missing file is inert. Anything unreadable, oversized or not a regular
/// file is not.
pub(in crate::pretool) fn npmrc_inert(path: &Path) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return absent(&error),
    };
    if !metadata.is_file() || metadata.len() > MAX_NPMRC_BYTES {
        return false;
    }
    // A bare carriage return starts a new line for npm's ini parser, so it
    // ends one here too.
    fs::read_to_string(path).is_ok_and(|text| text.split(['\n', '\r']).all(inert_line))
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
    let line = npmrc_keys::js_trim(line);
    if line.is_empty() || line.starts_with(['#', ';']) {
        return true;
    }
    // An ini section nests its keys where this check would not see them.
    if line.starts_with('[') {
        return false;
    }
    // The key npm acts on is the one its ini parser decodes, not the written
    // text; a line this proof cannot decode is not shown to be inert.
    let Some(key) = npmrc_keys::parsed_key(line) else {
        return false;
    };
    let key = key
        .trim_end_matches("[]")
        .to_ascii_lowercase()
        .replace('_', "-");
    // npm expands `${VAR}` in keys too, so `${X?}registry` reads as `registry`.
    !key.contains("${") && !key.ends_with(":registry") && !UNSAFE_KEYS.contains(&key.as_str())
}

#[cfg(test)]
#[path = "npm_reads_tests.rs"]
mod tests;
