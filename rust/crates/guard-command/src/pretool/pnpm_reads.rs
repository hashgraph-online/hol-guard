//! Read-only pnpm queries: `pnpm outdated`, `pnpm view`/`pnpm info` and
//! `pnpm audit`.
//!
//! These are the same three registry reports [`super::npm_reads`] proves for
//! npm, over the same configuration. `outdated` reads the project manifest and
//! the lockfile and asks the registry for the published versions of the names
//! already there, `view` prints one package's public metadata, and `audit`
//! sends those same installed names and versions to the advisory endpoint.
//! None resolves a new tree, writes to the project or runs package code, so a
//! report that a dependency moved on stays a report.
//!
//! pnpm reads registry and certificate settings from `.npmrc` the way npm
//! does, so part of the proof is npm's: every `.npmrc` pnpm could read has to
//! leave the registry, its trust and npm's paths alone, and no inherited npm
//! or Node variable may move them either. That check already refuses a
//! `pnpmfile` or `global-pnpmfile` line, which is how an ini file names
//! pnpm's hook module.
//!
//! pnpm also has settings files of its own, and they can move the same fetch.
//! A project writes them in `pnpm-workspace.yaml`, where `registry`,
//! `registries`, `pnpmfile` and `configDependencies` all point the command
//! somewhere else, and the user's own `pnpm` configuration directory holds
//! the global `config.yaml` beside the older ini `rc` and the `auth.ini`
//! credentials and certificates live in. So every one of those files is read
//! too, and a key that moves the fetch, its trust, pnpm's paths or its hook
//! module keeps the review.
//!
//! The variables are pnpm's own as well: pnpm no longer reads `npm_config_*`
//! and takes `pnpm_config_*` instead, so `pnpm_config_registry` moves the
//! registry exactly as a configuration line would. The environment check
//! [`super::PathContext::npm_config_inert`] reads both spellings.
//!
//! A project may also carry the hook module at its default name. pnpm loads
//! `.pnpmfile.cjs` — `.pnpmfile.mjs` as well, since pnpm 11 — from the
//! directory holding the lockfile, and the hooks in it are ordinary
//! JavaScript pnpm runs in its own process, so the reading needs no such file
//! above the working directory. A workspace that keeps one stays reviewed.
//!
//! Still reviewed:
//! - every other subcommand. `install`, `add`, `update`, `dlx` and `patch`
//!   resolve or run code, `store` and `prune` rewrite the store, and `publish`
//!   sends the project to a registry.
//! - `--dir`, `--filter`, `--workspace-root` and `-w`, which choose another
//!   project or another set of them, and `--registry`, which moves the fetch
//!   the configuration check just pinned.
//! - `--global` and `-g`, which read the tree at pnpm's own global directory.
//!   npm's `prefix` is not where pnpm keeps it, so the `.npmrc` check pins
//!   nothing about that tree.
//! - `audit --fix`, which rewrites the manifest, and any operand on it.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

pub(super) fn safe_pnpm_read(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let Some((subcommand, rest)) = arguments.split_first() else {
        return false;
    };
    let shape = match subcommand.as_str() {
        "outdated" => outdated_arguments(rest),
        "view" | "info" => super::npm_reads::view_arguments(rest),
        "audit" => audit_arguments(rest),
        _ => false,
    };
    shape
        && context.npm_config_inert
        && context.shell_home_matches
        && super::npm_reads::configuration_inert(context)
        && settings_inert(context)
        && hook_module_absent(context)
}

/// The report over the installed names. `--recursive` widens it to every
/// package of a workspace already on disk, which is the same read repeated.
/// `--global` is not among them: it reads the tree at pnpm's own global
/// directory, which `global-dir` and `PNPM_HOME` name rather than npm's
/// `prefix`, so nothing this proof reads says where that tree is.
fn outdated_arguments(arguments: &[String]) -> bool {
    arguments.iter().all(|argument| {
        matches!(
            argument.as_str(),
            "--json" | "--long" | "--compatible" | "--no-table" | "--table" | "--recursive" | "-r"
        ) || matches!(
            argument.strip_prefix("--format="),
            Some("table" | "list" | "json")
        ) || super::npm_reads::plain_registry_spec(argument)
    })
}

/// The advisory report. pnpm writes the severity bound either way, so both
/// spellings are read, and the value has to be one of the levels pnpm names.
/// `--fix` rewrites the manifest, so it is not among them, and the command
/// takes no operand.
fn audit_arguments(arguments: &[String]) -> bool {
    let mut remaining = arguments.iter();
    while let Some(argument) = remaining.next() {
        let accepted = matches!(
            argument.as_str(),
            "--json"
                | "--recursive"
                | "-r"
                | "--dev"
                | "-D"
                | "--prod"
                | "-P"
                | "--no-optional"
                | "--ignore-registry-errors"
        ) || matches!(
            argument.strip_prefix("--audit-level="),
            Some("info" | "low" | "moderate" | "high" | "critical")
        );
        if accepted {
            continue;
        }
        if argument == "--audit-level" {
            let level = remaining.next().map(String::as_str);
            if matches!(
                level,
                Some("info" | "low" | "moderate" | "high" | "critical")
            ) {
                continue;
            }
        }
        return false;
    }
    true
}

/// The default names of pnpm's hook module. pnpm 11 loads the ECMAScript
/// spelling beside the older CommonJS one, and either is JavaScript it runs
/// in its own process.
const HOOK_MODULES: [&str; 2] = [".pnpmfile.cjs", ".pnpmfile.mjs"];

/// No hook module at or above the working directory, by both the written path
/// and the physical one, so a link in the walked path cannot hide a file pnpm
/// would still find.
fn hook_module_absent(context: super::PathContext<'_>) -> bool {
    let Some(cwd) = context.cwd.map(Path::new) else {
        return false;
    };
    if !cwd.is_absolute() {
        return false;
    }
    let Ok(physical) = fs::canonicalize(cwd) else {
        return false;
    };
    cwd.ancestors()
        .chain(physical.ancestors())
        .all(|directory| {
            HOOK_MODULES
                .iter()
                .all(|name| nothing_at(&directory.join(name)))
        })
}

/// The settings files pnpm reads that are not npm's.
///
/// A project writes them in `pnpm-workspace.yaml`, read from the workspace
/// root, and the user's own `pnpm` configuration directory holds the global
/// `config.yaml`, the older ini `rc` and the `auth.ini` credentials and
/// certificates live in. The project file is read from every ancestor of both
/// the written and the physical working directory, which covers whichever one
/// pnpm picks as the root without reproducing its search.
///
/// A configuration directory moved by `XDG_CONFIG_HOME` is not read. That
/// variable is exported by the user's own shell setup on the machines that
/// use it, and the file it moves is one only someone who can already write
/// the home directory can write, so reading only the default locations keeps
/// an ordinary `pnpm outdated` out of review there.
fn settings_inert(context: super::PathContext<'_>) -> bool {
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
        .all(|directory| {
            WORKSPACE_MANIFESTS
                .iter()
                .all(|name| yaml_settings_inert(&directory.join(name)))
        })
        && CONFIG_DIRECTORIES.iter().all(|relative| {
            let directory = home.join(relative);
            CONFIG_INI_FILES
                .iter()
                .all(|name| super::npm_reads::npmrc_inert(&directory.join(name)))
                && yaml_settings_inert(&directory.join("config.yaml"))
        })
}

/// The project settings file, by both spellings of a YAML suffix.
const WORKSPACE_MANIFESTS: [&str; 2] = ["pnpm-workspace.yaml", "pnpm-workspace.yml"];

/// Where pnpm keeps the configuration directory on each platform, below the
/// user's home: the XDG location Linux uses, the preferences directory on
/// macOS, and the local application data directory on Windows.
const CONFIG_DIRECTORIES: [&str; 3] = [
    ".config/pnpm",
    "Library/Preferences/pnpm",
    "AppData/Local/pnpm/config",
];

/// The ini files in that directory. `rc` is the configuration file pnpm read
/// before the YAML one, and `auth.ini` is where `pnpm login` and the
/// certificate settings are written. Both are npm's ini format, so npm's own
/// line check reads them.
const CONFIG_INI_FILES: [&str; 2] = ["rc", "auth.ini"];

const MAX_SETTINGS_BYTES: u64 = 64 * 1024;

/// Whether a pnpm YAML settings file leaves the fetch, its trust, pnpm's
/// paths and its hook module alone. A missing file is inert; anything
/// unreadable, oversized or not a regular file is not.
///
/// [`super::lockfile_install`] reads the same project file for a different
/// question and answers it the other way round. An install resolves
/// a tree and runs the code in it, so it admits only the keys it knows and
/// reviews a workspace that carries anything else. A report resolves nothing
/// and runs nothing, so the keys that matter here are the ones that move the
/// fetch or the hook module, and a workspace that sets `nodeLinker` or
/// `shamefullyHoist` keeps its report.
fn yaml_settings_inert(path: &Path) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            return matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
        }
    };
    if !metadata.is_file() || metadata.len() > MAX_SETTINGS_BYTES {
        return false;
    }
    // YAML ends a line on a carriage return of its own as well as on a line
    // feed, and `str::lines` keeps a lone `\r` inside the line it returns, so
    // a settings file written with old Mac endings would hand this reading one
    // line holding every key. Splitting on both characters reads each key.
    fs::read_to_string(path).is_ok_and(|text| text.split(['\n', '\r']).all(inert_setting_line))
}

/// Settings that move where pnpm fetches from, how it trusts that transport,
/// which other settings it loads, where it writes, or which hook module it
/// runs. pnpm writes them in camel case and the ini files in kebab case, so
/// the comparison drops everything that is not a letter or a digit.
const UNSAFE_SETTINGS: [&str; 24] = [
    "registry",
    "registries",
    "ca",
    "cafile",
    "cert",
    "clientcertificates",
    "key",
    "proxy",
    "httpproxy",
    "httpsproxy",
    "noproxy",
    "strictssl",
    "nodeoptions",
    "nodepath",
    "pnpmfile",
    "globalpnpmfile",
    "configdependencies",
    "userconfig",
    "globalconfig",
    "globaldir",
    "globalbindir",
    "prefix",
    "location",
    "global",
];

/// One line of a YAML settings file.
///
/// Every line that names a key is read, nested ones included, so a key below
/// a mapping this list says nothing about is still screened. A line that
/// names no key carries a value of a key already read, and a key written with
/// an expansion in it is a key this check cannot decode.
///
/// Several spellings put a key somewhere this line-by-line reading cannot see
/// it, so they end the reading rather than passing. An explicit key writes
/// the name after `?` and the value on a later line, leaving neither line
/// shaped like the `name: value` this screens. A flow mapping carries its own
/// keys inside braces on a line whose own key is something else, so
/// `catalog: {registry: ...}` would be read as `catalog` alone. A merge key
/// copies another mapping's keys in under a name of `<<`, which screens as no
/// name at all.
///
/// A tag, an anchor or an alias in front of the key moves the name the parser
/// reads away from the text on the line: `!!str registry`, `&a registry` and
/// an `*a` standing for a `registry` anchored earlier all name `registry` to
/// js-yaml while the comparison below would reduce them to something else. A
/// double-quoted key carries escapes, so `"\u0072egistry"` names `registry`
/// too. A flow sequence hides every one of them again: js-yaml turns the
/// array a bracketed key holds into the string its elements spell, so
/// `[!!str registry]`, `[*a]` and `["\u0072egistry"]` each name
/// `registry` while putting a `[` where this screen reads for a tag. Each of
/// those ends the reading as well.
///
/// pnpm loads these files with js-yaml's default schema, which resolves all
/// of them, so a settings file that spells one is no longer a file this check
/// can call inert.
fn inert_setting_line(line: &str) -> bool {
    let line = line.trim();
    let line = line.strip_prefix('-').unwrap_or(line).trim_start();
    if line.is_empty() || line.starts_with('#') {
        return true;
    }
    if line.starts_with('?')
        || line.starts_with("<<")
        || line.contains('{')
        || line.starts_with(['!', '&', '*', '['])
    {
        return false;
    }
    let key = match line.chars().next() {
        Some(quote @ ('"' | '\'')) => match line[quote.len_utf8()..].split_once(quote) {
            // A backslash inside a double-quoted key is an escape js-yaml
            // resolves into a character this reading never sees.
            Some((quoted, _)) if quote == '"' && quoted.contains('\\') => return false,
            Some((quoted, rest)) if rest.trim_start().starts_with(':') => quoted,
            _ => return true,
        },
        // YAML names a key with a colon and a space, or ends the line on the
        // colon when a mapping follows, so a key that carries colons of its
        // own stays whole: `@scope:registry` and the `//host/:_authToken`
        // spelling of a credential are both read here. A bare `key:value` is
        // one scalar to YAML and names nothing.
        // YAML separates a key from its value with a space or a tab after
        // the colon, so both are read here; a bare `key:value` is one scalar
        // to YAML and names nothing.
        _ => match key_end(line) {
            Some(end) => &line[..end],
            None => match line.strip_suffix(':') {
                Some(key) => key,
                None => return true,
            },
        },
    };
    let key = key.trim().to_ascii_lowercase();
    let named: String = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect();
    !key.contains("${")
        && !key.contains("//")
        && !key.contains(":_auth")
        && !key.ends_with(":registry")
        && !UNSAFE_SETTINGS.contains(&named.as_str())
}

/// Where the key ends on a line that names one.
///
/// The first colon followed by a space or a tab separates the key from its
/// value. A colon with anything else after it belongs to the key, so
/// `@scope:registry` and the `//host/:_authToken` spelling of a credential
/// are both read whole.
fn key_end(line: &str) -> Option<usize> {
    line.char_indices().find_map(|(index, character)| {
        (character == ':' && matches!(line[index + 1..].chars().next(), Some(' ' | '\t')))
            .then_some(index)
    })
}

/// Absence is the one error that answers the question. Any other means the
/// path was not read, which is not a reading that it holds nothing.
fn nothing_at(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(error) => error.kind() == ErrorKind::NotFound,
    }
}

#[cfg(test)]
#[path = "pnpm_reads_tests.rs"]
mod tests;
