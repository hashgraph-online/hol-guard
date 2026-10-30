//! Composer and Bundler verbs that read a dependency tree the project owns.
//!
//! [`super::package`] keeps every package manager out of the contained route
//! because each one installs what it runs, and an install the sandbox has no
//! network for would fail where it works today. Composer and Bundler have a
//! second surface: both install into a directory beside the manifest —
//! `vendor` and `vendor/bundle` — so a verb that reads that tree reads the
//! workspace and nothing else. Running the project's own test suite through
//! `composer run-script test` or `bundle exec rspec` is the shape a PHP or
//! Ruby developer repeats all day, and today it is the one ecosystem whose
//! ordinary work stops for an approval while its neighbours stay quiet.
//!
//! A contained run is given a private scratch `HOME`, so only a project whose
//! dependencies are materialized beside the manifest is routed here. A project
//! that resolves its gems through the caller's own gem home, or its packages
//! through Composer's home cache, would answer for the sandbox rather than the
//! developer, so it keeps the admission it has today — the same gate `uv run`
//! applies to a project whose `.venv` is not materialized yet.
//!
//! Every verb that reaches a registry stays out: `install`, `update`,
//! `require`, `remove`, `lock`, `outdated`, `diagnose` and the rest are not in
//! the lists below, and an option this module does not know keeps the command
//! out as well, because Composer's `show --latest` and `--available` turn a
//! local listing into a registry query.
//!
//! Composer also answers to the names a project's own manifest gives it: with
//! a `test` script declared, `composer test` runs what `composer run-script
//! test` runs, and that short spelling is the one a PHP developer types. It is
//! admitted on the same terms, and only for a name Composer has no command of,
//! so a manifest cannot reach `install` or `update` by declaring a script
//! under their names.
//!
//! Three more things decide which project and which tree a run reads, and
//! each keeps the command out when it cannot be read as a plain path under the
//! workspace:
//!
//! * Composer reads `-d` and `--working-dir` from anywhere on the line,
//!   including behind the script it runs and behind `--`, and the project it
//!   moves to is not the one the checks looked at.
//! * The tree is wherever the project's own configuration puts it:
//!   `config.vendor-dir` in `composer.json` and `BUNDLE_PATH` in
//!   `.bundle/config`. A directory that merely carries the conventional name
//!   is no proof of where the packages are read from, and a path that leaves
//!   the workspace, by `..`, by an absolute name or by a link, is one the
//!   sandbox does not hold.
//! * A verb that hands the line to a project tool may hand it to a package
//!   manager (`composer exec composer install`, `bundle exec gem install`),
//!   which installs what it runs. Package review reads the outer command, so
//!   the delegated line keeps its review here.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// The managers that install into a directory the project owns.
pub(super) const VENDORED_MANAGERS: &[&str] = &["composer", "bundle", "bundler"];

/// Composer verbs that read the project rather than a registry. `validate`
/// reads the manifest and lockfile alone; the rest report or run what is
/// already installed under `vendor`.
const COMPOSER_LOCAL_VERBS: &[&str] = &[
    "validate",
    "show",
    "info",
    "exec",
    "run",
    "run-script",
    "dump-autoload",
    "dumpautoload",
    "check-platform-reqs",
    "licenses",
];
/// The verbs above that need the installed tree beside the manifest.
const COMPOSER_VENDOR_VERBS: &[&str] = &[
    "show",
    "info",
    "exec",
    "run",
    "run-script",
    "dump-autoload",
    "dumpautoload",
    "check-platform-reqs",
    "licenses",
];
/// Composer options a local verb may carry. The list is an allowlist because
/// the options that reach a registry are many and grow: `--latest`, `--all`
/// and `--available` each turn `show` into a registry query, so an option this
/// module does not know keeps the command out.
const COMPOSER_INERT_FLAGS: &[&str] = &[
    "-q",
    "--quiet",
    "-n",
    "--no-interaction",
    "--no-ansi",
    "--ansi",
    "--no-plugins",
    "--no-scripts",
    "--no-cache",
    "--strict",
    "--format=json",
    "--format=text",
];
/// Composer verbs that hand the rest of the line to a project tool. What that
/// tool reads is the workspace the sandbox already bounds.
const COMPOSER_PROGRAM_VERBS: &[&str] = &["exec", "run", "run-script"];

/// Composer's own command names, including the abbreviations and aliases its
/// dispatcher answers to. A manifest that declares a script under one of these
/// never reaches it from the line, because Composer runs its own command
/// first, and that is where `install`, `update` and `require` reach a
/// registry. The script shortcut below therefore reads only a name Composer
/// has no command of.
const COMPOSER_RESERVED_VERBS: &[&str] = &[
    "about",
    "archive",
    "audit",
    "browse",
    "bump",
    "cc",
    "check-platform-reqs",
    "clear-cache",
    "clearcache",
    "completion",
    "config",
    "create-project",
    "depends",
    "diagnose",
    "dump-autoload",
    "dumpautoload",
    "exec",
    "fund",
    "global",
    "help",
    "home",
    "i",
    "info",
    "init",
    "install",
    "licenses",
    "list",
    "outdated",
    "policy",
    "prohibits",
    "r",
    "reinstall",
    "remove",
    "repo",
    "repository",
    "require",
    "rm",
    "run",
    "run-script",
    "search",
    "self-update",
    "selfupdate",
    "show",
    "status",
    "suggests",
    "u",
    "uninstall",
    "update",
    "upgrade",
    "validate",
    "why",
    "why-not",
];

/// Bundler verbs that read the bundle the project owns. `exec` starts a
/// project tool; the rest report what the bundle already holds.
const BUNDLE_LOCAL_VERBS: &[&str] = &["exec", "list", "show", "check"];

// The variables that move a manager's project, configuration or dependency
// directories. Set in front of the command, any of them replaces what the
// project's own files say, so the tree those files name is no longer the one
// the run reads.
const COMPOSER_VARIABLE_PREFIXES: &[&str] = &["COMPOSER"];
const BUNDLE_VARIABLE_PREFIXES: &[&str] = &["BUNDLE", "GEM_", "RUBY"];

/// Package tools a delegated line must not name. Each one installs, fetches or
/// updates what it runs, so a verb that hands the line to one is not the local
/// work this module admits.
const DELEGATED_PACKAGE_TOOLS: &[&str] = &[
    "composer", "bundle", "bundler", "gem", "npm", "npx", "pnpm", "pnpx", "yarn", "bun", "bunx",
    "pip", "pip3", "pipx", "pipenv", "poetry", "uv", "uvx", "cargo", "go", "brew", "apt",
    "apt-get", "dnf", "yum", "apk",
];

/// How much of a project's configuration is read to find its dependency tree.
const CONFIG_BYTES: u64 = 1 << 20;

/// Whether a Composer or Bundler segment runs a verb against a dependency
/// tree the workspace holds. `directory` is where the chain stands by the time
/// the segment runs, so a `cd` ahead of it decides which project is read.
pub(super) fn local_vendored_work(
    name: &str,
    arguments: &[String],
    environment_names: &[String],
    directory: &Path,
    workspace: &Path,
) -> bool {
    let composer = name == "composer";
    let prefixes = if composer {
        COMPOSER_VARIABLE_PREFIXES
    } else {
        BUNDLE_VARIABLE_PREFIXES
    };
    if environment_names.iter().any(|variable| {
        let variable = variable.to_ascii_uppercase();
        prefixes.iter().any(|prefix| variable.starts_with(prefix))
    }) {
        return false;
    }
    let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
    if composer {
        local_composer_work(&arguments, directory, workspace)
    } else {
        local_bundle_work(&arguments, directory, workspace)
    }
}

/// The arguments up to the `--` that ends a verb's own options.
fn before_separator<'a>(arguments: &[&'a str]) -> Vec<&'a str> {
    arguments
        .iter()
        .copied()
        .take_while(|word| *word != "--")
        .collect()
}

/// Whether `word` is Composer's working-directory option in a spelling its
/// argument parser reads: `-d`, `-dPATH`, a short cluster that carries `d`
/// such as `-qd`, `--working-dir` or `--working-dir=PATH`.
fn moves_composer(word: &str) -> bool {
    if word == "--working-dir" || word.starts_with("--working-dir=") {
        return true;
    }
    word.starts_with('-') && !word.starts_with("--") && word[1..].contains('d')
}

/// Whether the line a verb hands on names a package tool anywhere: as the
/// program, behind `env` or `sh -c`, or as an interpreter's script. The names
/// are matched on the last path component, so `vendor/bin/composer` and
/// `composer.phar` count.
fn names_a_package_tool(words: &[&str]) -> bool {
    words.iter().any(|word| {
        word.split(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    ';' | '&' | '|' | '(' | ')' | '`' | '"' | '\'' | '='
                )
        })
        .filter(|piece| !piece.is_empty())
        .any(|piece| {
            let base = piece
                .rsplit('/')
                .next()
                .unwrap_or(piece)
                .to_ascii_lowercase();
            let base = base.strip_suffix(".phar").unwrap_or(&base);
            DELEGATED_PACKAGE_TOOLS.contains(&base)
        })
    })
}

/// `relative` joined onto `directory`, when it is a plain path the workspace
/// holds: no expansion, no `..`, no absolute name, and no link on the way that
/// resolves outside the workspace. A path that does not exist yet passes; the
/// caller decides whether it has to.
fn inside(directory: &Path, relative: &str, workspace: &Path) -> Option<PathBuf> {
    if relative.is_empty() || relative.contains(['$', '{', '}', '~', '`', '\\', '\0']) {
        return None;
    }
    let path = Path::new(relative);
    if !path
        .components()
        .all(|part| matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return None;
    }
    let joined = directory.join(path);
    match joined.canonicalize() {
        Ok(real) => real
            .starts_with(workspace.canonicalize().ok()?)
            .then_some(joined),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(joined),
        Err(_) => None,
    }
}

/// The text of a configuration file, `Some(None)` when it does not exist and
/// `None` when it cannot be read whole.
fn read_config(path: &Path) -> Option<Option<String>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(None),
        Err(_) => return None,
    };
    let mut text = Vec::new();
    file.take(CONFIG_BYTES + 1).read_to_end(&mut text).ok()?;
    if text.len() as u64 > CONFIG_BYTES {
        return None;
    }
    String::from_utf8(text).ok().map(Some)
}

/// This project's own `composer.json`: `Value::Null` when the directory has
/// none, and `None` when it cannot be read whole or is not the object
/// Composer reads.
fn composer_manifest(directory: &Path) -> Option<serde_json::Value> {
    match read_config(&directory.join("composer.json"))? {
        Some(text) => serde_json::from_str(&text).ok(),
        None => Some(serde_json::Value::Null),
    }
}

/// Whether the manifest lets a plugin bring commands of its own. Composer
/// registers a plugin's commands before it turns the project's scripts into
/// commands, and the plugin wins a name collision, so a declared script name
/// is only that script while no plugin may run. Since Composer 2.2 a plugin
/// runs only where the project's own `config.allow-plugins` admits it, which
/// is what this reads: an absent or false setting is the project telling
/// Composer to run none.
fn allows_plugins(manifest: &serde_json::Value) -> bool {
    match manifest
        .get("config")
        .and_then(|config| config.get("allow-plugins"))
    {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(allowed)) => *allowed,
        Some(serde_json::Value::Object(entries)) => entries
            .values()
            .any(|entry| entry != &serde_json::Value::Bool(false)),
        Some(_) => true,
    }
}

/// How many scripts are read before the shortcut gives up. One script stands
/// for another by name, and a manifest can spell a chain or a cycle.
const SCRIPT_DEPTH: usize = 8;

/// Whether the manifest declares `name` among the project's own scripts and
/// the work it declares is the project's own. Composer turns each script name
/// into a command of its own, so a line that names one runs the work
/// `composer run-script NAME` runs -- and that work is the manifest's, not the
/// line's, so the line alone cannot say whether a package manager is in it.
///
/// A script is a line, a list of lines, or `@other` standing for another of
/// the project's scripts, which is followed here the way Composer follows it.
/// `@php` and `@putenv` are Composer's own spellings for a program and a
/// variable; `@composer` is Composer itself, which is the manager this is
/// looking for. Anything else the manifest spells is left to the review.
fn script_is_local(manifest: &serde_json::Value, name: &str) -> bool {
    let Some(scripts) = manifest
        .get("scripts")
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    let mut read: Vec<&str> = Vec::new();
    let mut pending: Vec<&str> = vec![name];
    while let Some(current) = pending.pop() {
        if read.contains(&current) {
            continue;
        }
        if read.len() == SCRIPT_DEPTH {
            return false;
        }
        read.push(current);
        let lines = match scripts.get(current) {
            Some(serde_json::Value::String(line)) => vec![line.as_str()],
            Some(serde_json::Value::Array(entries)) => {
                let mut lines = Vec::with_capacity(entries.len());
                for entry in entries {
                    match entry.as_str() {
                        Some(line) => lines.push(line),
                        None => return false,
                    }
                }
                lines
            }
            _ => return false,
        };
        for line in lines {
            let Some(reference) = line.trim_start().strip_prefix('@') else {
                if names_a_package_tool(&[line]) {
                    return false;
                }
                continue;
            };
            let (head, rest) = match reference.split_once(char::is_whitespace) {
                Some((head, rest)) => (head, rest),
                None => (reference, ""),
            };
            match head {
                "php" | "putenv" => {
                    if names_a_package_tool(&[rest]) {
                        return false;
                    }
                }
                "composer" => return false,
                other => pending.push(other),
            }
        }
    }
    true
}

/// The directory Composer reads this project's packages from, when the
/// project's own configuration puts it, or leaves it, under the workspace and
/// the packages are installed there.
fn composer_tree(
    manifest: &serde_json::Value,
    directory: &Path,
    workspace: &Path,
) -> Option<PathBuf> {
    let setting = |key: &str| -> Option<Option<String>> {
        match manifest.get("config").and_then(|config| config.get(key)) {
            None => Some(None),
            Some(serde_json::Value::String(value)) => Some(Some(value.clone())),
            Some(_) => None,
        }
    };
    let vendor = setting("vendor-dir")?.unwrap_or_else(|| "vendor".to_owned());
    let tree = inside(directory, &vendor, workspace)?;
    if let Some(bin) = setting("bin-dir")? {
        inside(directory, &bin.replace("{$vendor-dir}", &vendor), workspace)?;
    }
    tree.is_dir().then_some(tree)
}

/// How one line of `.bundle/config` spells `key`. Bundler reads a line as a
/// setting only when the key starts the line and its colon is followed by
/// white space or ends the line, so `BUNDLE_PATH:vendor/bundle`, an indented
/// key and a key with a space before its colon are not the setting it names.
/// `Some(None)` is a line about another key, `Some(Some(value))` is the
/// setting, and `None` is a spelling of this key that Bundler may read
/// differently from this reader.
fn bundle_line(line: &str, key: &str) -> Option<Option<String>> {
    let Some(rest) = line.trim_start().strip_prefix(key) else {
        return Some(None);
    };
    if rest.starts_with(|letter: char| letter == '_' || letter.is_ascii_alphanumeric()) {
        return Some(None);
    }
    let value = match rest.strip_prefix(':') {
        Some("") if line.starts_with(key) => "",
        Some(tail) if line.starts_with(key) && tail.starts_with([' ', '\t']) => tail.trim(),
        _ => return None,
    };
    if value.ends_with(':') || value.contains(": ") || value.contains(":\t") {
        return None;
    }
    Some(Some(value.trim_matches(['"', '\'']).to_owned()))
}

/// The value `.bundle/config` holds for `key`: `Some(None)` when the file does
/// not set it, and `None` when it sets it more than once or spells it in a way
/// `bundle_line` refuses. Bundler keeps the last of a repeated key, so a reader
/// that took the first would answer for a tree the run does not read, and a
/// repeat is ambiguous enough to refuse.
fn bundle_setting(config: &str, key: &str) -> Option<Option<String>> {
    let mut found = None;
    for line in config.lines() {
        if let Some(value) = bundle_line(line, key)? {
            if found.replace(value).is_some() {
                return None;
            }
        }
    }
    Some(found)
}

/// The directory Bundler reads this project's gems from. Bundler puts them
/// where the project's own `.bundle/config` says, so a bundle that config does
/// not name resolves through the caller's gem home, which the sandbox
/// replaces; a path that leaves the workspace is one it does not hold.
fn bundle_tree(directory: &Path, workspace: &Path) -> Option<PathBuf> {
    let config = read_config(&directory.join(".bundle").join("config"))??;
    // `BUNDLE_PATH__SYSTEM` and its siblings choose the system gem home
    // whatever `BUNDLE_PATH` says, so a configuration that sets one does not
    // name this directory's bundle.
    if config
        .lines()
        .any(|line| line.trim_start().starts_with("BUNDLE_PATH__"))
    {
        return None;
    }
    // A Gemfile or app-config elsewhere makes this directory's files not the
    // bundle's.
    if bundle_setting(&config, "BUNDLE_GEMFILE")?.is_some()
        || bundle_setting(&config, "BUNDLE_APP_CONFIG")?.is_some()
    {
        return None;
    }
    let deployment = bundle_setting(&config, "BUNDLE_DEPLOYMENT")?;
    let path = match bundle_setting(&config, "BUNDLE_PATH")? {
        Some(path) => path,
        None => deployment
            .filter(|value| value == "true")
            .map(|_| "vendor/bundle".to_owned())?,
    };
    let tree = inside(directory, &path, workspace)?;
    tree.is_dir().then_some(tree)
}

fn local_composer_work(arguments: &[&str], directory: &Path, workspace: &Path) -> bool {
    if arguments.iter().any(|word| moves_composer(word)) {
        return false;
    }
    let words = before_separator(arguments);
    let Some(index) = words
        .iter()
        .position(|word| !COMPOSER_INERT_FLAGS.contains(word))
    else {
        return false;
    };
    let verb = words[index];
    let manifest = match composer_manifest(directory) {
        Some(manifest) => manifest,
        None => return false,
    };
    if !COMPOSER_LOCAL_VERBS.contains(&verb) {
        // A name Composer has no command of is one the project's own manifest
        // gave it: Composer runs that script, which is the work `run-script`
        // runs under a longer spelling. What follows the name is the script's
        // own line, read here the way a delegated line is read above.
        return !verb.starts_with('-')
            && !COMPOSER_RESERVED_VERBS.contains(&verb)
            && !allows_plugins(&manifest)
            && script_is_local(&manifest, verb)
            && composer_tree(&manifest, directory, workspace).is_some()
            && !names_a_package_tool(&arguments[index + 1..]);
    }
    if COMPOSER_VENDOR_VERBS.contains(&verb)
        && composer_tree(&manifest, directory, workspace).is_none()
    {
        return false;
    }
    if COMPOSER_PROGRAM_VERBS.contains(&verb) {
        // The script or binary comes first; what follows is its own line,
        // which the sandbox bounds like any other workspace command, unless
        // it hands the work to a package manager.
        let line = &arguments[index + 1..];
        return line.first().is_some_and(|word| !word.starts_with('-'))
            && !names_a_package_tool(line)
            // `run` and `run-script` name a script, so the work is the
            // manifest's here too, read under the longer spelling.
            && (verb == "exec"
                || line
                    .first()
                    .is_some_and(|script| script_is_local(&manifest, script)));
    }
    words[index + 1..]
        .iter()
        .all(|word| !word.starts_with('-') || COMPOSER_INERT_FLAGS.contains(word))
}

fn local_bundle_work(arguments: &[&str], directory: &Path, workspace: &Path) -> bool {
    let words = before_separator(arguments);
    let Some(&verb) = words.first() else {
        return false;
    };
    if !BUNDLE_LOCAL_VERBS.contains(&verb) {
        return false;
    }
    // Without a bundle the project's configuration names, the gems resolve
    // through the caller's own home, which the sandbox replaces.
    if bundle_tree(directory, workspace).is_none() {
        return false;
    }
    if verb != "exec" {
        return words[1..].iter().all(|word| !word.starts_with('-'));
    }
    let line = &arguments[1..];
    line.first().is_some_and(|word| !word.starts_with('-')) && !names_a_package_tool(line)
}

#[cfg(test)]
#[path = "workspace_contained_vendored_tests.rs"]
mod vendored_tests;
