//! The attributes files a Git read loads from outside its work tree.
//!
//! The temporary-removal proof keeps the review for any operand that is one
//! of these files, so a name this module misses is a file the removal could
//! take from under the read. Every setting it cannot place keeps the review.
use super::search_scope_plain_skips::read_small;
use std::cell::RefCell;
use std::path::{Path, PathBuf};

/// More configuration files than this, counting the ones they include, keep
/// the review.
const MAX_CONFIG_FILES: usize = 16;

/// Configuration files Git reads outside the repository.
const SYSTEM_CONFIGS: &[&str] = &[
    "/etc/gitconfig",
    "/opt/homebrew/etc/gitconfig",
    "/usr/local/etc/gitconfig",
];

/// Attributes files Git reads outside the repository.
const SYSTEM_ATTRIBUTES: &[&str] = &[
    "/etc/gitattributes",
    "/opt/homebrew/etc/gitattributes",
    "/usr/local/etc/gitattributes",
];

thread_local! {
    /// The session's `XDG_CONFIG_HOME` while an evaluation with a stamped
    /// execution environment runs; `None` outside one.
    static SESSION_XDG: RefCell<Option<Option<String>>> = const { RefCell::new(None) };
}

/// Resolves the user configuration directory the way the Git probe does
/// until the guard drops: the stamped environment's value when one is
/// supplied, the process value when none is. A nested scope restores the
/// outer one.
pub(super) fn session_scope(
    environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> SessionScope {
    let stamped = environment.map(|environment| environment.xdg_config_home.clone());
    SessionScope(SESSION_XDG.with(|cell| cell.replace(stamped)))
}

#[must_use]
pub(super) struct SessionScope(Option<Option<String>>);

impl Drop for SessionScope {
    fn drop(&mut self) {
        let outer = self.0.take();
        let _ = SESSION_XDG.try_with(|cell| cell.replace(outer));
    }
}

/// Where the configuration and attributes outside a repository live.
pub(super) struct SourceRoots {
    pub(super) system_configs: Vec<PathBuf>,
    pub(super) system_attributes: Vec<PathBuf>,
    pub(super) xdg: Option<PathBuf>,
}

impl SourceRoots {
    /// The system files and the user configuration directory the session's
    /// Git reads.
    pub(super) fn session() -> Self {
        let xdg = match SESSION_XDG.with(|cell| cell.borrow().clone()) {
            Some(stamped) => stamped.map(PathBuf::from),
            None => std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        };
        Self {
            system_configs: SYSTEM_CONFIGS.iter().map(PathBuf::from).collect(),
            system_attributes: SYSTEM_ATTRIBUTES.iter().map(PathBuf::from).collect(),
            xdg: xdg.filter(|directory| directory.is_absolute()),
        }
    }
}

/// The attributes files Git reads outside the work tree, resolved through
/// links: each Git directory's `info/attributes`, the user and system files,
/// and every `core.attributesFile` the configuration names, following
/// `include.path` and `includeIf.*.path`. `None` when a setting names a file
/// this cannot place, a configuration file cannot be read or parsed, or a
/// named file cannot be resolved for a reason other than its absence.
pub(super) fn attribute_sources(
    roots: &SourceRoots,
    home: Option<&Path>,
    git_directories: &[PathBuf],
) -> Option<Vec<PathBuf>> {
    let mut configs = roots.system_configs.clone();
    let mut sources = roots.system_attributes.clone();
    if let Some(home) = home {
        configs.extend([home.join(".gitconfig"), home.join(".config/git/config")]);
        sources.push(home.join(".config/git/attributes"));
    }
    if let Some(xdg) = &roots.xdg {
        configs.push(xdg.join("git/config"));
        sources.push(xdg.join("git/attributes"));
    }
    for directory in git_directories {
        configs.extend([directory.join("config"), directory.join("config.worktree")]);
        sources.push(directory.join("info/attributes"));
    }
    let named = configs.len();
    let mut index = 0;
    while let Some(config) = configs.get(index).cloned() {
        index += 1;
        let Some(text) = read_small(&config).ok()? else {
            continue;
        };
        for entry in config_entries(&text)? {
            let placed = || match (entry.value.strip_prefix("~/"), home) {
                (Some(rest), Some(home)) => Some(home.join(rest)),
                _ if Path::new(&entry.value).is_absolute() => Some(PathBuf::from(&entry.value)),
                _ => None,
            };
            match (entry.section.as_str(), entry.key.as_str()) {
                // Git resolves a relative attributes path against the
                // directory it runs in, which a later step may change.
                ("core", "attributesfile") if !entry.subsection => sources.push(placed()?),
                ("include", "path") | ("includeif", "path") => {
                    if configs.len() >= named + MAX_CONFIG_FILES {
                        return None;
                    }
                    // An include is read relative to the file that names it.
                    // `~user/` and `%(prefix)/` are not modeled.
                    let include = match placed() {
                        Some(path) => path,
                        None if entry.value.starts_with(['~', '%']) => return None,
                        None => config.parent()?.join(&entry.value),
                    };
                    configs.push(include);
                }
                _ => {}
            }
        }
    }
    sources
        .iter()
        .filter_map(|source| match std::fs::canonicalize(source) {
            Ok(path) => Some(Some(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => Some(None),
        })
        .collect()
}

/// One `key = value` line of a configuration file, with its section.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ConfigEntry {
    pub(super) section: String,
    pub(super) subsection: bool,
    pub(super) key: String,
    pub(super) value: String,
}

/// The entries of a configuration file, read the way Git reads them: a key
/// may follow its `[section]` header on the same line, an unquoted `#` or
/// `;` starts a comment, a quoted value keeps both, a trailing `\` continues
/// the value on the next line and the escapes `\"`, `\\`, `\n`, `\t` and
/// `\b` decode. `None` for syntax Git would refuse.
pub(super) fn config_entries(text: &str) -> Option<Vec<ConfigEntry>> {
    let mut characters = text.chars().peekable();
    let mut entries = Vec::new();
    let mut section = String::new();
    let mut subsection = false;
    loop {
        while characters.next_if(|c| c.is_whitespace()).is_some() {}
        let Some(character) = characters.next() else {
            return Some(entries);
        };
        match character {
            '#' | ';' => while characters.next_if(|c| *c != '\n').is_some() {},
            '\u{feff}' if entries.is_empty() && section.is_empty() => {}
            '[' => {
                let mut name = String::new();
                subsection = false;
                loop {
                    match characters.next()? {
                        ']' => break,
                        '"' => {
                            subsection = true;
                            loop {
                                match characters.next()? {
                                    '"' => break,
                                    '\\' => {
                                        characters.next()?;
                                    }
                                    '\n' => return None,
                                    _ => {}
                                }
                            }
                        }
                        c if c.is_ascii_alphanumeric() || c == '-' || c == '.' => {
                            name.push(c.to_ascii_lowercase());
                        }
                        ' ' | '\t' => {}
                        _ => return None,
                    }
                }
                // The older `[section.subsection]` spelling.
                if let Some((head, _)) = name.split_once('.') {
                    name = head.to_owned();
                    subsection = true;
                }
                section = name;
            }
            c if c.is_ascii_alphabetic() => {
                let mut key = String::from(c.to_ascii_lowercase());
                while let Some(c) = characters.next_if(|c| c.is_ascii_alphanumeric() || *c == '-') {
                    key.push(c.to_ascii_lowercase());
                }
                while characters.next_if(|c| *c == ' ' || *c == '\t').is_some() {}
                let value = match characters.peek() {
                    Some('=') => {
                        characters.next();
                        config_value(&mut characters)?
                    }
                    None | Some('\n' | '\r' | '#' | ';') => String::from("true"),
                    Some(_) => return None,
                };
                entries.push(ConfigEntry {
                    section: section.clone(),
                    subsection,
                    key,
                    value,
                });
            }
            _ => return None,
        }
    }
}

fn config_value(characters: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<String> {
    let mut value = String::new();
    let mut quoted = false;
    let mut spaces = 0_usize;
    while characters.next_if(|c| *c == ' ' || *c == '\t').is_some() {}
    while let Some(character) = characters.next() {
        match character {
            '\n' if quoted => return None,
            '\n' => break,
            '\r' if !quoted && characters.peek() == Some(&'\n') => {}
            '#' | ';' if !quoted => {
                while characters.next_if(|c| *c != '\n').is_some() {}
                break;
            }
            ' ' | '\t' if !quoted => spaces += 1,
            _ => {
                if !value.is_empty() || quoted || character == '"' {
                    value.extend(std::iter::repeat_n(' ', spaces));
                }
                spaces = 0;
                match character {
                    '"' => quoted = !quoted,
                    '\\' => match characters.next()? {
                        '\n' => {}
                        '\r' if characters.next_if_eq(&'\n').is_some() => {}
                        'n' => value.push('\n'),
                        't' => value.push('\t'),
                        'b' => value.push('\u{8}'),
                        escaped @ ('"' | '\\') => value.push(escaped),
                        _ => return None,
                    },
                    other => value.push(other),
                }
            }
        }
    }
    (!quoted).then_some(value)
}

#[cfg(test)]
#[path = "removal_git_sources_tests.rs"]
mod tests;
