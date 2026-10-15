//! Digest every file whose edit changes which helpers a read-only git runs.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::OnceLock;

use guard_contracts::write_canonical_json;
use regex::Regex;
use serde_json::Value;

use super::context::Ctx;
use super::fs_path;
use super::reasons::{Proof, GIT_HELPER_CONFIG, UNPROVEN_LAUNCH};

const MAX_CONFIG_BYTES: u64 = 1_048_576;
const MAX_CONFIG_FILES: usize = 24;
const MAX_INCLUDE_DEPTH: usize = 3;
const MAX_HOOK_FILES: usize = 32;
const MAX_ATTRIBUTE_DIRECTORIES: usize = 20_000;
const SIGNATURE_PLACEHOLDER: &str = "%G";
const GIT_HELPER_ENVIRONMENT: [&str; 3] = ["GIT_EXTERNAL_DIFF", "GIT_PAGER", "GIT_ATTR_SOURCE"];
const CONFIG_NAMES: [&str; 4] = ["config", "config.worktree", ".gitconfig", "gitconfig"];
/// The filter driver `git lfs install` writes: its program is fixed.
const LFS_FILTER: [(&str, &str); 4] = [
    ("clean", "git-lfs clean -- %f"),
    ("smudge", "git-lfs smudge -- %f"),
    ("process", "git-lfs filter-process"),
    ("required", "true"),
];

fn section_header() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r#"^\s*\[\s*([A-Za-z0-9-]+)(?:\s+"((?:[^"\\]|\\.)*)"|\.([^\s\]]*))?\s*\](.*)$"#)
            .expect("static pattern")
    })
}

fn config_key() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        Regex::new(r"^\s*([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*?)\s*)?$").expect("static pattern")
    })
}

fn any_section() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"^\s*\[").expect("static pattern"))
}

fn include_path() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| Regex::new(r"(?i)^\s*path\s*=\s*(.+?)\s*$").expect("static pattern"))
}

fn injects_git_helper(name: &str, value: &str) -> bool {
    // GIT_CONFIG_NOSYSTEM only drops a config file, and `cat` is the no-op pager.
    if name == "GIT_CONFIG_NOSYSTEM" || (name == "GIT_PAGER" && value == "cat") {
        return false;
    }
    name.starts_with("GIT_CONFIG") || GIT_HELPER_ENVIRONMENT.contains(&name)
}

/// Python's `Path.name in {...}` for a candidate path.
fn is_config_name(path: &str) -> bool {
    CONFIG_NAMES.contains(&fs_path::name(path).as_str())
}

fn config_path(value: &str, config_file: &str, home: Option<&str>) -> String {
    let candidate = match (value.strip_prefix("~/"), home) {
        (Some(rest), Some(home)) => fs_path::join(home, rest),
        _ => fs_path::norm(value),
    };
    if fs_path::is_abs(&candidate) {
        candidate
    } else {
        fs_path::join(&fs_path::parent(config_file), &candidate)
    }
}

/// The ordered, de-duplicated config and attribute candidates.
fn candidates(root: &str, git_dir: &str, common_dir: &str, ctx: &Ctx) -> Vec<String> {
    let mut found = vec![
        fs_path::join(common_dir, "config"),
        fs_path::join(git_dir, "config"),
        fs_path::join(git_dir, "config.worktree"),
        fs_path::join(common_dir, "info/attributes"),
        fs_path::join(git_dir, "info/attributes"),
        fs_path::join(root, ".gitattributes"),
        ctx.engines.system_git_config(),
    ];
    let mut bases: Vec<String> = Vec::new();
    if let Some(xdg) = ctx
        .env
        .get("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
    {
        bases.push(fs_path::norm(xdg));
    }
    if let Some(home) = ctx.home {
        bases.push(fs_path::join(home, ".config"));
    }
    for base in bases {
        found.push(fs_path::join(&base, "git/config"));
        found.push(fs_path::join(&base, "git/attributes"));
    }
    if let Some(home) = ctx.home {
        found.push(fs_path::join(home, ".gitconfig"));
    }
    let mut seen = BTreeSet::new();
    found.retain(|path| seen.insert(path.clone()));
    found
}

/// `_git_config_digest`: fails closed when the environment or any config file
/// selects a helper program, since a digest cannot bind what that helper does.
pub(super) fn git_config_digest(
    root: &str,
    git_dir: &str,
    common_dir: &str,
    ctx: &Ctx,
) -> Proof<String> {
    if ctx
        .env
        .iter()
        .any(|(name, value)| injects_git_helper(name, value))
    {
        return Err(GIT_HELPER_CONFIG);
    }
    let candidates = candidates(root, git_dir, common_dir, ctx);
    let configs: BTreeSet<String> = candidates
        .iter()
        .filter(|path| is_config_name(path))
        .cloned()
        .collect();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut hook_dirs: Vec<String> = Vec::new();
    let mut queue: VecDeque<(String, usize)> =
        candidates.into_iter().map(|path| (path, 0)).collect();
    while let Some((path, depth)) = queue.pop_front() {
        ctx.check()?;
        if seen.contains_key(&path) {
            continue;
        }
        if seen.len() >= MAX_CONFIG_FILES {
            return Err(UNPROVEN_LAUNCH);
        }
        if !fs_path::is_file(&path) {
            seen.insert(path, "absent".to_owned());
            continue;
        }
        let size = std::fs::metadata(&path).map_err(|_| UNPROVEN_LAUNCH)?.len();
        if size > MAX_CONFIG_BYTES {
            return Err(UNPROVEN_LAUNCH);
        }
        let data = fs_path::read_bounded(&path, MAX_CONFIG_BYTES).ok_or(UNPROVEN_LAUNCH)?;
        seen.insert(path.clone(), fs_path::sha256_hex(&data));
        // Included files are config whatever they are named; the rest are attributes.
        if configs.contains(&path) || depth > 0 {
            let included = scan_config(
                &String::from_utf8_lossy(&data),
                &path,
                ctx.home,
                &mut hook_dirs,
            )?;
            if !included.is_empty() && depth + 1 > MAX_INCLUDE_DEPTH {
                return Err(UNPROVEN_LAUNCH);
            }
            queue.extend(included.into_iter().map(|target| (target, depth + 1)));
        }
    }
    let mut hooks = vec![fs_path::join(common_dir, "hooks")];
    hooks.extend(hook_dirs);
    let mut visited_hooks = BTreeSet::new();
    for hooks_dir in hooks
        .into_iter()
        .filter(|dir| visited_hooks.insert(dir.clone()))
    {
        seen.extend(hook_digests(&hooks_dir)?);
    }
    seen.extend(nested_attribute_digests(root, ctx)?);
    // `sorted(seen.items())` as compact JSON pairs.
    let pairs: Vec<Value> = seen
        .iter()
        .map(|(key, value)| serde_json::json!([key, value]))
        .collect();
    let mut encoded = Vec::new();
    write_canonical_json(&Value::Array(pairs), &mut encoded).map_err(|_| UNPROVEN_LAUNCH)?;
    Ok(fs_path::sha256_hex(&encoded))
}

/// Hash every installed hook script; git can run one for read-only commands.
fn hook_digests(hooks_dir: &str) -> Proof<BTreeMap<String, String>> {
    let mut digests = BTreeMap::new();
    if !fs_path::is_dir(hooks_dir) {
        return Ok(digests);
    }
    let mut names: Vec<String> = std::fs::read_dir(hooks_dir)
        .map_err(|_| UNPROVEN_LAUNCH)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()
        .map_err(|_| UNPROVEN_LAUNCH)?;
    names.sort();
    for name in names {
        let entry = fs_path::join(hooks_dir, &name);
        if name.ends_with(".sample") || !fs_path::is_file(&entry) {
            continue;
        }
        let size = std::fs::metadata(&entry)
            .map_err(|_| UNPROVEN_LAUNCH)?
            .len();
        if digests.len() >= MAX_HOOK_FILES || size > MAX_CONFIG_BYTES {
            return Err(UNPROVEN_LAUNCH);
        }
        let data = fs_path::read_bounded(&entry, MAX_CONFIG_BYTES).ok_or(UNPROVEN_LAUNCH)?;
        digests.insert(format!("hook:{entry}"), fs_path::sha256_hex(&data));
    }
    Ok(digests)
}

/// A build cache (`CACHEDIR.TAG`, e.g. Cargo `target`) or a Python virtual environment.
fn is_cache_tree(directory: &str) -> bool {
    fs_path::is_file(&fs_path::join(directory, "CACHEDIR.TAG"))
        || fs_path::is_file(&fs_path::join(directory, "pyvenv.cfg"))
}

/// Hash every nested `.gitattributes` under the worktree (the root one is a candidate).
fn nested_attribute_digests(root: &str, ctx: &Ctx) -> Proof<BTreeMap<String, String>> {
    let mut digests = BTreeMap::new();
    let mut visited = 0usize;
    let mut pending = vec![root.to_owned()];
    while let Some(current) = pending.pop() {
        ctx.check()?;
        // An unreadable directory is skipped, as `os.walk` does.
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        let mut has_attributes = false;
        for entry in entries.flatten() {
            // A huge directory must not outlive the request budget.
            ctx.check()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = fs_path::join(&current, &name);
            if fs_path::is_dir(&path) {
                let is_link = entry.file_type().is_ok_and(|kind| kind.is_symlink());
                if name != ".git" && name != "node_modules" && !is_cache_tree(&path) && !is_link {
                    pending.push(path);
                }
            } else if name == ".gitattributes" {
                has_attributes = true;
            }
        }
        visited += 1;
        if visited > MAX_ATTRIBUTE_DIRECTORIES {
            return Err(UNPROVEN_LAUNCH);
        }
        if current == root || !has_attributes {
            continue;
        }
        let path = fs_path::join(&current, ".gitattributes");
        let size = std::fs::metadata(&path).map_err(|_| UNPROVEN_LAUNCH)?.len();
        if size > MAX_CONFIG_BYTES || digests.len() >= MAX_CONFIG_FILES {
            return Err(UNPROVEN_LAUNCH);
        }
        let data = fs_path::read_bounded(&path, MAX_CONFIG_BYTES).ok_or(UNPROVEN_LAUNCH)?;
        digests.insert(path, fs_path::sha256_hex(&data));
    }
    Ok(digests)
}

/// Whether a `[section] key` selects a program or file git would run or read.
fn selects_helper(section: &str, name: &str) -> bool {
    match section {
        "core" => matches!(name, "fsmonitor" | "pager" | "attributesfile"),
        "pager" | "filter" => true,
        "diff" => matches!(name, "command" | "textconv" | "external"),
        "interactive" => name == "difffilter",
        "log" => name == "showsignature",
        _ => false,
    }
}

/// Include targets and hook directories of one config file; an error when a
/// key selects a helper program.
fn scan_config(
    text: &str,
    config_file: &str,
    home: Option<&str>,
    hook_dirs: &mut Vec<String>,
) -> Proof<Vec<String>> {
    let mut included = Vec::new();
    let mut section = String::new();
    let mut subsection = String::new();
    for raw_line in python_splitlines(text) {
        let mut line = raw_line;
        if let Some(header) = section_header().captures(raw_line) {
            section = header[1].to_lowercase();
            subsection = match (header.get(2), header.get(3)) {
                (Some(quoted), _) => quoted.as_str().to_owned(),
                (None, dotted) => dotted.map_or("", |value| value.as_str()).to_lowercase(),
            };
            line = header.get(4).map_or("", |rest| rest.as_str());
        } else if any_section().is_match(raw_line) {
            // A header this parser cannot read could hide a helper: fail closed.
            return Err(GIT_HELPER_CONFIG);
        }
        scan_key(
            line,
            &section,
            &subsection,
            config_file,
            home,
            hook_dirs,
            &mut included,
        )?;
    }
    Ok(included)
}

fn scan_key(
    line: &str,
    section: &str,
    subsection: &str,
    config_file: &str,
    home: Option<&str>,
    hook_dirs: &mut Vec<String>,
    included: &mut Vec<String>,
) -> Proof<()> {
    let Some(key) = config_key().captures(line) else {
        return Ok(());
    };
    let name = key[1].to_lowercase();
    let value = key
        .get(2)
        .map_or("", |value| value.as_str())
        .trim_matches('"');
    if section == "filter" && subsection == "lfs" && LFS_FILTER.contains(&(name.as_str(), value)) {
        return Ok(());
    }
    if section == "core" && name == "hookspath" {
        // Hashing the directory binds the hooks git would run from it.
        if value.is_empty() || !(value.starts_with("~/") || fs_path::is_abs(value)) {
            return Err(GIT_HELPER_CONFIG);
        }
        hook_dirs.push(config_path(value, config_file, home));
        return Ok(());
    }
    if value.contains(SIGNATURE_PLACEHOLDER) || selects_helper(section, &name) {
        return Err(GIT_HELPER_CONFIG);
    }
    if matches!(section, "include" | "includeif") && name == "path" {
        let Some(path) = include_path().captures(line) else {
            return Err(GIT_HELPER_CONFIG);
        };
        included.push(config_path(
            path[1].trim().trim_matches('"'),
            config_file,
            home,
        ));
    }
    Ok(())
}

/// `str.splitlines()` for the line terminators that can occur in a config file.
fn python_splitlines(text: &str) -> Vec<&str> {
    text.split_inclusive([
        '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
        '\u{2029}',
    ])
    .map(|line| {
        line.trim_end_matches([
            '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
            '\u{2029}',
        ])
    })
    .collect()
}
