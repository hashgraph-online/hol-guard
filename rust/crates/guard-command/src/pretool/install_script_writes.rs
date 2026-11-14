//! File writes that add an install lifecycle script to `package.json`.
//!
//! npm, pnpm, Yarn and Bun run a manifest's `preinstall`, `install` and
//! `postinstall` scripts on every later install, for everyone who installs
//! the project, without asking. Adding one is how a planted instruction
//! turns into code that runs long after the session ends, so the write is
//! reviewed. Editing a manifest that already declares the script, or adding
//! any other script such as `prepare` or `test`, stays an ordinary edit.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

static INSTALL_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?P<key>(?:pre|post)?install)"\s*:\s*"(?P<value>[^"]*)"#)
        .expect("install script pattern compiles")
});
/// A dependency's version range or source: `"install": "^0.13.0"` under
/// `dependencies` names a package, not a script. The whole value must read
/// as a range, tag or source with no shell syntax, so a script such as
/// `>/dev/null; node setup.js` is not mistaken for one.
static DEPENDENCY_SPEC: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^\s*(?:",
        r"(?:[\^~]|[<>]=?|=)?\s*v?\d+(?:\.[\dx*]+){0,2}(?:-[0-9A-Za-z.-]+)?",
        r"(?:\s*(?:\|\||-|\s)\s*(?:[\^~]|[<>]=?|=)?\s*v?\d+(?:\.[\dx*]+){0,2}(?:-[0-9A-Za-z.-]+)?)*",
        r"|\*|latest|next",
        r"|(?:npm|workspace|file|link|github|git(?:\+[a-z]+)?|https?):[^\s;&|`$<>()]+",
        r")\s*$",
    ))
    .expect("dependency spec pattern compiles")
});
static PATCH_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\*\*\* (?:Add|Update) File:\s*(?P<path>.+?)\s*$")
        .expect("patch file pattern compiles")
});

const INSTALL_NAMES: [&str; 3] = ["preinstall", "install", "postinstall"];
const OLD_KEYS: [&str; 2] = ["old_string", "oldString"];
const NEW_KEYS: [&str; 4] = ["new_string", "newString", "content", "contents"];
const PATH_KEYS: [&str; 3] = ["file_path", "filePath", "path"];
/// The largest manifest read from disk as the baseline of a write.
const MAX_MANIFEST_BYTES: u64 = 1 << 20;

fn manifest(path: &str) -> bool {
    path.trim_end_matches(['"', '\''])
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|name| name == "package.json")
}

fn text<'v>(object: &'v Map<String, Value>, keys: &[&str]) -> Option<&'v str> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_str))
}

/// `text` with each JSON `\uXXXX` escape decoded, so `"postinstall"`
/// reads as the key a package manager sees.
fn unescaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("\\u") {
        out.push_str(&rest[..at]);
        let decoded = rest
            .get(at + 2..at + 6)
            .filter(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .and_then(char::from_u32);
        if let Some(ch) = decoded {
            out.push(ch);
            rest = &rest[at + 6..];
        } else {
            out.push_str("\\u");
            rest = &rest[at + 2..];
        }
    }
    out.push_str(rest);
    out
}

/// The install lifecycle scripts `text` declares. A whole manifest is read
/// as JSON, so only keys under `scripts` count. A fragment is matched after
/// its escapes decode, leaving out a key whose value is a version range.
fn install_keys(text: &str) -> Vec<String> {
    if let Ok(Value::Object(manifest)) = serde_json::from_str::<Value>(text) {
        return manifest
            .get("scripts")
            .and_then(Value::as_object)
            .map(|scripts| {
                scripts
                    .keys()
                    .filter(|key| INSTALL_NAMES.contains(&key.as_str()))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
    }
    let decoded = unescaped(text);
    INSTALL_SCRIPT
        .captures_iter(&decoded)
        .filter(|found| !DEPENDENCY_SPEC.is_match(&found["value"]))
        .map(|found| found["key"].to_owned())
        .collect()
}

/// The install scripts the manifest at `path` already declares on disk. A
/// whole-file write or a hashline edit carries no old text, so this is what
/// tells a rewrite of an existing script from a new one. A missing or
/// unreadable manifest declares none.
fn existing_keys(path: &str, cwd: Option<&str>) -> Vec<String> {
    let path = Path::new(path.trim());
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(cwd) = cwd {
        Path::new(cwd).join(path)
    } else {
        return Vec::new();
    };
    match std::fs::metadata(&full) {
        Ok(meta) if meta.is_file() && meta.len() <= MAX_MANIFEST_BYTES => {
            std::fs::read_to_string(&full)
                .map(|body| install_keys(&body))
                .unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

/// Whether `new` declares an install script that neither `old` nor the
/// manifest on disk at `path` declares.
fn introduces(old: &str, new: &str, path: &str, cwd: Option<&str>) -> bool {
    let added = install_keys(new);
    if added.is_empty() {
        return false;
    }
    let mut before = install_keys(old);
    before.extend(existing_keys(path, cwd));
    added.iter().any(|key| !before.contains(key))
}

/// Whether one `old`/`new` replacement, or a whole-file body, in `object`
/// aimed at a manifest adds an install script.
fn replacement_adds(
    object: &Map<String, Value>,
    inherited: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some(path) = text(object, &PATH_KEYS)
        .or(inherited)
        .filter(|path| manifest(path))
    else {
        return false;
    };
    text(object, &NEW_KEYS)
        .is_some_and(|new| introduces(text(object, &OLD_KEYS).unwrap_or(""), new, path, cwd))
}

/// The path an Oh My Pi hashline header (`[path#TAG]` or `[path]`) names.
fn hashline_header(line: &str) -> Option<&str> {
    let body = line.trim_end().strip_prefix('[')?.strip_suffix(']')?;
    Some(body.rsplit_once('#').map_or(body, |(path, _)| path).trim())
}

/// Whether a Codex `apply_patch` body or an Oh My Pi hashline edit adds an
/// install script to a manifest it creates or updates, beyond one it removes
/// in the same file or one the manifest already declares.
fn patch_adds(patch: &str, cwd: Option<&str>) -> bool {
    let mut target: Option<String> = None;
    let mut source: Option<String> = None;
    let (mut hashline, mut in_put) = (false, false);
    let (mut removed, mut added) = (String::new(), String::new());
    let mut found = false;
    let mut close = |target: &Option<String>, removed: &mut String, added: &mut String| {
        if target
            .as_deref()
            .is_some_and(|path| introduces(removed, added, path, cwd))
        {
            found = true;
        }
        removed.clear();
        added.clear();
    };
    for raw in patch.lines() {
        let line = raw.trim_end_matches('\r');
        let header = PATCH_FILE
            .captures(line)
            .map(|file| (file["path"].to_owned(), false))
            .or_else(|| hashline_header(line).map(|path| (path.to_owned(), true)));
        if let Some((path, is_hashline)) = header {
            close(&target, &mut removed, &mut added);
            source = (!is_hashline).then(|| path.clone());
            target = manifest(&path).then_some(path);
            (hashline, in_put) = (is_hashline, false);
            continue;
        }
        // `*** Move to:` writes the source file, with the hunks that follow,
        // to the destination. A script the source already holds on disk
        // arrives in the manifest without appearing on a `+` row.
        if let Some(destination) = line.strip_prefix("*** Move to:") {
            let destination = destination.trim();
            close(&target, &mut removed, &mut added);
            target = manifest(destination).then(|| destination.to_owned());
            if target.is_some() {
                for key in source
                    .as_deref()
                    .map(|path| existing_keys(path, cwd))
                    .unwrap_or_default()
                {
                    added.push_str(&["\"", key.as_str(), "\": \"moved\"\n"].concat());
                }
            }
            continue;
        }
        if line.starts_with("*** ") {
            close(&target, &mut removed, &mut added);
            target = None;
            continue;
        }
        if hashline && (line.starts_with("PUT") || line.starts_with("CUT")) {
            in_put = line.starts_with("PUT");
            continue;
        }
        if let Some(row) = line.strip_prefix('+') {
            added.push_str(row);
            added.push('\n');
        } else if let Some(row) = line.strip_prefix('-') {
            removed.push_str(row);
            removed.push('\n');
        } else if hashline && in_put {
            // Oh My Pi keeps a row under `PUT` without its `+` as content.
            added.push_str(line);
            added.push('\n');
        }
    }
    close(&target, &mut removed, &mut added);
    found
}

/// Whether a file tool call adds a `preinstall`, `install` or `postinstall`
/// script to a `package.json`. `cwd` resolves a relative path when the
/// manifest on disk is read for its existing scripts.
pub(super) fn adds_install_script(input: &Map<String, Value>, cwd: Option<&str>) -> bool {
    let top = text(input, &PATH_KEYS);
    if replacement_adds(input, None, cwd) {
        return true;
    }
    if input
        .get("edits")
        .and_then(Value::as_array)
        .is_some_and(|edits| {
            edits
                .iter()
                .filter_map(Value::as_object)
                .any(|edit| replacement_adds(edit, top, cwd))
        })
    {
        return true;
    }
    input
        .get("input")
        .and_then(Value::as_str)
        .or_else(|| input.get("command").and_then(Value::as_str))
        .filter(|patch| {
            patch.trim_start().starts_with("*** Begin Patch")
                || patch.lines().any(|line| hashline_header(line).is_some())
        })
        .is_some_and(|patch| patch_adds(patch, cwd))
}

#[cfg(test)]
#[path = "install_script_writes_tests.rs"]
mod tests;
