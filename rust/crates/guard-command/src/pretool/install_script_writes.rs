//! File writes that add an install lifecycle script to `package.json`.
//!
//! npm, pnpm, Yarn and Bun run a manifest's `preinstall`, `install` and
//! `postinstall` scripts on every later install, for everyone who installs
//! the project, without asking. Adding one is how a planted instruction
//! turns into code that runs long after the session ends, so the write is
//! reviewed. Editing a manifest that already declares the script, or adding
//! any other script such as `prepare` or `test`, stays an ordinary edit.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

static INSTALL_SCRIPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""(?P<key>(?:pre|post)?install)"\s*:\s*""#)
        .expect("install script pattern compiles")
});
static PATCH_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\*\*\* (?:Add|Update) File:\s*(?P<path>.+?)\s*$")
        .expect("patch file pattern compiles")
});

const OLD_KEYS: [&str; 2] = ["old_string", "oldString"];
const NEW_KEYS: [&str; 4] = ["new_string", "newString", "content", "contents"];
const PATH_KEYS: [&str; 3] = ["file_path", "filePath", "path"];

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

fn install_keys(text: &str) -> Vec<&str> {
    INSTALL_SCRIPT
        .captures_iter(text)
        .filter_map(|found| found.name("key").map(|key| key.as_str()))
        .collect()
}

/// Whether `new` declares an install script `old` does not.
fn introduces(old: &str, new: &str) -> bool {
    let before = install_keys(old);
    install_keys(new).iter().any(|key| !before.contains(key))
}

/// Whether one `old`/`new` replacement, or a whole-file body, in `object`
/// aimed at a manifest adds an install script.
fn replacement_adds(object: &Map<String, Value>, inherited: Option<&str>) -> bool {
    let path = text(object, &PATH_KEYS).or(inherited);
    if !path.is_some_and(manifest) {
        return false;
    }
    text(object, &NEW_KEYS)
        .is_some_and(|new| introduces(text(object, &OLD_KEYS).unwrap_or(""), new))
}

/// Whether a patch adds an install script line to a manifest it creates or
/// updates, beyond one it removes in the same file.
fn patch_adds(patch: &str) -> bool {
    let mut in_manifest = false;
    let (mut removed, mut added) = (String::new(), String::new());
    let mut found = false;
    let mut close = |removed: &mut String, added: &mut String, in_manifest: bool| {
        if in_manifest && introduces(removed, added) {
            found = true;
        }
        removed.clear();
        added.clear();
    };
    for line in patch.lines() {
        if let Some(file) = PATCH_FILE.captures(line) {
            close(&mut removed, &mut added, in_manifest);
            in_manifest = manifest(&file["path"]);
        } else if line.starts_with("*** ") {
            close(&mut removed, &mut added, in_manifest);
            in_manifest = false;
        } else if let Some(row) = line.strip_prefix('+') {
            added.push_str(row);
            added.push('\n');
        } else if let Some(row) = line.strip_prefix('-') {
            removed.push_str(row);
            removed.push('\n');
        }
    }
    close(&mut removed, &mut added, in_manifest);
    found
}

/// Whether a file tool call adds a `preinstall`, `install` or `postinstall`
/// script to a `package.json`.
pub(super) fn adds_install_script(input: &Map<String, Value>) -> bool {
    let top = text(input, &PATH_KEYS);
    if replacement_adds(input, None) {
        return true;
    }
    if input
        .get("edits")
        .and_then(Value::as_array)
        .is_some_and(|edits| {
            edits
                .iter()
                .filter_map(Value::as_object)
                .any(|edit| replacement_adds(edit, top))
        })
    {
        return true;
    }
    input
        .get("input")
        .and_then(Value::as_str)
        .or_else(|| input.get("command").and_then(Value::as_str))
        .filter(|patch| patch.trim_start().starts_with("*** Begin Patch"))
        .is_some_and(patch_adds)
}

#[cfg(test)]
#[path = "install_script_writes_tests.rs"]
mod tests;
