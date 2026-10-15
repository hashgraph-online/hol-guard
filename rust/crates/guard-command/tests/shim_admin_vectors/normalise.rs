//! Normalisation shared with `scripts/ci/shim_admin_vector_support.py`: the
//! scratch directory and the content digests derived from it are replaced so a
//! recorded result does not depend on where the replay ran.

use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) const ROOT_TOKEN: &str = "{root}";
const SIDECAR_MARK: &[u8] = b"\n# hol-guard-sidecar\n";

#[derive(Clone)]
pub(crate) enum Entry {
    Dir,
    Link(String),
    File { exec: u32, data: Vec<u8> },
}

pub(crate) type Tree = BTreeMap<String, Entry>;

/// Spellings of the scratch directory an implementation emits: one on POSIX;
/// on Windows also doubled backslashes (`repr`, JSON) and forward slashes.
pub(crate) fn root_forms(root: &str) -> Vec<String> {
    if root.contains('\\') {
        vec![
            root.replace('\\', "\\\\"),
            root.to_owned(),
            root.replace('\\', "/"),
        ]
    } else {
        vec![root.to_owned()]
    }
}

pub(crate) fn replace_root_bytes(data: &[u8], root: &str) -> Vec<u8> {
    root_forms(root)
        .iter()
        .fold(data.to_vec(), |current, form| {
            replace_bytes(&current, form.as_bytes(), ROOT_TOKEN.as_bytes())
        })
}

pub(crate) fn replace_root_text(text: &str, root: &str) -> String {
    root_forms(root)
        .iter()
        .fold(text.to_owned(), |current, form| {
            current.replace(form, ROOT_TOKEN)
        })
}

/// `st_mode & 0o111` as Python reports it for a regular file.
#[cfg(unix)]
fn exec_bits(meta: &fs::Metadata, _path: &Path) -> u32 {
    meta.permissions().mode() & 0o111
}

/// Windows has no mode bits; `os.stat` synthesises the exec bits from the extension.
#[cfg(windows)]
fn exec_bits(_meta: &fs::Metadata, path: &Path) -> u32 {
    let extension = path
        .extension()
        .map(|ext| ext.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if matches!(extension.as_str(), "exe" | "cmd" | "bat" | "com") {
        0o111
    } else {
        0
    }
}

pub(crate) fn sha(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub(crate) fn replace_bytes(data: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut index = 0;
    while index < data.len() {
        if !from.is_empty() && data[index..].starts_with(from) {
            out.extend_from_slice(to);
            index += from.len();
        } else {
            out.push(data[index]);
            index += 1;
        }
    }
    out
}

pub(crate) fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// Replace maximal 64-character lowercase-hex runs known to `map`.
pub(crate) fn remap_text(text: &str, map: &BTreeMap<String, String>) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        if is_lower_hex(bytes[index]) {
            let mut end = index;
            while end < bytes.len() && is_lower_hex(bytes[end]) {
                end += 1;
            }
            let run = &text[index..end];
            if run.len() == 64 {
                out.push_str(map.get(run).map_or(run, String::as_str));
            } else {
                out.push_str(run);
            }
            index = end;
        } else {
            let width = text[index..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&text[index..index + width]);
            index += width;
        }
    }
    out
}

/// Replace the scratch directory in every string of `value` with the token.
pub(crate) fn tokenise(value: &Value, root: &str) -> Value {
    match value {
        Value::String(text) => Value::String(replace_root_text(text, root)),
        Value::Array(items) => Value::Array(items.iter().map(|v| tokenise(v, root)).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (replace_root_text(key, root), tokenise(item, root)))
                .collect(),
        ),
        other => other.clone(),
    }
}

pub(crate) fn substitute(value: &Value, from: &str, to: &str) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace(from, to)),
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| substitute(v, from, to)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.replace(from, to), substitute(item, from, to)))
                .collect(),
        ),
        other => other.clone(),
    }
}

pub(crate) fn remap_value(value: &Value, map: &BTreeMap<String, String>) -> Value {
    match value {
        Value::String(text) => Value::String(remap_text(text, map)),
        Value::Array(items) => Value::Array(items.iter().map(|v| remap_value(v, map)).collect()),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, item)| (remap_text(key, map), remap_value(item, map)))
                .collect(),
        ),
        other => other.clone(),
    }
}

pub(crate) fn snapshot(root: &Path) -> Tree {
    fn walk(base: &Path, current: &Path, tree: &mut Tree) {
        let mut names: Vec<_> = fs::read_dir(current)
            .expect("read dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        names.sort();
        for name in names {
            let path = current.join(&name);
            let relative = path
                .strip_prefix(base)
                .expect("relative")
                .to_string_lossy()
                .replace('\\', "/");
            let meta = fs::symlink_metadata(&path).expect("lstat");
            if meta.file_type().is_symlink() {
                let target = fs::read_link(&path).expect("readlink");
                tree.insert(relative, Entry::Link(target.to_string_lossy().into_owned()));
            } else if meta.is_dir() {
                tree.insert(relative, Entry::Dir);
                walk(base, &path, tree);
            } else {
                tree.insert(
                    relative,
                    Entry::File {
                        exec: exec_bits(&meta, &path),
                        data: fs::read(&path).expect("read"),
                    },
                );
            }
        }
    }
    let mut tree = Tree::new();
    walk(root, root, &mut tree);
    tree
}

pub(crate) fn collect_hashes(tree: &Tree, root: &str, map: &mut BTreeMap<String, String>) {
    let mut candidates: Vec<Vec<u8>> = Vec::new();
    for (relative, entry) in tree {
        let Entry::File { data, .. } = entry else {
            continue;
        };
        candidates.push(data.clone());
        let (parent, name) = relative.rsplit_once('/').unwrap_or(("", relative));
        let sidecar = if parent.is_empty() {
            None
        } else {
            tree.get(&format!("{parent}/.{name}.py"))
        };
        let mut attested = data.clone();
        attested.extend_from_slice(SIDECAR_MARK);
        if let Some(Entry::File { data: sidecar, .. }) = sidecar {
            attested.extend_from_slice(sidecar);
        }
        candidates.push(attested);
    }
    for data in candidates {
        let normalised = replace_root_bytes(&data, root);
        if normalised != data {
            map.insert(sha(&data), sha(&normalised));
        }
    }
}

pub(crate) fn normalised_bytes(data: &[u8], root: &str, map: &BTreeMap<String, String>) -> Vec<u8> {
    let data = replace_root_bytes(data, root);
    match String::from_utf8(data.clone()) {
        Ok(text) => remap_text(&text, map).into_bytes(),
        Err(_) => data,
    }
}

pub(crate) fn tree_digest(tree: &Tree, root: &str, map: &BTreeMap<String, String>) -> Value {
    let mut digest = serde_json::Map::new();
    for (relative, entry) in tree {
        let item = match entry {
            Entry::Dir => json!(["d"]),
            Entry::Link(target) => json!(["l", replace_root_text(target, root)]),
            Entry::File { exec, data } => {
                json!(["f", exec, sha(&normalised_bytes(data, root, map))])
            }
        };
        digest.insert(relative.clone(), item);
    }
    Value::Object(digest)
}

pub(crate) fn tree_files(tree: &Tree, root: &str, map: &BTreeMap<String, String>) -> Value {
    let mut files = serde_json::Map::new();
    for (relative, entry) in tree {
        let item = match entry {
            Entry::Dir => json!({"kind": "dir"}),
            Entry::Link(target) => {
                json!({"kind": "symlink", "target": replace_root_text(target, root)})
            }
            Entry::File { exec, data } => {
                let bytes = normalised_bytes(data, root, map);
                match String::from_utf8(bytes.clone()) {
                    Ok(text) => json!({"kind": "file", "exec": exec, "text": text}),
                    Err(_) => json!({
                        "kind": "file",
                        "exec": exec,
                        "b64": base64::engine::general_purpose::STANDARD.encode(&bytes),
                    }),
                }
            }
        };
        files.insert(relative.clone(), item);
    }
    Value::Object(files)
}
