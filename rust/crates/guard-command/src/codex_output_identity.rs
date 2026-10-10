//! Canonical `git-pathspec-selection-v2` identity payload hashing.

use sha2::{Digest, Sha256};

use crate::codex_output_py::PyPath;

fn json_str(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if (c as u32) < 0x80 => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

/// A `bytes.decode("utf-8", "surrogateescape")` string as ASCII JSON: invalid
/// bytes become the lone surrogates `\udcXX`.
fn json_bytes(out: &mut String, bytes: &[u8]) {
    let mut text = String::new();
    out.push('"');
    for chunk in bytes.utf8_chunks() {
        text.clear();
        json_str(&mut text, chunk.valid());
        out.push_str(&text[1..text.len() - 1]);
        for byte in chunk.invalid() {
            out.push_str(&format!("\\udc{byte:02x}"));
        }
    }
    out.push('"');
}

fn json_list<T>(out: &mut String, items: &[T], mut write: impl FnMut(&mut String, &T)) {
    out.push('[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write(out, item);
    }
    out.push(']');
}

fn json_opt_path(out: &mut String, value: Option<&PyPath>) {
    match value {
        Some(path) => json_str(out, &path.to_string()),
        None => out.push_str("null"),
    }
}

/// One worktree entry as it appears in the identity.
pub(crate) enum WorktreeEntry {
    Present {
        relative: Vec<u8>,
        device: u64,
        inode: u64,
        mode: u32,
        size: u64,
        mtime_ns: i128,
    },
    Missing {
        relative: Vec<u8>,
    },
}

/// The pieces of the `git-pathspec-selection-v2` payload.
pub(crate) struct IdentityPayload<'a> {
    pub(crate) reason_code: &'a str,
    pub(crate) cwd: Option<&'a PyPath>,
    pub(crate) repository_root: Option<&'a PyPath>,
    pub(crate) pathspecs: &'a [String],
    pub(crate) global_modes: &'a [String],
    pub(crate) resolved_paths: &'a [String],
    pub(crate) index_entries: &'a [(Vec<u8>, String, String)],
    pub(crate) worktree_entries: &'a [WorktreeEntry],
}

/// `_selection_identity` over the canonical JSON (sorted keys, ASCII, compact).
pub(crate) fn selection_identity(payload: &IdentityPayload) -> String {
    let mut out = String::from("{\"cwd\":");
    json_opt_path(&mut out, payload.cwd);
    out.push_str(",\"global_modes\":");
    json_list(&mut out, payload.global_modes, |out, item| {
        json_str(out, item)
    });
    out.push_str(",\"index_entries\":");
    json_list(
        &mut out,
        payload.index_entries,
        |out, (name, mode, object)| {
            out.push('[');
            json_bytes(out, name);
            out.push(',');
            json_str(out, mode);
            out.push(',');
            json_str(out, object);
            out.push(']');
        },
    );
    out.push_str(",\"pathspecs\":");
    json_list(&mut out, payload.pathspecs, |out, item| json_str(out, item));
    out.push_str(",\"reason_code\":");
    json_str(&mut out, payload.reason_code);
    out.push_str(",\"repository_root\":");
    json_opt_path(&mut out, payload.repository_root);
    out.push_str(",\"resolved_paths\":");
    json_list(&mut out, payload.resolved_paths, |out, item| {
        json_str(out, item)
    });
    out.push_str(",\"schema\":\"git-pathspec-selection-v2\",\"worktree_entries\":");
    json_list(
        &mut out,
        payload.worktree_entries,
        |out, entry| match entry {
            WorktreeEntry::Present {
                relative,
                device,
                inode,
                mode,
                size,
                mtime_ns,
            } => {
                out.push('[');
                json_bytes(out, relative);
                out.push_str(&format!(",{device},{inode},{mode},{size},{mtime_ns}]"));
            }
            WorktreeEntry::Missing { relative } => {
                out.push('[');
                json_bytes(out, relative);
                out.push_str(",\"missing\"]");
            }
        },
    );
    out.push('}');
    hex::encode(Sha256::digest(out.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_the_canonical_json_hash() {
        let payload = IdentityPayload {
            reason_code: "git_pathspec_no_match",
            cwd: None,
            repository_root: None,
            pathspecs: &[],
            global_modes: &[],
            resolved_paths: &[],
            index_entries: &[],
            worktree_entries: &[],
        };
        let expected = hex::encode(Sha256::digest(
            br#"{"cwd":null,"global_modes":[],"index_entries":[],"pathspecs":[],"reason_code":"git_pathspec_no_match","repository_root":null,"resolved_paths":[],"schema":"git-pathspec-selection-v2","worktree_entries":[]}"#,
        ));
        assert_eq!(selection_identity(&payload), expected);
        let mut out = String::new();
        json_bytes(&mut out, b"a\xffb\xc3\xa9");
        assert_eq!(out, "\"a\\udcffb\\u00e9\"");
    }

    #[test]
    fn identity_matches_hashes_recorded_from_python() {
        let empty = IdentityPayload {
            reason_code: "git_pathspec_no_match",
            cwd: None,
            repository_root: None,
            pathspecs: &[],
            global_modes: &[],
            resolved_paths: &[],
            index_entries: &[],
            worktree_entries: &[],
        };
        assert_eq!(
            selection_identity(&empty),
            "75c765d675257dedfba0f7b6fd44904739f0fd3f92fd888d51bdca80b7a29cdc"
        );
        let cwd = PyPath::new("/r/p");
        let root = PyPath::new("/r");
        let pathspecs = ["src/café.py".to_owned(), ":(glob)*.rs".to_owned()];
        let modes = ["--literal-pathspecs".to_owned()];
        let resolved = ["src/café.py".to_owned()];
        let index = [
            (
                "src/café.py".as_bytes().to_vec(),
                "100644".to_owned(),
                "abc123".to_owned(),
            ),
            (b"a\xffb".to_vec(), "100755".to_owned(), "def456".to_owned()),
        ];
        let worktree = [
            WorktreeEntry::Present {
                relative: "src/café.py".as_bytes().to_vec(),
                device: 16_777_220,
                inode: 12_345,
                mode: 33_188,
                size: 77,
                mtime_ns: 1_700_000_000_123_456_789,
            },
            WorktreeEntry::Missing {
                relative: b"gone.txt".to_vec(),
            },
        ];
        let full = IdentityPayload {
            reason_code: "git_pathspec_resolved",
            cwd: Some(&cwd),
            repository_root: Some(&root),
            pathspecs: &pathspecs,
            global_modes: &modes,
            resolved_paths: &resolved,
            index_entries: &index,
            worktree_entries: &worktree,
        };
        assert_eq!(
            selection_identity(&full),
            "a6296a708d19a8b35e9558c2ae2955ca7c29439bc417c5b7bc44db22af009fac"
        );
    }
}
