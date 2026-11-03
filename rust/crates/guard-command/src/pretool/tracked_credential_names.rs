//! Whether a document whose name carries a credential word is a project file
//! rather than a secret.
//!
//! `command.kubernetes-secrets.json` describes a feature; it holds no secret.
//! The name screens cannot tell that apart from `prod-secrets.json`, so the
//! file itself must prove it: a small regular JSON, YAML, TOML or Markdown file
//! in the session's repository or one of its linked worktrees, listed in that
//! repository's index, outside every credential-store directory, with no
//! credential-shaped value in it and no Kubernetes `Secret` object. Anything
//! else keeps the review its name earns.

use super::TrackedFiles;
use crate::pretool::secret_aliases::operand;
use crate::pretool::sensitive_command;
use crate::{CanonicalCommandV1, CommandSegmentV1};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::Path;

/// The formats the proof covers. A script or source file named for a secret
/// keeps its review.
const DOCUMENT_EXTENSIONS: &[&str] = &["json", "md", "toml", "yaml", "yml"];
/// Builtins after which a relative path names a file in another directory.
const DIRECTORY_CHANGES: &[&str] = &["cd", "chdir", "popd", "pushd"];
/// Options that point a program at another directory, so its relative
/// operands resolve there: `git -C`, `make --directory`, `bun --cwd`.
const DIRECTORY_OPTIONS: &[&str] = &[
    "--chdir",
    "--cwd",
    "--directory",
    "--git-dir",
    "--prefix",
    "--root",
    "--work-tree",
];

thread_local! {
    static WALK: RefCell<Option<TrackedFiles>> = const { RefCell::new(None) };
}

/// Shares one [`TrackedFiles`] among the [`committed_document`] proofs a walk
/// makes until the guard drops, so the walk parses each repository index once
/// and stays inside one content budget. A nested walk keeps the outer one.
pub(in crate::pretool) fn document_walk() -> DocumentWalk {
    DocumentWalk(WALK.with(|walk| {
        let mut walk = walk.borrow_mut();
        let owner = walk.is_none();
        if owner {
            *walk = Some(TrackedFiles::default());
        }
        owner
    }))
}

#[must_use]
pub(in crate::pretool) struct DocumentWalk(bool);

impl Drop for DocumentWalk {
    fn drop(&mut self) {
        if self.0 {
            let _ = WALK.try_with(|walk| walk.borrow_mut().take());
        }
    }
}

/// Whether `canonical`, a resolved path, is a credential-named document that
/// is not proven to be a tracked project file.
pub(in crate::pretool) fn unproven(canonical: &Path, cwd: Option<&str>) -> bool {
    guard_secure_fs::credential_named_path(canonical) && !tracked_document(canonical, cwd)
}

/// Whether `canonical` is a tracked, secret-free document of the session's
/// repository or of a linked worktree of the same repository.
pub(in crate::pretool) fn tracked_document(canonical: &Path, cwd: Option<&str>) -> bool {
    let Some(workspace) = cwd.and_then(|root| std::fs::canonicalize(root).ok()) else {
        return false;
    };
    let same_tree =
        repository_root(&workspace).is_some_and(|root| repository_root(canonical) == Some(root));
    (same_tree || super::super::worktree_writes::same_repository_worktree(&workspace, canonical))
        && committed_document(canonical)
}

/// Whether `path` is a small, secret-free document listed in the index of
/// whichever repository holds it. A recursive search reads every file it
/// reaches, so a sibling checkout's committed catalog entry is held to the
/// same proof as one in the session's own repository.
pub(in crate::pretool) fn committed_document(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| DOCUMENT_EXTENSIONS.contains(&&*extension.to_ascii_lowercase()))
        && !path
            .components()
            .any(|part| part.as_os_str().eq_ignore_ascii_case(".git"))
        && guard_secure_fs::sensitive_path_family(path).is_none()
        && WALK.with(|walk| match walk.borrow_mut().as_mut() {
            Some(tracked) => tracked.non_secret(path),
            None => TrackedFiles::default().non_secret(path),
        })
        && std::fs::read(path).is_ok_and(|bytes| !secret_object(&String::from_utf8_lossy(&bytes)))
}

/// Whether `value`, a path as a command or tool spelled it, resolves to a
/// document [`tracked_document`] proves.
pub(in crate::pretool) fn resolves_to_tracked(value: &str, cwd: Option<&str>) -> bool {
    let supplied = Path::new(value);
    let target = match cwd {
        _ if supplied.is_absolute() => supplied.to_path_buf(),
        Some(cwd) => Path::new(cwd).join(supplied),
        None => return false,
    };
    std::fs::canonicalize(target).is_ok_and(|canonical| tracked_document(&canonical, cwd))
}

/// `text` with one occurrence of each credential-named word of `words` left
/// out, or `None` when one of those words is anything but a path to a proven
/// tracked document or a ref name of `refs`. Only an occurrence that stands as a shell word of its own
/// is removed, once per word, so a redirect target, assignment or script word
/// that repeats the path stays in place for the caller's screen. When `moves`
/// is set the command changes directory first, so a relative path may name a
/// file other than the one the proof read.
pub(in crate::pretool) fn without_tracked_words<'a>(
    text: &str,
    words: impl IntoIterator<Item = &'a String>,
    cwd: Option<&str>,
    moves: bool,
    refs: &BTreeSet<String>,
) -> Option<String> {
    let mut rest = text.to_owned();
    for word in words.into_iter().filter(|word| sensitive_command(word)) {
        if !refs.contains(word.as_str()) {
            operand(word)
                .filter(|value| !moves || Path::new(value).is_absolute())
                .filter(|value| resolves_to_tracked(value, cwd))?;
        }
        if let Some(at) = standalone(&rest, word) {
            rest.replace_range(at..at + word.len(), " ");
        }
    }
    Some(rest)
}

/// `text` without the words of `words` that name tracked documents, when
/// every credential-named one does; otherwise `text` unchanged.
pub(in crate::pretool) fn screened<'a>(
    model: &CanonicalCommandV1,
    text: String,
    words: impl IntoIterator<Item = &'a String>,
    cwd: Option<&str>,
) -> String {
    let moves = moves_directory(model);
    let refs = crate::pretool::ref_name_words::ref_names(model, cwd, moves);
    without_tracked_words(&text, words, cwd, moves, &refs).unwrap_or(text)
}

/// The text a credential-word screen reads for `segment`: `text`, or the
/// segment's own text, without the words that name tracked documents when
/// every credential-named word does.
pub(in crate::pretool) fn segment_screen_text(
    model: &CanonicalCommandV1,
    segment: &CommandSegmentV1,
    text: Option<String>,
    cwd: Option<&str>,
) -> String {
    let text = text.unwrap_or_else(|| segment.text.clone());
    screened(model, text, segment_words(segment), cwd)
}

/// The text the command authority's credential-word screen reads: the
/// command without heredoc data bodies, and without the words that name
/// tracked documents when every credential-named word in it does.
pub(in crate::pretool) fn command_screen_text(
    model: &CanonicalCommandV1,
    text: &str,
    cwd: Option<&str>,
) -> String {
    let text = super::super::data_heredocs::without_data_bodies(text);
    screened(model, text, command_words(model), cwd)
}

/// The executable and arguments of `segment`.
pub(in crate::pretool) fn segment_words(
    segment: &CommandSegmentV1,
) -> impl Iterator<Item = &String> {
    segment.executable.iter().chain(&segment.arguments)
}

/// The executable and arguments of every segment of `model`.
pub(in crate::pretool) fn command_words(
    model: &CanonicalCommandV1,
) -> impl Iterator<Item = &String> {
    model.segments.iter().flat_map(segment_words)
}

/// Whether a segment of `model` changes directory or points its program at
/// another one. A short-option cluster holding `C` counts, so `tar -xC` and
/// `grep -C2` both keep the review a relative tracked path would shed.
pub(in crate::pretool) fn moves_directory(model: &CanonicalCommandV1) -> bool {
    model.segments.iter().any(|segment| {
        segment.executable.as_deref().is_some_and(|executable| {
            DIRECTORY_CHANGES.contains(&crate::pretool::executable_basename(executable))
        }) || segment
            .tokens
            .iter()
            .any(|token| match token.strip_prefix("--") {
                Some(_) => DIRECTORY_OPTIONS.iter().any(|option| {
                    token
                        .strip_prefix(option)
                        .is_some_and(|tail| tail.is_empty() || tail.starts_with('='))
                }),
                None => token
                    .strip_prefix('-')
                    .is_some_and(|flags| flags.contains('C')),
            })
    })
}

/// The byte offset of the first occurrence of `word` in `text` that stands
/// as a shell word of its own: between the text's ends, blanks, quotes or
/// command separators, never inside a longer word such as `../x/word` or
/// `OUT=word`.
fn standalone(text: &str, word: &str) -> Option<usize> {
    let boundary = |c: char| c.is_whitespace() || "'\";&|()".contains(c);
    text.match_indices(word).map(|(at, _)| at).find(|&at| {
        text[..at].chars().next_back().is_none_or(boundary)
            && text[at + word.len()..].chars().next().is_none_or(boundary)
    })
}

/// The nearest directory at or above `path` that holds a `.git` entry.
fn repository_root(path: &Path) -> Option<&Path> {
    path.ancestors()
        .find(|directory| std::fs::symlink_metadata(directory.join(".git")).is_ok())
}

/// Whether `text` declares a Kubernetes `Secret`, or any kind named for one
/// (`SealedSecret`, `ExternalSecret`), in YAML, JSON or TOML spelling. A
/// manifest's values are often base64 and pass the secret detector, so the
/// declared kind is the only reliable mark. Outside JSON, which is decoded
/// here, an escape can spell `kind` or `Secret` past the plain reading, so a
/// document holding a backslash is not proven either.
pub(in crate::pretool) fn secret_object(text: &str) -> bool {
    declared_kind(text)
        || match serde_json::from_str::<Value>(text) {
            Ok(value) => json_secret_kind(&value),
            Err(_) => text.contains('\\'),
        }
}

/// Whether `text`, a value a tool call carries such as an edit's new text or
/// a command, declares a `Secret` kind in plain or JSON spelling.
pub(in crate::pretool) fn declares_secret_object(text: &str) -> bool {
    declared_kind(text) || serde_json::from_str::<Value>(text).is_ok_and(|v| json_secret_kind(&v))
}

/// The plain reading of every `kind` key. A value that does not start with a
/// word, such as a YAML tag, anchor, alias, block scalar or escape, hides
/// the kind and counts as a `Secret`.
fn declared_kind(text: &str) -> bool {
    text.match_indices("kind").any(|(at, _)| {
        let rest = text[at + 4..].trim_start_matches(['"', '\'']).trim_start();
        let Some(value) = rest.strip_prefix([':', '=']) else {
            return false;
        };
        let value = value.trim_start().trim_start_matches(['"', '\'']);
        let end = value
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .unwrap_or(value.len());
        end == 0 || value[..end].to_ascii_lowercase().contains("secret")
    })
}

/// Whether a decoded JSON document holds a `kind` that is not a plain string
/// or that names a `Secret`, at any depth.
fn json_secret_kind(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, child)| {
            (key == "kind"
                && child
                    .as_str()
                    .is_none_or(|kind| kind.to_ascii_lowercase().contains("secret")))
                || json_secret_kind(child)
        }),
        Value::Array(items) => items.iter().any(json_secret_kind),
        _ => false,
    }
}

#[cfg(test)]
#[path = "tracked_credential_names_tests.rs"]
mod tests;
