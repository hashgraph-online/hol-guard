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

/// [`unproven`] for a path a request names, rather than for what a command
/// does with one. A repository commits `.env.example` beside the source it
/// documents, and the index and secret screens a tracked document already
/// passes are the proof that the file is the template its name claims.
pub(in crate::pretool) fn unproven_request(canonical: &Path, cwd: Option<&str>) -> bool {
    unproven(canonical, cwd) && !tracked_dotenv_template(canonical, cwd)
}

/// Whether `path` is a committed dotenv template of the session's repository
/// whose values are the placeholders such a template documents.
///
/// The index membership and the secret screen are the ones
/// [`tracked_document`] applies. What this does not apply is the
/// document-extension list, because a template carries the suffix its
/// ecosystem gave it rather than a document's, and the dotenv family screen,
/// because the template is the file the family screen is being read past. A
/// template holding a real value fails the secret screen and keeps its
/// review.
///
/// The directories above the template are screened as the directories they
/// are, so a template parked inside `.gnupg` or beside `.aws/credentials`
/// keeps that family whatever the index says about it.
pub(in crate::pretool) fn tracked_dotenv_template(path: &Path, cwd: Option<&str>) -> bool {
    if !path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(guard_secure_fs::dotenv_template_basename)
    {
        return false;
    }
    if path
        .parent()
        .is_some_and(|parent| guard_secure_fs::sensitive_path_family(parent).is_some())
    {
        return false;
    }
    let Some(workspace) = cwd.and_then(|root| std::fs::canonicalize(root).ok()) else {
        return false;
    };
    let same_tree =
        repository_root(&workspace).is_some_and(|root| repository_root(path) == Some(root));
    (same_tree
        || super::super::worktree_writes::same_repository_worktree(&workspace, path)
        || super::super::worktree_writes::primary_checkout_of_worktree(&workspace, path))
        && !path
            .components()
            .any(|part| part.as_os_str().eq_ignore_ascii_case(".git"))
        && WALK.with(|walk| match walk.borrow_mut().as_mut() {
            Some(tracked) => tracked.non_secret(path),
            None => TrackedFiles::default().non_secret(path),
        })
}

/// Whether `canonical` is a tracked, secret-free document of the session's
/// repository, of a linked worktree of the same repository, or of the primary
/// checkout a session running from a worktree was cut from.
pub(in crate::pretool) fn tracked_document(canonical: &Path, cwd: Option<&str>) -> bool {
    let Some(workspace) = cwd.and_then(|root| std::fs::canonicalize(root).ok()) else {
        return false;
    };
    let same_tree =
        repository_root(&workspace).is_some_and(|root| repository_root(canonical) == Some(root));
    (same_tree
        || super::super::worktree_writes::same_repository_worktree(&workspace, canonical)
        || super::super::worktree_writes::primary_checkout_of_worktree(&workspace, canonical))
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
        && guard_secure_fs::sensitive_path_family_beside_name_proof(path).is_none()
        && WALK.with(|walk| match walk.borrow_mut().as_mut() {
            Some(tracked) => tracked.non_secret(path),
            None => TrackedFiles::default().non_secret(path),
        })
}

/// Whether `path` is a raster image listed in the index of whichever
/// repository holds it, outside every credential store, whose bytes open with
/// the signature its extension names. A search that walks into a committed
/// screenshot such as `auth-login.png` reads compressed pixels, and grep and
/// rg print no line from a binary file; the head of the image, where a text
/// chunk or comment would sit, is still scanned for credentials.
pub(in crate::pretool) fn committed_image(path: &Path) -> bool {
    !path
        .components()
        .any(|part| part.as_os_str().eq_ignore_ascii_case(".git"))
        && guard_secure_fs::sensitive_path_family(path).is_none()
        && WALK.with(|walk| match walk.borrow_mut().as_mut() {
            Some(tracked) => tracked.tracked_image(path),
            None => TrackedFiles::default().tracked_image(path),
        })
}

/// Whether `value`, a path as a request spelled it, resolves to a committed
/// dotenv template [`tracked_dotenv_template`] proves.
///
/// The name the request wrote is screened as well as the file it resolves to.
/// A link named `.env`, or one parked in a credential store, reads as the
/// secret it is named after whatever it points at, so the relief covers only
/// a request that both spells a template and lands on one.
pub(in crate::pretool) fn resolves_to_tracked_dotenv_template(
    value: &str,
    cwd: Option<&str>,
) -> bool {
    let supplied = Path::new(value);
    if !supplied
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(guard_secure_fs::dotenv_template_basename)
    {
        return false;
    }
    let target = match cwd {
        _ if supplied.is_absolute() => supplied.to_path_buf(),
        Some(cwd) => Path::new(cwd).join(supplied),
        None => return false,
    };
    if target
        .parent()
        .is_some_and(|parent| guard_secure_fs::sensitive_path_family(parent).is_some())
    {
        return false;
    }
    std::fs::canonicalize(target).is_ok_and(|canonical| tracked_dotenv_template(&canonical, cwd))
}

/// Whether `value`, a path as a request spelled it, names a document whose
/// only sensitive family is the key-name rule and resolves to one
/// [`tracked_document`] proves.
///
/// The spelled path is screened as well as the file it resolves to, so a
/// document parked in a key container, or a link named for a key file that
/// points at a committed page, keeps its review. A relative request is
/// screened where it lands, so the directories above a bare name requested
/// from inside a credential store keep their family.
pub(in crate::pretool) fn resolves_to_tracked_key_named_document(
    value: &str,
    cwd: Option<&str>,
) -> bool {
    let supplied = Path::new(value);
    let target = match cwd {
        _ if supplied.is_absolute() => supplied.to_path_buf(),
        Some(cwd) => Path::new(cwd).join(supplied),
        None => return false,
    };
    guard_secure_fs::sensitive_path_family_beside_name_proof(supplied).is_none()
        && target
            .parent()
            .is_none_or(|parent| guard_secure_fs::sensitive_path_family(parent).is_none())
        && supplied
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(guard_secure_fs::wallet_key_named)
        && resolves_to_tracked(value, cwd)
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

/// Whether `text` holds a JSON Web Key with private material: a `kty` member
/// beside a filled `d`, `p`, `q`, `dp`, `dq`, `qi` or `k` member. A JWK keeps
/// its secret in these one-letter members, which the credential scan does not
/// read as assignments, so a key-named document holding one, in JSON, YAML,
/// TOML or a fenced block of Markdown, would otherwise pass as clean. A JSON
/// document is read again after decoding so an escape cannot spell a member
/// past the plain reading; outside JSON, [`secret_object`] already refuses a
/// document that holds a backslash.
pub(in crate::pretool) fn private_jwk(text: &str) -> bool {
    plain_private_jwk(text)
        || serde_json::from_str::<Value>(text)
            .is_ok_and(|value| plain_private_jwk(&value.to_string()))
}

fn plain_private_jwk(text: &str) -> bool {
    keyed_value(text, "kty", 1)
        && ["d", "p", "q", "dp", "dq", "qi", "k"]
            .iter()
            .any(|member| keyed_value(text, member, 16))
}

/// Whether `key` appears as a member name, at a word boundary and followed by
/// `:` or `=`, whose value opens with at least `min` base64url characters.
/// A value this plain reading cannot see counts as filled: one that starts on
/// the next line, after a YAML block-scalar header, tag, anchor, alias or
/// comment, or inside a TOML multiline string.
fn keyed_value(text: &str, key: &str, min: usize) -> bool {
    text.match_indices(key).any(|(at, _)| {
        if text[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return false;
        }
        let rest = text[at + key.len()..]
            .trim_start_matches(['"', '\''])
            .trim_start_matches([' ', '\t']);
        let Some(value) = rest.strip_prefix([':', '=']) else {
            return false;
        };
        let value = value.trim_start_matches([' ', '\t']);
        let quoted = value.trim_start_matches(['"', '\'']);
        hidden_value(value)
            || hidden_value(quoted)
            || quoted
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .count()
                >= min
    })
}

/// Whether a member's value does not start on its own line as plain text.
fn hidden_value(value: &str) -> bool {
    value.is_empty() || value.starts_with(['\n', '\r', '|', '>', '!', '&', '*', '#'])
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

#[cfg(test)]
#[path = "tracked_image_tests.rs"]
mod image_tests;

#[cfg(test)]
#[path = "tracked_private_jwk_tests.rs"]
mod private_jwk_tests;
