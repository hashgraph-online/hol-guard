//! Content clearance for a recursive search that would reach a sensitive file.
//!
//! A content search prints only the lines that match its pattern, so a file
//! the pattern cannot match adds nothing to its output, whatever the file is
//! named. A recursive search of a repository root is held for a `.env.bak` or
//! a `.dev.vars` beside the code even when the pattern is a plain word that
//! none of those files contains. This module reads such a file locally, never
//! returns or logs a byte of it, and answers one question: does the pattern
//! provably not occur in it.
//!
//! Only a pattern made of plain characters and `|` alternatives is cleared.
//! Every dialect that could run it (`grep` basic or extended, ripgrep, Perl)
//! reads those characters the same way, and the check is deliberately wider
//! than any of them: it ignores case, lets `.` cross lines, and anchors
//! nothing. A pattern with an operator, a class, an escape, or an inverted
//! match is never cleared. A file that is large, not plain ASCII (binary,
//! UTF-16, Latin-1 or any other encoding a locale could read differently), a
//! key container, or inside a credential store is never cleared either, so
//! those keep the review.

use super::search::SECRET_EXTENSIONS;
use std::cell::Cell;
use std::io::Read;
use std::path::Path;

const MAX_PATTERN_BYTES: usize = 512;
const MAX_FILE_BYTES: u64 = 256 * 1024;
/// Content one search may read across every file it clears.
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FILES: usize = 64;
/// Directories that hold credential stores, never project files.
const STORE_DIRECTORIES: &[&str] = &[
    ".aws", ".ssh", ".gnupg", ".kube", ".docker", ".azure", ".gcloud", ".config", ".npm", ".git",
];
/// Sensitive families whose files are configuration with values in it. Key
/// material, password stores and credential caches stay out of this list.
const CLEARABLE_FAMILIES: &[&str] = &[
    "local .env file",
    "environment setup credentials",
    "authentication credentials",
    "npm registry credentials",
    "Python package credentials",
    "Terraform variable secrets",
];

/// A search pattern that is proven absent from the sensitive files a search
/// would reach.
pub(in crate::pretool) struct PatternClearance {
    matcher: regex::bytes::Regex,
    spent: Cell<u64>,
    files: Cell<usize>,
}

impl PatternClearance {
    /// `None` unless `pattern` is plain enough to read the same way in every
    /// search dialect.
    pub(in crate::pretool) fn new(pattern: &str) -> Option<Self> {
        if pattern.len() > MAX_PATTERN_BYTES || !plain_pattern(pattern) {
            return None;
        }
        let matcher = regex::bytes::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .multi_line(true)
            .dot_matches_new_line(true)
            .size_limit(1 << 20)
            .build()
            .ok()?;
        Some(Self {
            matcher,
            spent: Cell::new(0),
            files: Cell::new(0),
        })
    }

    /// Whether `path` is a regular file whose bytes the pattern cannot match.
    pub(in crate::pretool) fn clears(&self, path: &Path) -> bool {
        if !clearable_name(path) {
            return false;
        }
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return false;
        };
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
            return false;
        }
        // Past either budget the search keeps its review.
        self.files.set(self.files.get() + 1);
        self.spent.set(self.spent.get() + metadata.len());
        if self.files.get() > MAX_FILES || self.spent.get() > MAX_TOTAL_BYTES {
            return false;
        }
        let Ok(file) = std::fs::File::open(path) else {
            return false;
        };
        let mut bytes = Vec::new();
        if file
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_FILE_BYTES
        {
            return false;
        }
        // Only plain ASCII is read the same way by every host. Another byte
        // can be a character, a part of one, or a stray byte depending on the
        // locale and the decoder, and `.` then covers a different span than
        // this check's. A NUL byte, a UTF-16 mark and Latin-1 text all fall here.
        if !bytes.is_ascii() || bytes.contains(&0) {
            return false;
        }
        !self.matcher.is_match(&bytes)
    }

    /// Whether a walk that refused `path` by its name may go on: a file the
    /// pattern cannot match, or a directory searched below.
    pub(in crate::pretool) fn admits(&self, path: &Path, metadata: &std::fs::Metadata) -> bool {
        if metadata.is_file() {
            self.clears(path)
        } else {
            self.may_descend(path)
        }
    }

    /// Whether a hidden or sensitive-named directory may be searched below,
    /// each file in it clearing on its own.
    pub(in crate::pretool) fn may_descend(&self, path: &Path) -> bool {
        clearable_name(path)
            && std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir())
            && guard_secure_fs::sensitive_path_family(path).is_none()
    }
}

/// Plain characters only: words, digits, spaces, a little punctuation and `.`
/// (any character in every dialect), with `|` between non-empty alternatives.
fn plain_pattern(pattern: &str) -> bool {
    pattern.split('|').all(|alternative| {
        !alternative.is_empty()
            && alternative.chars().all(|character| {
                character.is_ascii_alphanumeric()
                    || matches!(
                        character,
                        '_' | '-'
                            | ' '
                            | ':'
                            | '/'
                            | '='
                            | '@'
                            | '#'
                            | '%'
                            | '~'
                            | ','
                            | '.'
                            | '!'
                            | '<'
                            | '>'
                            | '&'
                    )
            })
    })
}

/// A name whose content this clearance may read: not inside a credential
/// store, not a key container, not a sensitive family outside the
/// configuration list, and not named for the credentials it stores
/// (`credentials.json`, `secrets/db.json`). What stays is the hidden
/// configuration a project keeps beside its code, such as `.env.bak` or
/// `.dev.vars`.
fn clearable_name(path: &Path) -> bool {
    let in_store = path.components().any(|part| {
        part.as_os_str()
            .to_str()
            .is_none_or(|part| STORE_DIRECTORIES.contains(&part.to_ascii_lowercase().as_str()))
    });
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    !in_store
        && !SECRET_EXTENSIONS.contains(&extension.as_str())
        && match guard_secure_fs::sensitive_path_family(path) {
            Some((family, _)) => CLEARABLE_FAMILIES.contains(&family),
            None => !guard_secure_fs::credential_named_path(path),
        }
}

#[cfg(test)]
#[path = "search_pattern_clearance_tests.rs"]
mod tests;
