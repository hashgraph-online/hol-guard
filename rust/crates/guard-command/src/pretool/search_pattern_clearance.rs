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
//! nothing. Two escapes are read too, each more widely than any dialect does:
//! `\|` is an alternative in basic `grep` and a literal `|` everywhere else,
//! and every alternative is a part of that literal; `\.` is one literal dot
//! to a regex and two characters to `grep -F`, so it is checked as one or two
//! of any character. Several `-e` patterns are checked as alternatives of one.
//! A pattern with an operator, a class, another escape, or an inverted match
//! is never cleared. A file that is large, not plain ASCII (binary,
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
        Self::any(std::slice::from_ref(&pattern))
    }

    /// `None` unless every pattern is plain; a line matching any of them
    /// is printed, as with `grep -e a -e b`.
    pub(in crate::pretool) fn any<P: AsRef<str>>(patterns: &[P]) -> Option<Self> {
        let source: usize = patterns.iter().map(|pattern| pattern.as_ref().len()).sum();
        if patterns.is_empty() || source > MAX_PATTERN_BYTES {
            return None;
        }
        let readings = patterns
            .iter()
            .map(|pattern| wide_reading(pattern.as_ref()))
            .collect::<Option<Vec<_>>>()?;
        let matcher = regex::bytes::RegexBuilder::new(&readings.join("|"))
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

    /// The expression this clearance matches with: two clearances that share
    /// it clear the same files, so a walk can be remembered under it.
    pub(in crate::pretool) fn expression(&self) -> &str {
        self.matcher.as_str()
    }

    /// The bytes and files this clearance has read so far. A walk that starts
    /// from other counts can stop at another file, so a remembered walk is
    /// keyed by them.
    pub(in crate::pretool) fn charged(&self) -> (u64, u64) {
        (
            self.spent.get(),
            u64::try_from(self.files.get()).unwrap_or(u64::MAX),
        )
    }

    /// Leave the counters where a remembered walk left them, so the walks
    /// after it get no more than they would have had.
    pub(in crate::pretool) fn recharge(&self, spent: u64, files: u64) {
        self.spent.set(spent);
        self.files.set(usize::try_from(files).unwrap_or(usize::MAX));
    }

    /// Whether `path` is a regular file whose bytes the pattern cannot match.
    pub(in crate::pretool) fn clears(&self, path: &Path) -> bool {
        clearable_name(path, false) && self.clears_bytes(path)
    }

    /// [`Self::clears`] for a committed manifest the walk holds for the
    /// Kubernetes `Secret` it declares rather than for its name. A credential
    /// word in the name (`app-secrets.yaml`) describes that object, so only
    /// the store, extension and family rules apply: a pattern that cannot
    /// occur in the manifest prints none of its values.
    pub(in crate::pretool) fn clears_secret_manifest(&self, path: &Path) -> bool {
        clearable_name(path, true) && self.clears_bytes(path)
    }

    fn clears_bytes(&self, path: &Path) -> bool {
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
        clearable_name(path, false)
            && std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir())
            && guard_secure_fs::sensitive_path_family(path).is_none()
    }
}

/// The regex this check runs for `pattern`, or `None` unless the pattern is
/// plain: words, digits, spaces, a little punctuation and `.` (any character
/// in every dialect), with `|` or `\|` between non-empty alternatives and
/// `\.` read as one or two of any character.
fn wide_reading(pattern: &str) -> Option<String> {
    let mut alternatives = vec![String::new()];
    let mut characters = pattern.chars();
    while let Some(character) = characters.next() {
        let current = alternatives.last_mut()?;
        match character {
            '|' => alternatives.push(String::new()),
            '\\' => match characters.next()? {
                '|' => alternatives.push(String::new()),
                '.' => current.push_str("..?"),
                _ => return None,
            },
            character if plain_character(character) => current.push(character),
            _ => return None,
        }
    }
    alternatives
        .iter()
        .all(|alternative| !alternative.is_empty())
        .then(|| alternatives.join("|"))
}

fn plain_character(character: char) -> bool {
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
}

/// A name whose content this clearance may read: not inside a credential
/// store, not a key container, not a sensitive family outside the
/// configuration list, and not named for the credentials it stores
/// (`credentials.json`, `secrets/db.json`). What stays is the hidden
/// configuration a project keeps beside its code, such as `.env.bak` or
/// `.dev.vars`.
fn clearable_name(path: &Path, manifest: bool) -> bool {
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
            None => manifest || !guard_secure_fs::credential_named_path(path),
        }
}

#[cfg(test)]
#[path = "search_pattern_clearance_tests.rs"]
mod tests;
