//! Reads one project file for the walk and keeps what it matched, and then
//! the files Git's search found holding the prompt's code names that the walk
//! did not reach. A large project has more files than the walk visits, so a
//! named constant or test deep in it was never read.
use super::finish::{finish, holds_word};
use super::{named_as, wanted_file, Seen, Walk, MAX_DEPTH, MAX_FILE_BYTES, SKIPPED_DIRS};
use crate::context_assistance_engine::prose;
use crate::context_assistance_prompt_ignore::{extend, ignored, Chain};
use crate::context_assistance_prompt_words::quoted;
use crate::context_assistance_prompt_words::{in_path, spelled, whole_word};
use guard_secure_fs::{credential_directory_path, credential_named_path};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

const MAX_SCANNED_BYTES: u64 = 12 * 1024 * 1024;
/// Files read from Git's search, at most.
const MAX_SEARCHED: usize = 16;

/// What the walk has read so far.
pub(super) struct Reading<'a> {
    terms: &'a [String],
    phrases: &'a [String],
    named: &'a [String],
    seen: Vec<Seen>,
    files: usize,
    scanned: u64,
    pub(super) complete: bool,
    spelled_in: Vec<usize>,
    held: Vec<(String, usize)>,
    read: HashSet<String>,
}

impl<'a> Reading<'a> {
    pub(super) fn new(
        terms: &'a [String],
        phrases: &'a [String],
        named: &'a [String],
        exact: &[String],
    ) -> Self {
        let mut held: Vec<(String, usize)> = Vec::new();
        for word in exact.iter().filter(|word| !word.is_empty()) {
            if !held.iter().any(|(known, _)| known == word) {
                held.push((word.clone(), 0));
            }
        }
        Self {
            terms,
            phrases,
            named,
            seen: Vec::new(),
            files: 0,
            scanned: 0,
            complete: true,
            spelled_in: vec![0; terms.len()],
            held,
            read: HashSet::new(),
        }
    }

    /// The walk's result; `stopped` when it ran out of time or visits.
    pub(super) fn finish(self, stopped: bool) -> Walk {
        let complete = self.complete && !stopped;
        let counts = (self.spelled_in, self.held, complete);
        finish(self.seen, self.files, self.terms, self.phrases, counts)
    }

    /// Reads the plain file at `path`, already checked to be one the walk may
    /// read, and keeps it when it matches the prompt.
    pub(super) fn file(&mut self, path: &Path, relative: String, metadata: Option<fs::Metadata>) {
        let size = metadata.as_ref().map_or(u64::MAX, fs::Metadata::len);
        if size == 0 || size > MAX_FILE_BYTES {
            self.complete &= size == 0;
            return;
        }
        self.files += 1;
        self.read.insert(relative.clone());
        let terms = self.terms;
        let in_path = in_path(&relative, terms);
        let mut text = None;
        self.complete &= self.scanned + size <= MAX_SCANNED_BYTES;
        if self.scanned + size <= MAX_SCANNED_BYTES {
            self.scanned += size;
            text = guard_secure_fs::read_bounded(path, MAX_FILE_BYTES as usize)
                .ok()
                .and_then(|read| String::from_utf8(read.bytes).ok());
            self.complete &= text.is_some();
        }
        // Read as written, as the rename list reads each file it lists.
        let text = text.unwrap_or_default();
        for (word, count) in &mut self.held {
            *count += usize::from(holds_word(&text, word));
        }
        let text = text.to_lowercase();
        let hits: Vec<u8> = terms
            .iter()
            .map(|term| text.matches(term.as_str()).take(8).count() as u8)
            .collect();
        let code = !prose(path);
        let whole: Vec<bool> = (terms.iter().zip(&hits))
            .map(|(term, &n)| code && n > 0 && whole_word(&text, term))
            .collect();
        for (count, holds) in self.spelled_in.iter_mut().zip(spelled(&text, terms, &hits)) {
            *count += usize::from(holds);
        }
        let quoted = quoted(&text, self.phrases);
        let named = named_as(&relative, self.named);
        if in_path.contains(&true)
            || hits.iter().any(|&n| n > 0)
            || quoted.contains(&true)
            || named.is_some()
        {
            self.seen.push(Seen {
                relative,
                modified: (metadata.and_then(|m| m.modified().ok()))
                    .unwrap_or(SystemTime::UNIX_EPOCH),
                in_path,
                hits,
                whole,
                quoted,
                named,
            });
        }
    }

    /// Reads `searched`, project-relative paths from Git's search, that the
    /// walk did not read, at most [`MAX_SEARCHED`] of them. Each passes the walk's own checks on the way down:
    /// no hidden, skipped, ignored or credential folder, no link, not too
    /// deep, and a wanted, non-credential, unignored file.
    pub(super) fn searched(&mut self, root: &Path, rules: &Chain, searched: &[String]) {
        let mut left = MAX_SEARCHED;
        for relative in searched {
            if left == 0 {
                break;
            }
            if self.read.contains(relative.as_str()) {
                continue;
            }
            left -= 1;
            if let Some(metadata) = admitted(root, rules, relative) {
                self.file(&root.join(relative), relative.clone(), Some(metadata));
            }
        }
    }
}

fn admitted(root: &Path, rules: &Chain, relative: &str) -> Option<fs::Metadata> {
    let parts: Vec<&str> = relative.split('/').collect();
    let (name, folders) = parts.split_last()?;
    if folders.len() > MAX_DEPTH
        || parts
            .iter()
            .any(|part| part.is_empty() || part.starts_with('.') || part.contains('\\'))
    {
        return None;
    }
    let mut rules = rules.clone();
    let mut at = String::new();
    for folder in folders {
        at = if at.is_empty() {
            (*folder).to_owned()
        } else {
            format!("{at}/{folder}")
        };
        let kind = fs::symlink_metadata(root.join(&at)).ok()?.file_type();
        if !kind.is_dir()
            || SKIPPED_DIRS.contains(folder)
            || credential_directory_path(Path::new(&at))
            || ignored(&rules, &at, true)
        {
            return None;
        }
        rules = extend(rules, &root.join(&at).join(".gitignore"), &at).ok()?;
    }
    let metadata = fs::symlink_metadata(root.join(relative)).ok()?;
    (metadata.file_type().is_file()
        && wanted_file(name)
        && !credential_named_path(Path::new(relative))
        && !ignored(&rules, relative, false))
    .then_some(metadata)
}

#[cfg(test)]
#[path = "context_assistance_prompt_files_read_tests.rs"]
mod tests;
