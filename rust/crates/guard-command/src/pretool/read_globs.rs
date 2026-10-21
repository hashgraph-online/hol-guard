//! Shell-expanded file globs for plain readers (`cat`, `wc`, `head`, `base64`).
//!
//! `wc -l ~/code/api/contracts/*.json` names one directory and a pattern for
//! its last component. The shell expands the pattern before the reader
//! starts, so this proof expands it first and admits the word only when every
//! name it can produce is a regular file that clears the literal read proof.
//!
//! The model is deliberately a superset of what a shell matches: only `*` and
//! `?` are accepted, only in the last component (directory wildcards are
//! modelled only inside the harness homes, see `harness_globs`), matching
//! ignores ASCII case (`nocaseglob`), and a hidden entry the pattern would
//! match under `dotglob` sends the read to review instead of relying on the
//! shell default. Entries with non-ASCII names also send it to review,
//! because `?` matches a byte or a character depending on the locale. The
//! directory prefix stays in every expanded word, so no match can begin with
//! `-` and be read as an option.

use std::path::{Path, PathBuf};

#[path = "read_globs_harness.rs"]
mod harness_globs;

const MAX_ENTRIES: usize = 4_096;
const MAX_MATCHES: usize = 256;

/// True when `value` is `<directory>/<pattern>` and every name the shell can
/// expand it to is a bounded, non-sensitive regular file.
pub(super) fn bounded_glob_file_read_target(
    value: &str,
    context: super::super::PathContext<'_>,
) -> bool {
    glob_file_matches(value, context).is_some()
}

/// The words the shell passes on for `value`, each `<directory>/<name>`,
/// when every one of them clears the proof above; `None` otherwise.
pub(in crate::pretool) fn glob_file_matches(
    value: &str,
    context: super::super::PathContext<'_>,
) -> Option<Vec<String>> {
    let (directory, pattern) = value.rsplit_once('/')?;
    if directory.contains(['*', '?']) {
        return harness_globs::harness_directory_glob_matches(value, context);
    }
    if directory.is_empty()
        || directory.starts_with('-')
        || directory.contains(['*', '?', '[', ']', '{', '}', '\\'])
        || !literal_pattern(pattern)
        || !super::verified_path_context(context.home_dir, context.cwd)
        || !super::bounded_read_target(directory, context.home_dir, context.cwd, true)
    {
        return None;
    }
    let base = directory_path(directory, context)?;
    let entries = std::fs::read_dir(&base).ok()?;
    let mut matches = Vec::new();
    for (inspected, entry) in entries.enumerate() {
        if inspected >= MAX_ENTRIES {
            return None;
        }
        let name = entry.ok()?.file_name();
        let name = name.to_str()?;
        if !name.is_ascii() {
            return None;
        }
        if !wildcard_matches(pattern.as_bytes(), name.as_bytes()) {
            continue;
        }
        if matches.len() >= MAX_MATCHES || !readable_match(directory, name, &base, context) {
            return None;
        }
        matches.push(format!("{directory}/{name}"));
    }
    (!matches.is_empty()).then_some(matches)
}

/// A last component holding `*` or `?` and otherwise only plain filename
/// characters. Brackets, braces, `**` and every zsh extended-glob character
/// stay out, as does a pattern that names hidden files on purpose.
fn literal_pattern(pattern: &str) -> bool {
    pattern.contains(['*', '?']) && plain_component(pattern)
}

/// One visible path component of plain filename characters, optionally
/// holding `*` or `?` but never `**`.
fn plain_component(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= 255
        && !component.contains("**")
        && !component.starts_with('.')
        && component.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'*' | b'?' | b'.' | b'_' | b'-' | b'+' | b'@' | b',')
        })
}

fn directory_path(directory: &str, context: super::super::PathContext<'_>) -> Option<PathBuf> {
    let expanded = if directory.starts_with('~') {
        super::super::read_paths::expand_home_read_path(directory, context.home_dir)?
    } else {
        directory.to_owned()
    };
    if Path::new(&expanded).is_absolute() {
        return Some(PathBuf::from(expanded));
    }
    let cwd = context.cwd?;
    let root = super::super::read_paths::expand_home_read_path(cwd, context.home_dir)
        .unwrap_or_else(|| cwd.to_owned());
    Path::new(&root)
        .is_absolute()
        .then(|| Path::new(&root).join(expanded))
}

/// A match is admitted exactly as the literal word the shell passes on.
fn readable_match(
    directory: &str,
    name: &str,
    base: &Path,
    context: super::super::PathContext<'_>,
) -> bool {
    if name.starts_with('.') {
        return false;
    }
    // A name holding whitespace is one word to the shell that expanded the
    // pattern, but several arguments once that word passes through an
    // unquoted expansion: `for f in src/*-n; do cat $f; done` reads
    // `src/public -n` here and runs `cat src/public -n`. The two are not the
    // same read, so a directory holding such a name keeps its review.
    if name.contains(char::is_whitespace) {
        return false;
    }
    // The same unquoted expansion is a pathname expansion as well: a matched
    // name that holds a glob character is a pattern once it passes through
    // `$f`, and the shell then reads whatever that pattern matches. A decoy
    // `x[.]pem` beside `x.pem` matches `src/x?.?pem` here with the harmless
    // extension `]pem`, but `cat $f` expands it back to `src/x.pem`. A name a
    // second expansion could rewrite keeps its review.
    if name.contains(['*', '?', '[', ']', '\\']) {
        return false;
    }
    let extension = Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let word = format!("{directory}/{name}");
    !super::super::search::SECRET_EXTENSIONS.contains(&extension.as_str())
        && !guard_secure_fs::credential_named_path(Path::new(name))
        && std::fs::symlink_metadata(base.join(name)).is_ok_and(|metadata| !metadata.is_dir())
        && super::bounded_read_target(&word, context.home_dir, context.cwd, false)
}

/// `*` and `?` over ASCII names, ignoring case.
fn wildcard_matches(pattern: &[u8], name: &[u8]) -> bool {
    let mut previous = vec![false; name.len() + 1];
    previous[0] = true;
    for &token in pattern {
        let mut current = vec![false; name.len() + 1];
        if token == b'*' {
            current[0] = previous[0];
            for index in 1..=name.len() {
                current[index] = previous[index] || current[index - 1];
            }
        } else {
            for index in 1..=name.len() {
                current[index] = previous[index - 1]
                    && (token == b'?' || token.eq_ignore_ascii_case(&name[index - 1]));
            }
        }
        previous = current;
    }
    previous[name.len()]
}

#[cfg(test)]
#[path = "read_globs_tests.rs"]
mod tests;
