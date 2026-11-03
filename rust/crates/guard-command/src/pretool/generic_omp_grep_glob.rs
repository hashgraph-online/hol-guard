//! Oh My Pi `glob` and `grep` accept a glob in `path`. The host walks only
//! below the folder before the first glob character, so that folder bounds
//! everything the selector can reach.

use super::contained_selector;
use crate::pretool::search_pattern_clearance::PatternClearance;
use crate::pretool::search_scope::{omp_glob_scope_proven, omp_grep_scope_proven};
use std::cell::RefCell;

/// The fixed folder a simple glob walks below; `None` for a selector whose
/// alternatives, classes or escapes could name a path outside it.
pub(super) fn glob_directory(target: &str) -> Option<&str> {
    let Some(index) = target.find(['*', '?', '[', '{']) else {
        return Some(target);
    };
    // A Windows drive root (`C:/` or, on Windows, `C:\`) anchors the
    // selector like `/` does. On Windows a backslash is a separator there,
    // never a glob escape.
    let drive = matches!(
        target.as_bytes(),
        [letter, b':', b'/', ..] if letter.is_ascii_alphabetic()
    ) || (cfg!(windows)
        && matches!(
            target.as_bytes(),
            [letter, b':', b'\\', ..] if letter.is_ascii_alphabetic()
        ));
    let selector = if drive {
        &target[3..]
    } else {
        target
            .strip_prefix("~/")
            .or_else(|| target.strip_prefix('/'))
            .unwrap_or(target)
    };
    let separators: &[char] = if drive && cfg!(windows) {
        &['/', '\\']
    } else {
        &['/']
    };
    // Restrict this proof to simple globs. Alternatives and escaped syntax can
    // synthesize traversal segments that are absent from the literal input.
    if !contained_selector(selector)
        || target.starts_with("//")
        || selector.contains("..")
        || selector.contains(|c: char| c == '\\' && !separators.contains(&c))
        || selector.contains(['[', ']', '{', '}', '(', ')'])
        // A colon after a drive names an alternate data stream.
        || (drive && selector.contains(':'))
    {
        return None;
    }
    let prefix = &target[..index];
    match prefix.rsplit_once(separators) {
        Some(("", _)) => Some("/"),
        Some((root, _)) if drive && root.len() == 2 => Some(&target[..3]),
        Some((directory, _)) => Some(directory),
        None => Some("."),
    }
}

/// The proof of each glob entry's fixed folder within one `grep` call, so
/// entries that share a folder, and the missing-path pass after the first,
/// walk it once.
#[derive(Default)]
pub(super) struct EntryProofs(RefCell<Vec<(String, bool)>>);

impl EntryProofs {
    /// A `grep` path entry with a glob searches a subset of the files below
    /// its fixed folder. It is proven when a search of that whole folder
    /// would be, with no ignore file narrowing it, and no link below the
    /// folder leads to anything that walk did not prove. The glob itself only
    /// narrows the search further, so whatever files it selects are covered.
    pub(super) fn proven(
        &self,
        entry: &str,
        home_dir: Option<&str>,
        cwd: Option<&str>,
        clearance: Option<&PatternClearance>,
    ) -> bool {
        if !entry.contains(['*', '?', '[', '{']) {
            return false;
        }
        let Some(directory) = glob_directory(entry) else {
            return false;
        };
        let known = self
            .0
            .borrow()
            .iter()
            .find(|(folder, _)| folder == directory)
            .map(|(_, proven)| *proven);
        known.unwrap_or_else(|| {
            let proven = omp_grep_scope_proven(directory, home_dir, cwd, false, clearance)
                && omp_glob_scope_proven(directory, home_dir, cwd, false);
            self.0.borrow_mut().push((directory.to_owned(), proven));
            proven
        })
    }
}

#[cfg(test)]
mod tests {
    use super::glob_directory;

    #[test]
    fn drive_rooted_globs_prove_their_fixed_directory() {
        assert_eq!(
            glob_directory("C:/Users/x/.agent/skills/**/SKILL.md"),
            Some("C:/Users/x/.agent/skills")
        );
        assert_eq!(glob_directory("C:/*.md"), Some("C:/"));
        assert_eq!(
            glob_directory(r"C:\Users\x\.agent\skills\**\SKILL.md"),
            cfg!(windows).then_some(r"C:\Users\x\.agent\skills")
        );
        for escape in [
            "C:/Users/x/**/../../.ssh/*",
            "C:/Users/x/{a,..}/*",
            "C:*.md",
            "C:/Users/x:stream/*",
            r"\\?\C:\Users\x\*",
        ] {
            assert_eq!(glob_directory(escape), None, "{escape:?}");
        }
        // A backslash escapes the star on Unix and separates on Windows.
        assert_eq!(
            glob_directory(r"C:/Users/x/\*/*"),
            cfg!(windows).then_some("C:/Users/x/")
        );
    }
}
