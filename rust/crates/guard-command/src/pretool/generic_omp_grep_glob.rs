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
        || !literal_groups_only(selector)
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

/// Whether every bracket class and parenthesised group in `selector` names
/// characters of one path segment and nothing more.
///
/// Next.js spells a dynamic route segment `[slug]` and a route group
/// `(group)`, so an ordinary project puts both in directory names that a
/// glob then walks through. A class of plain name characters can only ever
/// select a single character of one segment, which the fixed folder above the
/// first glob character already bounds. What this proof cannot accept is a
/// group that could synthesize a parent segment or a separator the literal
/// input does not show: a class holding a dot or a slash, a negated class, an
/// extended-glob group (`@(a|b)`) whose alternatives behave like a brace
/// expansion, or a brace expansion itself.
fn literal_groups_only(selector: &str) -> bool {
    if selector.contains(['{', '}', '|']) {
        return false;
    }
    let mut rest = selector;
    while let Some(index) = rest.find(['[', '(', ']', ')']) {
        let opener = rest.as_bytes()[index];
        let closer = match opener {
            b'[' => b']',
            b'(' => b')',
            // A closing character with no opener before it is not a group.
            _ => return false,
        };
        // An extended-glob group repeats or negates its alternatives, so the
        // character before `(` decides whether this is a plain parenthesis.
        if opener == b'('
            && matches!(
                rest[..index].chars().next_back(),
                Some('?' | '*' | '+' | '@' | '!')
            )
        {
            return false;
        }
        let after = &rest[index + 1..];
        let Some(end) = after.find(closer as char) else {
            return false;
        };
        let body = &after[..end];
        if body.is_empty()
            || body.contains(|c: char| {
                !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' ' | ','))
            })
        {
            return false;
        }
        // A hyphen between two class members is a glob range, not a literal.
        // A range such as [--0] includes '.' and '/', even though its written
        // endpoints are individually permitted above. Only same-kind ASCII
        // ranges can prove that every matched character stays in this segment.
        if opener == b'['
            && body.as_bytes().windows(3).any(|window| {
                window[1] == b'-'
                    && !((window[0].is_ascii_digit() && window[2].is_ascii_digit())
                        || (window[0].is_ascii_lowercase() && window[2].is_ascii_lowercase())
                        || (window[0].is_ascii_uppercase() && window[2].is_ascii_uppercase()))
            })
        {
            return false;
        }
        rest = &after[end + 1..];
    }
    true
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
    fn route_segment_directories_prove_their_fixed_directory() {
        // Next.js dynamic segments and route groups are ordinary directory
        // names an agent globs through every day.
        assert_eq!(glob_directory("app/items/[slug]/page.*"), Some("app/items"));
        assert_eq!(
            glob_directory("app/(group)/blog/*/page.tsx"),
            Some("app/(group)/blog")
        );
        assert_eq!(glob_directory("src/[abc]*.ts"), Some("src"));
        assert_eq!(glob_directory("src/[a-z]*.ts"), Some("src"));
        assert_eq!(glob_directory("src/[0-9]*.ts"), Some("src"));
        assert_eq!(glob_directory("src/[-a]*.ts"), Some("src"));
    }

    #[test]
    fn groups_that_could_name_another_directory_are_not_proven() {
        for escape in [
            // A class holding a dot or a separator can spell a parent segment.
            "app/[.][.]/*/secrets",
            "app/[/]etc/*",
            // Ranges can hide a dot or separator between innocent endpoints.
            "app/[--0][--0]/*",
            "app/[ -z]/*",
            "app/[A-z]/*",
            "app/[0-A]/*",
            // A negated class matches a leading dot the walk did not prove.
            "app/[!a]*/key",
            // Extended globs and brace expansions behave like alternatives.
            "app/@(one|two)/*.ts",
            "app/+(a)/*.ts",
            "app/{one,two}/*.ts",
            // An unbalanced or empty group is not a name.
            "app/[slug/*.ts",
            "app/[]/*.ts",
            "app/x]/*.ts",
        ] {
            assert_eq!(glob_directory(escape), None, "{escape:?}");
        }
    }

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
