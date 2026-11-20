//! The names a shell hands a command after it expands a pattern. `cp -r
//! src/* dist/` reaches `cp` as one argument per matching entry, so a scan
//! that reads the pattern instead of the entries cannot tell which files the
//! copy writes. These expand the pattern against the same directory the shell
//! would, and decline whenever the expansion is not the whole story.

use std::path::Path;

/// The entries one argument may name. A copy over more than this is no longer
/// the small edit workspace containment is for.
const MAX_MATCHES: usize = 512;

/// How many directory entries one argument's expansion may read. The match
/// limit above counts only the names a pattern keeps, and a pattern that
/// keeps none still reads every name beside it. A workspace directory can
/// hold far more entries than that, and the answer is wanted before the
/// command runs.
const MAX_INSPECTED: usize = 4096;

/// Characters a pattern may hold. Anything else the shell rewrites — a
/// variable, a command substitution, a brace list or an escape — leaves this
/// scan reading text the command never receives.
fn expandable(value: &str) -> bool {
    !value
        .chars()
        .any(|c| matches!(c, '$' | '`' | '{' | '}' | '\\' | '~'))
}

/// Whether the shell expands `value` by reading a directory.
pub(super) fn pattern(value: &str) -> bool {
    value.chars().any(|c| matches!(c, '*' | '?' | '['))
}

/// The arguments the command receives, with every pattern replaced by the
/// entries it names. `None` when any argument names something this scan
/// cannot resolve, which keeps the caller's refusal.
pub(super) fn expand_arguments(arguments: &[String], root: &Path) -> Option<Vec<String>> {
    if !arguments.iter().all(|argument| expandable(argument)) {
        return None;
    }
    if !arguments.iter().any(|argument| pattern(argument)) {
        return Some(arguments.to_vec());
    }
    if !root.is_absolute() {
        return None;
    }
    let mut expanded = Vec::new();
    for argument in arguments {
        if !pattern(argument) {
            expanded.push(argument.clone());
            continue;
        }
        if argument.starts_with('/') {
            return None;
        }
        let matches = expand(argument, root)?;
        if expanded.len().checked_add(matches.len())? > MAX_MATCHES {
            return None;
        }
        expanded.extend(matches);
    }
    Some(expanded)
}

/// The workspace-relative names `pattern` matches, in the order the shell
/// hands them over. `None` when the pattern matches nothing, because the
/// shell then passes the pattern itself and the command reads a name that is
/// not on disk.
fn expand(pattern: &str, root: &Path) -> Option<Vec<String>> {
    let directories_only = pattern.ends_with('/');
    let mut matches = vec![String::new()];
    let mut inspected = 0;
    for component in pattern.trim_end_matches('/').split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return None;
        }
        matches = step(component, &matches, root, &mut inspected)?;
        if matches.len() > MAX_MATCHES {
            return None;
        }
    }
    matches.retain(|found| !directories_only || root.join(found).is_dir());
    let mut matches: Vec<String> = matches
        .into_iter()
        .map(|found| {
            if directories_only {
                format!("{found}/")
            } else {
                found
            }
        })
        .collect();
    matches.sort();
    (!matches.is_empty()).then_some(matches)
}

/// Every name one component matches under the directories matched so far.
fn step(
    component: &str,
    prefixes: &[String],
    root: &Path,
    inspected: &mut usize,
) -> Option<Vec<String>> {
    if !self::pattern(component) {
        return Some(
            prefixes
                .iter()
                .map(|prefix| join(prefix, component))
                .collect(),
        );
    }
    let hidden = component.starts_with('.');
    let mut matches = Vec::new();
    for prefix in prefixes {
        let directory = if prefix.is_empty() {
            root.to_path_buf()
        } else {
            root.join(prefix)
        };
        // A directory that is not there matches nothing; one this scan cannot
        // read leaves the expansion unknown.
        if !directory.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(&directory).ok()? {
            *inspected += 1;
            if *inspected > MAX_INSPECTED {
                return None;
            }
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            if (name.starts_with('.') && !hidden) || !matches_component(component, name) {
                continue;
            }
            matches.push(join(prefix, name));
            if matches.len() > MAX_MATCHES {
                return None;
            }
        }
    }
    Some(matches)
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    }
}

/// Whether one path component matches one entry name. `*` and `?` stop at the
/// separator because each component is matched on its own. A bracket this
/// does not model matches no name at all, which leaves the expansion empty
/// and so declines.
fn matches_component(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    if !brackets_modeled(&pattern) {
        return false;
    }
    glob_match(&pattern, &name.chars().collect::<Vec<char>>())
}

/// Whether every bracket expression in the pattern is one this reads.
fn brackets_modeled(pattern: &[char]) -> bool {
    let mut index = 0;
    while index < pattern.len() {
        if pattern[index] != '[' {
            index += 1;
            continue;
        }
        match bracket(&pattern[index..]) {
            Some((_, length)) => index += length,
            None => return false,
        }
    }
    true
}

/// Matches left to right, returning to the last `*` on a mismatch rather than
/// recursing. Each return hands that `*` one more character of the name, so
/// the work is bounded by the two lengths instead of by the number of ways
/// several stars could divide the name between them.
fn glob_match(pattern: &[char], name: &[char]) -> bool {
    let (mut index, mut at) = (0, 0);
    // Where the last `*` stands, and how much of the name it has taken.
    let mut star: Option<(usize, usize)> = None;
    while at < name.len() {
        let matched = match pattern.get(index) {
            Some('*') => {
                star = Some((index, at));
                index += 1;
                continue;
            }
            Some('?') => true,
            Some('[') => match bracket(&pattern[index..]) {
                Some((set, length)) if in_set(&set, name[at]) => {
                    index += length;
                    at += 1;
                    continue;
                }
                _ => false,
            },
            Some(&literal) => literal == name[at],
            None => false,
        };
        if matched {
            index += 1;
            at += 1;
            continue;
        }
        let Some((star_index, taken)) = star else {
            return false;
        };
        star = Some((star_index, taken + 1));
        index = star_index + 1;
        at = taken + 1;
    }
    pattern[index..].iter().all(|&current| current == '*')
}

/// The characters a bracket expression holds, and how much of the pattern it
/// spans. `None` for a bracket this does not read: one the pattern never
/// closes, a POSIX class, collating symbol or equivalence class, whose
/// members are not the characters written between the brackets, or a range,
/// whose members the shell takes from the locale's collation order rather
/// than from the two characters' own order.
fn bracket(pattern: &[char]) -> Option<(Vec<char>, usize)> {
    let mut index = 1;
    if matches!(pattern.get(index), Some('!' | '^')) {
        index += 1;
    }
    // A `]` first in the set is the character itself, not the end.
    if pattern.get(index) == Some(&']') {
        index += 1;
    }
    while pattern.get(index).is_some_and(|c| *c != ']') {
        if pattern[index] == '[' && matches!(pattern.get(index + 1), Some(':' | '.' | '=')) {
            return None;
        }
        if pattern[index] == '-' && !matches!(pattern.get(index + 1), Some(']') | None) {
            return None;
        }
        index += 1;
    }
    if pattern.get(index) != Some(&']') {
        return None;
    }
    Some((pattern[..=index].to_vec(), index + 1))
}

/// Whether the set names this character. Every member is written out, since
/// `bracket` declines the forms that are not.
fn in_set(set: &[char], value: char) -> bool {
    let negated = matches!(set.get(1), Some('!' | '^'));
    let body = &set[1 + usize::from(negated)..set.len() - 1];
    body.contains(&value) != negated
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    struct Workspace(std::path::PathBuf);

    impl Drop for Workspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn workspace() -> Workspace {
        let root = std::env::temp_dir().join(format!(
            "guard-glob-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos(),
        ));
        std::fs::create_dir_all(root.join("src/nested")).unwrap();
        std::fs::create_dir(root.join("dist")).unwrap();
        for name in ["a.ts", "b.ts", "c.js"] {
            std::fs::write(root.join("src").join(name), b"x").unwrap();
        }
        std::fs::write(root.join("src/.hidden"), b"x").unwrap();
        // A digit class and a name the unclosed reading of it would match.
        std::fs::create_dir(root.join("classes")).unwrap();
        std::fs::write(root.join("classes/5"), b"x").unwrap();
        std::fs::write(root.join("classes/d]"), b"x").unwrap();
        Workspace(root)
    }

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().copied().map(str::to_owned).collect()
    }

    #[test]
    fn a_pattern_becomes_the_entries_the_shell_would_pass() {
        let root = workspace();
        assert_eq!(
            expand_arguments(&arguments(&["-r", "src/*", "dist/"]), &root.0),
            Some(arguments(&[
                "-r",
                "src/a.ts",
                "src/b.ts",
                "src/c.js",
                "src/nested",
                "dist/"
            ]))
        );
        assert_eq!(
            expand_arguments(&arguments(&["src/*.ts", "dist"]), &root.0),
            Some(arguments(&["src/a.ts", "src/b.ts", "dist"]))
        );
        assert_eq!(
            expand_arguments(&arguments(&["src/?.js", "dist"]), &root.0),
            Some(arguments(&["src/c.js", "dist"]))
        );
        assert_eq!(
            expand_arguments(&arguments(&["src/[ab].ts", "dist"]), &root.0),
            Some(arguments(&["src/a.ts", "src/b.ts", "dist"]))
        );
        assert_eq!(
            expand_arguments(&arguments(&["src/[!a]*.ts", "dist"]), &root.0),
            Some(arguments(&["src/b.ts", "dist"]))
        );
        // Only a pattern that asks for them matches a dot file, and a trailing
        // slash keeps directories alone.
        assert_eq!(
            expand_arguments(&arguments(&["src/.*", "dist"]), &root.0),
            Some(arguments(&["src/.hidden", "dist"]))
        );
        assert_eq!(
            expand_arguments(&arguments(&["src/*/", "dist"]), &root.0),
            Some(arguments(&["src/nested/", "dist"]))
        );
        // Several stars in one component still match what the shell matches.
        assert_eq!(
            expand_arguments(&arguments(&["src/*a*s", "dist"]), &root.0),
            Some(arguments(&["src/a.ts", "dist"]))
        );
    }

    #[test]
    fn an_expansion_this_scan_cannot_read_stays_unknown() {
        let root = workspace();
        for argument in [
            // Nothing on disk, so the command receives the pattern itself.
            "src/*.rs",
            "missing/*",
            // Text the shell rewrites before it expands a pattern.
            "$DIR/*",
            "`ls`/*",
            "{src,dist}/*",
            "src/\\*",
            "~/src/*",
            // Outside the directory the expansion is read from.
            "/etc/*",
            "../*",
            "src/../*",
            // A bracket the pattern never closes.
            "src/[ab.ts",
            // A character class, whose members are not the characters
            // written between the brackets. Reading it as a plain set would
            // match `classes/d]` while the shell matches `classes/5`.
            "classes/[[:digit:]]",
            // A range's members come from the locale's collation order.
            "classes/[0-9]",
            // Stars enough to make a backtracking matcher count the ways
            // they could divide a name, against a suffix no name carries.
            "src/*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*.zz",
        ] {
            assert_eq!(
                expand_arguments(&arguments(&[argument, "dist"]), &root.0),
                None,
                "{argument}"
            );
        }
        assert_eq!(
            expand_arguments(&arguments(&["src", "dist"]), &root.0),
            Some(arguments(&["src", "dist"]))
        );
    }

    #[test]
    fn a_pattern_that_reads_too_many_entries_stays_unknown() {
        // The match limit counts the names a pattern keeps. One that keeps
        // none still reads the whole directory, and the answer is wanted
        // before the command runs.
        let root = workspace();
        let wide = root.0.join("wide");
        std::fs::create_dir(&wide).unwrap();
        for index in 0..=MAX_INSPECTED {
            std::fs::write(wide.join(format!("f{index}")), b"x").unwrap();
        }
        assert_eq!(
            expand_arguments(&arguments(&["wide/*.none", "dist"]), &root.0),
            None
        );
    }

    #[test]
    fn a_pattern_over_too_many_entries_stays_unknown() {
        let root = workspace();
        let many = root.0.join("many");
        std::fs::create_dir(&many).unwrap();
        for index in 0..=MAX_MATCHES {
            std::fs::write(many.join(format!("f{index}")), b"x").unwrap();
        }
        assert_eq!(
            expand_arguments(&arguments(&["many/*", "dist"]), &root.0),
            None
        );
    }
}
