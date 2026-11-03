//! Whether a conditional include in the session's effective Git
//! configuration could reach a repository that does not exist yet.
//!
//! `git init` and a local `git clone` build a repository from the
//! configuration the session's Git reads, so an `includeIf` that brought in
//! `init.templateDir` would hand the new repository hooks a later command
//! there would run. Developers routinely keep one `includeIf "gitdir:..."`
//! in their global configuration to carry a work identity, and Git applies
//! it only to repositories below the directory it names. A condition whose
//! literal prefix cannot stand at the front of the new repository's Git
//! directory never reaches it, so it leaves the command where it stands.

use std::path::Path;

/// Whether the conditional include that the effective-configuration key
/// `key` names could apply to a repository whose Git directory will be
/// `git_dir`. Only a `gitdir:` condition with a literal, absolute head is
/// decided; every other condition, and every pattern this reader does not
/// resolve, could apply.
pub(in crate::pretool) fn could_apply(key: &str, git_dir: &Path, home: Option<&str>) -> bool {
    const PREFIX: &str = "includeif.";
    if !key
        .get(..PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(PREFIX))
    {
        return false;
    }
    let Some(condition) = condition(&key[PREFIX.len()..]) else {
        return true;
    };
    let Some(pattern) = gitdir_pattern(condition) else {
        return true;
    };
    let Some(resolved) = resolve(pattern, home) else {
        return true;
    };
    // Matching stops at the first wildcard: whatever follows it, the
    // characters before it must stand literally at the front of the path
    // Git compares. `**` is a wildcard too, so a pattern that could match
    // anywhere keeps its head empty and stays under review.
    let literal = &resolved[..resolved.find(['*', '?', '[']).unwrap_or(resolved.len())];
    let git_dir = fold(git_dir.to_string_lossy().as_ref());
    git_dir.starts_with(&fold(literal))
        || resolved_head(literal).is_some_and(|head| git_dir.starts_with(&fold(&head)))
}

/// `literal` with every link on the way resolved, or `None` when nothing of
/// it exists. Git compares the pattern with the repository's real path first
/// and with its absolute spelling second, and never resolves the pattern
/// itself, so a head spelled through a link - `/tmp` on macOS, a home
/// directory kept on another volume - still reaches a Git directory whose
/// canonical path looks nothing like it. The caller holds the canonical path,
/// so resolving the head brings the two spellings back together. The head may
/// name a directory that does not exist yet, so the longest existing ancestor
/// is resolved and the rest kept as spelled.
fn resolved_head(literal: &str) -> Option<String> {
    let mut existing = Path::new(literal);
    let mut missing = Vec::new();
    loop {
        if let Ok(resolved) = std::fs::canonicalize(existing) {
            let mut head = crate::runtime_read_paths::strip_verbatim_prefix(resolved);
            for component in missing.iter().rev() {
                head.push(component);
            }
            return Some(head.to_string_lossy().into_owned());
        }
        missing.push(existing.file_name()?.to_owned());
        existing = existing.parent()?;
    }
}

/// The condition of `<condition>.path`, the rest of an `includeIf` key, or
/// `None` for a conditional include this reader cannot read. Git lowercases
/// the section name and the condition with it, so every comparison here
/// folds case.
fn condition(rest: &str) -> Option<&str> {
    let (condition, name) = rest.rsplit_once('.')?;
    (name.eq_ignore_ascii_case("path") && !condition.is_empty()).then_some(condition)
}

/// The pattern of a `gitdir:` or `gitdir/i:` condition. Every other
/// condition - `onbranch:`, `hasconfig:` and anything Git adds - is `None`.
fn gitdir_pattern(condition: &str) -> Option<&str> {
    condition
        .strip_prefix("gitdir:")
        .or_else(|| condition.strip_prefix("gitdir/i:"))
        .filter(|pattern| !pattern.is_empty())
}

/// `pattern` as the absolute path Git compares, or `None` for a form this
/// reader does not resolve: an escape, a `~user` home, a value relative to
/// the file that wrote it, and a bare name, which Git reads as `**/<name>`
/// and so could stand anywhere.
fn resolve(pattern: &str, home: Option<&str>) -> Option<String> {
    if pattern.contains('\\') {
        return None;
    }
    if let Some(rest) = pattern.strip_prefix("~/") {
        let home = home?.trim_end_matches('/');
        return Some(format!("{home}/{rest}"));
    }
    (pattern.starts_with('/') && !pattern.starts_with("//")).then(|| pattern.to_owned())
}

/// The macOS and Windows volumes Git runs on fold case, and `gitdir/i`
/// folds it everywhere, so every comparison here does.
fn fold(value: &str) -> String {
    value.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::could_apply;
    use std::path::Path;

    const HOME: Option<&str> = Some("/Users/dev");

    #[test]
    fn a_work_identity_include_leaves_a_scratch_repository_alone() {
        assert!(!could_apply(
            "includeif.gitdir:~/Code/work/.path",
            Path::new("/private/tmp/scratch/.git"),
            HOME,
        ));
        assert!(!could_apply(
            "includeif.gitdir:/Users/dev/Code/work/.path",
            Path::new("/private/tmp/scratch/.git"),
            HOME,
        ));
    }

    #[test]
    fn an_include_over_the_new_repository_applies() {
        assert!(could_apply(
            "includeif.gitdir:/private/tmp/.path",
            Path::new("/private/tmp/scratch/.git"),
            HOME,
        ));
        assert!(could_apply(
            "includeif.gitdir:~/Code/work/.path",
            Path::new("/Users/dev/Code/work/app/.git"),
            HOME,
        ));
    }

    #[test]
    fn case_never_decides_the_answer() {
        assert!(could_apply(
            "includeif.gitdir/i:/Private/TMP/.path",
            Path::new("/private/tmp/scratch/.git"),
            HOME,
        ));
    }

    #[test]
    fn an_unresolved_pattern_or_condition_applies() {
        for key in [
            "includeif.onbranch:main.path",
            "includeif.hasconfig:remote.*.url:https://example.invalid/.path",
            "includeif.gitdir:work/.path",
            "includeif.gitdir:./sibling/.path",
            "includeif.gitdir:~other/work/.path",
            "includeif.gitdir:~/Code/wo\\rk/.path",
            "includeif.gitdir:.path",
            "includeif.gitdir:/Users/dev/Code/work/",
        ] {
            assert!(
                could_apply(key, Path::new("/private/tmp/scratch/.git"), HOME),
                "{key}"
            );
        }
    }

    #[test]
    fn a_wildcard_head_still_rules_a_distant_path_out() {
        assert!(!could_apply(
            "includeif.gitdir:/Users/dev/Code/*/app/.path",
            Path::new("/private/tmp/scratch/.git"),
            HOME,
        ));
        assert!(could_apply(
            "includeif.gitdir:/Users/dev/Code/*/app/.path",
            Path::new("/Users/dev/Code/work/app/.git"),
            HOME,
        ));
    }

    /// macOS reaches the shared temporary directory through a link, so the
    /// Git directory the caller holds is canonical while the pattern the user
    /// wrote is not. Git matches the spelling, and so must this.
    #[cfg(unix)]
    #[test]
    fn a_pattern_spelled_through_a_link_still_applies() {
        let root = std::env::temp_dir().join(format!(
            "guard-include-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let real = root.join("real");
        std::fs::create_dir_all(&real).expect("real");
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("link");
        let canonical = std::fs::canonicalize(&real).expect("canonical");
        let key = format!("includeif.gitdir:{}/.path", link.display());
        assert!(could_apply(&key, &canonical.join("app/.git"), HOME));
        let distant = std::fs::canonicalize(std::env::temp_dir()).expect("temp");
        assert!(!could_apply(&key, &distant.join("elsewhere/.git"), HOME));
        std::fs::remove_dir_all(&root).expect("clean");
    }

    #[test]
    fn an_ordinary_setting_is_not_a_conditional_include() {
        for key in [
            "init.templatedir",
            "include.path",
            "core.hookspath",
            "includeif",
        ] {
            assert!(
                !could_apply(key, Path::new("/private/tmp/scratch/.git"), HOME),
                "{key}"
            );
        }
    }

    #[test]
    fn a_home_relative_pattern_needs_a_home() {
        assert!(could_apply(
            "includeif.gitdir:~/Code/work/.path",
            Path::new("/private/tmp/scratch/.git"),
            None,
        ));
    }
}
