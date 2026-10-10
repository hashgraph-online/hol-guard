//! Directory targets for `cd` and `git -C`.
//!
//! Windows agents run POSIX commands through a shell that drops an unquoted
//! backslash, while the Windows parser keeps it. A drive path is therefore
//! proved only when every backslash in its segment survives the shell, and
//! only in the exact spelling of its canonical path.

pub(crate) fn safe_directory_target(target: &str) -> bool {
    // Windows spells an absolute directory with backslash separators. Check
    // a drive-absolute target in its forward-slash form; a backslash anywhere
    // else may be a shell escape and stays rejected.
    #[cfg(windows)]
    if let Some(target) = windows_drive_target(target) {
        return safe_directory_target(&target);
    }
    let tilde_head = target
        .strip_prefix('~')
        .map(|rest| rest.split('/').next().unwrap_or(""));
    let directory_history = tilde_head.is_some_and(|head| {
        head.starts_with(['+', '-'])
            || (!head.is_empty() && head.bytes().all(|byte| byte.is_ascii_digit()))
    });
    crate::is_plain_cd_target(target)
        && !directory_history
        && !target.contains(['*', '?', '[', ']', '\\'])
        && !super::sensitive_command(target)
        && !super::normalized_haystack(target)
            .split('/')
            .any(|component| matches!(component, ".ssh" | ".aws" | ".kube" | ".gnupg" | ".docker"))
}

pub(super) fn verified_cwd_target(value: &str, context: super::PathContext<'_>) -> Option<String> {
    if context.home_dir.is_none() || context.cwd.is_none() || !safe_directory_target(value) {
        return None;
    }
    let supplied = std::path::Path::new(value);
    let joined;
    let supplied = if supplied.is_absolute() {
        supplied
    } else {
        joined = relative_cwd_target(value, context)?;
        joined.as_path()
    };
    let canonical = std::fs::canonicalize(supplied).ok()?;
    // Non-aliased targets avoid CDPATH and logical/physical cwd ambiguity.
    if !absolute_path_spelling_matches(supplied, &canonical)
        || !canonical.is_dir()
        || !super::read_paths::resolved_path_allowed(&canonical, context.home_dir, context.cwd)
    {
        return None;
    }
    // Later operand proofs expect the cwd spelling the harness reports.
    #[cfg(windows)]
    let canonical = std::path::PathBuf::from(supplied.to_str()?.replace('/', "\\"));
    canonical.to_str().map(str::to_owned)
}

/// POSIX `cd` skips the CDPATH search for operands that begin with `.` or
/// `..`; any other relative operand needs proof that CDPATH is unset. The
/// lexical join is what a logical `cd` reaches, so the caller's spelling
/// check rejects symlinked components. `..` is never proved: the shell
/// resolves it against its logical `$PWD`, which may name a symlinked
/// parent the reported cwd does not show.
fn relative_cwd_target(value: &str, context: super::PathContext<'_>) -> Option<std::path::PathBuf> {
    if cfg!(windows) || value.starts_with('~') {
        return None;
    }
    let dotted = value == "." || value.starts_with("./");
    if !dotted && !context.cdpath_unset {
        return None;
    }
    let base = std::path::Path::new(context.cwd?);
    if !base.is_absolute() {
        return None;
    }
    let mut joined = std::path::PathBuf::new();
    for component in base.join(value).components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => return None,
            other => joined.push(other),
        }
    }
    Some(joined)
}

fn absolute_path_spelling_matches(supplied: &std::path::Path, canonical: &std::path::Path) -> bool {
    if canonical == supplied {
        return true;
    }
    // macOS exposes the root temporary directory through this fixed system
    // alias. Permit only the exact canonical suffix; deeper symlink aliases
    // remain rejected by the physical-cwd proof.
    #[cfg(target_os = "macos")]
    {
        let alias = std::path::Path::new("/tmp");
        let Ok(relative) = supplied.strip_prefix(alias) else {
            return false;
        };
        let Ok(alias_canonical) = std::fs::canonicalize(alias) else {
            return false;
        };
        alias_canonical == std::path::Path::new("/private/tmp")
            && canonical == alias_canonical.join(relative)
    }
    // Windows canonical paths carry the verbatim prefix.
    #[cfg(windows)]
    {
        supplied
            .to_str()
            .is_some_and(|text| exact_drive_spelling(text, canonical))
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (supplied, canonical);
        false
    }
}

/// The forward-slash form of a backslash-separated drive-absolute path.
pub(crate) fn windows_drive_target(target: &str) -> Option<String> {
    let bytes = target.as_bytes();
    (bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\')
        .then(|| target.replace('\\', "/"))
}

/// Whether a segment's drive-path arguments reach the program as parsed.
pub(crate) fn drive_targets_quoted(segment: &crate::CommandSegmentV1) -> bool {
    !cfg!(windows)
        || !segment
            .arguments
            .iter()
            .any(|argument| windows_drive_target(argument).is_some())
        || !shell_alters_backslash(&segment.text)
}

/// A backslash the shell would remove or reinterpret: any unquoted backslash,
/// or one inside double quotes that escapes the next character.
fn shell_alters_backslash(text: &str) -> bool {
    let mut quote = None;
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        match (quote, character) {
            (None, '\\') => return true,
            (None, '\'' | '"') => quote = Some(character),
            (Some('"'), '\\') if matches!(chars.peek(), Some('\\' | '"' | '$' | '`' | '\n')) => {
                return true
            }
            (Some(open), _) if character == open => quote = None,
            _ => {}
        }
    }
    false
}

/// Whether a drive-absolute path is spelled exactly as its canonical path,
/// so case, short names, junctions and dot components remain rejected.
#[cfg(windows)]
pub(crate) fn exact_drive_spelling(text: &str, canonical: &std::path::Path) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= 3
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
        && canonical.as_os_str() == format!(r"\\?\{}", text.replace('/', "\\")).as_str()
}

/// `exact_drive_spelling` for a drive-absolute target that must exist.
#[cfg(windows)]
pub(crate) fn exact_existing_drive_target(target: &str) -> bool {
    std::fs::canonicalize(target).is_ok_and(|canonical| exact_drive_spelling(target, &canonical))
}

#[cfg(test)]
mod tests {
    use super::shell_alters_backslash;

    #[test]
    fn only_backslashes_the_shell_keeps_are_accepted() {
        assert!(!shell_alters_backslash(r"cd 'C:\Users\a b' && mkdir out"));
        assert!(!shell_alters_backslash(r#"cd "C:\Users\a" && mkdir out"#));
        assert!(!shell_alters_backslash(r#"cd 'C:\a"b'"#));
        assert!(shell_alters_backslash(r"cd C:\Users\a && mkdir out"));
        assert!(shell_alters_backslash(r#"cd "C:\\Users""#));
        assert!(shell_alters_backslash(r#"cd "C:\Users\$HOME""#));
        assert!(shell_alters_backslash(r"cd 'C:\a' && echo \x"));
    }
}

impl<'a> super::PathContext<'a> {
    /// `cdpath_unset` is set only from a harness-stamped environment that
    /// declares no CDPATH, so a bare relative `cd` operand cannot be
    /// redirected by a CDPATH search.
    pub(crate) fn for_session(
        home_dir: Option<&'a str>,
        cwd: Option<&'a str>,
        execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    ) -> Self {
        let cdpath_unset = execution_environment.is_some_and(|environment| {
            environment.has_valid_shape()
                && !environment
                    .environment_names
                    .iter()
                    .any(|name| name == "CDPATH")
        });
        Self {
            home_dir,
            cwd,
            cdpath_unset,
        }
    }
}

#[cfg(test)]
#[path = "tests_relative_cd.rs"]
mod tests_relative_cd;
