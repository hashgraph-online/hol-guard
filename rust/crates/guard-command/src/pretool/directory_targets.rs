//! Directory targets for `cd` and `git -C`.
//!
//! Windows agents run POSIX commands through a shell that drops an unquoted
//! backslash, while the Windows parser keeps it. A drive path is therefore
//! proved only when every backslash in its segment survives the shell, and
//! only in the exact spelling of its canonical path.

#[path = "directory_targets_sibling.rs"]
pub(crate) mod sibling;

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
    // An unquoted leading `~` expands from the shell's HOME, so it is proved
    // only when that HOME is the declared one.
    let expanded;
    let value = if value == "~" || value.starts_with("~/") {
        if cfg!(windows) || !context.shell_home_matches {
            return None;
        }
        expanded = super::read_paths::expand_home_read_path(value, context.home_dir)?;
        expanded.as_str()
    } else {
        value
    };
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
/// check rejects symlinked components. `..` is proved only into a linked
/// worktree of the session's repository (see `sibling`): elsewhere the
/// shell resolves it against its logical `$PWD`, which may name a symlinked
/// parent the reported cwd does not show. On Windows a `:` can name a
/// drive-relative path (`C:src`) or an alternate data stream, and Git Bash
/// resolves a root-relative `/etc` against its own root rather than the
/// cwd's drive, so neither is joined; the caller's exact-spelling check
/// covers case, short names and junctions there.
fn relative_cwd_target(value: &str, context: super::PathContext<'_>) -> Option<std::path::PathBuf> {
    if value.starts_with('~')
        || (cfg!(windows) && (value.contains(':') || value.starts_with(['/', '\\'])))
    {
        return None;
    }
    let dotted = value == "." || value.starts_with("./") || value.starts_with("../");
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
            std::path::Component::ParentDir => {
                return sibling::linked_root(value, base);
            }
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

/// Whether every argument that begins with `~` reaches the program after the
/// shell expands it to home, as the path proofs assume. A quoted or escaped
/// `~` stays a literal relative path that names a different directory, so a
/// segment that spells one is refused rather than proved against home.
pub(crate) fn home_targets_unquoted(segment: &crate::CommandSegmentV1) -> bool {
    !segment
        .arguments
        .iter()
        .any(|argument| argument.starts_with('~'))
        || !shell_keeps_tilde_literal(&segment.text)
}

/// Search reads also accept a quoted `~` when the working directory has no
/// `~` entry: the literal relative path then names nothing, so the search
/// reads nothing, and the home spelling has already cleared the read screens.
pub(crate) fn search_home_targets_safe(
    segment: &crate::CommandSegmentV1,
    cwd: Option<&str>,
    home_dir: Option<&str>,
) -> bool {
    home_targets_unquoted(segment)
        || cwd
            .map(|cwd| {
                super::read_paths::expand_home_read_path(cwd, home_dir)
                    .unwrap_or_else(|| cwd.to_owned())
            })
            .filter(|cwd| std::path::Path::new(cwd).is_absolute())
            .is_some_and(|cwd| {
                matches!(
                    std::fs::symlink_metadata(std::path::Path::new(&cwd).join("~")),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound
                )
            })
}

fn shell_keeps_tilde_literal(text: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    let mut word_start = true;
    let chars: Vec<char> = text.chars().collect();
    for (index, character) in chars.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            if character == '~' {
                return true;
            }
            word_start = false;
            continue;
        }
        // `~"/project"` keeps the tilde literal: the slash is quoted, so the
        // shell does not expand it to home. The quote-stripped argument is
        // still `~/project`, which must not be proved as that home path.
        if quote.is_none()
            && word_start
            && character == '~'
            && mixed_tilde_prefix(&chars[index + 1..])
        {
            return true;
        }
        match (quote, character) {
            (Some(_), '~') => return true,
            (None | Some('"'), '\\') => escaped = true,
            (None, '\'' | '"') => quote = Some(character),
            (Some(open), _) if character == open => quote = None,
            (None, character) if is_shell_word_boundary(character) => {
                word_start = true;
                continue;
            }
            _ => {}
        }
        if quote.is_none() {
            word_start = false;
        }
    }
    false
}

/// A quote or escape between a word-initial `~` and the first unquoted `/`
/// means the shell will not perform the home expansion the path proof assumes.
fn mixed_tilde_prefix(rest: &[char]) -> bool {
    let mut escaped = false;
    for character in rest.iter().copied() {
        if escaped {
            return true;
        }
        match character {
            '\\' => escaped = true,
            '\'' | '"' => return true,
            '/' => return false,
            character if is_shell_word_boundary(character) => return false,
            _ => {}
        }
    }
    false
}

fn is_shell_word_boundary(character: char) -> bool {
    character.is_whitespace() || matches!(character, ';' | '|' | '&' | '(' | ')' | '<' | '>' | '\n')
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
        && canonical.as_os_str() == format!(r"\\?\{}", drive_separators(text)).as_str()
}

/// A drive path with each run of separators written as one backslash.
/// Windows resolves `C:\\a\\b` and `C:/a//b` to `C:\a\b`, so this changes
/// only the spelling of a separator, never which directory is named.
#[cfg(any(windows, test))]
fn drive_separators(text: &str) -> String {
    let mut spelled = String::with_capacity(text.len());
    for character in text.chars() {
        if !matches!(character, '/' | '\\') {
            spelled.push(character);
        } else if !spelled.ends_with('\\') {
            spelled.push('\\');
        }
    }
    spelled
}

/// `exact_drive_spelling` for a drive-absolute target that must exist.
#[cfg(windows)]
pub(crate) fn exact_existing_drive_target(target: &str) -> bool {
    std::fs::canonicalize(target).is_ok_and(|canonical| exact_drive_spelling(target, &canonical))
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
                    .any(|name| name.eq_ignore_ascii_case("CDPATH"))
        });
        // rustup reads these before any toolchain file, and either one can
        // name a toolchain directory. Without a stamped environment, the
        // runtime's own environment is what a probe would inherit.
        let rustup_override_absent = match execution_environment {
            Some(environment) => {
                environment.has_valid_shape()
                    && !environment
                        .environment_names
                        .iter()
                        .any(|name| rustup_selector(name))
            }
            None => !std::env::vars_os()
                .any(|(name, value)| !value.is_empty() && rustup_selector(&name.to_string_lossy())),
        };
        let npm_config_inert = match execution_environment {
            Some(environment) => {
                environment.has_valid_shape()
                    && !environment.environment_names.iter().any(|name| {
                        npm_selector(name)
                            && !super::npm_environment::inert_npm_config_name(name)
                            && !super::npm_environment::trusted_stamped_loader(
                                environment,
                                name,
                                home_dir,
                                cwd.as_slice(),
                            )
                    })
            }
            None => !std::env::vars_os().any(|(name, value)| {
                let name = name.to_string_lossy();
                !value.is_empty()
                    && npm_selector(&name)
                    && !super::npm_environment::inert_npm_config_name(&name)
            }),
        };
        // ripgrep reads RIPGREP_CONFIG_PATH unless the command passes
        // `--no-config`, and ignores it only when it is empty. A stamped
        // environment carries names without values, so any name counts.
        let ripgrep_config_absent = match execution_environment {
            Some(environment) => {
                environment.has_valid_shape()
                    && !environment
                        .environment_names
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(RIPGREP_CONFIG_NAME))
            }
            None => std::env::var_os(RIPGREP_CONFIG_NAME).is_none_or(|value| value.is_empty()),
        };
        // The shell expands `~` from its own HOME: the stamped one, or the
        // runtime's when no environment was stamped.
        let shell_home = match execution_environment {
            Some(environment) if environment.has_valid_shape() => environment.home.clone(),
            Some(_) => None,
            None => std::env::var("HOME").ok(),
        };
        let canonical = |path: &str| {
            std::path::Path::new(path)
                .is_absolute()
                .then(|| std::fs::canonicalize(path).ok())
                .flatten()
        };
        let shell_home_matches = home_dir.zip(shell_home).is_some_and(|(declared, shell)| {
            canonical(declared).is_some_and(|declared| canonical(&shell) == Some(declared))
        });
        Self {
            home_dir,
            cwd,
            cdpath_unset,
            rustup_override_absent,
            npm_config_inert,
            shell_home_matches,
            ripgrep_config_absent,
        }
    }
}

const RIPGREP_CONFIG_NAME: &str = "RIPGREP_CONFIG_PATH";

fn rustup_selector(name: &str) -> bool {
    name.eq_ignore_ascii_case("RUSTUP_TOOLCHAIN") || name.eq_ignore_ascii_case("RUSTUP_HOME")
}

/// npm reads every `npm_config_*` variable as configuration, including the
/// registry and the paths of its other config files. Node reads the rest
/// before npm's own code runs, and `NODE_TLS_REJECT_UNAUTHORIZED=0` turns off
/// certificate checks. `NODE_EXTRA_CA_CERTS` only adds to the trusted set,
/// usually for a company's TLS-inspecting proxy that already sees all of the
/// user's traffic; it leaves the registry where it was, and the agent's own
/// command cannot set the hook's environment.
fn npm_selector(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.starts_with("NPM_CONFIG_")
        || matches!(
            upper.as_str(),
            "NODE_OPTIONS"
                | "NODE_PATH"
                | "NODE_TLS_REJECT_UNAUTHORIZED"
                | "LD_PRELOAD"
                | "LD_LIBRARY_PATH"
                | "DYLD_INSERT_LIBRARIES"
                | "DYLD_LIBRARY_PATH"
        )
}

#[cfg(test)]
mod tests {
    use super::{drive_separators, shell_alters_backslash};

    #[test]
    fn repeated_drive_separators_spell_one_backslash() {
        assert_eq!(
            drive_separators(r"C:\\Users\\a\\project"),
            r"C:\Users\a\project"
        );
        assert_eq!(
            drive_separators("C:/Users//a/project"),
            r"C:\Users\a\project"
        );
        assert_eq!(drive_separators(r"C:\Users\a"), r"C:\Users\a");
        // Case, dot components and short names are untouched, so they still
        // fail the exact comparison against the canonical path.
        assert_eq!(
            drive_separators(r"c:\\users\\..\\PROGRA~1"),
            r"c:\users\..\PROGRA~1"
        );
    }

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

#[cfg(test)]
#[path = "tests_relative_cd.rs"]
mod tests_relative_cd;

#[cfg(test)]
#[path = "tests_relative_cd_windows.rs"]
mod tests_relative_cd_windows;
