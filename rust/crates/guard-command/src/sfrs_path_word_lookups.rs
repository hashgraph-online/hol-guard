//! Read-only lookup checks for the commands that rewrite or resolve a path
//! word (`developer_inspection.py`: the path-word command rules).

use std::path::{Path, PathBuf};

use crate::sfrs_read_only_filters::read_only_lookup_target_is_safe;

/// A path word the shell hands over without running anything of its own.
/// `$PWD` and `${REPO}` name a value the caller already holds; `$(…)`, a
/// backtick, a process substitution or a control operator run a command this
/// proof never screened.
pub(crate) fn path_word_runs_nothing(word: &str) -> bool {
    !["$(", "`", "<(", ">("]
        .iter()
        .any(|marker| word.contains(marker))
        && !word.contains(['|', ';', '&', '\n', '\r', '\0'])
}

/// `_read_only_lookup_path_word_args_are_safe`.
///
/// `basename` and `dirname` rewrite their operand as a string. Coreutils never
/// stats the path for either one, so the operand carries no read to check, and
/// only the option set has to stay narrow enough that it cannot grow one.
///
/// The shell still expands the word before coreutils sees it, so a substitution
/// anywhere in the segment — an operand, a `-s` suffix or a `--suffix=` value —
/// runs a command this proof never screened and leaves the rewrite recognized.
pub(crate) fn read_only_lookup_path_word_args_are_safe(command: &str, args: &[String]) -> bool {
    if !args.iter().all(|arg| path_word_runs_nothing(arg)) {
        return false;
    }
    let mut operands = 0usize;
    let mut after_options = false;
    let mut remaining = args.iter();
    while let Some(arg) = remaining.next() {
        if after_options {
            operands += 1;
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if command == "basename" && arg == "-s" {
            if remaining.next().is_none() {
                return false;
            }
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            let recognized = if command == "basename" {
                matches!(arg.as_str(), "-a" | "--multiple" | "-z" | "--zero")
                    || arg.starts_with("--suffix=")
            } else {
                matches!(arg.as_str(), "-z" | "--zero")
            };
            if !recognized {
                return false;
            }
            continue;
        }
        operands += 1;
    }
    operands > 0
}

/// `_read_only_lookup_resolved_path_args_are_safe`.
///
/// `readlink` and `realpath` do reach the filesystem: they resolve the operand
/// and print where it lands, which reports existence and symlink targets. The
/// operand therefore takes the same read check as `ls`, and the options that
/// would carry a path of their own stay outside the recognized set.
pub(crate) fn read_only_lookup_resolved_path_args_are_safe(
    command: &str,
    args: &[String],
    home_dir: Option<&Path>,
) -> bool {
    let Some(targets) = resolved_path_operands(command, args) else {
        return false;
    };
    !targets.is_empty()
        && targets
            .iter()
            .all(|target| read_only_lookup_target_is_safe(target, true, home_dir))
}

/// The operands of a `readlink` or `realpath` segment, or `None` when an
/// option outside the recognized set appears. None of the recognized options
/// takes a value, so every other word is an operand.
fn resolved_path_operands<'a>(command: &str, args: &'a [String]) -> Option<Vec<&'a str>> {
    let mut targets: Vec<&str> = Vec::new();
    let mut after_options = false;
    for arg in args {
        if after_options {
            targets.push(arg);
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            let recognized = if command == "readlink" {
                matches!(
                    arg.as_str(),
                    "-f" | "--canonicalize"
                        | "-e"
                        | "--canonicalize-existing"
                        | "-m"
                        | "--canonicalize-missing"
                        | "-n"
                        | "--no-newline"
                        | "-q"
                        | "-s"
                        | "--quiet"
                        | "--silent"
                        | "-z"
                        | "--zero"
                )
            } else {
                matches!(
                    arg.as_str(),
                    "-e" | "--canonicalize-existing"
                        | "-m"
                        | "--canonicalize-missing"
                        | "-L"
                        | "--logical"
                        | "-P"
                        | "--physical"
                        | "-q"
                        | "--quiet"
                        | "-s"
                        | "--strip"
                        | "--no-symlinks"
                        | "-z"
                        | "--zero"
                )
            };
            if !recognized {
                return None;
            }
            continue;
        }
        targets.push(arg);
    }
    Some(targets)
}

/// `readlink` and `realpath` print where their operand lands, so a workspace
/// symlink pointing at a secret reports a target the same name spelled
/// literally would never have passed. Resolve each operand the way the command
/// does and hold the answer to the screen its spelling took: inside the
/// inspection root, and not a path the read check refuses.
pub(crate) fn resolved_path_operands_resolve_safely(
    command: &str,
    args: &[String],
    cwd: &Path,
    root: &Path,
) -> bool {
    let Some(targets) = resolved_path_operands(command, args) else {
        return false;
    };
    let (Ok(resolved_root), Ok(resolved_cwd)) = (root.canonicalize(), cwd.canonicalize()) else {
        return false;
    };
    for target in targets {
        let stripped = target.trim().trim_matches(|c| c == '\'' || c == '"');
        if stripped.is_empty() {
            continue;
        }
        // The spelling is compared against the resolved working directory, so
        // a session rooted at a link to its own checkout — `/tmp` on macOS —
        // does not read as an escape.
        let mut candidate = PathBuf::from(stripped);
        if !candidate.is_absolute() {
            candidate = resolved_cwd.join(&candidate);
        }
        let resolved = match candidate.canonicalize() {
            Ok(resolved) => resolved,
            // The command prints an error for a path that is not there, which
            // discloses nothing the operand did not already spell.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return false,
        };
        // Following the link is the whole point of these two commands, so a
        // link inside the inspection root is ordinary. What it must not do is
        // report a place the operand's own spelling would never have passed.
        let Ok(relative) = resolved.strip_prefix(&resolved_root) else {
            return false;
        };
        if !read_only_lookup_target_is_safe(&relative.to_string_lossy(), true, Some(root)) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }

    #[test]
    fn a_rewritten_path_word_needs_no_read_check() {
        for command in ["basename", "dirname"] {
            assert!(read_only_lookup_path_word_args_are_safe(
                command,
                &words(&["/etc/ssh/sshd_config"])
            ));
            assert!(read_only_lookup_path_word_args_are_safe(
                command,
                &words(&["-z", "src/app"])
            ));
            assert!(!read_only_lookup_path_word_args_are_safe(command, &[]));
            assert!(!read_only_lookup_path_word_args_are_safe(
                command,
                &words(&["--handle=/etc/shadow", "x"])
            ));
        }
        assert!(read_only_lookup_path_word_args_are_safe(
            "basename",
            &words(&["-s", ".rs", "src/main.rs"])
        ));
        assert!(!read_only_lookup_path_word_args_are_safe(
            "basename",
            &words(&["-s"])
        ));
        // `-a` belongs to `basename` alone, so `dirname` must not inherit it.
        assert!(!read_only_lookup_path_word_args_are_safe(
            "dirname",
            &words(&["-a", "src/app"])
        ));
    }

    #[test]
    fn a_substituted_path_word_is_not_a_path_word() {
        for command in ["basename", "dirname"] {
            assert!(!read_only_lookup_path_word_args_are_safe(
                command,
                &words(&["$(touch /tmp/marker)"])
            ));
            assert!(!read_only_lookup_path_word_args_are_safe(
                command,
                &words(&["`touch /tmp/marker`"])
            ));
            assert!(!read_only_lookup_path_word_args_are_safe(
                command,
                &words(&["--", "$(touch /tmp/marker)"])
            ));
        }
        assert!(!read_only_lookup_path_word_args_are_safe(
            "basename",
            &words(&["-s", "$(touch /tmp/marker)", "src/main.rs"])
        ));
        assert!(!read_only_lookup_path_word_args_are_safe(
            "basename",
            &words(&["--suffix=$(touch /tmp/marker)", "src/main.rs"])
        ));
        // A parameter the caller already holds runs nothing of its own.
        assert!(read_only_lookup_path_word_args_are_safe(
            "dirname",
            &words(&["$PWD"])
        ));
        assert!(read_only_lookup_path_word_args_are_safe(
            "dirname",
            &words(&["${REPO_ROOT}/src"])
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_workspace_link_out_of_the_root_never_resolves_safely() {
        let root = tempfile::tempdir().expect("temp root");
        let outside = tempfile::tempdir().expect("outside root");
        let secret = outside.path().join("id_ed25519");
        std::fs::write(&secret, "key").expect("write secret");
        let inside = root.path().join("manifest.toml");
        std::fs::write(&inside, "[package]").expect("write manifest");
        std::os::unix::fs::symlink(&secret, root.path().join("key")).expect("link");
        std::os::unix::fs::symlink(&inside, root.path().join("shim")).expect("shim link");

        let root = root.path().canonicalize().expect("canonical root");
        let root = root.as_path();
        for command in ["readlink", "realpath"] {
            assert!(resolved_path_operands_resolve_safely(
                command,
                &words(&["manifest.toml"]),
                root,
                root,
            ));
            // A link that stays inside the root is what these commands are
            // for.
            assert!(resolved_path_operands_resolve_safely(
                command,
                &words(&["shim"]),
                root,
                root,
            ));
            // The operand names the workspace, but the answer names the
            // secret outside it.
            assert!(!resolved_path_operands_resolve_safely(
                command,
                &words(&["key"]),
                root,
                root,
            ));
            // A path that is not there discloses nothing beyond its spelling.
            assert!(resolved_path_operands_resolve_safely(
                command,
                &words(&["absent.toml"]),
                root,
                root,
            ));
            // An option outside the recognized set is never resolved at all.
            assert!(!resolved_path_operands_resolve_safely(
                command,
                &words(&["--relative-to=/etc", "manifest.toml"]),
                root,
                root,
            ));
        }
    }

    #[test]
    fn a_resolved_path_word_takes_the_read_check() {
        assert!(read_only_lookup_resolved_path_args_are_safe(
            "realpath",
            &words(&["."]),
            None
        ));
        assert!(read_only_lookup_resolved_path_args_are_safe(
            "readlink",
            &words(&["-f", "src/app"]),
            None
        ));
        // The operand is read, so the boundary `ls` enforces applies here too.
        assert!(!read_only_lookup_resolved_path_args_are_safe(
            "realpath",
            &words(&["../../etc/passwd"]),
            None
        ));
        assert!(!read_only_lookup_resolved_path_args_are_safe(
            "readlink",
            &words(&["-f", ".ssh/id_ed25519"]),
            None
        ));
        // An option carrying a path of its own stays outside the set.
        assert!(!read_only_lookup_resolved_path_args_are_safe(
            "realpath",
            &words(&["--relative-to=/etc", "."]),
            None
        ));
        assert!(!read_only_lookup_resolved_path_args_are_safe(
            "realpath",
            &[],
            None
        ));
    }
}
