//! Closed grammar for a `git apply` invocation that only reports whether a
//! patch would apply.
//!
//! `--check` stops Git before it touches the worktree, the index or any file
//! the caller named: it reads the patch, reads the files it mentions and
//! prints what would go wrong. The options that write something anyway, such
//! as `--build-fake-ancestor`, `--output`, `--reject` and `--whitespace=fix`,
//! and the ones that reach beyond the patch, such as `--directory`,
//! `--unsafe-paths` and the three-way merge, keep the review.

/// `arguments` are the tokens after the `apply` subcommand.
pub(crate) fn is_check_only(arguments: &[String]) -> bool {
    patch_targets(arguments).is_some()
}

/// The patch files a proven check reads, or `None` when the invocation is no
/// proven check. Named with no patch at all, Git reads the standard input it
/// was handed, so a check names at least one file of its own.
pub(crate) fn patch_targets(arguments: &[String]) -> Option<Vec<&str>> {
    let mut checking = false;
    let mut index = 0;
    let mut patches_only = false;
    let mut patches = Vec::new();
    while let Some(argument) = arguments.get(index) {
        index += 1;
        if patches_only {
            if !patch_target(argument) {
                return None;
            }
            patches.push(argument.as_str());
            continue;
        }
        match argument.as_str() {
            "--" => patches_only = true,
            "--check" => checking = true,
            "-v"
            | "--verbose"
            | "-q"
            | "--quiet"
            | "--recount"
            | "--no-add"
            | "-R"
            | "--reverse"
            | "--unidiff-zero"
            | "--binary"
            | "--allow-empty"
            | "--ignore-space-change"
            | "--ignore-whitespace"
            | "--stat"
            | "--numstat"
            | "--summary" => {}
            "--exclude" | "--include" => {
                if !arguments
                    .get(index)
                    .is_some_and(|value| literal_filter(value))
                {
                    return None;
                }
                index += 1;
            }
            value => {
                if let Some(pattern) = value
                    .strip_prefix("--exclude=")
                    .or_else(|| value.strip_prefix("--include="))
                {
                    if !literal_filter(pattern) {
                        return None;
                    }
                } else if let Some(mode) = value.strip_prefix("--whitespace=") {
                    // `fix` rewrites the lines it applies; the rest only
                    // decide what the check reports.
                    if !matches!(mode, "nowarn" | "warn" | "error" | "error-all") {
                        return None;
                    }
                } else if patch_target(value) {
                    patches.push(value);
                } else if !depth_option(value) {
                    return None;
                }
            }
        }
    }
    (checking && !patches.is_empty()).then_some(patches)
}

/// A patch the caller names inside the workspace. Git quotes the offending
/// line of whatever it was handed, so an absolute path or a `..` segment —
/// a file the workspace proof never read — is not one, and neither is an
/// option this grammar does not know, including a bare `-` for standard
/// input. A glob is not one either: the shell hands Git whatever the pattern
/// happened to match, which is not the file this spelling names.
fn patch_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with(['-', '/', '\\'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-/".contains(&byte))
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}

/// A path the caller keeps out of, or holds the patch to. Git reads it as a
/// pattern of its own, but the shell gets the word first, so a glob here names
/// whatever the working directory happened to hold rather than the paths this
/// spelling says.
fn literal_filter(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-/".contains(&byte))
        && value
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
}

/// `-p<n>` and `-C<n>`, which Git reads as a count attached to the letter.
fn depth_option(value: &str) -> bool {
    value
        .strip_prefix("-p")
        .or_else(|| value.strip_prefix("-C"))
        .is_some_and(|digits| {
            !digits.is_empty()
                && digits.len() <= 2
                && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::is_check_only;

    fn check(command: &str) -> bool {
        let words: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        is_check_only(&words)
    }

    #[test]
    fn checks_are_recognised() {
        for command in [
            "--check feature.patch",
            "--check -p1 feature.patch",
            "--check -C3 feature.patch",
            "--check --verbose feature.patch",
            "--check --stat --summary feature.patch",
            "--check --ignore-whitespace feature.patch",
            "--check --whitespace=error feature.patch",
            "--check --exclude=build feature.patch",
            "--check --include src/app.py feature.patch",
            "--check -R feature.patch",
            "--check -- patches/one.diff patches/two.diff",
        ] {
            assert!(check(command), "{command}");
        }
    }

    #[test]
    fn writing_and_unbounded_forms_are_not_checks() {
        for command in [
            "",
            "feature.patch",
            "--stat feature.patch",
            "--check --index feature.patch",
            "--check --cached feature.patch",
            "--check -3 feature.patch",
            "--check --3way feature.patch",
            "--check --reject feature.patch",
            "--check --unsafe-paths feature.patch",
            "--check --directory=src feature.patch",
            "--check --build-fake-ancestor=/tmp/ancestor feature.patch",
            "--check -o /tmp/out feature.patch",
            "--check --output=/tmp/out feature.patch",
            "--check --whitespace=fix feature.patch",
            "--check --exclude",
            "--check --exclude=$(id)",
            "--check -p",
            "--check -pX",
            "--check -",
            "--check $(id)",
            "--check -- ;id",
            "--check /etc/shadow",
            "--check ../../outside.patch",
            "--check ~/secret.patch",
            "--check -- patches/../../outside.patch",
            // Named with no patch, Git reads the standard input it was handed.
            "--check",
            "--check -p1",
            "--check --",
            // The shell hands Git whatever the pattern matched.
            "--check *.patch",
            "--check patches/*",
            "--check -- patches/?.diff",
            "--check --exclude=build/* feature.patch",
            "--check --include src/* feature.patch",
        ] {
            assert!(!check(command), "{command}");
        }
    }
}
