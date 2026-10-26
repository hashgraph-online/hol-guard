//! Closed grammar for a `git clean` invocation that only prints what it would
//! remove.
//!
//! Git removes nothing without `-f`, `--force` or an interactive session, so a
//! spelling that carries `-n` or `--dry-run` and none of those is a listing of
//! untracked paths. Anything else stays reviewed.

use super::git_branch_listing::bounded_pattern;

/// `arguments` are the tokens after the `clean` subcommand.
pub(crate) fn is_dry_run(arguments: &[String]) -> bool {
    let mut dry_run = false;
    let mut index = 0;
    let mut pathspecs_only = false;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        if pathspecs_only {
            if !bounded_pattern(argument) {
                return false;
            }
            continue;
        }
        match argument.as_str() {
            "--" => pathspecs_only = true,
            "-n" | "--dry-run" => dry_run = true,
            "-d" | "-x" | "-X" | "-q" | "--quiet" => {}
            "-e" | "--exclude" => {
                if !arguments
                    .get(index)
                    .is_some_and(|value| bounded_pattern(value))
                {
                    return false;
                }
                index += 1;
            }
            value => {
                if let Some(flags) = bundled_preview_flags(value) {
                    dry_run |= flags.contains('n');
                } else if let Some(pattern) = value.strip_prefix("--exclude=") {
                    if !bounded_pattern(pattern) {
                        return false;
                    }
                } else if value.starts_with('-') || !bounded_pattern(value) {
                    return false;
                }
            }
        }
    }
    dry_run
}

/// Bundled short flags such as `-ndx`, which Git reads as the separate flags.
/// Every letter must be a preview flag that takes no value; `-f` and `-i` are
/// left out because they are what turns the preview into a removal.
fn bundled_preview_flags(value: &str) -> Option<&str> {
    let flags = value
        .strip_prefix('-')
        .filter(|flags| !flags.starts_with('-'))?;
    (!flags.is_empty() && flags.chars().all(|flag| "ndxXq".contains(flag))).then_some(flags)
}

#[cfg(test)]
mod tests {
    use super::is_dry_run;

    fn preview(command: &str) -> bool {
        let words: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        is_dry_run(&words)
    }

    #[test]
    fn previews_are_recognised() {
        for command in [
            "-n",
            "--dry-run",
            "-nd",
            "-ndx",
            "-n -X",
            "-n -q",
            "--dry-run -d src",
            "-n -e build",
            "-n --exclude=build",
            "-n -- src tests",
        ] {
            assert!(preview(command), "{command}");
        }
    }

    #[test]
    fn removals_and_unbounded_forms_are_not_previews() {
        for command in [
            "",
            "-f",
            "-fd",
            "--force",
            "-i",
            "--interactive",
            "-n -f",
            "-nf",
            "-n --no-dry-run",
            "-d",
            "-x",
            "src",
            "-n -e",
            "-n -e $(id)",
            "-n --exclude=;id",
            "-n -- $(id)",
        ] {
            assert!(!preview(command), "{command}");
        }
    }
}
