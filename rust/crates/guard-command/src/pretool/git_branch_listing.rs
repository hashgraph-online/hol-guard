//! Closed grammar for a `git branch` invocation that only lists branches.
//!
//! Anything that can create, delete, rename, copy, retarget, edit or format
//! with executable atoms is outside this grammar and stays reviewed.

/// `arguments` are the tokens after the `branch` subcommand.
pub(crate) fn is_listing(arguments: &[String]) -> bool {
    let mut listing = false;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        match argument.as_str() {
            "--list" | "-l" => listing = true,
            "-a" | "--all" | "-r" | "--remotes" | "-v" | "-vv" | "--verbose" | "--show-current"
            | "--no-color" | "--color=never" | "--no-column" | "--column=never" | "--no-abbrev"
            | "-i" | "--ignore-case" => {}
            "--contains" | "--no-contains" | "--merged" | "--no-merged" => {
                if !arguments
                    .get(index)
                    .is_some_and(|value| bounded_revision(value))
                {
                    return false;
                }
                index += 1;
            }
            value => {
                if let Some(flags) = bundled_listing_flags(value) {
                    listing |= flags.contains('l');
                } else if let Some(key) = value.strip_prefix("--sort=") {
                    if !bounded_sort_key(key) {
                        return false;
                    }
                } else if let Some(revision) =
                    ["--contains=", "--no-contains=", "--merged=", "--no-merged="]
                        .iter()
                        .find_map(|prefix| value.strip_prefix(prefix))
                {
                    if !bounded_revision(revision) {
                        return false;
                    }
                } else if let Some(digits) = value.strip_prefix("--abbrev=") {
                    if digits.is_empty()
                        || digits.len() > 2
                        || !digits.bytes().all(|byte| byte.is_ascii_digit())
                    {
                        return false;
                    }
                } else if value.starts_with('-') || !bounded_pattern(value) || !listing {
                    // A bare positional creates a branch unless a list flag came first.
                    return false;
                }
            }
        }
    }
    true
}

/// Bundled short listing flags such as `-avv` or `-rl`, which Git reads as
/// the separate flags. Every letter must be a listing flag that takes no value.
fn bundled_listing_flags(value: &str) -> Option<&str> {
    let flags = value
        .strip_prefix('-')
        .filter(|flags| !flags.starts_with('-'))?;
    (!flags.is_empty() && flags.chars().all(|flag| "arvli".contains(flag))).then_some(flags)
}

fn bounded_revision(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with(['-', '/', '.', ':'])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-/~^".contains(&byte))
}

fn bounded_sort_key(value: &str) -> bool {
    let key = value.strip_prefix('-').unwrap_or(value);
    !key.is_empty()
        && key.len() <= 64
        && key.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-:_".contains(&byte)
        })
}

fn bounded_pattern(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-/*?".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::is_listing;

    fn listing(command: &str) -> bool {
        let words: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        is_listing(&words)
    }

    #[test]
    fn pure_listings_are_recognised() {
        for command in [
            "",
            "--list",
            "-a",
            "-r",
            "-vv",
            "-a -vv",
            "-avv",
            "-rv",
            "-al feat/*",
            "-vvi",
            "--show-current",
            "--no-color --no-column",
            "--color=never --list",
            "--list feat/*",
            "-l release-*",
            "--list --sort=-committerdate",
            "--contains HEAD~1",
            "--merged=origin/main",
            "--list --abbrev=8",
        ] {
            assert!(listing(command), "{command}");
        }
    }

    #[test]
    fn mutation_and_unbounded_forms_are_not_listings() {
        for command in [
            "new-feature",
            "new-feature origin/main",
            "feat/* --list",
            "-d old",
            "-D main",
            "-m old new",
            "-M old new",
            "-c old new",
            "-C old new",
            "-f main HEAD",
            "--force",
            "--delete",
            "--set-upstream-to=origin/main",
            "-u origin/main",
            "--unset-upstream",
            "--edit-description",
            "--track",
            "--format=%(refname)",
            "--list --format %(refname)",
            "--sort=%(refname)",
            "--sort=$(id)",
            "--contains",
            "--contains --list",
            "--contains :/x",
            "--list --",
            "--list $(id)",
            "--list ;id",
            "--list -d",
            "--color=always",
            "--abbrev=abc",
            "-ad old",
            "-avD main",
            "-vm old new",
            "-af main",
            "-au origin/main",
            "-av new-feature",
        ] {
            assert!(!listing(command), "{command}");
        }
    }
}
