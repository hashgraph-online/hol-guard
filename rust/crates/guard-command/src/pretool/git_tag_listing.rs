//! Closed grammar for a `git tag` invocation that only lists tags.
//!
//! Creating, deleting, signing or formatting a tag is outside this grammar and
//! stays reviewed. A bare `git tag` lists too, but the same spelling creates a
//! tag as soon as it carries an operand, so a listing has to say so with
//! `--list` or `-l`.

use super::git_branch_listing::{bounded_pattern, bounded_revision, bounded_sort_key};

/// `arguments` are the tokens after the `tag` subcommand.
pub(crate) fn is_listing(arguments: &[String]) -> bool {
    let mut listing = false;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        match argument.as_str() {
            "--list" | "-l" => listing = true,
            "-i" | "--ignore-case" | "--no-color" | "--color=never" | "--no-column"
            | "--column=never" | "--omit-empty" => {}
            "--contains" | "--no-contains" | "--merged" | "--no-merged" | "--points-at" => {
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
                } else if let Some(revision) = [
                    "--contains=",
                    "--no-contains=",
                    "--merged=",
                    "--no-merged=",
                    "--points-at=",
                ]
                .iter()
                .find_map(|prefix| value.strip_prefix(prefix))
                {
                    if !bounded_revision(revision) {
                        return false;
                    }
                } else if value.starts_with('-') || !bounded_pattern(value) || !listing {
                    // A bare positional names the tag to create unless a list
                    // flag came first.
                    return false;
                }
            }
        }
    }
    listing
}

/// Bundled short listing flags such as `-li`, which Git reads as the separate
/// flags. Every letter must be a listing flag that takes no value; `-n` is
/// left out because it carries an optional count.
fn bundled_listing_flags(value: &str) -> Option<&str> {
    let flags = value
        .strip_prefix('-')
        .filter(|flags| !flags.starts_with('-'))?;
    (!flags.is_empty() && flags.chars().all(|flag| "li".contains(flag))).then_some(flags)
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
            "--list",
            "-l",
            "-li",
            "--list v1.*",
            "-l release-*",
            "--list --sort=-creatordate",
            "--list --contains HEAD~1",
            "--list --points-at=HEAD",
            "--list --ignore-case v1.*",
            "--list --no-color --no-column",
        ] {
            assert!(listing(command), "{command}");
        }
    }

    #[test]
    fn writes_and_unbounded_forms_are_not_listings() {
        for command in [
            "",
            "v1.0.0",
            "v1.0.0 HEAD",
            "-a v1.0.0 -m release",
            "-d v1.0.0",
            "--delete v1.0.0",
            "-f v1.0.0",
            "-s v1.0.0",
            "-u key v1.0.0",
            "-m release v1.0.0",
            "-F notes v1.0.0",
            "--create-reflog v1.0.0",
            "--format=%(refname)",
            "--list --format %(refname)",
            "--list --sort=$(id)",
            "--list $(id)",
            "--list ;id",
            "--contains",
            "--contains HEAD",
            "--points-at :/x",
            "v1.0.0 --list",
            "-n",
            "-n3",
            "--color=always --list",
        ] {
            assert!(!listing(command), "{command}");
        }
    }
}
