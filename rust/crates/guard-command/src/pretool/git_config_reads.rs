//! `git config` reads proven without review.
//!
//! Reading configuration runs no helper beyond the pager, which the shared
//! configuration probe already checks. What a read can expose is a stored
//! credential: an `http.extraHeader`, a token a tool saved under its own key
//! (`hub.oauthtoken`, `github.token`), or a URL with embedded userinfo. The
//! lexical proof admits only read forms. The probe then lists the effective
//! configuration with the agent's own Git and refuses the read when an entry
//! it would print carries a credential.
use std::process::Command;
use std::time::Instant;

#[path = "git_config_writes.rs"]
pub(crate) mod writes;

/// Matches the session probe's bound. A long-lived clone keeps a
/// `branch.<name>.remote` and `.merge` pair for every branch it ever tracked,
/// and a quarter-megabyte cap held every config read there for review.
const LIST_LIMIT: u64 = 8 * 1024 * 1024;
const FLAGS: &[&str] = &[
    "--local",
    "--global",
    "--system",
    "--worktree",
    "--show-origin",
    "--show-scope",
    "--name-only",
    "--null",
    "-z",
    "--bool",
    "--int",
    "--bool-or-int",
    "--path",
    "--expiry-date",
    "--includes",
    "--no-includes",
];
/// Lowercase key fragments that name a stored credential.
const KEY_MARKERS: &[&str] = &[
    "token",
    "password",
    "passwd",
    "secret",
    "oauth",
    "extraheader",
    "authorization",
    "bearer",
    "apikey",
    "api-key",
    "privatekey",
    "private-key",
    "cookie",
];
/// Lowercase value fragments that carry a credential.
const VALUE_MARKERS: &[&str] = &[
    "authorization:",
    "bearer ",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
];

/// The configuration entries a read prints.
#[derive(Debug, PartialEq)]
pub(crate) enum Printed {
    Key(String),
    All,
}

/// The verb, the read mode and the operands of the arguments after `config`.
struct Form<'a> {
    verb: &'a str,
    mode: &'a str,
    operands: Vec<&'a str>,
}

/// Classifies the arguments after `config`. Only reads return a value; every
/// write form, `--file`/`--blob` sources and editor launches return `None`.
pub(crate) fn read_form(arguments: &[String]) -> Option<Printed> {
    let Form {
        verb,
        mode,
        operands,
    } = parse(arguments)?;
    let key = |name: &str| {
        (!name.is_empty() && !name.contains('=')).then(|| Printed::Key(name.to_ascii_lowercase()))
    };
    match (verb, mode, operands.as_slice()) {
        ("list", "", []) | ("", "--list" | "-l", []) => Some(Printed::All),
        ("get", "--get-regexp", [_]) | ("", "--get-regexp", [_] | [_, _]) => Some(Printed::All),
        ("get", "", [name]) | ("", "" | "--get" | "--get-all", [name]) => key(name),
        ("", "--get" | "--get-all", [name, _]) => key(name),
        _ => None,
    }
}

/// An operand the shell could expand into something Git reads as an option
/// rather than as the pattern Guard parsed. Expansion keeps a word's leading
/// literal text, so a word opening with a glob or an expansion is the only one
/// whose first character the parse cannot see: `[-]-file=*` is a pattern here
/// and `--file=secret`, naming a file of Git's choosing, by the time Git runs.
/// A bracket class is the one glob that writes its members down, so it is read
/// rather than refused outright.
fn could_expand_into_an_option(operand: &str) -> bool {
    match operand.chars().next() {
        None => true,
        Some('[') => leading_class_can_match_a_dash(operand),
        Some(first) => matches!(first, '*' | '?' | '{' | '~' | '$' | '\\'),
    }
}

/// Whether the bracket class an operand opens with could match a leading `-`.
/// A class is the one glob whose members are written down, so reading them
/// answers the question the leading character could not: `[r]emote.*url` can
/// only ever produce `r` and stays the pattern Guard parsed, while `[-]-file=*`
/// and `[^a]-file=*` can each produce a dash and keep the path screen.
///
/// Two shapes are read as classes that could hold a dash rather than taken
/// apart. A brace inside the class is expanded by the shell before the class
/// is ever a class, so `[!{a,-}]-file=*` is two words by the time Git sees it
/// and the members written here are not the members that run. And a range only
/// holds the characters between its ends under ASCII ordering: a shell
/// collating with `strcoll` under a UTF-8 locale follows the locale's order
/// instead, which in glibc's table puts `-` inside spans such as `[_-z]`. A
/// range whose ends do not sit in one ASCII alphanumeric span therefore leaves
/// the answer unknown, and since negating the class turns that answer around,
/// neither way is safe to assume and the class keeps the path screen.
fn leading_class_can_match_a_dash(operand: &str) -> bool {
    let chars: Vec<char> = operand.chars().collect();
    let Some((end, readable)) = super::class_end(&chars, 0) else {
        // A `[` with no closing `]` is literal, so the word still opens with
        // the bracket itself and never with a dash.
        return false;
    };
    if !readable {
        // A leading `]`, a backslash or a `[:name:]` puts members in the class
        // that this reader cannot enumerate, so the class is taken as one that
        // could hold a dash.
        return true;
    }
    let negated = matches!(chars.get(1), Some('!' | '^'));
    let members = &chars[usize::from(negated) + 1..end];
    if members.iter().any(|member| matches!(member, '{' | '}')) {
        // The shell expands braces before it reads a class, so these members
        // are not the ones that run.
        return true;
    }
    let mut listed = false;
    let mut index = 0;
    while index < members.len() {
        // A `-` with a member on each side spells a range; one that opens or
        // closes the class is a member of its own.
        if index + 2 < members.len() && members[index + 1] == '-' {
            let (low, high) = (members[index], members[index + 2]);
            let ascii_span =
                [('a', 'z'), ('A', 'Z'), ('0', '9')]
                    .into_iter()
                    .any(|(first, last)| {
                        (first..=last).contains(&low) && (first..=last).contains(&high)
                    });
            if !ascii_span {
                // Outside one ASCII alphanumeric span a locale's collation
                // decides what the range holds. Whether `-` is inside it is
                // unknown, and a negated class turns that answer around, so
                // neither way is the safe one to assume.
                return true;
            }
            listed |= low <= '-' && '-' <= high;
            index += 3;
            continue;
        }
        listed |= members[index] == '-';
        index += 1;
    }
    // A negated class matches every character it does not list, so it produces
    // a dash exactly when the listed members leave one out.
    listed != negated
}

/// The arguments the path screen still covers. A `--get-regexp` operand is
/// matched against the keys in the configuration file, so it is a pattern
/// rather than a path and the screen would refuse every `remote.*url`. Every
/// other argument is one the shell can expand over the files that are there,
/// turning `git config *` into the write `git config user.name value`, so it
/// keeps the screen those expanded words would face. An operand the shell
/// could turn into an option keeps it too, for the same reason.
pub(crate) fn screened_arguments(arguments: &[String]) -> Vec<&str> {
    let patterns = configuration_pattern_operands(parse(arguments));
    arguments
        .iter()
        .map(String::as_str)
        .filter(|argument| !patterns.contains(argument))
        .collect()
}

/// The `--get-regexp` operands of a `git config` read in `segment`, if it is
/// one. Git matches each against the keys in the configuration file and never
/// expands it over the files that are there, so it is a pattern rather than a
/// path and the screens that refuse every `remote.*url` do not apply to it.
///
/// An operand the shell could still turn into an option is left out, because
/// Guard would be reading a pattern where Git reads a flag.
pub(crate) fn configuration_patterns(segment: &crate::CommandSegmentV1) -> Vec<&str> {
    if crate::command_compatibility::basename(segment) != "git" {
        return Vec::new();
    }
    let arguments = &segment.arguments;
    let Some(index) = crate::command_compatibility::git_command_index(arguments) else {
        return Vec::new();
    };
    if arguments.get(index).map(String::as_str) != Some("config") {
        return Vec::new();
    }
    configuration_pattern_operands(parse(&arguments[index + 1..]))
}

/// The operands of `form` that Git reads as configuration patterns and the
/// shell cannot turn into anything else.
fn configuration_pattern_operands(form: Option<Form<'_>>) -> Vec<&str> {
    match form {
        Some(form) if form.mode == "--get-regexp" => form
            .operands
            .into_iter()
            .filter(|operand| !could_expand_into_an_option(operand))
            .collect(),
        _ => Vec::new(),
    }
}

fn parse(arguments: &[String]) -> Option<Form<'_>> {
    let (verb, rest) = match arguments.split_first() {
        Some((first, rest)) if matches!(first.as_str(), "get" | "list") => (first.as_str(), rest),
        _ => ("", arguments),
    };
    let mut mode = "";
    let mut operands = Vec::new();
    for argument in rest {
        let option = argument.as_str();
        if !option.starts_with('-') {
            operands.push(option);
        } else if FLAGS.contains(&option)
            || ["--type=", "--default="]
                .iter()
                .any(|prefix| option.starts_with(prefix))
            || (verb == "get" && matches!(option, "--all" | "--show-names"))
        {
            continue;
        } else if verb == "get" && option == "--regexp" {
            mode = "--get-regexp";
        } else if verb.is_empty()
            && mode.is_empty()
            && matches!(
                option,
                "--get" | "--get-all" | "--get-regexp" | "--list" | "-l"
            )
        {
            mode = option;
        } else {
            return None;
        }
    }
    Some(Form {
        verb,
        mode,
        operands,
    })
}

/// Git pages the listing forms (`--list`, `--get-all`, `--get-regexp`) by
/// default; a single-value get pages only when `pager.config` asks for it.
pub(super) fn pages_by_default(arguments: &[String]) -> bool {
    read_form(arguments) == Some(Printed::All)
        || arguments
            .iter()
            .any(|argument| matches!(argument.as_str(), "--get-all" | "--all"))
}

/// Lists the configuration the read would see and screens what it prints.
pub(super) fn credential_free(
    base: &Command,
    arguments: &[String],
    deadline: Instant,
) -> Option<bool> {
    let printed = read_form(arguments)?;
    let mut query = super::git_probe::copy_command(base)?;
    query.args(["--no-pager", "config", "--null", "--list"]);
    let (status, output) = super::git_probe::output(&mut query, deadline, LIST_LIMIT)?;
    if !status.success() {
        return None;
    }
    Some(entries_free(std::str::from_utf8(&output).ok()?, &printed))
}

/// Whether the text of a repository `config` file holds no credential: no
/// `credential` section, no key or value marker, and no URL with userinfo or a
/// query string. Screening each lowercased line is a superset of the entries.
pub(super) fn file_text_free(text: &str) -> bool {
    text.lines()
        .all(|line| !line.trim().to_ascii_lowercase().starts_with("[credential"))
        && text.lines().all(|line| {
            let line = line.to_ascii_lowercase();
            !KEY_MARKERS.iter().any(|marker| line.contains(marker))
                && !VALUE_MARKERS.iter().any(|marker| line.contains(marker))
                && !url_with_userinfo(&line)
                && !url_with_query(&line)
        })
}

fn entries_free(listing: &str, printed: &Printed) -> bool {
    listing
        .split('\0')
        .filter(|record| !record.is_empty())
        .all(|record| {
            let (key, value) = record.split_once('\n').unwrap_or((record, ""));
            let key = key.to_ascii_lowercase();
            // Section and variable names are case-insensitive; comparing the
            // whole key in lowercase screens a superset of the printed entry.
            if matches!(printed, Printed::Key(name) if *name != key) {
                return true;
            }
            let value = value.to_ascii_lowercase();
            !KEY_MARKERS.iter().any(|marker| key.contains(marker))
                && !VALUE_MARKERS.iter().any(|marker| value.contains(marker))
                && !url_with_userinfo(&key)
                && !url_with_userinfo(&value)
                && !url_with_query(&value)
        })
}

/// A URL with a query string, where services accept `access_token=` and
/// similar parameters. Remote and `insteadOf` URLs never need one.
fn url_with_query(text: &str) -> bool {
    text.match_indices("://").any(|(index, _)| {
        text[index + 3..]
            .split_whitespace()
            .next()
            .is_some_and(|rest| rest.contains('?'))
    })
}

/// A URL that embeds a secret: any password (`user:pw@`), or any user name
/// over HTTP, where a token is commonly passed as the user name.
/// `ssh://git@host` names only the SSH login and is not a credential.
fn url_with_userinfo(text: &str) -> bool {
    text.match_indices("://").any(|(index, _)| {
        let scheme = text[..index]
            .rsplit(|character: char| {
                !(character.is_ascii_alphanumeric() || "+.-".contains(character))
            })
            .next()
            .unwrap_or_default();
        let authority = text[index + 3..]
            .split(|character: char| character == '/' || character.is_whitespace())
            .next()
            .unwrap_or_default();
        authority.rsplit_once('@').is_some_and(|(userinfo, _)| {
            userinfo.contains(':') || !matches!(scheme, "ssh" | "git+ssh" | "ssh+git")
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{entries_free, read_form, Printed};

    fn form(command: &str) -> Option<Printed> {
        let arguments: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
        read_form(&arguments)
    }

    #[test]
    fn read_forms_are_classified() {
        for (command, expected) in [
            ("user.name", Some(Printed::Key("user.name".into()))),
            ("--get user.Email", Some(Printed::Key("user.email".into()))),
            (
                "--global --get-all remote.origin.fetch",
                Some(Printed::Key("remote.origin.fetch".into())),
            ),
            (
                "get --all user.name",
                Some(Printed::Key("user.name".into())),
            ),
            ("--list --show-origin", Some(Printed::All)),
            ("-l", Some(Printed::All)),
            ("list --global", Some(Printed::All)),
            ("--get-regexp ^remote\\.", Some(Printed::All)),
            ("get --regexp user", Some(Printed::All)),
            (
                "--type=bool --default=false core.bare",
                Some(Printed::Key("core.bare".into())),
            ),
        ] {
            assert_eq!(form(command), expected, "{command}");
        }
    }

    #[test]
    fn writes_and_other_sources_are_not_reads() {
        for command in [
            "user.name Someone",
            "--add user.name Someone",
            "--unset user.name",
            "--replace-all user.name x",
            "--remove-section user",
            "--rename-section a b",
            "-e",
            "--edit",
            "set user.name x",
            "unset user.name",
            "--file other.config --list",
            "-f other.config --list",
            "--blob HEAD:.gitmodules --list",
            "--list user.name",
            "",
        ] {
            assert_eq!(form(command), None, "{command}");
        }
    }

    #[test]
    fn printed_credentials_are_refused() {
        let all = Printed::All;
        for listing in [
            "http.https://github.com/.extraheader\nAUTHORIZATION: basic x\0",
            "hub.oauthtoken\nsynthetic\0",
            "github.token\nsynthetic\0",
            "remote.origin.url\nhttps://user:pw@example.com/repo.git\0",
            "remote.origin.url\nhttps://synthetic@example.com/repo.git\0",
            "url.https://synthetic@example.com/.insteadof\nhttps://example.com/\0",
            "alias.deploy\n!curl -H 'Authorization: Bearer x'\0",
            "remote.origin.url\nhttps://example.invalid/repo.git?access_token=synthetic\0",
        ] {
            assert!(!entries_free(listing, &all), "{listing}");
        }
        for listing in [
            "user.name\nFixture\0user.email\nfixture@example.invalid\0",
            "remote.origin.url\ngit@github.com:example/repo.git\0",
            "remote.origin.url\nssh://git@github.com/example/repo.git\0",
            "credential.helper\nosxkeychain\0",
            "filter.lfs.process\ngit-lfs filter-process\0",
        ] {
            assert!(entries_free(listing, &all), "{listing}");
        }
    }

    #[test]
    fn a_key_read_screens_only_that_key() {
        let listing = "user.name\nFixture\0github.token\nsynthetic\0";
        assert!(entries_free(listing, &Printed::Key("user.name".into())));
        assert!(!entries_free(listing, &Printed::Key("github.token".into())));
        assert!(!entries_free(listing, &Printed::All));
    }
}
