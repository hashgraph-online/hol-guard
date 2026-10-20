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

/// Classifies the arguments after `config`. Only reads return a value; every
/// write form, `--file`/`--blob` sources and editor launches return `None`.
pub(crate) fn read_form(arguments: &[String]) -> Option<Printed> {
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
