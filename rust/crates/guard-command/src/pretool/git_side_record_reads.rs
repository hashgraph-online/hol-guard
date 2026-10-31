//! The printing spellings of the records Git keeps beside the history: a
//! bisect session's log, a commit's notes and the replacement refs.
//!
//! `git bisect log` replays what the session has recorded so far,
//! `git notes list` and `git notes show` print the notes ref, and
//! `git replace -l` prints the replacements the repository has. None of them
//! touches a ref, the index or the worktree, so an agent reading where a
//! bisect stands, what a commit was annotated with, or which objects are
//! replaced asks for nothing.
//!
//! Every other spelling of those subcommands does reach something. `bisect
//! start`, `good`, `bad`, `skip` and `reset` move `HEAD` and write the
//! session's refs; `bisect run`, `visualize` and `view` run a program the
//! text names. `notes add`, `append`, `copy`, `edit`, `remove`, `prune` and
//! `merge` write the notes ref, and `edit` opens the configured editor.
//! `git replace <object> <replacement>`, `--edit`, `--graft`, `--convert-graft-file`
//! and `-d` write or delete a replacement ref, which changes what every later
//! read of the history reports. They keep their review.

/// Whether `arguments`, the tokens after `subcommand`, name a printing form
/// of that record.
pub(crate) fn read_form(subcommand: &str, arguments: &[String]) -> bool {
    match subcommand {
        "bisect" => bisect_read_form(arguments),
        "notes" => notes_read_form(arguments),
        "replace" => replace_read_form(arguments),
        _ => false,
    }
}

/// A bisect session has one printing form: `log`, which takes no options.
fn bisect_read_form(arguments: &[String]) -> bool {
    arguments.iter().map(String::as_str).eq(["log"])
}

/// Which printing form of `git notes` the tokens after `notes` spell.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NoteRead {
    List,
    Show,
}

/// Whether the tokens after `notes` print a note. `git notes show` hands the
/// note to `git show`, which pages under its own `pager.show` setting, so the
/// configuration proof needs this form apart from the listing.
pub(crate) fn shows_a_note(arguments: &[String]) -> bool {
    note_read(arguments) == Some(NoteRead::Show)
}

fn notes_read_form(arguments: &[String]) -> bool {
    note_read(arguments).is_some()
}

/// Git reads `--ref`, which chooses the notes ref, as an option of `git notes`
/// itself, ahead of the subcommand: `git notes --ref build list`. The
/// subcommands take no options of their own, so `list --ref build` is a usage
/// error in Git and is not read here. Bare `git notes` is `git notes list`,
/// and both printing forms take at most one object: `list` prints every note
/// without one, and `show` defaults to `HEAD`.
fn note_read(arguments: &[String]) -> Option<NoteRead> {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let mut index = 0;
    while let Some(word) = words.get(index) {
        index += 1;
        match word.strip_prefix("--ref") {
            Some("") => {
                if !words.get(index).is_some_and(|value| object_name(value)) {
                    return None;
                }
                index += 1;
            }
            Some(attached) => {
                if !attached.strip_prefix('=').is_some_and(object_name) {
                    return None;
                }
            }
            None => {
                index -= 1;
                break;
            }
        }
    }
    let (read, objects) = match words[index..].split_first() {
        None => return Some(NoteRead::List),
        Some((&"list", objects)) => (NoteRead::List, objects),
        Some((&"show", objects)) => (NoteRead::Show, objects),
        _ => return None,
    };
    match objects {
        [] => Some(read),
        [object] if object_name(object) => Some(read),
        _ => None,
    }
}

/// Whether the tokens after `replace` spell the listing form. Git's own
/// usage is `git replace [--format=<format>] [-l [<pattern>]]`, and bare
/// `git replace` is that listing with no pattern. Every other spelling takes
/// an object and writes or deletes a replacement ref.
fn replace_read_form(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    let mut index = 0;
    let mut listed = false;
    while let Some(word) = words.get(index) {
        index += 1;
        if let Some(value) = word.strip_prefix("--format=") {
            if !replace_format(value) {
                return false;
            }
            continue;
        }
        match *word {
            "--format" => {
                if !words.get(index).is_some_and(|value| replace_format(value)) {
                    return false;
                }
                index += 1;
            }
            "-l" | "--list" => {
                if listed {
                    return false;
                }
                listed = true;
                if let Some(value) = words.get(index).filter(|value| !value.starts_with('-')) {
                    if !ref_pattern(value) {
                        return false;
                    }
                    index += 1;
                }
            }
            _ => return false,
        }
    }
    true
}

/// The three listing formats `git replace --format` takes.
fn replace_format(value: &str) -> bool {
    matches!(value, "short" | "medium" | "long")
}

/// A `git replace -l` pattern: a ref name's characters plus the wildcards
/// Git matches them with, and nothing a shell or a path traversal needs.
fn ref_pattern(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('-')
        && !value.contains("..")
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/_-.^~@{}*?".contains(character))
}

/// A word Git reads as an object or a ref: the characters a ref name and the
/// revision suffixes `HEAD~2`, `HEAD^`, `@{u}` and `branch@{1}` are spelled
/// with, and nothing a shell or a path traversal needs.
fn object_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('-')
        && !value.contains("..")
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/_-.^~@{}".contains(character))
}

#[cfg(test)]
mod tests {
    use super::{read_form, shows_a_note};

    fn words(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn a_bisect_session_prints_only_its_log() {
        assert!(read_form("bisect", &words("log")));
    }

    #[test]
    fn every_other_bisect_spelling_keeps_its_review() {
        for arguments in [
            "",
            "start",
            "start HEAD HEAD~10",
            "good",
            "bad HEAD",
            "skip",
            "reset",
            "run ./flaky.sh",
            "visualize",
            "view",
            "log --stat",
            "log extra",
        ] {
            assert!(!read_form("bisect", &words(arguments)), "{arguments}");
        }
    }

    #[test]
    fn a_note_prints_as_a_listing_or_a_single_note() {
        for arguments in [
            "",
            "list",
            "list HEAD",
            "show",
            "show HEAD",
            "show HEAD~2",
            "--ref build",
            "--ref build list",
            "--ref=build list",
            "--ref build list HEAD",
            "--ref=build show",
            "--ref build show HEAD",
            "--ref refs/notes/build show HEAD~2",
            "--ref a --ref b list",
            // `list` here is the ref the option chose, and bare `git notes` lists it.
            "--ref list",
        ] {
            assert!(read_form("notes", &words(arguments)), "{arguments}");
        }
    }

    #[test]
    fn a_note_that_writes_or_names_an_unread_option_keeps_its_review() {
        for arguments in [
            "add -m fix HEAD",
            "append -m more HEAD",
            "copy HEAD~1 HEAD",
            "edit HEAD",
            "remove HEAD",
            "prune",
            "merge other",
            "--ref build add -m fix HEAD",
            "--ref build edit HEAD",
            "list -n",
            "list --pretty=raw",
            "show --ref",
            "show HEAD extra",
            "show ../outside",
            // Git takes `--ref` ahead of the subcommand and refuses it after.
            "list --ref build",
            "list --ref=build HEAD",
            "show --ref build HEAD",
            "--ref",
            "--ref=",
            "--ref ../outside list",
            "--ref=../outside show HEAD",
            "--ref -x list",
            "--refs build list",
            "--ref build HEAD",
            "HEAD",
        ] {
            assert!(!read_form("notes", &words(arguments)), "{arguments}");
        }
    }

    #[test]
    fn only_the_show_form_hands_the_note_to_git_show() {
        for arguments in ["show", "show HEAD", "--ref build show HEAD", "--ref=b show"] {
            assert!(shows_a_note(&words(arguments)), "{arguments}");
        }
        for arguments in [
            "",
            "list",
            "list HEAD",
            "--ref build",
            "--ref build list",
            "add HEAD",
        ] {
            assert!(!shows_a_note(&words(arguments)), "{arguments}");
        }
    }

    #[test]
    fn a_replacement_ref_prints_as_a_listing() {
        for arguments in [
            "",
            "-l",
            "--list",
            "-l commit*",
            "--list refs/replace/*",
            "--format=short",
            "--format=medium",
            "--format long",
            "--format=long -l",
            "-l --format=long",
        ] {
            assert!(read_form("replace", &words(arguments)), "{arguments}");
        }
    }

    #[test]
    fn a_replacement_that_writes_or_deletes_keeps_its_review() {
        for arguments in [
            "HEAD~1 HEAD",
            "-f HEAD~1 HEAD",
            "--edit HEAD",
            "--graft HEAD",
            "--convert-graft-file",
            "-d HEAD",
            "--delete HEAD",
            "--format",
            "--format=raw",
            "--format raw",
            "-l -l",
            "-l ../outside",
            "-l commit extra",
        ] {
            assert!(!read_form("replace", &words(arguments)), "{arguments}");
        }
    }

    #[test]
    fn no_other_record_reads_through_this_door() {
        assert!(!read_form("stash", &words("list")));
    }
}
