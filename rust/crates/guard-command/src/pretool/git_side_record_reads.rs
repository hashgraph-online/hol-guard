//! The printing spellings of the two records Git keeps beside the history:
//! a bisect session's log and a commit's notes.
//!
//! `git bisect log` replays what the session has recorded so far, and
//! `git notes list` and `git notes show` print the notes ref. None of the
//! three touches a ref, the index or the worktree, so an agent reading where
//! a bisect stands or what a commit was annotated with asks for nothing.
//!
//! Every other spelling of either subcommand does reach something. `bisect
//! start`, `good`, `bad`, `skip` and `reset` move `HEAD` and write the
//! session's refs; `bisect run`, `visualize` and `view` run a program the
//! text names. `notes add`, `append`, `copy`, `edit`, `remove`, `prune` and
//! `merge` write the notes ref, and `edit` opens the configured editor. They
//! keep their review.

/// Whether `arguments`, the tokens after `subcommand`, name a printing form
/// of that record.
pub(crate) fn read_form(subcommand: &str, arguments: &[String]) -> bool {
    match subcommand {
        "bisect" => bisect_read_form(arguments),
        "notes" => notes_read_form(arguments),
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
    fn no_other_record_reads_through_this_door() {
        assert!(!read_form("stash", &words("list")));
    }
}
