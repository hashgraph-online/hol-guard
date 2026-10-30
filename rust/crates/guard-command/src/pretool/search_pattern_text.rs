//! Every search pattern one command writes: Git's own (`git grep`,
//! `git log -S`) and a stdin-only pipeline filter's (`… | rg -n password`).
//! Both kinds make the same claim about a word -- it selects lines of text
//! the command already produced, and names nothing the command opens -- and a
//! single command can hold both, so the whole-command screen sets them aside
//! together. A mask taken over one kind alone leaves the other kind's pattern
//! in view, which is what made `git diff -- src | rg -n password` ask for
//! review while `git diff -- src` and `rg -n password src` each ran.

use super::search_scope_tracked::names;
use crate::CanonicalCommandV1;

/// The command's text with every search pattern left out, or `None` when no
/// segment holds one. A segment is read as a Git search first, since that
/// mask keeps the subcommand and its pathspecs, and as a pipeline filter
/// otherwise.
pub(super) fn command_without_patterns(model: &CanonicalCommandV1) -> Option<String> {
    let mut masked = false;
    let parts = model
        .segments
        .iter()
        .map(|segment| {
            match super::git_search_text::segment_without_patterns(segment)
                .or_else(|| super::filter_pattern_text::segment_without_patterns(segment))
            {
                Some(text) => {
                    masked = true;
                    text
                }
                None => segment.text.clone(),
            }
        })
        .collect::<Vec<_>>();
    masked.then(|| parts.join(" ; "))
}

/// Whether the whole command trips the sensitive-text floor once its search
/// patterns are set aside, reading `text` without heredoc data bodies and
/// without the words that name tracked documents.
pub(super) fn command_sensitive(model: &CanonicalCommandV1, text: &str, cwd: Option<&str>) -> bool {
    let rest = command_without_patterns(model)
        .map(|rest| names::screened(model, rest, names::command_words(model), cwd));
    super::git_search_text::sensitive_beyond_patterns(
        &names::command_screen_text(model, text, cwd),
        rest,
    )
}

#[cfg(test)]
mod tests {
    use super::command_sensitive;

    fn sensitive(command: &str) -> bool {
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .expect("the command parses");
        command_sensitive(&model, command, None)
    }

    /// The two kinds of pattern are set aside in the same pass, so a Git
    /// search piped into a filter sheds both. Reading one kind alone left the
    /// other in view and sent ordinary review work to the approval center.
    #[test]
    fn both_kinds_of_search_pattern_are_set_aside_together() {
        for command in [
            "git diff -- src | rg -n password",
            "git diff --stat | grep -i api_key",
            "ls -R src | grep -i secret",
            "git grep -n password -- src",
            "git log -S aws_secret_access_key --oneline",
            "git log -S secret -- src | rg -n password",
        ] {
            assert!(!sensitive(command), "{command} still reads as sensitive");
        }
    }

    /// Only the patterns are set aside. A producer that opens a secret, a
    /// pathspec that names one, a home credential path and an environment
    /// dump each name something the command reads, so the mask leaves every
    /// one of them in view.
    #[test]
    fn everything_outside_the_patterns_keeps_its_screen() {
        for command in [
            "cat .env | rg -n password",
            "git grep -n foo -- .env",
            "git log -p -- ~/.aws/credentials | rg -n token",
            "printenv | grep -i token",
        ] {
            assert!(sensitive(command), "{command} lost a signal to the mask");
        }
    }
}
