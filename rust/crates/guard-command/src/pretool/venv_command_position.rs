//! Where one command ends and the next begins, for a token stream that marks
//! only `| ; & < >` as control.
//!
//! The activation projection rewrites the word the command runs next and
//! answers for that word alone. Every other command in the text runs under a
//! `PATH` the projection has changed the reading of, so the scan has to see
//! those command positions or decline the text. These are the ways a word
//! reaches command position without a control token in front of it.

/// `NAME=value` ahead of a command is a prefix the command runs behind, so
/// the word after it is still in command position. A flag that carries its
/// own value, `--maxfail=1`, is not one: its name is not an identifier.
pub(crate) fn assignment_prefix(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// A word that puts another word in command position with no control token
/// between them. `shell_tokens` reads only `| ; & < >` as control, so each of
/// these would hide a later command from the scan that rewrites the first.
pub(crate) fn hides_a_command_position(word: &str) -> bool {
    assignment_prefix(word)
        || matches!(
            word,
            "{" | "}"
                | "("
                | ")"
                | "!"
                | "if"
                | "then"
                | "elif"
                | "else"
                | "while"
                | "until"
                | "for"
                | "in"
                | "do"
                | "case"
                | "time"
                | "command"
                | "builtin"
                | "exec"
                | "eval"
                | "env"
                | "nohup"
                | "setsid"
                | "stdbuf"
                | "nice"
                | "ionice"
                | "timeout"
                | "xargs"
                | "watch"
                | "parallel"
                | "sudo"
                | "doas"
        )
}
