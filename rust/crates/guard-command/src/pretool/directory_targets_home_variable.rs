//! `$HOME` and `${HOME}` as a directory word.
//!
//! The shell reads `~`, `$HOME` and `${HOME}` from one place: its own HOME.
//! A directory proof that already turns `~` into the declared home, and
//! refuses the word when the shell's HOME is some other directory, therefore
//! holds for the variable spellings without being widened. Only the two steps
//! the tilde needs are repeated here: the segment has to leave the word for
//! the shell to expand, and the remainder has to be a path the directory
//! screens accept on its own.

/// The `~` spelling of a directory word that names home through the variable,
/// or `None` when the word is some other shape.
///
/// A whole word of `$HOME` or `${HOME}`, or one followed by `/`, is the only
/// shape read this way. `$HOMEBREW_PREFIX` names a different variable, and a
/// remainder carrying a further expansion is left to the screens to refuse,
/// so the answer is always a word the tilde arm accepts in full.
pub(crate) fn tilde_spelling(value: &str) -> Option<String> {
    let rest = value
        .strip_prefix("${HOME}")
        .or_else(|| value.strip_prefix("$HOME"))?;
    if !rest.is_empty() && !rest.starts_with('/') {
        return None;
    }
    let spelled = format!("~{rest}");
    crate::is_plain_cd_target(&spelled).then_some(spelled)
}

/// Whether every `$HOME` the segment writes as a directory word reaches the
/// shell as an expansion.
///
/// A single-quoted or escaped `$` keeps the word literal, so the shell looks
/// for a directory actually named `$HOME` below the working directory -- the
/// one place the agent writes without review. Guard reads the same argument
/// text either way, because the tokenizer has already removed the quotes, so
/// the segment's own spelling is what tells the two apart.
pub(crate) fn home_variables_expand(segment: &crate::CommandSegmentV1) -> bool {
    !segment
        .arguments
        .iter()
        .any(|argument| tilde_spelling(argument).is_some())
        || !shell_keeps_variable_literal(&segment.text)
}

/// Whether any `$HOME` in the text is quoted or escaped into a literal.
///
/// The screen is deliberately coarse: it answers for the segment rather than
/// for one word, and `$HOMEBREW_PREFIX` counts as a mention. Both only ever
/// hold a word back to review.
fn shell_keeps_variable_literal(text: &str) -> bool {
    let characters: Vec<char> = text.chars().collect();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (index, character) in characters.iter().copied().enumerate() {
        if escaped {
            escaped = false;
            // `\$HOME` is a literal `$HOME` inside double quotes and out.
            if character == '$' && names_home(&unquoted_head(&characters[index + 1..])) {
                return true;
            }
            continue;
        }
        match character {
            '\\' if quote != Some('\'') => escaped = true,
            '\'' | '"' if quote.is_none() => quote = Some(character),
            _ if Some(character) == quote => quote = None,
            // The tokenizer has removed the quotes, so Guard reads `$HOME`
            // from `'$'HOME`, `"$"HOME` and `$HO"ME"` alike. The shell runs
            // none of them as an expansion: a quoted `$` is a literal
            // dollar, and a quote inside the name ends it before `HOME` is
            // spelled. Whenever the quote-stripped text names home but the
            // written text does not spell it contiguously outside single
            // quotes, the word stays literal.
            '$' if names_home(&unquoted_head(&characters[index + 1..]))
                && (quote == Some('\'') || !names_home(&characters[index + 1..])) =>
            {
                return true
            }
            _ => {}
        }
    }
    false
}

fn names_home(rest: &[char]) -> bool {
    let head: String = rest.iter().take(6).collect();
    head.starts_with("HOME") || head.starts_with("{HOME}")
}

/// The characters after a `$` as the tokenizer leaves them, with the quoting
/// removed. Six are enough to spell `{HOME}`.
fn unquoted_head(rest: &[char]) -> Vec<char> {
    rest.iter()
        .copied()
        .filter(|character| !matches!(character, '\'' | '"' | '\\'))
        .take(6)
        .collect()
}

/// Whether the shell hands a `$HOME` word to the program as one argument
/// naming the directory it spells.
///
/// POSIX exempts the result of a tilde expansion from both field splitting
/// and pathname expansion. An unquoted `$HOME` has neither exemption, so a
/// proof taken over the tilde spelling would describe a command the shell
/// never runs. A home path holding a space, a tab or a newline arrives as
/// several arguments -- `git worktree add $HOME/wt` becomes `add <first
/// word> -b injected/wt` when home is named `<first word> -b injected`. A
/// home holding `*`, `?` or `[` is matched against the filesystem instead,
/// so it can become a different path, or several of them, whenever entries
/// beside it match. An unknown home is refused for the same reason.
pub(crate) fn home_expands_to_one_word(home_dir: Option<&str>) -> bool {
    home_dir.is_some_and(|home| {
        !home
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '*' | '?' | '['))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_home_variable_word_reads_as_its_tilde_spelling() {
        assert_eq!(tilde_spelling("$HOME"), Some("~".to_owned()));
        assert_eq!(tilde_spelling("${HOME}"), Some("~".to_owned()));
        assert_eq!(
            tilde_spelling("$HOME/projects"),
            Some("~/projects".to_owned())
        );
        assert_eq!(
            tilde_spelling("${HOME}/projects"),
            Some("~/projects".to_owned())
        );
    }

    #[test]
    fn another_variable_or_a_further_expansion_is_not_a_home_word() {
        assert_eq!(tilde_spelling("$HOMEBREW_PREFIX/bin"), None);
        assert_eq!(tilde_spelling("$HOME$PWD"), None);
        assert_eq!(tilde_spelling("$HOME/$PROJECT"), None);
        assert_eq!(tilde_spelling("$HOME/../etc"), Some("~/../etc".to_owned()));
        assert_eq!(tilde_spelling("~/projects"), None);
        assert_eq!(tilde_spelling("/Users/someone"), None);
    }

    #[test]
    fn a_quoted_or_escaped_dollar_keeps_the_word_literal() {
        assert!(shell_keeps_variable_literal("ls '$HOME/projects'"));
        assert!(shell_keeps_variable_literal("ls \\$HOME/projects"));
        assert!(shell_keeps_variable_literal("ls \"\\$HOME/projects\""));
        assert!(!shell_keeps_variable_literal("ls $HOME/projects"));
        assert!(!shell_keeps_variable_literal("ls \"$HOME/projects\""));
        assert!(!shell_keeps_variable_literal("ls ${HOME}/projects"));
        assert!(!shell_keeps_variable_literal("echo 'no variable here'"));
    }

    #[test]
    fn quoting_inside_the_spelling_keeps_the_word_literal() {
        // The tokenizer reads `$HOME` from each of these, but the shell
        // spells no expansion: the dollar is quoted, or a quote ends the
        // name before `HOME` is written.
        assert!(shell_keeps_variable_literal("ls '$'HOME/projects"));
        assert!(shell_keeps_variable_literal("ls \"$\"HOME/projects"));
        assert!(shell_keeps_variable_literal("ls $HO\"ME\"/projects"));
        assert!(shell_keeps_variable_literal("ls $'HOME'/projects"));
        // A quote that opens after a whole `$HOME` leaves the expansion.
        assert!(!shell_keeps_variable_literal("ls $HOME\"/projects\""));
        assert!(!shell_keeps_variable_literal("ls \"$HOME\"/projects"));
    }

    #[test]
    fn a_home_that_would_split_into_words_is_refused() {
        assert!(home_expands_to_one_word(Some("/Users/someone")));
        assert!(!home_expands_to_one_word(Some(
            "/tmp/guard home -b injected"
        )));
        assert!(!home_expands_to_one_word(Some("/tmp/guard\thome")));
        // An unquoted expansion is also matched against the filesystem, so a
        // home that is a pattern names whatever happens to be beside it.
        assert!(!home_expands_to_one_word(Some("/srv/w*")));
        assert!(!home_expands_to_one_word(Some("/srv/w?rk")));
        assert!(!home_expands_to_one_word(Some("/srv/[w]ork")));
        assert!(!home_expands_to_one_word(None));
    }
}
