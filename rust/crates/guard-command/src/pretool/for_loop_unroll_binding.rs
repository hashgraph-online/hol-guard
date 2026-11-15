//! Which builtins in a loop body can bind a name, read from the words the
//! shell builds rather than from every run of letters in the text.

/// The builtins and keywords that bind the name written beside them.
/// `command` and `builtin` are here because they run the builtins that do,
/// and `set` because ksh spells an array assignment `set -A name`. The list
/// is a shell's, not one shell's: zsh stores output in a name with
/// `print -v`, reads a line with `getln`, and parses options with
/// `zparseopts`, `zstyle -s` and `zformat -a`, and bash 5.3 fills an array
/// with `compgen -V`.
const BINDING_WORDS: &[&str] = &[
    ".",
    "builtin",
    "command",
    "compgen",
    "coproc",
    "declare",
    "eval",
    "exec",
    "export",
    "float",
    "for",
    "getln",
    "getopts",
    "integer",
    "let",
    "local",
    "mapfile",
    "nameref",
    "print",
    "printf",
    "read",
    "readarray",
    "readonly",
    "select",
    "set",
    "source",
    "typeset",
    "unset",
    "vared",
    "wait",
    "zformat",
    "zparseopts",
    "zstyle",
];

/// Whether the item holds a word that, once the shell removes its quoting,
/// is one of [`BINDING_WORDS`].
///
/// A separator splits words only where it stands unquoted, so
/// `jq 'select(.n != null)'` hands jq one argument and runs no `select`.
/// Quoting inside a word still comes off, so `'re'ad n` and `r\ead n` are
/// both `read`. A `$'...'` or `$"..."` word can spell a builtin through an
/// escape the text does not show, so either one counts as a binding word.
/// So does bash 5.3's `${ list; }` and `${| list; }`, which run their list in
/// the current shell even inside double quotes.
pub(super) fn holds_a_binding_word(text: &str) -> bool {
    text.contains("$'")
        || text.contains("$\"")
        || text
            .match_indices("${")
            .any(|(at, _)| text[at + 2..].starts_with(|c: char| c.is_whitespace() || c == '|'))
        || shell_words(text)
            .iter()
            .any(|word| BINDING_WORDS.contains(&word.as_str()))
}

/// The item's words with their quoting removed, split at whitespace and the
/// operators that start a new word wherever those stand outside quotes.
fn shell_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        match character {
            '\'' => word.extend(characters.by_ref().take_while(|quoted| *quoted != '\'')),
            '"' => {
                let mut escaped = false;
                for quoted in characters.by_ref() {
                    if escaped {
                        word.push(quoted);
                        escaped = false;
                    } else if quoted == '\\' {
                        escaped = true;
                    } else if quoted == '"' {
                        break;
                    } else {
                        word.push(quoted);
                    }
                }
            }
            '\\' => word.extend(characters.next()),
            separator
                if separator.is_whitespace()
                    || matches!(separator, ';' | '&' | '|' | '(' | ')' | '<' | '>') =>
            {
                if !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
            }
            other => word.push(other),
        }
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::holds_a_binding_word;

    #[test]
    fn a_builtin_named_inside_quoted_text_binds_nothing() {
        for item in [
            "jq -c '{n:.number,checks:[.c[]?|select(.conclusion!=null)]}'",
            "echo 'read n'",
            "grep \"export n\" notes.txt",
            "jq '.[] | select(.n == 1)' x.json",
        ] {
            assert!(!holds_a_binding_word(item), "{item}");
        }
    }

    #[test]
    fn a_builtin_the_shell_runs_still_binds() {
        for item in [
            "read n",
            "'re'ad n",
            "r\\ead n",
            "\"read\" n",
            "echo x | read n",
            "(read n)",
            "eval 'n=1'",
            "printf -v n x",
            "$'\\x72ead' n",
            "$\"read\" n",
            "echo \"${ read n; }\"",
            "echo \"${| read n; }\"",
            "echo ok;select n in a; do :; done",
        ] {
            assert!(holds_a_binding_word(item), "{item}");
        }
    }
}
