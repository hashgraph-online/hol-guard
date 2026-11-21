//! Which builtins in a loop body can bind a name, read from the words the
//! shell builds rather than from every run of letters in the text.

/// The builtins and keywords that bind the name written beside them.
/// `command` and `builtin` are here because they run the builtins that do,
/// and `set` because ksh spells an array assignment `set -A name`. `trap`
/// runs its quoted action in the current shell, as `eval` does. The list
/// is a shell's, not one shell's: zsh stores output in a name with
/// `print -v`, reads a line with `getln`, and parses options with
/// `zparseopts`, `zstyle -s` and `zformat -a`, declares with `private`, and
/// loops with `foreach` and `repeat`; bash 5.3 fills an array with
/// `compgen -V`. `repeat N` runs the simple command after its count, so an
/// assignment there binds in the current shell.
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
    "foreach",
    "getln",
    "getopts",
    "integer",
    "let",
    "local",
    "mapfile",
    "nameref",
    "print",
    "private",
    "printf",
    "read",
    "readarray",
    "readonly",
    "repeat",
    "select",
    "set",
    "source",
    "trap",
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
/// both `read`. An unquoted `$'...'` or `$"..."` word can spell a builtin
/// through an escape the text does not show, so either one counts as a
/// binding word. So does bash 5.3's `${ list; }` and `${| list; }`, which run
/// their list in the current shell even inside double quotes. Inside single
/// quotes neither form is special, so the `$'` that ends `grep 'f$'` is text.
pub(super) fn holds_a_binding_word(text: &str) -> bool {
    let (words, hidden) = shell_words(text);
    hidden
        || words
            .iter()
            .any(|word| BINDING_WORDS.contains(&word.as_str()))
}

/// The item's words with their quoting removed, split at whitespace and the
/// operators that start a new word wherever those stand outside quotes, and
/// whether a dollar form there can run or spell a word the text does not show.
fn shell_words(text: &str) -> (Vec<String>, bool) {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut hidden = false;
    let mut characters = text.chars().peekable();
    // `${ list; }` or `${| list; }` right after a `$` the shell expands.
    let runs_a_list = |rest: &mut std::iter::Peekable<std::str::Chars<'_>>| {
        let mut ahead = rest.clone();
        ahead.next() == Some('{') && ahead.next().is_some_and(|c| c.is_whitespace() || c == '|')
    };
    while let Some(character) = characters.next() {
        match character {
            '\'' => word.extend(characters.by_ref().take_while(|quoted| *quoted != '\'')),
            '"' => {
                while let Some(quoted) = characters.next() {
                    match quoted {
                        '\\' => word.extend(characters.next()),
                        '"' => break,
                        '$' => {
                            hidden |= runs_a_list(&mut characters);
                            word.push(quoted);
                        }
                        _ => word.push(quoted),
                    }
                }
            }
            '\\' => word.extend(characters.next()),
            '$' => {
                hidden |=
                    matches!(characters.peek(), Some('\'' | '"')) || runs_a_list(&mut characters);
                word.push(character);
            }
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
    (words, hidden)
}

/// Words that may stand in front of a command's assignments without becoming
/// its command word: the reserved words that open or join a compound command,
/// `!`, `time`, and zsh's `-`, `noglob` and `nocorrect` precommand modifiers.
const TRANSPARENT_WORDS: &[&str] = &[
    "!",
    "-",
    "[[",
    "{",
    "}",
    "case",
    "do",
    "done",
    "elif",
    "else",
    "esac",
    "fi",
    "function",
    "if",
    "in",
    "noglob",
    "nocorrect",
    "select",
    "then",
    "time",
    "until",
    "while",
];

/// Whether `NAME=`, `NAME+=` or `NAME[` stands where the shell reads it as an
/// assignment: in front of the command word of its simple command. After the
/// command word the same text is an argument, so `gh api -F n=$n` or `echo
/// n=$n` hands the word to the command and binds nothing in the shell.
///
/// The text is read with its quoting, so `x='a b' n=1` is still two
/// assignments. A redirection anywhere before the word counts every later
/// word, since a redirection may stand among the assignments. Text the shell
/// rewrites before it splits words -- a backtick, a backslash, a `$(`, `${`,
/// `$'` or `$"` form, or a quote left open -- is read the old way: any word
/// that starts with `NAME=` counts. `rewritten` says whether the item as
/// written holds such text; see [`rewritten`].
pub(super) fn assigns(text: &str, name: &str, rewritten: bool) -> bool {
    let shaped = |word: &str| assignment_shaped(word, Some(name));
    match (!rewritten)
        .then(|| assignment_position_words(text))
        .flatten()
    {
        Some(words) => words.iter().any(|word| shaped(word)),
        None => text
            .split(|c: char| {
                c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>')
            })
            .any(shaped),
    }
}

/// Whether the shell rewrites part of `item` before it splits words. Inside
/// plain single quotes it rewrites nothing, so a jq filter such as
/// `'gsub("\n";" ")'` is text there. The item is read as written: the copy
/// with its quotes removed shows a backslash the shell never acts on.
pub(super) fn rewritten(item: &str) -> bool {
    let unquoted = outside_single_quotes(item);
    unquoted.contains(['`', '\\'])
        || ["$(", "${", "$'", "$\""]
            .iter()
            .any(|form| unquoted.contains(form))
}

/// The text without its plain single-quoted spans. A `$'…'` span is kept, as
/// its escapes are rewritten. A quote left open drops the rest of the text;
/// `assignment_position_words` then finds the open quote and reads it all.
fn outside_single_quotes(text: &str) -> String {
    let mut out = String::new();
    let mut double = false;
    let mut previous = None;
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => {
                out.push(character);
                out.extend(characters.next());
                previous = None;
                continue;
            }
            '"' => double = !double,
            '\'' if !double && previous != Some('$') => {
                characters.find(|quoted| *quoted == '\'');
                previous = None;
                continue;
            }
            _ => {}
        }
        out.push(character);
        previous = Some(character);
    }
    out
}

/// `IDENT=`, `IDENT+=` or `IDENT[` at the start of a word; with a name, only
/// that identifier.
fn assignment_shaped(word: &str, name: Option<&str>) -> bool {
    let identifier = word
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .map_or(word, |end| &word[..end]);
    let rest = &word[identifier.len()..];
    !identifier.is_empty()
        && !identifier.starts_with(|c: char| c.is_ascii_digit())
        && name.is_none_or(|name| identifier == name)
        && (rest.starts_with('=') || rest.starts_with("+=") || rest.starts_with('['))
}

/// The words, quoting removed, that stand where the shell may read an
/// assignment, or `None` when a quote is left open. A separator, a newline or
/// a parenthesis starts a new simple command; a `#` at the start of a word
/// comments out the rest of its line.
fn assignment_position_words(text: &str) -> Option<Vec<String>> {
    let mut found = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut command_seen = false;
    let mut redirected = false;
    let mut after_time = false;
    let mut characters = text.chars().peekable();
    let mut finish = |word: &mut String,
                      started: &mut bool,
                      command_seen: &mut bool,
                      redirected: bool,
                      after_time: &mut bool| {
        if !*started {
            return;
        }
        *started = false;
        let taken = std::mem::take(word);
        if redirected || !*command_seen {
            found.push(taken.clone());
        }
        if *command_seen {
            return;
        }
        if *after_time && taken.starts_with('-') {
            return;
        }
        *after_time = taken == "time";
        if !assignment_shaped(&taken, None) && !TRANSPARENT_WORDS.contains(&taken.as_str()) {
            *command_seen = true;
        }
    };
    while let Some(character) = characters.next() {
        match character {
            '\'' => {
                started = true;
                loop {
                    match characters.next()? {
                        '\'' => break,
                        quoted => word.push(quoted),
                    }
                }
            }
            '"' => {
                started = true;
                loop {
                    match characters.next()? {
                        '"' => break,
                        quoted => word.push(quoted),
                    }
                }
            }
            '#' if !started => {
                for skipped in characters.by_ref() {
                    if skipped == '\n' {
                        break;
                    }
                }
                command_seen = false;
                redirected = false;
                after_time = false;
            }
            '<' | '>' => {
                finish(
                    &mut word,
                    &mut started,
                    &mut command_seen,
                    redirected,
                    &mut after_time,
                );
                redirected = true;
            }
            ';' | '&' | '|' | '(' | ')' | '\n' => {
                finish(
                    &mut word,
                    &mut started,
                    &mut command_seen,
                    redirected,
                    &mut after_time,
                );
                command_seen = false;
                redirected = false;
                after_time = false;
            }
            blank if blank.is_whitespace() => {
                finish(
                    &mut word,
                    &mut started,
                    &mut command_seen,
                    redirected,
                    &mut after_time,
                );
            }
            other => {
                started = true;
                word.push(other);
            }
        }
    }
    finish(
        &mut word,
        &mut started,
        &mut command_seen,
        redirected,
        &mut after_time,
    );
    Some(found)
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
            "grep -c 'n$' x.json",
            "grep -c 'n${ x' x.json",
        ] {
            assert!(!holds_a_binding_word(item), "{item}");
        }
    }

    /// After the command word, `NAME=value` is an argument the command reads,
    /// not an assignment: `gh api -F n=$n` and `echo n=$n` leave the loop
    /// variable alone.
    #[test]
    fn an_argument_spelled_like_an_assignment_is_not_a_rebinding() {
        for (looped, unrolled) in [
            ("for n in a b; do echo n=$n; done", "echo n=a; echo n=b"),
            (
                "for n in 7688 7519; do gh api graphql -f query='query{viewer{login}}' -F n=$n; done",
                "gh api graphql -f query='query{viewer{login}}' -F n=7688; \
                 gh api graphql -f query='query{viewer{login}}' -F n=7519",
            ),
            (
                "for f in a b; do echo 'x y' f=$f; done",
                "echo 'x y' f=a; echo 'x y' f=b",
            ),
            (
                "for n in 1 2; do gh api graphql -F n=$n --jq '.x | gsub(\"\\n\";\" \")'; done",
                "gh api graphql -F n=1 --jq '.x | gsub(\"\\n\";\" \")'; \
                 gh api graphql -F n=2 --jq '.x | gsub(\"\\n\";\" \")'",
            ),
        ] {
            assert_eq!(
                crate::pretool::for_loop_unroll::unroll(looped).as_deref(),
                Some(unrolled),
                "{looped}"
            );
        }
    }

    #[test]
    fn a_word_after_the_command_word_assigns_nothing() {
        for item in [
            "echo n=\u{1}",
            "gh api graphql -f query='query{viewer{login}}' -F n=\u{1}",
            "env n=1 printenv",
            "echo 'a b' n=1",
            "echo ok # n=1",
            "time -p echo n=1",
            "echo nn=1 xn=1",
            "gh api -F n=\u{1} --jq 'gsub(\"\\n\";\" \")'",
            "echo 'a`b`' n=1",
            "echo '$(x)' n=1",
        ] {
            assert!(!super::assigns(item, "n", super::rewritten(item)), "{item}");
        }
    }

    #[test]
    fn an_assignment_the_shell_reads_still_assigns() {
        for item in [
            "n=1",
            "n+=1 echo",
            "n[0]=1",
            "x='a b' n=1",
            "x=\"a b\" n=1 cat",
            ">out n=1",
            "echo a >out n=1",
            "time n=1",
            "time -p n=1",
            "! n=1",
            "- n=1",
            "{ n=1; }",
            "if n=1; then :; fi",
            "(n=1)",
            "echo a; n=1",
            "echo a && n=1",
            "echo a | n=1 cat",
            "echo a\nn=1",
            "echo # note\nn=1",
            "echo `x` n=1",
            "echo $(x) n=1",
            "echo \\x n=1",
            "echo 'open n=1",
            "x='a\\b' n=1",
            "echo \"\\x\" n=1",
            "echo $'\\x' n=1",
            "echo \\' n=1",
        ] {
            assert!(super::assigns(item, "n", super::rewritten(item)), "{item}");
        }
    }

    /// A loop whose body binds its variable where the shell reads it stays
    /// folded, so the loop keeps its review.
    #[test]
    fn a_rebinding_the_shell_reads_keeps_the_loop_folded() {
        for looped in [
            "for f in README.md; do x='a b' f=/etc/passwd; cat $f; done",
            "for f in README.md; do time f=/etc/passwd; cat $f; done",
            "for f in README.md; do ! f=/etc/passwd; cat $f; done",
            "for f in README.md; do { f=/etc/passwd; }; cat $f; done",
            "for f in README.md; do echo ok # note\nf=/etc/passwd; cat $f; done",
            "for f in README.md; do repeat 1 f=/etc/passwd; cat $f; done",
            "for f in README.md; do private f=/etc/passwd; cat $f; done",
            "for f in README.md; do - f=/etc/passwd; cat $f; done",
            "for f in README.md; do foreach f (/etc/passwd) cat $f; end; done",
        ] {
            assert_eq!(
                crate::pretool::for_loop_unroll::unroll(looped),
                None,
                "{looped}"
            );
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
            "echo ${ read n; }",
            "trap 'read n < names.txt' DEBUG",
            "echo ok;select n in a; do :; done",
            "repeat 2 n=1",
            "private n=1",
            "foreach n (a b) echo; end",
        ] {
            assert!(holds_a_binding_word(item), "{item}");
        }
    }
}
