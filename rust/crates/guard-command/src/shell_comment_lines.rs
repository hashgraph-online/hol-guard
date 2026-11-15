//! Lines the shell reads as nothing but a comment.
//!
//! Agents often head a multi-line command with a note such as
//! `# check the PR; list its threads`. Bash and zsh scripts run with comments
//! on, so that line runs nothing. The parser had no notion of a comment and
//! read it as a program named `#`, and every `;` in the note started another
//! step. Those steps proved nothing, so a command whose real steps were all
//! read-only went to review.
//!
//! Each whole-line comment, with the newline that ends it, is blanked to
//! spaces before the text is split, so character positions stay where they
//! were. Only a line whose first word
//! starts with a `#` the shell would read as a comment is touched; a `#` in a
//! quote, in a `${...}` expansion, or later on a line is left alone.

/// `raw` with its comments blanked to spaces, positions kept. The general
/// scan leaves text holding `$(`, `${` or a backtick alone; this module
/// follows those and still blanks the whole-line comments in it.
pub(crate) fn mask_comments(raw: &str) -> String {
    let code = crate::data_flow::mask_shell_comments(raw);
    mask_comment_lines(&code).unwrap_or(code)
}

/// `text` with every whole-line comment replaced by spaces, or `None` when
/// there is none or this scan cannot be sure which lines bash reads as
/// comments.
///
/// It stays out of the way when the text holds a heredoc (`<<`), whose body
/// lines are data, or legacy `$[...]` arithmetic, when a quote or expansion
/// never closes, and when a `case` pattern inside parentheses could unbalance
/// them.
/// A line that a trailing backslash joins to the one before is not a fresh
/// line, so a `#` at its start is not taken as a comment either. Only spaces
/// and tabs may come before it, as in bash: a carriage return is a word.
/// A comment later on a line (`git status # "`) makes the scan give up, since
/// bash reads quotes in it as text and this scan would pair them.
pub(crate) fn mask_comment_lines(text: &str) -> Option<String> {
    // In legacy `$[...]` arithmetic a line-initial `#` is still arithmetic,
    // and a `$(...)` in it runs. Bash drops a backslash-newline before it
    // reads either token, so `$\<newline>[` opens one too.
    let joined = text.replace("\\\n", "");
    if joined.contains("<<") || joined.contains("$[") {
        return None;
    }
    let characters: Vec<char> = text.chars().collect();
    let mut out: Vec<char> = Vec::with_capacity(characters.len());
    // What is open, innermost last: `'`, `"`, `A` for a `$'...'` string,
    // a backtick, `(` for any parenthesis (a subshell, `$(`, `((`), and `{`
    // for `${` and the braces inside it. A comment inside parentheses is left
    // alone: inside `((...))` the shell reads `#` as part of the arithmetic
    // and still expands any `$(...)` in it.
    let mut open: Vec<char> = Vec::new();
    let mut line_start = true;
    // Whether a word starts here: after a blank, `;|&()<>` or a newline.
    let mut boundary = true;
    let mut masked = false;
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        // A comment inside a subshell or backticks may contain quote and
        // delimiter characters that Bash ignores. Never let those characters
        // change the scanner state and hide later executable substitutions.
        if boundary
            && character == '#'
            && matches!(open.last().copied(), None | Some('(') | Some('`'))
            && (!open.is_empty() || !line_start)
        {
            return None;
        }
        if open.is_empty() && line_start && character == '#' {
            // The newline goes too: the splitter reads an empty line as an
            // empty step, and the next line is still a fresh one.
            let end = characters[index..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(characters.len(), |at| index + at + 1);
            out.extend(std::iter::repeat_n(' ', end - index));
            index = end;
            masked = true;
            continue;
        }
        out.push(character);
        index += 1;
        if open.last() == Some(&'\'') {
            if character == '\'' {
                open.pop();
            }
            continue;
        }
        if character == '\\' {
            // The escaped character, a newline included, is part of this word.
            if let Some(&next) = characters.get(index) {
                out.push(next);
                index += 1;
            }
            line_start = false;
            boundary = false;
            continue;
        }
        if open.is_empty() && character == '\n' {
            line_start = true;
            boundary = true;
            continue;
        }
        line_start &= matches!(character, ' ' | '\t');
        boundary = matches!(
            character,
            ' ' | '\t' | '\n' | ';' | '|' | '&' | '(' | ')' | '<' | '>'
        );
        let next = characters.get(index).copied();
        match (open.last().copied(), character) {
            (Some('"'), '"')
            | (Some('`'), '`')
            | (Some('('), ')')
            | (Some('{'), '}')
            | (Some('A'), '\'') => {
                open.pop();
            }
            (Some('A'), _) => {}
            (_, '$') if matches!(next, Some('(' | '{')) => {
                open.push(if next == Some('(') { '(' } else { '{' });
                out.push(next.unwrap_or_default());
                index += 1;
            }
            (Some('"'), '`') => open.push('`'),
            (Some('"'), _) => {}
            (_, '$') if next == Some('\'') => {
                open.push('A');
                out.push('\'');
                index += 1;
            }
            (_, '(') => open.push('('),
            (Some('{'), '{') => open.push('{'),
            (_, 'c') if open.contains(&'(') && starts_case(&characters, index - 1) => return None,
            (_, '\'' | '"' | '`') => open.push(character),
            _ => {}
        }
    }
    (open.is_empty() && masked).then(|| out.into_iter().collect())
}

/// Whether the word `case` starts at `at`.
fn starts_case(characters: &[char], at: usize) -> bool {
    let boundary = |c: Option<&char>| c.is_none_or(|c| !c.is_alphanumeric() && *c != '_');
    characters.get(at..at + 4) == Some(&['c', 'a', 's', 'e'][..])
        && boundary(characters.get(at + 4))
        && (at == 0 || boundary(characters.get(at - 1)))
}

#[cfg(test)]
#[path = "shell_comment_lines_tests.rs"]
mod tests;
