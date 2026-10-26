//! The parts of a sourced file that run nothing: comments, and functions the
//! file defines but never calls.
//!
//! The virtualenv `activate` script every Python project carries ends with a
//! convenience wrapper:
//!
//! ```sh
//! # Make sure to unalias pydoc if it's already there
//! alias pydoc 2>/dev/null >/dev/null && unalias pydoc || true
//!
//! pydoc () {
//!     python -m pydoc "$@"
//! }
//! ```
//!
//! Nothing in the file calls that wrapper and neither does the command that
//! sourced the file, so sourcing it cannot run `python`. Reading its body as
//! part of the file's words handed every virtualenv an interpreter it never
//! runs, and the command lost the bounded owner set reading the file had just
//! given it. The script's prose comments read the same way: a sentence ending
//! in a full stop put `.` in a command position, which is the shell's other
//! name for `source`.

/// The text with every comment removed.
///
/// `None` leaves the text alone: a quote that never closes means this scan
/// cannot say which `#` the shell would read as a comment, and dropping the
/// wrong one would drop a command with it.
pub(super) fn without_comments(text: &str) -> Option<String> {
    let characters: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    // What is still open, innermost last: `'`, `"`, a `$(` substitution as
    // `(`, or a backtick. A substitution inside a double-quoted string holds
    // quotes of its own, so `"$(echo " # ")"` closes nothing at its second
    // `"` and the `#` between them is data rather than a comment.
    let mut open: Vec<char> = Vec::new();
    let mut escaped = false;
    let mut fresh = true;
    let mut comment = false;
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        index += 1;
        if comment {
            if character != '\n' {
                continue;
            }
            comment = false;
        }
        if escaped {
            escaped = false;
            out.push(character);
            // An escaped space joins the word it follows, as in `echo a\ #b`,
            // so no new word starts after it and no comment can either.
            fresh = false;
            continue;
        }
        if open.last() == Some(&'\'') {
            out.push(character);
            if character == '\'' {
                open.pop();
            }
            continue;
        }
        if character == '\\' {
            escaped = true;
            out.push(character);
            fresh = false;
            continue;
        }
        match open.last() {
            Some('"') => {
                out.push(character);
                match character {
                    '"' => {
                        open.pop();
                    }
                    '`' => open.push('`'),
                    '$' if characters.get(index) == Some(&'(') => {
                        out.push('(');
                        index += 1;
                        open.push('(');
                    }
                    _ => {}
                }
                continue;
            }
            Some('(') => {
                out.push(character);
                match character {
                    ')' => {
                        open.pop();
                    }
                    // A subshell inside the substitution opens parens of its
                    // own, and its `)` closes the subshell rather than the
                    // substitution. Without this the scan leaves the
                    // substitution early and reads the quote after it as the
                    // close of the string holding it.
                    '(' => open.push('('),
                    // A `case` pattern ends in a `)` that closes nothing,
                    // which this scan cannot tell from the substitution's own.
                    // The text is not plain enough to take apart.
                    'c' if opens_case(&characters, index - 1) => return None,
                    '\'' | '"' | '`' => open.push(character),
                    '$' if characters.get(index) == Some(&'(') => {
                        out.push('(');
                        index += 1;
                        open.push('(');
                    }
                    _ => {}
                }
                continue;
            }
            Some('`') => {
                out.push(character);
                if character == '`' {
                    open.pop();
                }
                continue;
            }
            _ => {}
        }
        if character == '\'' || character == '"' {
            open.push(character);
        } else if character == '#' && fresh {
            comment = true;
            continue;
        }
        // A `#` starts a comment only where a word starts. `main#2` is one
        // word, and so is the fragment in `curl https://host/p#frag`.
        fresh = character.is_whitespace() || matches!(character, ';' | '&' | '|' | '(');
        out.push(character);
    }
    (open.is_empty() && !escaped).then_some(out)
}

/// Whether `case` starts a shell word at `start`: nothing a name could carry
/// on stands on either side of it, so `case x in` counts and `lowercase` and
/// `case_of` do not.
fn opens_case(characters: &[char], start: usize) -> bool {
    characters[start..].starts_with(&['c', 'a', 's', 'e'])
        && (start == 0 || !name_character(characters[start - 1]))
        && characters
            .get(start + 4)
            .is_none_or(|next| !name_character(*next))
}

/// The literal with the definition of every function nothing calls removed.
///
/// `None` leaves the text exactly as it stands, either because nothing in it
/// is dead or because it is not plain enough to take apart this way. A body
/// is removed only when a line opens it with nothing after the brace and a
/// later line closes it with nothing else on it, so the span removed is the
/// definition and never a neighbour.
pub(super) fn without_uncalled_definitions(literal: &str, command: &str) -> Option<String> {
    // A heredoc's body is data the shell never reads as a definition, and
    // `unquoted_literal` hands this scan the whole text unchanged when it
    // finds one, so `name () {` could sit inside that data.
    if literal.contains("<<") || quoted_substitution_spans_lines(literal) {
        return None;
    }
    let masked = super::mask_double_quoted_separators(literal);
    // Bash's `${ cmd; }` runs what it holds, and its braces are not a body.
    // A text still carrying one is left for the rest of the scan to judge.
    if masked.contains("${") {
        return None;
    }
    let characters: Vec<char> = literal.chars().collect();
    let masked: Vec<char> = masked.chars().collect();
    if masked.len() != characters.len() {
        return None;
    }
    let lines = line_bounds(&masked);
    let mut dead: Vec<(usize, usize)> = Vec::new();
    let mut at = 0;
    while at < lines.len() {
        let Some(name) = defines(&span(&masked, lines[at])) else {
            at += 1;
            continue;
        };
        // A file defining its own `which` or `command` redefines what a
        // lookup means, and the lookup rewriting that runs before this scan
        // has already turned those calls into plain words, so nothing here
        // can tell a call to the function from a lookup of a program.
        if matches!(name.as_str(), "which" | "command") {
            return None;
        }
        let close = body_end(&masked, &lines, at)?;
        if !invoked(&masked, &lines, (at, close), &name) && !names(command, &name) {
            dead.push((lines[at].0, lines[close].1));
        }
        at = close + 1;
    }
    if dead.is_empty() {
        return None;
    }
    let kept = characters
        .iter()
        .enumerate()
        .filter(|(index, _)| {
            !dead
                .iter()
                .any(|(start, end)| (*start..*end).contains(index))
        })
        .map(|(_, character)| *character)
        .collect();
    Some(kept)
}

/// Whether a double-quoted span holding a substitution runs past its line.
///
/// `mask_double_quoted_separators` leaves such a span alone, so a `name () {`
/// written inside it would read as a definition this scan could take out
/// while the shell reads it as data.
fn quoted_substitution_spans_lines(literal: &str) -> bool {
    let mut inside = false;
    let mut substitutes = false;
    let mut lines = false;
    let mut previous = ' ';
    for character in literal.chars() {
        if character == '"' && previous != '\\' {
            if inside && substitutes && lines {
                return true;
            }
            inside = !inside;
            substitutes = false;
            lines = false;
        } else if inside {
            lines |= character == '\n';
            substitutes |= character == '`' || (character == '(' && previous == '$');
        }
        previous = character;
    }
    inside && substitutes && lines
}

/// The function a line defines, for the two shapes a script is written in:
/// `name () {` and `function name {`. The brace has to close the line, so the
/// body is what follows it rather than something to find inside the line.
fn defines(line: &str) -> Option<String> {
    let head = line.trim().strip_suffix('{')?.trim_end().to_owned();
    let (keyword, rest) = match head.strip_prefix("function ") {
        Some(rest) => (true, rest.trim_start()),
        None => (false, head.as_str()),
    };
    let end = rest
        .find(|character: char| !name_character(character))
        .unwrap_or(rest.len());
    let (name, after) = rest.split_at(end);
    let after: String = after.chars().filter(|c| !c.is_whitespace()).collect();
    (!name.is_empty() && (after == "()" || (keyword && after.is_empty()))).then(|| name.to_owned())
}

/// The line closing the definition opened at `at`, or `None` when the body
/// holds a brace this scan cannot place. Stopping there keeps a body whose
/// shape is unclear in the text the rest of the scan reads.
fn body_end(masked: &[char], lines: &[(usize, usize)], at: usize) -> Option<usize> {
    for (index, bounds) in lines.iter().enumerate().skip(at + 1) {
        let line = span(masked, *bounds);
        let text = line.trim();
        if text == "}" {
            return Some(index);
        }
        if text.contains(['{', '}']) {
            return None;
        }
    }
    None
}

/// Whether anything outside the definition could still run `name`.
///
/// A name handed to `unset -f`, `alias` or `type` is a function those look up
/// rather than run, which is how a generated script tidies up around its own
/// wrapper. Anywhere else the body stays in the text: in a command position,
/// glued into a word such as `p=pydoc`, or handed to something like `trap`
/// that could run it later.
fn invoked(masked: &[char], lines: &[(usize, usize)], body: (usize, usize), name: &str) -> bool {
    let rest: String = lines
        .iter()
        .enumerate()
        .filter(|(index, _)| *index < body.0 || *index > body.1)
        .map(|(_, bounds)| span(masked, *bounds))
        .collect();
    rest.split(|character: char| {
        matches!(
            character,
            ';' | '&' | '|' | '(' | ')' | '{' | '}' | '\n' | '`'
        )
    })
    .any(|piece| runs(piece, name))
}

/// Whether one simple command could run `name`.
fn runs(piece: &str, name: &str) -> bool {
    // The shell joins quoted and escaped pieces into one word before it looks
    // the command up, so `f""oo`, `'f'oo` and `f\oo` all call `foo`. Taking
    // that splicing out first keeps such a call visible to the tests below.
    let mut words = piece
        .split_whitespace()
        .map(|word| {
            word.chars()
                .filter(|character| !matches!(character, '\'' | '"' | '\\'))
                .collect::<String>()
        })
        .skip_while(|word| super::SHELL_PREFIXES.contains(&word.as_str()));
    let Some(first) = words.next() else {
        return false;
    };
    // The shell calls `foo` for `"foo"`, `\foo` and `foo>/dev/null` too, and
    // none of those is the bare name, so the first word takes the same
    // conservative substring test as the words after it.
    if first.contains(name) {
        return true;
    }
    let looks_up = matches!(
        first.as_str(),
        "unset" | "unalias" | "alias" | "type" | "declare" | "typeset"
    );
    words.any(|word| word.contains(name) && !(looks_up && word == name))
}

/// Whether the command that sourced the file spells the name at all. It runs
/// in the same shell, so a wrapper the file leaves behind is the command's to
/// call: `source .venv/bin/activate && pydoc json` runs that body.
fn names(command: &str, name: &str) -> bool {
    command
        // A separator needs no space around it, so `source ./f;foo` is one
        // whitespace-separated token holding both a path and a call. Cutting on
        // the separators first keeps that call visible.
        .split(|character: char| {
            character.is_whitespace()
                || matches!(
                    character,
                    ';' | '&' | '|' | '(' | ')' | '{' | '}' | '`' | '<' | '>'
                )
        })
        // The file being read is not a call to anything: `source ./pydoc`
        // names the path it reads, and a wrapper inside it stays dead.
        .filter(|piece| !piece.contains('/'))
        .any(|piece| {
            // The shell joins quoted and escaped pieces into one word before it
            // looks the command up, so `py""doc`, `'py'doc` and `p\ydoc` all
            // call `pydoc`. Taking that splicing out keeps the call visible.
            let spliced: String = piece
                .chars()
                .filter(|character| !matches!(character, '\'' | '"' | '\\'))
                .collect();
            spliced
                .split(|character: char| !name_character(character))
                .any(|word| word == name)
        })
}

fn name_character(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '-' | '.' | ':')
}

/// Each line's `(start, end)` in characters, the end past its newline.
fn line_bounds(masked: &[char]) -> Vec<(usize, usize)> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (index, character) in masked.iter().enumerate() {
        if *character == '\n' {
            lines.push((start, index + 1));
            start = index + 1;
        }
    }
    if start < masked.len() {
        lines.push((start, masked.len()));
    }
    lines
}

fn span(masked: &[char], bounds: (usize, usize)) -> String {
    masked[bounds.0..bounds.1].iter().collect()
}
