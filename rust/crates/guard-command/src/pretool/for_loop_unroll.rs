//! A shell `for` loop over literal words is the same command list written out
//! once per word. Expanding it lets the ordinary proofs decide each unrolled
//! step, so a read-only loop is admitted exactly when its unrolled form is and
//! nothing about the loop itself grants extra authority. Anything this
//! recognizer does not fully understand returns `None`, which keeps the
//! existing review behavior.

const MAX_WORDS: usize = 32;
const MAX_WORD_BYTES: usize = 256;
const MAX_BODY_BYTES: usize = 2048;
const MAX_UNROLLED_BYTES: usize = 8192;

const CONTROL_WORDS: &[&str] = &[
    "!", "[[", "case", "coproc", "do", "done", "elif", "else", "esac", "fi", "for", "function",
    "if", "in", "select", "then", "time", "until", "while",
];

/// zsh specials outside the PATH family that `valid_identifier` rejects.
const SHELL_SPECIAL_NAMES: &[&str] = &[
    "argv",
    "fignore",
    "histchars",
    "mailpath",
    "pipestatus",
    "psvar",
    "signals",
    "status",
    "watch",
];

/// The unrolled command text for a top-level `for NAME in WORD...; do BODY; done`
/// over literal words, or `None` when the command is anything else.
pub(super) fn unroll(command: &str) -> Option<String> {
    if command
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return None;
    }
    let (prefix, rest) = cd_prefix(command.trim())?;
    let rest = keyword(rest, "for")?;
    let (name, rest) = next_word(rest)?;
    if !valid_identifier(name) || !ordinary_loop_name(name) {
        return None;
    }
    let rest = keyword(rest, "in")?;
    let (words, rest) = header_words(rest)?;
    if words.is_empty() || words.len() > MAX_WORDS {
        return None;
    }
    let rest = rest.trim_start_matches([' ', '\t', '\n', ';']);
    let rest = keyword(rest, "do")?;
    let (items, tail) = body_items(rest, name)?;
    let tail = redirect_tail(tail)?;
    if items.is_empty() || items.iter().any(|(text, _)| rebinds(text, name)) {
        return None;
    }
    let mut out = prefix;
    for word in &words {
        for (text, separator) in &items {
            let step = substitute(text, word)?;
            out.push_str(&step);
            if !tail.is_empty() {
                out.push(' ');
                out.push_str(&tail);
            }
            out.push_str(separator);
        }
        if out.len() > MAX_UNROLLED_BYTES {
            return None;
        }
    }
    let trimmed = out.trim_end_matches([' ', ';']);
    Some(trimmed.to_owned())
}

/// An optional leading `cd DIR && ` with a literal directory. It is kept once
/// in front of the unrolled list. If `cd` fails the loop never runs, while the
/// unrolled list may still run its later items; the unrolled form can only do
/// more, so admitting it still covers the loop.
fn cd_prefix(command: &str) -> Option<(String, &str)> {
    let Some(rest) = keyword(command, "cd") else {
        return Some((String::new(), command));
    };
    let (dir, rest) = next_word(rest)?;
    if !safe_value(dir) || dir.starts_with('-') {
        return None;
    }
    let rest = rest.trim_start_matches([' ', '\t']).strip_prefix("&&")?;
    Some((
        format!("cd {dir} && "),
        rest.trim_start_matches([' ', '\t', '\n']),
    ))
}

/// Consume `keyword` followed by whitespace.
fn keyword<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    let text = text.trim_start_matches([' ', '\t', '\n']);
    let rest = text.strip_prefix(keyword)?;
    rest.starts_with([' ', '\t', '\n'])
        .then(|| rest.trim_start_matches([' ', '\t']))
}

fn next_word(text: &str) -> Option<(&str, &str)> {
    let end = text.find([' ', '\t', '\n', ';'])?;
    (end > 0).then(|| (&text[..end], &text[end..]))
}

fn valid_identifier(name: &str) -> bool {
    // Loop variables also modify the environment seen by commands in the
    // body. Rebinding PATH, HOME, IFS, Git configuration variables, or other
    // exported uppercase names can change which commands actually execute.
    // Only ordinary lowercase identifiers are admitted to this proof.
    // Exclude a leading underscore because '_' itself is shell-special.
    // zsh additionally ties these lowercase arrays to PATH, CDPATH, FPATH,
    // MANPATH and MODULE_PATH, so they can change command lookup.
    if matches!(
        name,
        "path" | "cdpath" | "fpath" | "manpath" | "module_path"
    ) {
        return false;
    }
    let mut chars = name.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn safe_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_WORD_BYTES
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '.' | '/' | '@' | '%' | '+' | '=' | ':' | ',' | '-')
        })
}

/// Literal words up to the first unquoted `;` or newline.
fn header_words(text: &str) -> Option<(Vec<String>, &str)> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut in_word = false;
    let mut chars = text.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        match c {
            ' ' | '\t' => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            ';' | '\n' => {
                if in_word {
                    words.push(current);
                }
                return words
                    .iter()
                    .all(|word| safe_value(word))
                    .then(|| (words, &text[index..]));
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next()?.1 {
                        '\'' => break,
                        other => current.push(other),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next()?.1 {
                        '"' => break,
                        '$' | '`' | '\\' => return None,
                        other => current.push(other),
                    }
                }
            }
            '$' | '`' | '\\' | '(' | ')' | '{' | '}' | '*' | '?' | '[' | ']' | '~' | '&' | '|'
            | '<' | '>' | '#' | '!' => return None,
            other => {
                in_word = true;
                current.push(other);
            }
        }
    }
    None
}

/// Split the body into list items (with the separator that follows each) and
/// return the text after the closing `done`. Items keep a marker where
/// `$NAME` appeared; `substitute` expands it. Any construct outside the simple
/// command list grammar returns `None`.
fn body_items<'a>(text: &'a str, name: &str) -> Option<(Vec<(String, &'static str)>, &'a str)> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut items: Vec<(String, &'static str)> = Vec::new();
    let mut item = String::new();
    // Whether the next word to start is a command word, and whether the
    // previous operator was a redirection (so the next word is its target).
    let mut command_position = true;
    let mut redirect_target = false;
    let mut at_word_start = true;
    let mut i = 0;
    if chars.last().map_or(0, |(index, _)| *index) > MAX_BODY_BYTES {
        return None;
    }
    while i < chars.len() {
        let (byte, c) = chars[i];
        let rest = &text[byte..];
        match c {
            ' ' | '\t' => {
                item.push(c);
                at_word_start = true;
                i += 1;
            }
            '\n' | ';' | '&' | '|' => {
                let (separator, width): (&'static str, usize) =
                    if c == '|' && rest.starts_with("||") {
                        (" || ", 2)
                    } else if c == '&' && rest.starts_with("&&") {
                        (" && ", 2)
                    } else if c == '|' {
                        if rest.starts_with("|&") || item.trim().is_empty() {
                            return None;
                        }
                        item.push('|');
                        command_position = true;
                        redirect_target = false;
                        at_word_start = true;
                        i += 1;
                        continue;
                    } else if c == '&' {
                        // `>&2` and `&>file` are redirections; a lone `&` backgrounds.
                        if item.ends_with(['>', '<']) || rest.starts_with("&>") {
                            item.push('&');
                            redirect_target = true;
                            at_word_start = true;
                            i += 1;
                            continue;
                        }
                        return None;
                    } else if c == ';' && (rest.starts_with(";;") || rest.starts_with(";&")) {
                        return None;
                    } else {
                        ("; ", 1)
                    };
                let trimmed = item.trim().to_owned();
                if trimmed.is_empty() {
                    // Blank separators (after `do`, doubled newlines) are fine;
                    // an empty slot around && or || is not.
                    if separator != "; " {
                        return None;
                    }
                    if let Some(last) = items.last() {
                        if last.1 != "; " {
                            return None;
                        }
                    }
                } else {
                    items.push((trimmed, separator));
                }
                item.clear();
                command_position = true;
                redirect_target = false;
                at_word_start = true;
                i += width;
                if separator == "; " {
                    let after = &text[chars.get(i).map_or(text.len(), |(b, _)| *b)..];
                    let lead = after.trim_start_matches([' ', '\t', '\n', ';']);
                    if starts_with_done(lead) {
                        if items.last().is_none_or(|last| last.1 != "; ") {
                            return None;
                        }
                        return Some((items, &lead["done".len()..]));
                    }
                }
            }
            '>' | '<' => {
                if rest.starts_with("<<") || rest.starts_with("<(") || rest.starts_with(">(") {
                    return None;
                }
                item.push(c);
                command_position = false;
                redirect_target = true;
                at_word_start = true;
                i += 1;
            }
            '`' | '(' | ')' | '{' | '}' => return None,
            '#' if at_word_start => return None,
            '\\' => {
                let next = chars.get(i + 1)?.1;
                if next == '\n' {
                    return None;
                }
                item.push('\\');
                item.push(next);
                at_word_start = false;
                command_position = false;
                redirect_target = false;
                i += 2;
            }
            '\'' => {
                item.push('\'');
                i += 1;
                loop {
                    let q = chars.get(i)?.1;
                    item.push(q);
                    i += 1;
                    if q == '\'' {
                        break;
                    }
                }
                at_word_start = false;
                command_position = false;
                redirect_target = false;
            }
            '"' => {
                let argument = !command_position && !redirect_target;
                item.push('"');
                i += 1;
                loop {
                    let q = chars.get(i)?.1;
                    i += 1;
                    match q {
                        '"' => {
                            item.push('"');
                            break;
                        }
                        '`' => return None,
                        '\\' => {
                            let escaped = chars.get(i)?.1;
                            i += 1;
                            item.push('\\');
                            item.push(escaped);
                        }
                        '$' => item.push_str(&reference(&chars, &mut i, name, argument)?),
                        other => item.push(other),
                    }
                }
                at_word_start = false;
                command_position = false;
                redirect_target = false;
            }
            '$' => {
                let argument = !command_position && !redirect_target;
                i += 1;
                item.push_str(&reference(&chars, &mut i, name, argument)?);
                at_word_start = false;
                command_position = false;
                redirect_target = false;
            }
            other => {
                item.push(other);
                at_word_start = false;
                command_position = false;
                redirect_target = false;
                i += 1;
            }
        }
    }
    None
}

/// Whether a body item can change the loop variable or `IFS`, so a later
/// `$NAME` would not expand to the word written in the header. References
/// are already placeholders here, so any remaining bare `NAME` or `IFS` is a
/// target for `read`, `printf -v`, `declare`, `unset`, an assignment and so
/// on. A `-NAME` flag such as `[ -f ... ]` is not a target; an attached
/// `-vNAME` is.
fn rebinds(item: &str, name: &str) -> bool {
    let mut previous = ' ';
    let mut token = String::new();
    let mut flagged = false;
    for c in item.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || c == '_' {
            if token.is_empty() {
                flagged = previous == '-';
            }
            token.push(c);
        } else if !token.is_empty() {
            let target = |candidate: &str| {
                if flagged {
                    candidate.strip_prefix('v') == Some(name) || candidate == "vIFS"
                } else {
                    candidate == name || candidate == "IFS"
                }
            };
            if target(&token) {
                return true;
            }
            token.clear();
        }
        previous = c;
    }
    false
}

fn starts_with_done(text: &str) -> bool {
    text.strip_prefix("done").is_some_and(|rest| {
        rest.is_empty() || rest.starts_with([' ', '\t', '\n', ';', '>', '<', '&'])
    })
}

/// Consume a `$NAME` or `${NAME}` reference (the `$` is already consumed) and
/// return a placeholder. A reference in command or redirect position, a
/// different variable, or any other expansion rejects the loop.
fn reference(chars: &[(usize, char)], i: &mut usize, name: &str, argument: bool) -> Option<String> {
    if !argument {
        return None;
    }
    let braced = chars.get(*i).is_some_and(|(_, c)| *c == '{');
    if braced {
        *i += 1;
    }
    let mut ident = String::new();
    while let Some(&(_, c)) = chars.get(*i) {
        if c.is_ascii_alphanumeric() || c == '_' {
            ident.push(c);
            *i += 1;
        } else {
            break;
        }
    }
    if ident != name {
        return None;
    }
    if braced {
        if chars.get(*i)?.1 != '}' {
            return None;
        }
        *i += 1;
    }
    Some(MARKER.to_owned())
}

const MARKER: &str = "\u{1}";

fn substitute(item: &str, word: &str) -> Option<String> {
    // Every pipeline stage must start with a plain word: no marker, no
    // assignment, no shell keyword. A leading redirection such as
    // `2>/dev/null $f` would hide the real command word from this check, so a
    // stage that starts with one is rejected. A glob in the command word
    // (`/usr/bin/doc?er`) could name any program, so it keeps the loop on
    // the unmodeled path.
    for stage in item.split('|') {
        let first = stage.split_whitespace().next()?;
        let bare = first.trim_start_matches(|c: char| c.is_ascii_digit());
        if first.contains(MARKER)
            || first.contains('=')
            || bare.starts_with(['>', '<', '&'])
            || (first != "[" && first.contains(['*', '?', '[']))
            || CONTROL_WORDS.contains(&first)
        {
            return None;
        }
    }
    Some(item.replace(MARKER, word))
}

/// The redirect text after `done`, restricted to plain redirections.
fn redirect_tail(tail: &str) -> Option<String> {
    // Newlines after done start new commands and must not be trimmed away.
    let tail = tail.trim_start_matches([' ', '\t']).trim_end();
    if tail.is_empty() {
        return Some(String::new());
    }
    if !(tail.starts_with(['>', '<', '&']) || tail.starts_with(|c: char| c.is_ascii_digit())) {
        return None;
    }
    let bytes: Vec<char> = tail.chars().collect();
    for (index, &c) in bytes.iter().enumerate() {
        match c {
            ';' | '|' | '$' | '`' | '(' | ')' | '\n' | '{' | '}' | '#' | '\'' | '"' | '\\'
            | '*' | '?' | '[' | '~' => return None,
            '&' => {
                let prev = index.checked_sub(1).map(|i| bytes[i]);
                if !(prev == Some('>') || bytes.get(index + 1) == Some(&'>')) {
                    return None;
                }
            }
            '<' if bytes.get(index + 1) == Some(&'<') => return None,
            _ => {}
        }
    }
    Some(tail.to_owned())
}

/// `valid_identifier` already limits loop variables to lowercase names. The
/// `*_proxy` names are lowercase environment variables, and the zsh specials
/// change shell state, so binding either changes what the body would run.
fn ordinary_loop_name(name: &str) -> bool {
    !name.ends_with("_proxy") && !SHELL_SPECIAL_NAMES.contains(&name)
}
