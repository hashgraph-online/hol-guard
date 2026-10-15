//! Words and list operators of the plain `&&` / `;` lists that chain
//! literal substitution understands, and the word scans that decide whether
//! a command could set a variable behind its back.

#[derive(Clone, Copy, PartialEq)]
pub(super) enum Token {
    Word(usize, usize),
    Pipe,
    And,
    Sequence,
}

/// Shell words and list operators. `None` for any construct that can run
/// code, group commands, branch or expand in ways this pass does not model.
pub(super) fn tokenize(chars: &[char]) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut start: Option<usize> = None;
    let mut index = 0usize;
    while index < chars.len() {
        let c = chars[index];
        let previous = index.checked_sub(1).map(|i| chars[i]);
        let next = chars.get(index + 1).copied();
        let operator = match c {
            ' ' | '\t' => Some(None),
            '|' if previous == Some('>') => None,
            '|' if matches!(next, Some('|' | '&')) => return None,
            '|' => Some(Some((Token::Pipe, 1))),
            '&' if next == Some('&') => Some(Some((Token::And, 2))),
            '&' if next == Some('>') || matches!(previous, Some('>' | '<')) => None,
            '&' => return None,
            ';' if matches!(next, Some(';' | '&')) => return None,
            ';' => Some(Some((Token::Sequence, 1))),
            '<' if next == Some('<') => return None,
            '`' | '(' | ')' | '{' | '}' => return None,
            '#' if start.is_none() => return None,
            _ => None,
        };
        if let Some(operator) = operator {
            if let Some(word) = start.take() {
                tokens.push(Token::Word(word, index));
            }
            let width = operator.map_or(1, |(token, width)| {
                tokens.push(token);
                width
            });
            index += width;
            continue;
        }
        start.get_or_insert(index);
        index = match c {
            '\\' => index + 2,
            '\'' => index + 1 + chars[index + 1..].iter().position(|&c| c == '\'')? + 1,
            '"' => double_quoted_end(chars, index + 1)?,
            '$' => expansion_end(chars, index)?,
            _ => index + 1,
        };
        if index > chars.len() {
            return None;
        }
    }
    if let Some(word) = start {
        tokens.push(Token::Word(word, chars.len()));
    }
    Some(tokens)
}

/// The index after the closing quote of a double-quoted string starting at
/// `index`; `None` when it substitutes a command or is unterminated.
fn double_quoted_end(chars: &[char], mut index: usize) -> Option<usize> {
    while index < chars.len() {
        match chars[index] {
            '"' => return Some(index + 1),
            '\\' => index += 2,
            '`' => return None,
            '$' => index = expansion_end(chars, index)?,
            _ => index += 1,
        }
    }
    None
}

/// The index after a `$` expansion: `$NAME`, `${NAME}`, a special parameter
/// or a lone `$`. Command and arithmetic substitution, ANSI-C and locale
/// quoting, and any other `${...}` form are refused.
fn expansion_end(chars: &[char], index: usize) -> Option<usize> {
    match chars.get(index + 1) {
        Some('(' | '\'' | '"' | '[') => None,
        Some('{') => {
            let close = chars[index + 2..].iter().position(|&c| c == '}')? + index + 2;
            let name: String = chars[index + 2..close].iter().collect();
            identifier(&name).then_some(close + 1)
        }
        _ => Some(index + 1),
    }
}

/// A pipeline stage's words as `(start, end)` spans.
pub(super) type Stage = Vec<(usize, usize)>;

/// `(stages, separator)` for each `&&` / `;` list item; a trailing `;` is
/// allowed, an empty item or stage is not.
pub(super) fn items(tokens: &[Token]) -> Option<Vec<(Vec<Stage>, Token)>> {
    let mut items = Vec::new();
    let mut stages = vec![Vec::new()];
    for (position, token) in tokens.iter().enumerate() {
        match *token {
            Token::Word(start, end) => stages.last_mut()?.push((start, end)),
            Token::Pipe => {
                if stages.last()?.is_empty() {
                    return None;
                }
                stages.push(Vec::new());
            }
            separator => {
                if stages.iter().any(Vec::is_empty) {
                    return None;
                }
                items.push((std::mem::replace(&mut stages, vec![Vec::new()]), separator));
                if separator == Token::And && position + 1 == tokens.len() {
                    return None;
                }
            }
        }
    }
    if stages.iter().any(|stage| !stage.is_empty()) {
        if stages.iter().any(Vec::is_empty) {
            return None;
        }
        items.push((stages, Token::Sequence));
    }
    (!items.is_empty()).then_some(items)
}

pub(super) fn identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Whether `text` names a variable `target` accepts as a bare word or as the
/// operand of an attached flag such as `-vNAME`, the forms in which a builtin
/// takes a variable to set. `$NAME` and `${NAME}` are uses, not targets.
/// Quotes and escapes are removed first, as the shell removes them before
/// the builtin sees `O"UT"`, `'O'UT` or `O\UT` as `OUT`.
pub(super) fn names_variable(text: &str, target: impl Fn(&str) -> bool) -> bool {
    let mut previous = ' ';
    let mut opener = ' ';
    let mut token = String::new();
    let dequoted = text.chars().filter(|c| !matches!(c, '\'' | '"' | '\\'));
    for c in dequoted.chain(std::iter::once(' ')) {
        if c == '_' || c.is_ascii_alphanumeric() {
            if token.is_empty() {
                opener = previous;
            }
            token.push(c);
        } else if !token.is_empty() {
            let named = match opener {
                '$' | '{' => false,
                '-' => (1..token.len()).any(|split| {
                    token[..split].bytes().all(|b| b.is_ascii_alphabetic())
                        && target(&token[split..])
                }),
                _ => target(&token),
            };
            if named {
                return true;
            }
            token.clear();
        }
        previous = c;
    }
    false
}

/// Whether a word can still expand to text this pass did not see: an
/// unresolved expansion, or an unquoted glob that could match a file named
/// after a variable.
pub(super) fn opaque(word: &str) -> bool {
    let (mut single, mut double, mut escaped) = (false, false, false);
    for c in word.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '$' if !single => return true,
            '*' | '?' | '[' if !single && !double => return true,
            _ => {}
        }
    }
    false
}
