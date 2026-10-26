//! Which braced parameter expansions carry no evaluation of their own.
//!
//! `${NAME}` substitutes a value the shell then splits into words, so the
//! text still names every program it runs. Several other brace forms do not
//! stop at substitution: `${NAME@P}` expands the value as a prompt, which
//! performs command substitution; the `${NAME:OFFSET}` and `${NAME:OFF:LEN}`
//! offsets, `${ARRAY[INDEX]}` subscripts and `${!NAME}` indirection evaluate
//! their contents as arithmetic, which does the same; `${NAME:=WORD}` and
//! `${NAME/PATTERN/WORD}` change shell state or expand a replacement. A value
//! reaches those forms without an assignment the text shows (`printf -v`),
//! so only the forms whose bodies cannot evaluate are read as values.

/// Every `${...}` in the text substitutes a value and nothing else.
pub(super) fn expansions_are_inert(text: &str) -> bool {
    let mut rest = text;
    while let Some(at) = rest.find("${") {
        let body = &rest[at + 2..];
        let Some(close) = body.find('}') else {
            return false;
        };
        if !inert_body(&body[..close]) {
            return false;
        }
        rest = &body[close + 1..];
    }
    true
}

/// The text between `${` and its `}`: a name, optionally with an operator
/// that substitutes a literal word.
fn inert_body(body: &str) -> bool {
    // `${#NAME}` is the value's length.
    let body = body.strip_prefix('#').unwrap_or(body);
    let end = body
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(body.len());
    let (name, operator) = body.split_at(end);
    if name.is_empty() {
        return false;
    }
    let word = if operator.is_empty() {
        return true;
    } else if let Some(rest) = operator.strip_prefix(':') {
        // `:-`, `:+` and `:?` substitute. A `:` followed by anything else is
        // either the assigning `:=` or an arithmetic offset.
        match rest.strip_prefix(['-', '+', '?']) {
            Some(word) => word,
            None => return false,
        }
    } else if let Some(rest) = operator
        .strip_prefix("##")
        .or_else(|| operator.strip_prefix('#'))
        .or_else(|| operator.strip_prefix("%%"))
        .or_else(|| operator.strip_prefix('%'))
        .or_else(|| operator.strip_prefix(['-', '+', '?']))
    {
        rest
    } else {
        // `@` transformations, `[` subscripts, `=` assignment and `/`
        // replacement all evaluate their contents or change shell state.
        return false;
    };
    // The word is substituted, so an expansion inside it runs there instead.
    !word.contains(['$', '`'])
}

#[cfg(test)]
#[path = "native_command_unmodeled_expansion_body_tests.rs"]
mod tests;
