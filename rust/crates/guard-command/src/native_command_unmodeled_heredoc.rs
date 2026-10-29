//! The one heredoc a command's first line opens.
//!
//! A heredoc puts literal bytes on standard input. What matters to a review is
//! where that body ends, because everything under the delimiter is data while
//! everything beside it on the line is still command text. A delimiter read
//! wrong moves that boundary, and whatever lands on the wrong side of it is
//! either hidden from the review or kept from reaching one.

/// The one heredoc a first line opens: what runs before it, what follows its
/// delimiter on the same line, the delimiter itself and the body under it.
/// A second `<<` on that line opens a heredoc this reading does not hold.
pub(super) struct FirstHeredoc<'a> {
    pub(super) before: &'a str,
    pub(super) trailing: &'a str,
    pub(super) delimiter: &'a str,
    pub(super) quoted: bool,
    pub(super) body: &'a str,
}

pub(super) fn first_heredoc(text: &str) -> Option<FirstHeredoc<'_>> {
    let (line, body) = text.split_once('\n')?;
    let (before, after) = line.split_once("<<")?;
    let after = after.strip_prefix('-').unwrap_or(after).trim_start();
    let (delimiter, quoted, trailing) = delimiter_word(after)?;
    (!trailing.contains("<<")).then_some(FirstHeredoc {
        before,
        trailing,
        delimiter,
        quoted,
        body,
    })
}

/// The delimiter a `<<` names, read the way the shell reads it: one word,
/// ending where the word ends.
///
/// Two spellings say plainly what the delimiter is. An unquoted run of
/// ordinary characters is its own text, and a word inside one pair of quotes
/// is the text between them. Every other spelling — a word quoted in parts, a
/// backslash, a quote the line never closes, anything glued to the closing
/// quote — names a delimiter whose text differs from what the line shows, and
/// that difference moves the end of the body. The shell ends `<<'EOF'x` at
/// `EOFx`, so reading it as `EOF` would hand the review a body that still
/// holds the commands the shell is about to run.
fn delimiter_word(after: &str) -> Option<(&str, bool, &str)> {
    if let Some(quote) = after.chars().next().filter(|c| matches!(c, '\'' | '"')) {
        let inside = &after[quote.len_utf8()..];
        let end = inside.find(quote)?;
        let trailing = &inside[end + quote.len_utf8()..];
        return ends_the_word(trailing).then_some((&inside[..end], true, trailing));
    }
    let end = after
        .find(|current: char| !plain_delimiter_char(current))
        .unwrap_or(after.len());
    let (delimiter, trailing) = after.split_at(end);
    (!delimiter.is_empty() && ends_the_word(trailing)).then_some((delimiter, false, trailing))
}

/// Whether the word ends here: at the end of the line, at whitespace, or at an
/// operator that starts the next piece of the command.
fn ends_the_word(trailing: &str) -> bool {
    trailing.chars().next().is_none_or(|current| {
        current.is_whitespace() || matches!(current, ';' | '|' | '&' | '<' | '>' | '(' | ')')
    })
}

/// The characters an unquoted delimiter may be written with. Quote removal
/// leaves such a word exactly as written, so the characters on the line are
/// the delimiter. A quote, a backslash or an expansion makes it something
/// else, so none of them belongs here.
fn plain_delimiter_char(current: char) -> bool {
    current.is_ascii_alphanumeric()
        || matches!(current, '_' | '-' | '.' | '+' | ':' | '@' | '%' | ',' | '/')
}

/// One heredoc on the first line whose body cannot run commands: its
/// delimiter is quoted, or the body expands nothing. The heredoc need not end
/// the line. What follows the delimiter is the rest of the command, so it
/// answers for its own data movement the way the text around it does.
/// Reading the delimiter as everything left on the line left
/// `sort <<'EOF' > out.txt` unparseable here, and an unparseable shape has no
/// floor to reach, which blocks it outright with no approval left to give it.
pub(super) fn input_heredoc(text: &str) -> bool {
    let Some(heredoc) = first_heredoc(text) else {
        return false;
    };
    if !super::plain_after_heredocs(&format!("{}{}", heredoc.before, heredoc.trailing)) {
        return false;
    }
    let mut lines: Vec<&str> = heredoc.body.lines().collect();
    if lines.pop().map(str::trim) != Some(heredoc.delimiter)
        || lines.iter().any(|body| body.trim() == heredoc.delimiter)
    {
        return false;
    }
    heredoc.quoted || lines.iter().all(|body| !body.contains(['$', '`', '\\']))
}

#[cfg(test)]
#[path = "native_command_unmodeled_heredoc_tests.rs"]
mod tests;
