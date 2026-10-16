/// True when the command visibly leaves a quote open, so the shell would stop
/// with a syntax error instead of running it. This only chooses the wording of
/// a stop; it never relaxes one. Heredocs, comments, ANSI-C quotes and command
/// substitutions are skipped, because their quotes do not follow the plain
/// rules and the claim could be wrong. A `#` inside quotes or a word (`"fix
/// #12`) is plain text, so only one that starts an unquoted word is a comment.
pub(super) fn leaves_quote_open(command: &str) -> bool {
    if ["<<", "$'", "$(", "`"]
        .iter()
        .any(|marker| command.contains(marker))
    {
        return false;
    }
    let (mut quote, mut escaped, mut word_start) = (None, false, true);
    for character in command.chars() {
        match quote {
            Some('\'') if character == '\'' => quote = None,
            Some('\'') => {}
            Some(_) if escaped => escaped = false,
            Some(_) if character == '"' => quote = None,
            Some(_) => escaped = character == '\\',
            None if escaped => escaped = false,
            None if character == '#' && word_start => return false,
            None if character == '\\' => escaped = true,
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None => {}
        }
        word_start = quote.is_none()
            && !escaped
            && (character.is_whitespace() || ";&|()".contains(character));
    }
    quote.is_some()
}

#[cfg(test)]
#[path = "open_quote_tests.rs"]
mod tests;
