//! Whether the shell passes a character through to the program unchanged.

/// True when every `target` in the raw segment text is literal: inside single
/// quotes, or escaped with a backslash, so the shell passes it through instead
/// of expanding a variable or running a command substitution.
pub(crate) fn literal_everywhere(text: &str, target: char) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for character in text.chars() {
        match quote {
            Some('\'') => {
                if character == '\'' {
                    quote = None;
                }
            }
            _ if escaped => escaped = false,
            _ if character == '\\' => escaped = true,
            _ if character == target => return false,
            Some(_) if character == '"' => quote = None,
            None if matches!(character, '\'' | '"') => quote = Some(character),
            _ => {}
        }
    }
    true
}
