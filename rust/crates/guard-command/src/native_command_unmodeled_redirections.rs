//! Shell redirections blanked out of text the unmodeled floor scans by hand.

/// `shell` with every unquoted redirection and its target blanked, so a
/// leading `</dev/null`, `2>&1`, `>&log` or `>|log` cannot hide the program
/// it feeds once the text is split at `&` and `|`.
pub(super) fn without_redirections(shell: &str) -> String {
    let chars: Vec<char> = shell.chars().collect();
    let mut kept = String::with_capacity(shell.len());
    let mut quote = None;
    let mut index = 0;
    while index < chars.len() {
        let character = chars[index];
        if let Some(open) = quote {
            quote = (character != open).then_some(open);
            kept.push(character);
            index += 1;
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            kept.push(character);
            index += 1;
            continue;
        }
        let word_start =
            index == 0 || chars[index - 1].is_whitespace() || ";&|(){}`".contains(chars[index - 1]);
        let mut operator = index;
        if word_start {
            while operator < chars.len() && chars[operator].is_ascii_digit() {
                operator += 1;
            }
        }
        if character == '&' && chars.get(index + 1) == Some(&'>') {
            operator = index + 1;
        } else if !matches!(chars.get(operator), Some('<' | '>'))
            || (operator > index && !word_start)
        {
            kept.push(character);
            index += 1;
            continue;
        }
        let mut end = operator;
        while end < chars.len() && matches!(chars[end], '<' | '>') {
            end += 1;
        }
        if matches!(chars.get(end), Some('&' | '|')) {
            end += 1;
        }
        while end < chars.len() && chars[end].is_whitespace() {
            end += 1;
        }
        let mut target_quote = None;
        while end < chars.len() {
            let next = chars[end];
            match target_quote {
                Some(open) if next == open => target_quote = None,
                Some(_) => {}
                None if matches!(next, '\'' | '"') => target_quote = Some(next),
                None if next.is_whitespace() || ";&|()<>`".contains(next) => break,
                None => {}
            }
            end += 1;
        }
        kept.push(' ');
        index = end;
    }
    kept
}
