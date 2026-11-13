//! Program source read the way its interpreter reads it: comments outside
//! string literals dropped, strings that span lines folded onto one line, and
//! code inside template and f-string replacement fields brought out of the
//! string, so the literal readers in the parent module see each command.

use super::super::Language;

/// `source` with each comment that starts outside a string literal removed:
/// `#` comments for Python, `//` and `/* */` comments for Node. A marker
/// inside a quoted string is kept, so `os.system("git reset --hard # note")`
/// still reads the whole command.
///
/// String state carries across lines. A Python triple-quoted string or a
/// backtick template stays open over line ends, and an escaped line end joins
/// the next line, as the interpreter does. A string that spans lines is
/// written back as one `"`-quoted line (inner `"` as `'`, line ends as `;`)
/// so the one-line literal readers pair its quotes the way the interpreter
/// does and still see each command inside it. A `${...}` in a Node template
/// runs as code, so it is written back outside the string.
pub(in crate::pretool::script_content) fn without_comments(
    language: Language,
    source: &str,
) -> String {
    let mut code = String::with_capacity(source.len());
    let mut quote: Option<&'static str> = None;
    // Each `${...}` or Python `{...}` replacement field the scan is inside:
    // its open brace depth, the string it returns to and whether that string
    // is a Python f-string.
    let mut interpolations: Vec<(usize, &'static str, bool)> = Vec::new();
    // Whether the open string is a Python f-string.
    let mut formatted = false;
    let mut in_block = false;
    let mut in_line_comment = false;
    let mut chars = source.char_indices();
    while let Some((at, ch)) = chars.next() {
        let rest = &source[at..];
        if let Some(close) = quote {
            let spans_lines = close.len() == 3 || close == "`";
            if ch == '\\' {
                match chars.next() {
                    // A line continuation inside a string adds nothing.
                    Some((_, '\n')) => {}
                    Some((_, '"')) if spans_lines => code.push_str("\\'"),
                    Some((_, escaped)) => {
                        code.push(ch);
                        code.push(escaped);
                    }
                    None => code.push(ch),
                }
            } else if rest.starts_with(close) {
                code.push_str(if spans_lines { "\"" } else { close });
                // Delimiters are ASCII, one char per byte.
                for _ in 1..close.len() {
                    chars.next();
                }
                quote = None;
                formatted = false;
            } else if close == "`" && rest.starts_with("${") {
                code.push_str("\"+(");
                chars.next();
                interpolations.push((0, close, false));
                quote = None;
            } else if formatted && (rest.starts_with("{{") || rest.starts_with("}}")) {
                code.push_str(&rest[..2]);
                chars.next();
            } else if formatted && ch == '{' {
                code.push_str(if spans_lines { "\"" } else { close });
                code.push_str("+(");
                interpolations.push((0, close, true));
                quote = None;
                formatted = false;
            } else if spans_lines {
                code.push(match ch {
                    '\n' => ';',
                    '"' => '\'',
                    other => other,
                });
            } else if ch == '\n' {
                // A one-quote string cannot span a bare line end.
                quote = None;
                code.push(ch);
            } else {
                code.push(ch);
            }
            continue;
        }
        if ch == '\n' {
            in_line_comment = false;
            code.push(ch);
            continue;
        }
        if in_line_comment {
            continue;
        }
        if in_block {
            if rest.starts_with("*/") {
                chars.next();
                in_block = false;
            }
            continue;
        }
        match language {
            Language::Python if ch == '#' => {
                in_line_comment = true;
                continue;
            }
            Language::Node if rest.starts_with("//") => {
                in_line_comment = true;
                continue;
            }
            Language::Node if rest.starts_with("/*") => {
                chars.next();
                in_block = true;
                continue;
            }
            _ => {}
        }
        if let Some((depth, close, was_formatted)) = interpolations.last_mut() {
            match ch {
                '{' => *depth += 1,
                '}' if *depth == 0 => {
                    let (close, was_formatted) = (*close, *was_formatted);
                    interpolations.pop();
                    let spans_lines = close.len() == 3 || close == "`";
                    code.push_str(")+");
                    code.push_str(if spans_lines { "\"" } else { close });
                    quote = Some(close);
                    formatted = was_formatted;
                    continue;
                }
                '}' => *depth -= 1,
                _ => {}
            }
        }
        let opened = match ch {
            '"' if language == Language::Python && rest.starts_with("\"\"\"") => Some("\"\"\""),
            '\'' if language == Language::Python && rest.starts_with("'''") => Some("'''"),
            '"' => Some("\""),
            '\'' => Some("'"),
            '`' => Some("`"),
            _ => None,
        };
        if let Some(open) = opened {
            formatted = language == Language::Python && f_string_prefix(&source[..at]);
            let spans_lines = open.len() == 3 || open == "`";
            code.push_str(if spans_lines { "\"" } else { open });
            for _ in 1..open.len() {
                chars.next();
            }
            quote = Some(open);
            continue;
        }
        code.push(ch);
    }
    code
}

/// Whether `before` ends in a Python string prefix that makes the string an
/// f-string (`f`, `rf`, `Fr`), not part of a longer name.
fn f_string_prefix(before: &str) -> bool {
    let prefix: String = before
        .chars()
        .rev()
        .take_while(char::is_ascii_alphabetic)
        .collect();
    let head = &before[..before.len() - prefix.len()];
    prefix.len() <= 2
        && prefix.to_ascii_lowercase().contains('f')
        && prefix
            .to_ascii_lowercase()
            .chars()
            .all(|letter| matches!(letter, 'f' | 'r'))
        && !head.ends_with(|ch: char| ch.is_alphanumeric() || ch == '_')
}
