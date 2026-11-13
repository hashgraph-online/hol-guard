//! Shell words and the boundaries between simple commands.
//!
//! Unlike a plain word split, this keeps unquoted `;`, `&`, `|`, parentheses,
//! backticks and newlines as boundaries, so `echo ';' rm x` stays one command
//! and `echo ready` followed by `rm x` on the next line becomes two. Quoted
//! text stays inside its word. An unclosed quote runs to the end of the
//! command, so a malformed command still yields its words.

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Token {
    Word(String),
    /// Ends a simple command.
    Boundary,
    /// `<`, `>` and their variants: the next word is a redirection target.
    Redirect,
}

pub(super) fn tokens(command: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = command.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                for quoted in chars.by_ref() {
                    if quoted == '\'' {
                        break;
                    }
                    word.push(quoted);
                }
            }
            '"' => {
                in_word = true;
                while let Some(quoted) = chars.next() {
                    match quoted {
                        '"' => break,
                        '\\' => match chars.next() {
                            Some(escaped @ ('"' | '\\' | '$' | '`')) => word.push(escaped),
                            Some('\n') | None => {}
                            Some(other) => {
                                word.push('\\');
                                word.push(other);
                            }
                        },
                        _ => word.push(quoted),
                    }
                }
            }
            '\\' => {
                if let Some(escaped) = chars.next().filter(|next| *next != '\n') {
                    in_word = true;
                    word.push(escaped);
                }
            }
            '#' if !in_word => while chars.next_if(|next| *next != '\n').is_some() {},
            ' ' | '\t' | '\r' => finish(&mut out, &mut word, &mut in_word),
            '\n' | ';' | '|' | '(' | ')' | '`' => {
                finish(&mut out, &mut word, &mut in_word);
                out.push(Token::Boundary);
            }
            '&' => {
                finish(&mut out, &mut word, &mut in_word);
                if chars.next_if_eq(&'>').is_some() {
                    chars.next_if_eq(&'>');
                    out.push(Token::Redirect);
                } else {
                    out.push(Token::Boundary);
                }
            }
            '<' | '>' => {
                // A descriptor number before the operator (`2>`) is not a word.
                if in_word && !word.is_empty() && word.chars().all(|d| d.is_ascii_digit()) {
                    word.clear();
                    in_word = false;
                } else {
                    finish(&mut out, &mut word, &mut in_word);
                }
                while chars.next_if(|next| matches!(next, '<' | '>')).is_some() {}
                if chars.next_if_eq(&'&').is_some() {
                    // `>&2` copies a descriptor and names no file.
                    while chars
                        .next_if(|next| next.is_ascii_digit() || *next == '-')
                        .is_some()
                    {}
                } else if chars.peek() != Some(&'(') {
                    // `<(...)` is a process substitution: its `(` is a boundary.
                    out.push(Token::Redirect);
                }
            }
            _ => {
                in_word = true;
                word.push(c);
            }
        }
    }
    finish(&mut out, &mut word, &mut in_word);
    out
}

fn finish(out: &mut Vec<Token>, word: &mut String, in_word: &mut bool) {
    if *in_word {
        out.push(Token::Word(std::mem::take(word)));
        *in_word = false;
    }
}
