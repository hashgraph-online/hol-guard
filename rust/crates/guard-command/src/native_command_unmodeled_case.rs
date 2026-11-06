//! The labels of a `case` construct.
//!
//! `case "$f" in *.ts|*.tsx) tsc "$f";; *) exit 1;; esac` matches its labels
//! where the shell would otherwise read a program, and a label is glob-shaped
//! by design. The owner scan read `*)` as a command word the shell builds at
//! run time and refused the whole construct, so an ordinary `case` blocked
//! outright with no approval left to give it, while the same construct spelled
//! with literal labels alone reached review. Taking the labels out leaves
//! every word the shell can actually run where it stood.
//!
//! Only a plainly written construct is read this way. A `(` anywhere in the
//! text may open a subshell, a function body or an extglob rather than a label
//! list, and a label holding an expansion, a substitution or a redirect could
//! name something of its own; either keeps the refusal it had.
//!
//! The words have to be the construct's own. `case` is a keyword only where
//! the shell still reads one, which is at the start of a command and after a
//! reserved word, never after a program such as `command`, `builtin` or
//! `nohup`: the shell reads `nohup case` as the program `case`, so it opens
//! nothing here either. A `#` comment runs to the end of its line, so neither
//! the keywords nor the `)` a comment holds take a label. Without both,
//! `echo case in; /usr/bin/pyth?n3 -c 'import os' # )` would have blanked away
//! the one word the shell builds at run time and handed the command the review
//! card it was refused.

/// The words after which the shell still reads a reserved word. A program that
/// runs another, `nohup` among them, is not one of them: after it the shell
/// reads a program name, so a `case` written there opens no construct.
const KEYWORD_POSITION: &[&str] = &[
    "do", "then", "else", "elif", "while", "until", "if", "!", "time", "{",
];

#[derive(Clone, Copy, PartialEq)]
enum Quote {
    None,
    Single,
    Double,
}

/// The text with every `case` label replaced by the command separator that
/// stood at its end, so the clause body keeps the command position the label
/// used to hold and nothing else moves.
pub(super) fn without_case_labels(text: &str) -> String {
    if text.contains('(') || !text.contains(')') {
        return text.to_owned();
    }
    let characters: Vec<char> = text.chars().collect();
    let mut blanked = characters.clone();
    let mut quote = Quote::None;
    let mut open = 0usize;
    let mut awaiting_in = false;
    let mut label: Option<usize> = None;
    let mut word: Option<usize> = None;
    let mut command_position = true;
    let mut index = 0usize;
    while index <= characters.len() {
        let current = characters.get(index).copied();
        let boundary = match (quote, current) {
            (Quote::None, None) => true,
            (Quote::None, Some(character)) => {
                character.is_whitespace() || matches!(character, ';' | ')' | '&' | '|')
            }
            _ => false,
        };
        if boundary {
            if let Some(start) = word.take() {
                let keyword: String = characters[start..index].iter().collect();
                match keyword.as_str() {
                    "case" if command_position => {
                        open += 1;
                        awaiting_in = true;
                    }
                    "in" if awaiting_in => {
                        awaiting_in = false;
                        label = Some(index);
                    }
                    "esac" if open > 0 => {
                        open -= 1;
                        label = None;
                    }
                    _ => {}
                }
                // Only a reserved word keeps the next word where the shell
                // still reads a reserved word.
                command_position = KEYWORD_POSITION.contains(&keyword.as_str());
            }
        } else if current.is_some_and(|character| !character.is_whitespace()) && word.is_none() {
            word = Some(index);
        }
        let Some(current) = current else { break };
        match quote {
            Quote::Single => {
                if current == '\'' {
                    quote = Quote::None;
                }
            }
            Quote::Double => match current {
                '\\' => index += 1,
                '"' => quote = Quote::None,
                _ => {}
            },
            Quote::None => match current {
                '\\' => index += 1,
                '\'' => quote = Quote::Single,
                '"' => quote = Quote::Double,
                // A comment runs to the end of its line. The shell reads no
                // keyword and no `)` inside one, so neither may take a label.
                '#' if word == Some(index) => {
                    word = None;
                    index = characters[index..]
                        .iter()
                        .position(|character| *character == '\n')
                        .map_or(characters.len() - 1, |offset| index + offset - 1);
                }
                ')' => {
                    if let Some(start) = label.take() {
                        if !take_label(&mut blanked, &characters, start, index) {
                            return text.to_owned();
                        }
                    }
                    command_position = true;
                }
                ';' | '&' | '|' | '\n' => {
                    command_position = true;
                    if current == ';' && open > 0 && characters.get(index + 1) == Some(&';') {
                        index += 1;
                        label = Some(index + 1);
                    }
                }
                _ => {}
            },
        }
        index += 1;
    }
    blanked.into_iter().collect()
}

/// Takes the label out, leaving a `;` where its `)` stood. The separator is
/// what keeps the clause body in command position: blanking the label away
/// entirely would join the body to the words before it, and the owner scan
/// reads only the first word of each command it finds.
///
/// A label is left alone, and the whole text with it, when it holds anything
/// the shell could read as more than a pattern. A pattern never holds a
/// command separator or a comment, so a span that does is a run of commands
/// that only looks like one, and the span has to read as a label list besides:
/// one pattern, or several with a `|` between them, and nothing else.
fn take_label(blanked: &mut [char], characters: &[char], start: usize, end: usize) -> bool {
    if characters[start..end]
        .iter()
        .any(|character| matches!(character, '$' | '`' | '<' | '>' | ';' | '&' | '#' | '\n'))
    {
        return false;
    }
    let span: String = characters[start..end].iter().collect();
    if !reads_as_a_label_list(&span) {
        return false;
    }
    for slot in &mut blanked[start..end] {
        *slot = ' ';
    }
    blanked[end] = ';';
    true
}

/// Whether the span between `in` and its `)` is a label list: `a`, or
/// `*.ts | *.tsx`, and nothing else. A pattern is a single word, so blanks
/// belong only around the `|` that separates two of them. A span holding
/// whitespace-separated words is a run of commands wearing a label's shape,
/// and one holding `{` or a nested keyword is a construct of its own.
fn reads_as_a_label_list(span: &str) -> bool {
    span.split('|').all(|pattern| {
        let pattern = pattern.trim();
        !pattern.is_empty() && !pattern.chars().any(char::is_whitespace)
    })
}

#[cfg(test)]
#[path = "native_command_unmodeled_case_tests.rs"]
mod tests;
