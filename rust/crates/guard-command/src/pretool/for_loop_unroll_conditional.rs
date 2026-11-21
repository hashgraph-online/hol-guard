//! An `if … fi` statement inside a `for` loop body.
//!
//! The body grammar reads a conditional as the plain items between its
//! keywords: `if [ -x "$p" ]`, `then echo "$p"` and `fi`. Those items only
//! mean something together, so each statement is written out once per word as
//! one step, with the loop word put into every command it holds. The
//! unrolled list is then a run of ordinary conditionals, which the
//! conditional rewrite reads in the next round, and the ordinary proofs decide
//! every command in it. A statement this reader does not follow exactly
//! (a nested `if`, a keyword in the wrong place, an empty branch, a
//! redirection on `fi`) keeps the loop on the unmodeled path.

use super::body::substitute;

/// Where the reader stands inside one conditional.
#[derive(Clone, Copy, PartialEq)]
enum Part {
    /// The test list after `if` or `elif`.
    Test,
    /// The list after `then`.
    Then,
    /// The list after `else`.
    Else,
}

/// The body items written out for `word`, each with the separator that
/// follows it. A plain item stays one step; a conditional becomes one step
/// holding the whole statement.
///
/// `tail` is the redirection written after `done`. It goes on every command
/// the steps run, inside a conditional as well, as the loop's redirection
/// covered each of them. The conditional rewrite reads a statement with a
/// redirection after `fi` only as a whole command, so writing it there
/// would keep a list holding the statement on the unmodeled path.
pub(super) fn written_steps(
    items: &[(String, &'static str)],
    word: &str,
    tail: &str,
) -> Option<Vec<(String, &'static str)>> {
    let word = &Words { word, tail };
    let mut steps = Vec::new();
    let mut open: Option<Conditional> = None;
    for (text, separator) in items {
        let (keyword, rest) = split_keyword(text);
        match open.as_mut() {
            None if keyword == Some("if") => {
                let mut conditional = Conditional::default();
                conditional.keyword("if", rest, separator, word)?;
                open = Some(conditional);
            }
            None => steps.push((
                word.with_tail(super::super::control_flow_flatten::unnegated_part(
                    &substitute(text, word.word)?,
                    separator,
                )),
                *separator,
            )),
            Some(conditional) => match keyword {
                Some("fi") => {
                    if !rest.is_empty() || !conditional.closable() {
                        return None;
                    }
                    conditional.text.push_str("fi");
                    steps.push((std::mem::take(&mut conditional.text), *separator));
                    open = None;
                }
                Some(keyword) => conditional.keyword(keyword, rest, separator, word)?,
                None => conditional.command(text, separator, word)?,
            },
        }
    }
    open.is_none().then_some(steps)
}

/// The loop word and the redirection every written command carries.
struct Words<'a> {
    word: &'a str,
    tail: &'a str,
}

impl Words<'_> {
    fn with_tail(&self, mut step: String) -> String {
        if !self.tail.is_empty() {
            step.push(' ');
            step.push_str(self.tail);
        }
        step
    }
}

/// A keyword this reader follows, and the item text after it.
fn split_keyword(text: &str) -> (Option<&'static str>, &str) {
    for keyword in ["if", "then", "elif", "else", "fi"] {
        if let Some(rest) = text.strip_prefix(keyword) {
            if rest.is_empty() || rest.starts_with([' ', '\t']) {
                return (Some(keyword), rest.trim_start());
            }
        }
    }
    (None, text)
}

/// One conditional being written out.
#[derive(Default)]
struct Conditional {
    text: String,
    part: Option<Part>,
    /// Whether the current part holds a command yet. The shell refuses an
    /// empty test or branch.
    has_command: bool,
    /// Whether the previous item ended in `; ` (or a newline), which is the
    /// only separator a keyword may follow.
    after_list: bool,
}

impl Conditional {
    fn closable(&self) -> bool {
        self.after_list && self.has_command && matches!(self.part, Some(Part::Then | Part::Else))
    }

    fn keyword(
        &mut self,
        keyword: &str,
        rest: &str,
        separator: &'static str,
        word: &Words<'_>,
    ) -> Option<()> {
        let next = match (keyword, self.part) {
            ("if", None) => Part::Test,
            ("then", Some(Part::Test)) | ("elif" | "else", Some(Part::Then))
                if self.after_list && self.has_command =>
            {
                if keyword == "elif" {
                    Part::Test
                } else if keyword == "else" {
                    Part::Else
                } else {
                    Part::Then
                }
            }
            // A nested `if` and every other order keeps its review.
            _ => return None,
        };
        self.part = Some(next);
        self.has_command = false;
        self.text.push_str(keyword);
        self.text.push(' ');
        if rest.is_empty() {
            // `then` on a line of its own reads as `then` followed by the
            // next command. Any other separator after a bare keyword is a
            // syntax error.
            if separator != "; " {
                return None;
            }
            self.after_list = true;
            return Some(());
        }
        self.command(rest, separator, word)
    }

    fn command(&mut self, text: &str, separator: &'static str, word: &Words<'_>) -> Option<()> {
        self.part?;
        self.text
            .push_str(&word.with_tail(substitute(text, word.word)?));
        self.text.push_str(separator);
        self.has_command = true;
        self.after_list = separator == "; ";
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn items(list: &[(&str, &'static str)]) -> Vec<(String, &'static str)> {
        list.iter()
            .map(|(text, separator)| ((*text).to_owned(), *separator))
            .collect()
    }

    #[test]
    fn a_conditional_becomes_one_step() {
        let steps = written_steps(
            &items(&[
                ("if [ -x a ]", "; "),
                ("then echo a", "; "),
                ("else echo none", "; "),
                ("fi", "; "),
                ("pwd", "; "),
            ]),
            "w",
            "",
        )
        .unwrap();
        assert_eq!(
            steps,
            vec![
                (
                    "if [ -x a ]; then echo a; else echo none; fi".to_owned(),
                    "; "
                ),
                ("pwd".to_owned(), "; ")
            ]
        );
    }

    #[test]
    fn a_keyword_on_its_own_line_joins_the_next_command() {
        let steps = written_steps(
            &items(&[
                ("if test -d a", " && "),
                ("test -r a", "; "),
                ("then", "; "),
                ("ls a", "; "),
                ("fi", "; "),
            ]),
            "w",
            "",
        )
        .unwrap();
        assert_eq!(steps[0].0, "if test -d a && test -r a; then ls a; fi");
    }

    #[test]
    fn the_loop_redirection_goes_on_every_command() {
        let steps = written_steps(
            &items(&[
                ("echo M", "; "),
                ("if test -f a", "; "),
                ("then head a", "; "),
                ("fi", "; "),
            ]),
            "w",
            "2>/dev/null",
        )
        .unwrap();
        assert_eq!(
            steps,
            vec![
                ("echo M 2>/dev/null".to_owned(), "; "),
                (
                    "if test -f a 2>/dev/null; then head a 2>/dev/null; fi".to_owned(),
                    "; "
                ),
            ]
        );
    }

    #[test]
    fn shapes_outside_the_statement_grammar_return_none() {
        for list in [
            // Nested conditional.
            vec![
                ("if true", "; "),
                ("then if true", "; "),
                ("then ls", "; "),
                ("fi", "; "),
                ("fi", "; "),
            ],
            // Empty branch.
            vec![("if true", "; "), ("then", "; "), ("fi", "; ")],
            // Keyword after `&&`.
            vec![("if true", " && "), ("then ls", "; "), ("fi", "; ")],
            // Redirection on `fi`.
            vec![("if true", "; "), ("then ls", "; "), ("fi > out", "; ")],
            // Never closed.
            vec![("if true", "; "), ("then ls", "; ")],
            // `else` before `then`.
            vec![("if true", "; "), ("else ls", "; "), ("fi", "; ")],
            // A stray `fi`.
            vec![("fi", "; ")],
        ] {
            assert!(written_steps(&items(&list), "w", "").is_none(), "{list:?}");
        }
    }
}
