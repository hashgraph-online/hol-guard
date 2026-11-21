//! The in-page arrow function `TAB.evaluate` accepts, for the browser eval
//! parser in `generic_omp_eval_browser.rs`.

use super::lex::{page_token, Token, RESERVED};
use super::{Parser, MAX_DEPTH};

impl Parser {
    /// The arrow function `evaluate` serializes into the page, with plain
    /// identifier parameters and a body that passes `page_token`. It must
    /// end at the argument, so it is passed rather than called in place.
    pub(super) fn page_function(&mut self) -> Option<()> {
        if self.peek_ident("async") {
            self.pos += 1;
        }
        if self.eat_punct('(') {
            if !self.eat_punct(')') {
                loop {
                    let param = self.ident()?;
                    if RESERVED.contains(&param.as_str()) {
                        return None;
                    }
                    if self.eat_punct(')') {
                        break;
                    }
                    self.punct(',')?;
                }
            }
        } else if RESERVED.contains(&self.ident()?.as_str()) {
            return None;
        }
        self.punct('=')?;
        self.punct('>')?;
        let block = self.peek() == Some(&Token::Punct('{'));
        let mut stack: Vec<char> = Vec::new();
        loop {
            if self.pos >= self.tokens.len() || !page_token(&self.tokens, self.pos) {
                return None;
            }
            match self.peek()?.clone() {
                Token::Punct(',' | ')') if stack.is_empty() => break,
                Token::Punct(c @ ('(' | '[' | '{')) => {
                    stack.push(match c {
                        '(' => ')',
                        '[' => ']',
                        _ => '}',
                    });
                    if stack.len() > MAX_DEPTH * 4 {
                        return None;
                    }
                }
                Token::Punct(c @ (')' | ']' | '}')) => {
                    if stack.pop() != Some(c) {
                        return None;
                    }
                    self.pos += 1;
                    if block && stack.is_empty() {
                        // A block body ends at its brace; only the next
                        // argument or the call's close may follow.
                        return matches!(self.peek(), Some(Token::Punct(',' | ')'))).then_some(());
                    }
                    continue;
                }
                _ => {}
            }
            self.pos += 1;
        }
        Some(())
    }
}
