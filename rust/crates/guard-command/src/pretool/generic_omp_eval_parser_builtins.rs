//! Global helpers an eval program may use to look at a value: `JSON.stringify`,
//! `typeof`, and the `Object` functions that list a value's keys or reach its
//! prototype. None of them calls anything on the value, so each only adds
//! what its argument already records.

use super::super::tokens::Token;
use super::Parser;

impl Parser {
    /// The helper `word` names, with the cursor just after it.
    pub(super) fn builtin(&mut self, word: &str, depth: usize) -> Option<()> {
        match word {
            "JSON" => {
                self.eat('.')?;
                self.eat_ident("stringify")?;
                self.one_arg(depth)
            }
            // `typeof x` binds tighter than any operator the grammar takes,
            // so its operand is the value that follows, postfix included.
            "typeof" if self.typeof_draft_method() => Some(()),
            "typeof" => self.value(depth + 1),
            "Object" => {
                self.eat('.')?;
                match self.next()? {
                    Token::Ident(name)
                        if matches!(
                            name.as_str(),
                            "keys" | "getOwnPropertyNames" | "getPrototypeOf"
                        ) =>
                    {
                        self.one_arg(depth)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn one_arg(&mut self, depth: usize) -> Option<()> {
        self.eat('(')?;
        self.value(depth + 1)?;
        self.eat(')')
    }
}
