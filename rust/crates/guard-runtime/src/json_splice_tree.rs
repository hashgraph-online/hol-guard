//! The byte layout of a JSON document for [`super`]: each value's span,
//! and the whitespace around every member and item.

use std::ops::Range;

use crate::pyjson::{self, PyVal};

use super::parse;

pub(super) struct Tree<'a> {
    pub(super) text: &'a str,
    pub(super) root: Node,
}

pub(super) struct Node {
    pub(super) span: Range<usize>,
    pub(super) value: PyVal,
    pub(super) kind: Kind,
}

pub(super) enum Kind {
    Scalar,
    Object {
        members: Vec<Member>,
        close: Range<usize>,
    },
    Array {
        items: Vec<Item>,
        close: Range<usize>,
    },
}

pub(super) struct Member {
    pub(super) name: String,
    pub(super) lead: Range<usize>,
    /// The key string and the `:` with its whitespace, up to the value.
    pub(super) head: Range<usize>,
    pub(super) value: Node,
    /// Whitespace between the value and the following `,`.
    pub(super) tail: Range<usize>,
}

pub(super) struct Item {
    pub(super) lead: Range<usize>,
    pub(super) value: Node,
    pub(super) tail: Range<usize>,
}

impl<'a> Tree<'a> {
    pub(super) fn read(text: &'a str) -> Option<Self> {
        let value = pyjson::parse_unique(text).ok()?;
        // A value holding a lone surrogate escape has no faithful string
        // form to compare, so it is never spliced.
        if parse(text)? != value {
            return None;
        }
        let mut scanner = Scanner {
            bytes: text.as_bytes(),
            at: 0,
        };
        let start = scanner.space();
        let mut root = scanner.value(0)?;
        let end = scanner.space();
        if end.end != text.len() || start.end != root.span.start {
            return None;
        }
        fill(&mut root, value)?;
        Some(Self { text, root })
    }

    pub(super) fn slice(&self, range: &Range<usize>) -> &'a str {
        &self.text[range.clone()]
    }
}

/// Hand each node the parsed value at its position.
pub(super) fn fill(node: &mut Node, value: PyVal) -> Option<()> {
    match (&mut node.kind, &value) {
        (Kind::Scalar, PyVal::List(_) | PyVal::Dict(_)) => return None,
        (Kind::Scalar, _) => {}
        (Kind::Object { members, .. }, PyVal::Dict(entries)) => {
            if members.len() != entries.len() {
                return None;
            }
            for (member, (name, child)) in members.iter_mut().zip(entries) {
                member.name.clone_from(name);
                fill(&mut member.value, child.clone())?;
            }
        }
        (Kind::Array { items, .. }, PyVal::List(children)) => {
            if items.len() != children.len() {
                return None;
            }
            for (item, child) in items.iter_mut().zip(children) {
                fill(&mut item.value, child.clone())?;
            }
        }
        _ => return None,
    }
    node.value = value;
    Some(())
}

pub(super) struct Scanner<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) at: usize,
}

impl Scanner<'_> {
    fn space(&mut self) -> Range<usize> {
        let start = self.at;
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
        start..self.at
    }

    fn eat(&mut self, byte: u8) -> Option<()> {
        (self.bytes.get(self.at) == Some(&byte)).then(|| self.at += 1)
    }

    fn value(&mut self, depth: usize) -> Option<Node> {
        if depth > 900 {
            return None;
        }
        let start = self.at;
        let kind = match self.bytes.get(self.at)? {
            b'{' => self.object(depth)?,
            b'[' => self.array(depth)?,
            b'"' => {
                self.string()?;
                Kind::Scalar
            }
            _ => {
                while !matches!(
                    self.bytes.get(self.at),
                    None | Some(b',' | b']' | b'}' | b':' | b' ' | b'\t' | b'\n' | b'\r')
                ) {
                    self.at += 1;
                }
                if self.at == start {
                    return None;
                }
                Kind::Scalar
            }
        };
        Some(Node {
            span: start..self.at,
            value: PyVal::Null,
            kind,
        })
    }

    fn string(&mut self) -> Option<()> {
        self.eat(b'"')?;
        loop {
            match self.bytes.get(self.at)? {
                b'"' => {
                    self.at += 1;
                    return Some(());
                }
                b'\\' => self.at += 2,
                _ => self.at += 1,
            }
        }
    }

    fn object(&mut self, depth: usize) -> Option<Kind> {
        self.eat(b'{')?;
        let mut members = Vec::new();
        let first = self.space();
        if self.eat(b'}').is_some() {
            return Some(Kind::Object {
                members,
                close: first,
            });
        }
        let mut lead = first;
        loop {
            let head_start = self.at;
            self.string()?;
            self.space();
            self.eat(b':')?;
            self.space();
            let head = head_start..self.at;
            let value = self.value(depth + 1)?;
            let after = self.space();
            let member = |tail| Member {
                name: String::new(),
                lead: lead.clone(),
                head: head.clone(),
                value,
                tail,
            };
            if self.eat(b',').is_some() {
                members.push(member(after));
                lead = self.space();
                continue;
            }
            self.eat(b'}')?;
            let end = after.end;
            members.push(member(end..end));
            return Some(Kind::Object {
                members,
                close: after,
            });
        }
    }

    fn array(&mut self, depth: usize) -> Option<Kind> {
        self.eat(b'[')?;
        let mut items = Vec::new();
        let first = self.space();
        if self.eat(b']').is_some() {
            return Some(Kind::Array {
                items,
                close: first,
            });
        }
        let mut lead = first;
        loop {
            let value = self.value(depth + 1)?;
            let after = self.space();
            if self.eat(b',').is_some() {
                items.push(Item {
                    lead,
                    value,
                    tail: after,
                });
                lead = self.space();
                continue;
            }
            self.eat(b']')?;
            let end = after.end;
            items.push(Item {
                lead,
                value,
                tail: end..end,
            });
            return Some(Kind::Array {
                items,
                close: after,
            });
        }
    }
}
