//! The Python syntax a Codex hook launcher check reads: literal strings and
//! integers, call arguments and literal sequences, from a tree-sitter parse.
//!
//! Each reader answers what Python's `ast` module would: parentheses around
//! an expression are transparent, an f-string or a bytes literal is not a
//! string constant, and a starred element is spread only when it spreads a
//! literal sequence itself.

use tree_sitter::Node;

/// An expression, or the list a starred assignment target collects.
#[derive(Clone, Copy)]
pub(super) enum Expr<'a, 't> {
    Node(Node<'t>),
    List(&'a [Node<'t>]),
}

/// The named children, without comments.
pub(super) fn kids<'t>(node: Node<'t>) -> Vec<Node<'t>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect()
}

/// The named nodes of one field, in order.
pub(super) fn field_nodes<'t>(node: Node<'t>, name: &str) -> Vec<Node<'t>> {
    let mut cursor = node.walk();
    node.children_by_field_name(name, &mut cursor)
        .filter(Node::is_named)
        .collect()
}

/// The expression inside any parentheses.
pub(super) fn bare(mut node: Node<'_>) -> Node<'_> {
    while node.kind() == "parenthesized_expression" {
        match kids(node).as_slice() {
            [inner] if !matches!(inner.kind(), "yield" | "list_splat") => node = *inner,
            _ => break,
        }
    }
    node
}

pub(super) fn text<'s>(node: Node<'_>, src: &'s str) -> &'s str {
    src.get(node.byte_range()).unwrap_or_default()
}

/// Every node under `root`, itself included, parents first.
pub(super) fn walk(root: Node<'_>) -> Vec<Node<'_>> {
    let mut found = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        found.push(node);
        let mut children = kids(node);
        children.reverse();
        stack.extend(children);
    }
    found
}

/// `ast.Constant` holding a `str`.
pub(super) fn string_value(node: Node<'_>, src: &str) -> Option<String> {
    let node = bare(node);
    match node.kind() {
        "string" => one_string(node, src),
        "concatenated_string" => kids(node)
            .into_iter()
            .map(|part| one_string(part, src))
            .collect(),
        _ => None,
    }
}

fn one_string(node: Node<'_>, src: &str) -> Option<String> {
    let parts = kids(node);
    let start = parts.iter().find(|part| part.kind() == "string_start")?;
    let end = parts.iter().find(|part| part.kind() == "string_end")?;
    let prefix = text(*start, src)
        .trim_end_matches(['\'', '"'])
        .to_lowercase();
    if prefix.contains(['f', 'b', 't']) || parts.iter().any(|part| part.kind() == "interpolation") {
        return None;
    }
    let body = src.get(start.end_byte()..end.start_byte())?;
    Some(if prefix.contains('r') {
        body.to_owned()
    } else {
        unescape(body)
    })
}

fn unescape(body: &str) -> String {
    let mut out = String::new();
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let Some(next) = chars.next() else {
            out.push('\\');
            break;
        };
        let simple = match next {
            '\n' => Some(None),
            '\\' | '\'' | '"' => Some(Some(next)),
            'a' => Some(Some('\u{7}')),
            'b' => Some(Some('\u{8}')),
            'f' => Some(Some('\u{c}')),
            'n' => Some(Some('\n')),
            'r' => Some(Some('\r')),
            't' => Some(Some('\t')),
            'v' => Some(Some('\u{b}')),
            _ => None,
        };
        if let Some(value) = simple {
            out.extend(value);
            continue;
        }
        let width = match next {
            'x' => 2,
            'u' => 4,
            'U' => 8,
            '0'..='7' => {
                let mut digits = String::from(next);
                while digits.len() < 3 && chars.peek().is_some_and(|c| ('0'..='7').contains(c)) {
                    digits.extend(chars.next());
                }
                out.extend(
                    u32::from_str_radix(&digits, 8)
                        .ok()
                        .and_then(char::from_u32),
                );
                continue;
            }
            _ => 0,
        };
        let digits: String = (0..width).filter_map(|_| chars.next()).collect();
        match u32::from_str_radix(&digits, 16)
            .ok()
            .and_then(char::from_u32)
        {
            Some(decoded) if width > 0 && digits.len() == width => out.push(decoded),
            _ => {
                out.push('\\');
                out.push(next);
                out.push_str(&digits);
            }
        }
    }
    out
}

/// `ast.Constant` holding an `int` (a `bool` is one too).
pub(super) fn int_value(node: Node<'_>, src: &str) -> Option<i128> {
    let node = bare(node);
    match node.kind() {
        "true" => Some(1),
        "false" => Some(0),
        "integer" => {
            let digits = text(node, src).replace('_', "").to_lowercase();
            let (radix, body) = match digits.get(..2) {
                Some("0x") => (16, &digits[2..]),
                Some("0o") => (8, &digits[2..]),
                Some("0b") => (2, &digits[2..]),
                _ => (10, digits.as_str()),
            };
            i128::from_str_radix(body, radix).ok()
        }
        _ => None,
    }
}

/// A call's positional arguments, and its keywords by name (`None` for `**`).
pub(super) struct Args<'t> {
    pub(super) positional: Vec<Node<'t>>,
    pub(super) keywords: Vec<(Option<String>, Node<'t>)>,
}

impl<'t> Args<'t> {
    pub(super) fn of(call: Node<'t>, src: &str) -> Self {
        let mut args = Args {
            positional: Vec::new(),
            keywords: Vec::new(),
        };
        let Some(list) = call.child_by_field_name("arguments") else {
            return args;
        };
        if list.kind() != "argument_list" {
            args.positional.push(list);
            return args;
        }
        for item in kids(list) {
            match item.kind() {
                "keyword_argument" => {
                    let name = item
                        .child_by_field_name("name")
                        .map(|n| text(n, src).to_owned());
                    if let Some(value) = item.child_by_field_name("value") {
                        args.keywords.push((name, value));
                    }
                }
                "dictionary_splat" => args.keywords.extend(kids(item).first().map(|v| (None, *v))),
                _ => args.positional.push(item),
            }
        }
        args
    }

    /// `args[0]` unless it is starred, else the keyword named `keyword`.
    pub(super) fn first_or(&self, keyword: &str) -> Option<Node<'t>> {
        match self.positional.first() {
            Some(first) if first.kind() != "list_splat" => Some(*first),
            _ => self
                .keywords
                .iter()
                .find(|(name, _)| name.as_deref() == Some(keyword))
                .map(|(_, value)| *value),
        }
    }

    pub(super) fn keyword(&self, keyword: &str) -> Option<Node<'t>> {
        self.keywords
            .iter()
            .find(|(name, _)| name.as_deref() == Some(keyword))
            .map(|(_, value)| *value)
    }
}

pub(super) const SEQUENCES: [&str; 6] = [
    "list",
    "tuple",
    "expression_list",
    "pattern_list",
    "tuple_pattern",
    "list_pattern",
];

/// `_literal_sequence`: the elements, a starred literal spread in place.
pub(super) fn literal_sequence<'a, 't>(expr: Expr<'a, 't>, out: &mut Vec<Node<'t>>) -> bool {
    let node = match expr {
        Expr::List(items) => {
            out.extend_from_slice(items);
            return true;
        }
        Expr::Node(node) => bare(node),
    };
    if !SEQUENCES.contains(&node.kind()) {
        return false;
    }
    for item in kids(node) {
        if matches!(
            item.kind(),
            "list_splat" | "parenthesized_list_splat" | "list_splat_pattern"
        ) {
            let inner = kids(item);
            let Some(spread) = inner.first() else {
                return false;
            };
            let spread = match spread.kind() {
                "list_splat" => kids(*spread).first().copied().unwrap_or(*spread),
                _ => *spread,
            };
            if !literal_sequence(Expr::Node(spread), out) {
                return false;
            }
        } else {
            out.push(item);
        }
    }
    true
}

/// How many function and lambda bodies `node` holds, itself included.
pub(super) fn count_bodies(node: Node<'_>) -> usize {
    walk(node)
        .into_iter()
        .filter(|item| matches!(item.kind(), "function_definition" | "lambda"))
        .count()
}
