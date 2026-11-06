//! JSON settings files, rewritten as Python's `json.dumps` writes them.

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;

use super::{DUPLICATE_KEY, NOT_JSON, NOT_OBJECT, REPEATED_KEY, UNWRITABLE_TEXT};

/// A JSON value with its object keys in file order.
pub(super) enum Node {
    Leaf(Value),
    List(Vec<Node>),
    Object(Vec<(String, Node)>),
}

impl Node {
    pub(super) fn value(&self) -> Value {
        match self {
            Self::Leaf(value) => value.clone(),
            Self::List(items) => Value::Array(items.iter().map(Self::value).collect()),
            Self::Object(entries) => Value::Object(
                entries
                    .iter()
                    .map(|(key, node)| (key.clone(), node.value()))
                    .collect(),
            ),
        }
    }
}

pub(super) fn json_root(text: &str) -> Result<Vec<(String, Node)>, String> {
    if is_blank(text) {
        return Ok(Vec::new());
    }
    match parse_json(text)? {
        Node::Object(root) => Ok(root),
        _ => Err(NOT_OBJECT.to_owned()),
    }
}

pub(super) fn lookup<'a>(entries: &'a mut [(String, Node)], key: &str) -> Option<&'a mut Node> {
    entries
        .iter_mut()
        .find(|(name, _)| name == key)
        .map(|(_, node)| node)
}

/// The node under `key`, added at the end when missing.
pub(super) fn upsert<'a>(
    entries: &'a mut Vec<(String, Node)>,
    key: &str,
    empty: Option<Node>,
) -> &'a mut Node {
    let index = match entries.iter().position(|(name, _)| name == key) {
        Some(index) => index,
        None => {
            entries.push((key.to_owned(), empty.unwrap_or(Node::Object(Vec::new()))));
            entries.len() - 1
        }
    };
    &mut entries[index].1
}

/// Sets `key` in place, or adds it at the end.
pub(super) fn set(entries: &mut Vec<(String, Node)>, key: &str, node: Node) {
    *upsert(entries, key, None) = node;
}

pub(super) fn parse_json(text: &str) -> Result<Node, String> {
    let value: Value = serde_json::from_str(text).map_err(json_error)?;
    let shape: Shape = serde_json::from_str(text).map_err(json_error)?;
    Ok(ordered(value, shape))
}

fn json_error(error: serde_json::Error) -> String {
    let message = error.to_string();
    if message.contains(DUPLICATE_KEY) {
        REPEATED_KEY.to_owned()
    } else if message.contains("surrogate") || message.contains("end of hex escape") {
        // Python reads a lone surrogate but cannot write it back as UTF-8.
        UNWRITABLE_TEXT.to_owned()
    } else {
        NOT_JSON.to_owned()
    }
}

fn ordered(value: Value, shape: Shape) -> Node {
    match (value, shape) {
        (Value::Object(mut map), Shape::Object(keys)) => Node::Object(
            keys.into_iter()
                .filter_map(|(key, shape)| {
                    let value = map.remove(&key)?;
                    Some((key, ordered(value, shape)))
                })
                .collect(),
        ),
        (Value::Array(items), Shape::List(shapes)) => Node::List(
            items
                .into_iter()
                .zip(shapes)
                .map(|(value, shape)| ordered(value, shape))
                .collect(),
        ),
        (value, _) => Node::Leaf(value),
    }
}

/// The key order of a JSON text; a repeated key is refused.
enum Shape {
    Scalar,
    List(Vec<Shape>),
    Object(Vec<(String, Shape)>),
}

impl<'de> Deserialize<'de> for Shape {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ShapeVisitor)
    }
}

struct ShapeVisitor;

impl<'de> Visitor<'de> for ShapeVisitor {
    type Value = Shape;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Shape, E> {
        Ok(Shape::Scalar)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Shape, E> {
        Ok(Shape::Scalar)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Shape, E> {
        Ok(Shape::Scalar)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Shape, E> {
        Ok(Shape::Scalar)
    }

    fn visit_str<E>(self, _: &str) -> Result<Shape, E> {
        Ok(Shape::Scalar)
    }

    fn visit_unit<E>(self) -> Result<Shape, E> {
        Ok(Shape::Scalar)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Shape, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<Shape>()? {
            items.push(item);
        }
        Ok(Shape::List(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Shape, A::Error> {
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(DUPLICATE_KEY));
            }
            let value = map.next_value::<Shape>()?;
            entries.push((key, value));
        }
        Ok(Shape::Object(entries))
    }
}

/// `root` rendered as Python's `json.dumps` would, with the indentation and
/// line endings of `text`.
pub(super) fn dump_like(root: &Node, text: &str) -> String {
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = String::new();
    write_node(root, json_indent(text), newline, 0, &mut out);
    if text.ends_with('\n') || is_blank(text) {
        out.push_str(newline);
    }
    out
}

fn write_node(node: &Node, indent: &str, newline: &str, level: usize, out: &mut String) {
    let open = |out: &mut String, level: usize| {
        out.push_str(newline);
        out.push_str(&indent.repeat(level));
    };
    match node {
        Node::Leaf(value) => out.push_str(&value.to_string()),
        Node::List(items) if items.is_empty() => out.push_str("[]"),
        Node::Object(entries) if entries.is_empty() => out.push_str("{}"),
        Node::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                open(out, level + 1);
                write_node(item, indent, newline, level + 1, out);
            }
            open(out, level);
            out.push(']');
        }
        Node::Object(entries) => {
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                open(out, level + 1);
                out.push_str(&Value::String(key.clone()).to_string());
                out.push_str(": ");
                write_node(item, indent, newline, level + 1, out);
            }
            open(out, level);
            out.push('}');
        }
    }
}

/// The leading spaces or tabs of the first indented line, else two spaces.
fn json_indent(text: &str) -> &str {
    const BREAKS: [char; 10] = [
        '\n', '\r', '\u{0b}', '\u{0c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
        '\u{2029}',
    ];
    text.split(BREAKS)
        .find_map(|line| {
            let stripped = line.trim_start_matches([' ', '\t']);
            (!stripped.is_empty() && stripped.len() != line.len())
                .then(|| &line[..line.len() - stripped.len()])
        })
        .unwrap_or("  ")
}

/// Python's `str.isspace` for every character.
pub(super) fn is_blank(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}
