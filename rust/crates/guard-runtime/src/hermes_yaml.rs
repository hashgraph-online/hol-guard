//! Bounded YAML loading with the PyYAML `SafeLoader` (YAML 1.1) value rules
//! the Hermes configuration and skill frontmatter were written against.
//!
//! The event stream comes from a pure-Rust YAML parser; this module applies
//! the Hermes limits while it streams (no aliases, nesting, node count), then
//! resolves and constructs scalars the way PyYAML does (`yes`/`no`/`on`/`off`
//! are booleans, `0755` is octal, `1:30` is sexagesimal) and rejects duplicate
//! keys. A timestamp, binary or set is a value Hermes does not accept.
//!
//! Outcomes are split in two. A [`Failure`] is something the Python loader
//! also reports, and callers surface it as the configuration reason. A refusal
//! (`Err`) is input CPython raises an unrelated exception on, or a number too
//! large to carry; callers fail closed rather than guess.

use saphyr_parser::{Event, Parser, ScalarStyle};

use super::hermes_yaml_construct::{construct, into_pyval, validate, validate_json};
use super::pyjson::{parse_unique, JsonFailure, PyVal};

pub(crate) const MAX_DEPTH: usize = 32;
pub(crate) const MAX_NODES: usize = 20_000;
pub(crate) const MAX_ALIASES: usize = 0;

pub(crate) const ERR_UNREPRESENTABLE: &str = "native_runner_authority_hermes_yaml_unrepresentable";

/// Largest decimal digit count Python's `int()` accepts.
pub(crate) const MAX_INT_DIGITS: usize = 4_300;
/// Largest non-decimal literal converted here; Python converts any size.
pub(crate) const MAX_RADIX_DIGITS: usize = 8_192;

pub(crate) const TAG_PREFIX: &str = "tag:yaml.org,2002:";
pub(crate) const TAG_STR: &str = "tag:yaml.org,2002:str";
pub(crate) const TAG_MERGE: &str = "tag:yaml.org,2002:merge";
pub(crate) const TAG_VALUE: &str = "tag:yaml.org,2002:value";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    Parse,
    Alias,
    Depth,
    Nodes,
    Duplicate,
    Invalid,
}

impl Failure {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Failure::Parse => "config_parse_error",
            Failure::Alias => "config_alias_limit_exceeded",
            Failure::Depth => "config_depth_limit_exceeded",
            Failure::Nodes => "config_node_limit_exceeded",
            Failure::Duplicate => "config_duplicate_key",
            Failure::Invalid => "config_value_invalid",
        }
    }
}

/// A node of the composed document.
pub(crate) enum Node {
    Scalar {
        value: String,
        style: ScalarStyle,
        tag: Option<String>,
    },
    Seq {
        items: Vec<Node>,
        tag: Option<String>,
    },
    Map {
        pairs: Vec<(Node, Node)>,
        tag: Option<String>,
    },
}

impl Node {
    pub(crate) fn tag(&self) -> Option<&str> {
        match self {
            Node::Scalar { tag, .. } | Node::Seq { tag, .. } | Node::Map { tag, .. } => {
                tag.as_deref()
            }
        }
    }
}

/// A constructed value, including the Python values Hermes refuses.
pub(crate) enum Value {
    Null,
    Bool(bool),
    Int(String),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    Dict(Vec<(Value, Value)>),
    /// A `datetime`, `bytes`, `set` or a non-empty `!!omap`/`!!pairs`: Python
    /// builds it, and the Hermes validator then rejects it.
    Foreign(Foreign),
}

pub(crate) enum Foreign {
    Timestamp(String),
    Bytes(Vec<u8>),
    Set,
    Pairs,
}

/// `Err` is a refusal; `Ok(Err)` is a failure the Python loader also reports.
pub(crate) type Built<T> = Result<Result<T, Failure>, &'static str>;

pub(crate) fn fail<T>(failure: Failure) -> Built<T> {
    Ok(Err(failure))
}

macro_rules! step {
    ($expr:expr) => {
        match $expr {
            Ok(Ok(value)) => value,
            Ok(Err(failure)) => return Ok(Err(failure)),
            Err(refusal) => return Err(refusal),
        }
    };
}
pub(crate) use step;

/// PyYAML's reader refuses control characters before it yields any event.
fn printable(text: &str) -> bool {
    text.chars().all(|ch| {
        matches!(ch,
            '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{7E}' | '\u{85}'
            | '\u{A0}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}')
    })
}

fn tag_text(tag: &saphyr_parser::Tag) -> String {
    if tag.handle == "!" {
        format!("!{}", tag.suffix)
    } else {
        format!("{}{}", tag.handle, tag.suffix)
    }
}

/// Load one bounded document. An empty document is `PyVal::Null`.
pub(crate) fn load(content: &str) -> Built<PyVal> {
    if !printable(content) {
        return fail(Failure::Parse);
    }
    // The scanner skips one byte order mark at the start of the stream.
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let value = match step!(compose(content)) {
        None => Value::Null,
        Some(node) => step!(construct(&node)),
    };
    step!(validate(&value));
    Ok(Ok(into_pyval(value)))
}

/// Load one bounded JSON document with the Hermes limits.
pub(crate) fn load_json(content: &str) -> Built<PyVal> {
    match parse_unique(content) {
        Ok(value) => validate_json(value),
        Err(JsonFailure::Syntax | JsonFailure::IntegerLimit) => fail(Failure::Parse),
        Err(JsonFailure::Duplicate) => fail(Failure::Duplicate),
        Err(JsonFailure::Unrepresentable) => Err(ERR_UNREPRESENTABLE),
    }
}

enum Open {
    Seq(Vec<Node>, Option<String>),
    Map(Vec<(Node, Node)>, Option<String>, Option<Node>),
}

fn attach(stack: &mut [Open], root: &mut Option<Node>, node: Node) {
    match stack.last_mut() {
        Some(Open::Seq(items, _)) => items.push(node),
        Some(Open::Map(pairs, _, key)) => match key.take() {
            Some(key) => pairs.push((key, node)),
            None => *key = Some(node),
        },
        None => *root = Some(node),
    }
}

/// PyYAML's scanner never skips a tab: outside a quoted or block scalar and a
/// comment it is "a character that cannot start any token". The YAML 1.2
/// parser accepts them, so find them here.
fn tab_outside_scalars(content: &str, spans: &mut [(usize, usize)]) -> bool {
    if !content.contains('\t') {
        return false;
    }
    spans.sort_unstable();
    let inside = |index: usize| {
        let slot = spans.partition_point(|(start, _)| *start <= index);
        slot > 0 && index < spans[slot - 1].1
    };
    let chars: Vec<char> = content.chars().collect();
    let mut line_start = 0usize;
    let mut comment = false;
    for (index, ch) in chars.iter().copied().enumerate() {
        match ch {
            '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}' => {
                line_start = index + 1;
                comment = false;
            }
            '#' if !comment
                && (index == line_start || matches!(chars[index - 1], ' ' | '\t'))
                && !inside(index) =>
            {
                comment = true;
            }
            '\t' if !comment && !inside(index) => return true,
            _ => {}
        }
    }
    false
}

/// Stream the events, applying the limits in event order, and compose the
/// single document.
fn compose(content: &str) -> Built<Option<Node>> {
    let mut parser = Parser::new_from_str(content);
    let mut aliases = 0usize;
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut documents = 0usize;
    let mut events: Vec<(Event, usize)> = Vec::new();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let chars: Vec<char> = content.chars().collect();
    let mut flow: Vec<bool> = Vec::new();
    let mut flow_depth = 0usize;
    for next in &mut parser {
        let (event, span) = match next {
            Ok(pair) => pair,
            Err(error) => {
                let unknown = error.info().contains("unknown anchor");
                return fail(if unknown {
                    Failure::Alias
                } else {
                    Failure::Parse
                });
            }
        };
        match &event {
            Event::Alias(_) => {
                aliases += 1;
                if aliases > MAX_ALIASES {
                    return fail(Failure::Alias);
                }
            }
            Event::MappingStart(_, _) | Event::SequenceStart(_, _) => {
                depth += 1;
                nodes += 1;
                if depth > MAX_DEPTH {
                    return fail(Failure::Depth);
                }
                let in_flow = matches!(chars.get(span.start.index()), Some('[' | '{'));
                flow_depth += usize::from(in_flow);
                flow.push(in_flow);
            }
            Event::MappingEnd | Event::SequenceEnd => {
                depth = depth.saturating_sub(1);
                flow_depth -= usize::from(flow.pop().unwrap_or(false));
            }
            Event::Scalar(value, style, _, _) => {
                nodes += 1;
                if *style != ScalarStyle::Plain {
                    spans.push((span.start.index(), span.end.index()));
                } else if value.starts_with(['|', '>', '%', '@', '`']) {
                    // PyYAML cannot start a plain scalar with these.
                    return fail(Failure::Parse);
                } else if flow_depth > 0 && value.starts_with(['?', ':']) {
                    // PyYAML reads a flow `?` or `:` as an indicator.
                    return Err(ERR_UNREPRESENTABLE);
                }
            }
            Event::DocumentStart(_) => documents += 1,
            _ => {}
        }
        if nodes > MAX_NODES {
            return fail(Failure::Nodes);
        }
        events.push((event, span.start.index()));
    }
    // PyYAML's composer accepts exactly one document.
    if documents > 1 || tab_outside_scalars(content, &mut spans) {
        return fail(Failure::Parse);
    }
    // A clip or keep block scalar that ends the stream without a line break
    // has no trailing newline in PyYAML; the parser reports one.
    let last_content = events.iter().rposition(|(event, _)| {
        !matches!(
            event,
            Event::MappingEnd | Event::SequenceEnd | Event::DocumentEnd | Event::StreamEnd
        )
    });
    let no_final_break = !content.ends_with(['\n', '\r']);
    let mut root: Option<Node> = None;
    let mut stack: Vec<Open> = Vec::new();
    for (position, (event, start)) in events.into_iter().enumerate() {
        match event {
            Event::Scalar(value, style, _, tag) => {
                let mut value = value.into_owned();
                let block = matches!(style, ScalarStyle::Literal | ScalarStyle::Folded);
                if block && value == "\n" {
                    // An empty block scalar is "" unless it keeps its breaks,
                    // which the parser does not say; read the header.
                    let header = chars.iter().skip(start).take_while(|ch| **ch != '\n');
                    if header.into_iter().any(|ch| *ch == '+') {
                        return Err(ERR_UNREPRESENTABLE);
                    }
                    value.clear();
                }
                if block
                    && no_final_break
                    && Some(position) == last_content
                    && value.ends_with('\n')
                {
                    value.pop();
                }
                let node = Node::Scalar {
                    value,
                    style,
                    tag: tag.map(|tag| tag_text(&tag)),
                };
                attach(&mut stack, &mut root, node);
            }
            Event::SequenceStart(_, tag) => {
                stack.push(Open::Seq(Vec::new(), tag.map(|tag| tag_text(&tag))));
            }
            Event::MappingStart(_, tag) => {
                stack.push(Open::Map(Vec::new(), tag.map(|tag| tag_text(&tag)), None));
            }
            Event::SequenceEnd => {
                if let Some(Open::Seq(items, tag)) = stack.pop() {
                    attach(&mut stack, &mut root, Node::Seq { items, tag });
                }
            }
            Event::MappingEnd => {
                if let Some(Open::Map(pairs, tag, _)) = stack.pop() {
                    attach(&mut stack, &mut root, Node::Map { pairs, tag });
                }
            }
            _ => {}
        }
    }
    Ok(Ok(root))
}
