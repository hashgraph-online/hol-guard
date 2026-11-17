//! Keep a user's JSON formatting through a Guard rewrite.
//!
//! Adapters render settings files with `json.dumps(indent=2)` parity, which
//! rewrites the user's indentation, inline objects and spacing even where
//! Guard changed nothing. [`preserve`] lays a fresh render over the text it
//! was derived from: every subtree whose value did not change keeps its
//! original bytes, a changed object or array is rebuilt member by member, and
//! only the members Guard added take the rendered text. A member Guard removes
//! takes its own surrounding whitespace with it, so an install followed by an
//! uninstall gives the user back the bytes they started with.
//!
//! The result always parses to the same value as the render; anything this
//! module cannot splice exactly (duplicate keys, reordered keys, text that is
//! not plain JSON) falls back to the render for that subtree or the document.

use std::ops::Range;

use crate::pyjson::{self, PyVal};

#[path = "json_splice_tree.rs"]
mod tree;

use tree::{Item, Kind, Member, Node, Tree};

/// Arrays above this many element comparisons take the rendered text rather
/// than an alignment.
const MAX_ALIGNMENT_CELLS: usize = 1_000_000;

/// `rendered`, re-laid over `original`'s formatting. `rendered` must be the
/// render of a value derived from `original`; the document's leading and
/// trailing whitespace come from `original`. `None` when the two cannot be
/// spliced, so the caller writes the render unchanged.
pub(crate) fn preserve(original: &str, rendered: &str) -> Option<String> {
    let old = Tree::read(original)?;
    let new = Tree::read(rendered)?;
    let mut out = String::with_capacity(original.len().max(rendered.len()));
    out.push_str(&original[..old.root.span.start]);
    emit(&old, &old.root, &new, &new.root, &mut out);
    out.push_str(&original[old.root.span.end..]);
    let same = matches!(
        (parse(&out), parse(rendered)),
        (Some(spliced), Some(expected)) if spliced == expected
    );
    same.then_some(out)
}

/// [`preserve`] for a whole file: the spliced text when `original` is given
/// and splices, else `rendered` followed by `default_end`.
pub(crate) fn document(original: Option<&str>, rendered: &str, default_end: &str) -> String {
    original
        .and_then(|original| preserve(original, rendered))
        .unwrap_or_else(|| format!("{rendered}{default_end}"))
}

fn parse(text: &str) -> Option<PyVal> {
    pyjson::parse_marking_lone_surrogates(text).ok()
}

/// One member or item of a rebuilt container: its leading whitespace, its
/// body, and the whitespace before a following comma.
struct Part {
    lead: String,
    body: String,
    tail: String,
}

fn emit(old: &Tree, o: &Node, new: &Tree, n: &Node, out: &mut String) {
    if o.value == n.value {
        out.push_str(old.slice(&o.span));
        return;
    }
    let rebuilt = match (&o.kind, &n.kind) {
        (Kind::Object { members: om, close }, Kind::Object { members: nm, .. })
            if !om.is_empty() && !nm.is_empty() =>
        {
            object_parts(old, om, new, nm).map(|parts| join(b'{', parts, old.slice(close), b'}'))
        }
        (Kind::Array { items: oi, close }, Kind::Array { items: ni, .. })
            if !oi.is_empty() && !ni.is_empty() =>
        {
            array_parts(old, oi, new, ni).map(|parts| join(b'[', parts, old.slice(close), b']'))
        }
        // Exactly one side is empty here: equal values returned above.
        (Kind::Object { close, .. }, Kind::Object { members: nm, .. }) => {
            let parts = nm.iter().map(|member| {
                rendered_part(
                    new,
                    &member.lead,
                    Some(&member.head),
                    &member.value,
                    &member.tail,
                )
            });
            inline_gap(old.slice(close), parts.collect(), b'{', b'}')
        }
        (Kind::Array { close, .. }, Kind::Array { items: ni, .. }) => {
            let parts = ni
                .iter()
                .map(|item| rendered_part(new, &item.lead, None, &item.value, &item.tail));
            inline_gap(old.slice(close), parts.collect(), b'[', b']')
        }
        _ => None,
    };
    match rebuilt {
        Some(text) => out.push_str(&text),
        None => out.push_str(new.slice(&n.span)),
    }
}

/// A container that gains its first member or loses its last one. Whitespace
/// inside an empty container that stays on one line (`{ }`) becomes the
/// closing gap of the filled container, and comes back when it empties
/// again, so install then uninstall returns the same bytes. Any other gap
/// takes the render.
fn inline_gap(close: &str, parts: Vec<Part>, open: u8, end: u8) -> Option<String> {
    if close.is_empty() || close.contains('\n') {
        return None;
    }
    Some(join(open, parts, close, end))
}

fn rendered_part(
    new: &Tree,
    lead: &Range<usize>,
    head: Option<&Range<usize>>,
    value: &Node,
    tail: &Range<usize>,
) -> Part {
    let mut body = head
        .map(|head| new.slice(head).to_owned())
        .unwrap_or_default();
    body.push_str(new.slice(&value.span));
    Part {
        lead: new.slice(lead).to_owned(),
        body,
        tail: new.slice(tail).to_owned(),
    }
}

fn join(open: u8, parts: Vec<Part>, close: &str, end: u8) -> String {
    let mut out = String::new();
    out.push(open as char);
    let count = parts.len();
    for (index, part) in parts.into_iter().enumerate() {
        out.push_str(&part.lead);
        out.push_str(&part.body);
        if index + 1 < count {
            out.push_str(&part.tail);
            out.push(',');
        }
    }
    out.push_str(close);
    out.push(end as char);
    out
}

fn object_parts(old: &Tree, om: &[Member], new: &Tree, nm: &[Member]) -> Option<Vec<Part>> {
    let kept_old: Vec<&str> = om
        .iter()
        .filter(|member| nm.iter().any(|other| other.name == member.name))
        .map(|member| member.name.as_str())
        .collect();
    let kept_new: Vec<&str> = nm
        .iter()
        .filter(|member| om.iter().any(|other| other.name == member.name))
        .map(|member| member.name.as_str())
        .collect();
    // A reorder cannot be spliced member by member.
    if kept_old != kept_new {
        return None;
    }
    let mut parts: Vec<Part> = Vec::with_capacity(nm.len());
    for member in nm {
        match om.iter().find(|other| other.name == member.name) {
            Some(original) => {
                let mut body = old.slice(&original.head).to_owned();
                emit(old, &original.value, new, &member.value, &mut body);
                parts.push(Part {
                    lead: old.slice(&original.lead).to_owned(),
                    body,
                    tail: old.slice(&original.tail).to_owned(),
                });
            }
            None => {
                let leads: Vec<&str> = om.iter().map(|member| old.slice(&member.lead)).collect();
                let lead = added_lead(&leads, parts.is_empty());
                let mut body = new.slice(&member.head).to_owned();
                body.push_str(new.slice(&member.value.span));
                parts.push(Part {
                    lead,
                    body,
                    tail: String::new(),
                });
            }
        }
    }
    Some(parts)
}

fn array_parts(old: &Tree, oi: &[Item], new: &Tree, ni: &[Item]) -> Option<Vec<Part>> {
    if oi.len().saturating_mul(ni.len()) > MAX_ALIGNMENT_CELLS {
        return None;
    }
    let pairs = align(oi, ni);
    let mut parts: Vec<Part> = Vec::with_capacity(ni.len());
    let kept = |parts: &mut Vec<Part>, original: &Item, item: &Item| {
        let mut body = String::new();
        emit(old, &original.value, new, &item.value, &mut body);
        parts.push(Part {
            lead: old.slice(&original.lead).to_owned(),
            body,
            tail: old.slice(&original.tail).to_owned(),
        });
    };
    let added = |parts: &mut Vec<Part>, item: &Item| {
        let leads: Vec<&str> = oi.iter().map(|item| old.slice(&item.lead)).collect();
        let lead = added_lead(&leads, parts.is_empty());
        parts.push(Part {
            lead,
            body: new.slice(&item.value.span).to_owned(),
            tail: String::new(),
        });
    };
    let (mut o, mut n) = (0, 0);
    for (anchor_o, anchor_n) in pairs.into_iter().chain([(oi.len(), ni.len())]) {
        // Between anchors, a changed container pairs with the original one
        // in the same place so its own unchanged parts keep their bytes.
        while n < anchor_n {
            if o < anchor_o && same_shape(&oi[o].value, &ni[n].value) {
                kept(&mut parts, &oi[o], &ni[n]);
                o += 1;
            } else {
                added(&mut parts, &ni[n]);
            }
            n += 1;
        }
        if anchor_n < ni.len() {
            kept(&mut parts, &oi[anchor_o], &ni[anchor_n]);
        }
        o = anchor_o + 1;
        n = anchor_n + 1;
    }
    Some(parts)
}

/// The whitespace before an added member or item: the original's own gap
/// between neighbours, so the addition reads like the rest of the container.
/// Removing the addition takes this whitespace with it, so it never shows in
/// the restored text.
fn added_lead(leads: &[&str], first: bool) -> String {
    let gap = match leads {
        [only] if !first && !only.contains('\n') => " ",
        [first_lead] => first_lead,
        [first_lead, ..] if first => first_lead,
        [_, second, ..] => second,
        [] => "",
    };
    gap.to_owned()
}

fn same_shape(old: &Node, new: &Node) -> bool {
    matches!(
        (&old.kind, &new.kind),
        (Kind::Object { .. }, Kind::Object { .. }) | (Kind::Array { .. }, Kind::Array { .. })
    )
}

/// The longest run of equal elements, as `(old, new)` index pairs.
fn align(oi: &[Item], ni: &[Item]) -> Vec<(usize, usize)> {
    let (rows, cols) = (oi.len(), ni.len());
    let mut table = vec![0u32; (rows + 1) * (cols + 1)];
    let at = |row: usize, col: usize| row * (cols + 1) + col;
    for row in (0..rows).rev() {
        for col in (0..cols).rev() {
            table[at(row, col)] = if oi[row].value.value == ni[col].value.value {
                table[at(row + 1, col + 1)] + 1
            } else {
                table[at(row + 1, col)].max(table[at(row, col + 1)])
            };
        }
    }
    let (mut row, mut col, mut pairs) = (0, 0, Vec::new());
    while row < rows && col < cols {
        if oi[row].value.value == ni[col].value.value {
            pairs.push((row, col));
            row += 1;
            col += 1;
        } else if table[at(row + 1, col)] >= table[at(row, col + 1)] {
            row += 1;
        } else {
            col += 1;
        }
    }
    pairs
}
