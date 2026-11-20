//! `existing_contract_config_paths`: which of a harness contract's config
//! paths exist on this machine, for the app list and `apps test`.
//!
//! A path is `~/...`, absolute, or relative to the home directory. A segment
//! with `*` or `?` matches the entries of its directory the way `glob` does,
//! so `*` never matches a name that starts with a dot.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Map, Value};

use super::{path_text, Ctx, Failure, Step};
use crate::harness_contract_registry;

pub(super) fn handles(op: &str) -> bool {
    op == "existing_contract_config_paths"
}

/// The request names the `harness`; the answer is `{"config_paths": [...]}`,
/// sorted and without repeats. A harness without a contract has none.
pub(super) fn dispatch(ctx: &Ctx, fields: &Map<String, Value>) -> Step<Value> {
    let harness = fields
        .get("harness")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    let declared = harness_contract_registry::config_paths(harness).unwrap_or_default();
    let mut existing: Vec<String> = declared
        .iter()
        .flat_map(|declared| candidates(&expand(ctx, declared)))
        .filter(|candidate| candidate.exists())
        .map(|candidate| path_text(&candidate))
        .collect();
    existing.sort();
    existing.dedup();
    Ok(json!({ "config_paths": existing }))
}

/// `~` is the home directory; a relative path starts from it too.
fn expand(ctx: &Ctx, declared: &str) -> PathBuf {
    let path = Path::new(declared);
    let mut parts = path.components();
    let first = parts.clone().next();
    if first == Some(Component::Normal(std::ffi::OsStr::new("~"))) {
        parts.next();
        return ctx.home.join(parts.as_path());
    }
    if path.is_absolute() {
        return path.components().collect();
    }
    ctx.home.join(path.components().collect::<PathBuf>())
}

fn has_magic(segment: &str) -> bool {
    segment.contains(['*', '?', '['])
}

fn candidates(path: &Path) -> Vec<PathBuf> {
    let segments: Vec<Component> = path.components().collect();
    if !segments
        .iter()
        .any(|segment| has_magic(&segment.as_os_str().to_string_lossy()))
    {
        return vec![path.to_path_buf()];
    }
    let mut found = vec![PathBuf::new()];
    for segment in segments {
        let text = segment.as_os_str().to_string_lossy().into_owned();
        let mut next = Vec::new();
        for base in &found {
            if !has_magic(&text) {
                next.push(base.join(segment));
                continue;
            }
            let Ok(entries) = fs::read_dir(base) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if matches(&text, &name) {
                    next.push(base.join(&name));
                }
            }
        }
        found = next;
    }
    found
}

/// `fnmatch` for `*`, `?` and `[...]` on one name, with glob's rule that a
/// leading dot is matched only by a pattern that spells it.
pub(super) fn matches(pattern: &str, name: &str) -> bool {
    if name.starts_with('.') && !pattern.starts_with('.') {
        return false;
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let name: Vec<char> = name.chars().collect();
    wild(&pattern, &name)
}

pub(super) fn wild(pattern: &[char], name: &[char]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((&'*', rest)) => (0..=name.len()).any(|skip| wild(rest, &name[skip..])),
        Some((&'?', rest)) => name.split_first().is_some_and(|(_, tail)| wild(rest, tail)),
        Some((&'[', rest)) => match (class(rest), name.split_first()) {
            (Some((accepts, after)), Some((first, tail))) => accepts(*first) && wild(after, tail),
            _ => false,
        },
        Some((literal, rest)) => name
            .split_first()
            .is_some_and(|(first, tail)| first == literal && wild(rest, tail)),
    }
}

type Accepts = Box<dyn Fn(char) -> bool>;

/// A `[...]` class: what it accepts and the pattern after its `]`.
fn class(rest: &[char]) -> Option<(Accepts, &[char])> {
    let negated = rest.first() == Some(&'!');
    let body = if negated { &rest[1..] } else { rest };
    let end = body.iter().skip(1).position(|c| *c == ']')? + 1;
    let members: Vec<char> = body[..end].to_vec();
    let after = &body[end + 1..];
    let accepts = move |c: char| {
        let mut index = 0;
        let mut hit = false;
        while index < members.len() {
            if index + 2 < members.len() && members[index + 1] == '-' {
                hit |= members[index] <= c && c <= members[index + 2];
                index += 3;
            } else {
                hit |= members[index] == c;
                index += 1;
            }
        }
        hit != negated
    };
    Some((Box::new(accepts), after))
}
