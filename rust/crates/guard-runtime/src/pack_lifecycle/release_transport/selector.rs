//! The advisory selector that names a published root, and the checks that tie
//! a fetched root back to it. A selector is a pointer, never authority: the
//! root it names is authenticated separately.
use super::super::hex;
use super::{invalid, Outcome};
use serde_json::{json, Value};

const SCHEMA: &str = "guard.extension-distribution-selector.v2";
const KEYS: [&str; 4] = ["schema", "source_sha", "publication_id", "root_sha256"];

struct Selected<'a> {
    source: &'a str,
    publication: &'a str,
    root: &'a str,
}

/// `<major>.<minor>`: one to twenty digits, a dot, one to ten digits.
fn publication(text: &str) -> Option<(&str, &str)> {
    let digits = |part: &str, most: usize| {
        (1..=most).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit())
    };
    let (major, minor) = text.split_once('.')?;
    (digits(major, 20) && digits(minor, 10)).then_some((major, minor))
}

fn tag_of(source: &str, publication: &str) -> String {
    format!("extension-distribution-{source}-{publication}")
}

fn check(value: &Value) -> Result<Selected<'_>, String> {
    let contract = || "delivery selector contract invalid".to_owned();
    let map = value.as_object().ok_or_else(contract)?;
    if map.len() != KEYS.len() || KEYS.iter().any(|key| !map.contains_key(*key)) {
        return Err(contract());
    }
    if map["schema"] != SCHEMA {
        return Err(contract());
    }
    let identity = || "delivery selector identity invalid".to_owned();
    let source = map["source_sha"].as_str().filter(|s| hex(s, 40));
    let text = map["publication_id"].as_str();
    let root = map["root_sha256"].as_str().filter(|s| hex(s, 64));
    let (Some(source), Some(text), Some(root)) = (source, text, root) else {
        return Err(identity());
    };
    let (major, minor) = publication(text).ok_or_else(identity)?;
    // Publication 0.0 is what a local build carries.
    if [major, minor]
        .iter()
        .all(|part| part.bytes().all(|b| b == b'0'))
    {
        return Err("local publication cannot become selected".into());
    }
    Ok(Selected {
        source,
        publication: text,
        root,
    })
}

pub(super) fn validate(input: &Value) -> Outcome {
    let selected = check(&input["value"])?;
    Ok(json!({"tag": tag_of(selected.source, selected.publication)}))
}

pub(super) fn tag(input: &Value) -> Outcome {
    let source = input["source"].as_str().filter(|s| hex(s, 40));
    let published = input["publication"]
        .as_str()
        .filter(|text| publication(text).is_some());
    match (source, published) {
        (Some(source), Some(published)) => Ok(json!({"tag": tag_of(source, published)})),
        _ => Err("release source or publication identity invalid".into()),
    }
}

/// A fetched root must be the one the selector names: the digest of the bytes
/// before they are verified, and the publication the verified manifest
/// carries after. Either may be asked alone.
pub(super) fn bind(input: &Value) -> Outcome {
    let selected = check(&input["selector"])?;
    let (digest, published) = (input.get("root_sha256"), input.get("publication_id"));
    if digest.is_none() && published.is_none() {
        return Err(invalid());
    }
    if digest.is_some_and(|value| value != selected.root) {
        return Err("release root differs from advisory selector".into());
    }
    if published.is_some_and(|value| value != selected.publication) {
        return Err("release root publication identity differs from selector".into());
    }
    Ok(json!({"bound": true}))
}
