//! The evaluator for `opencode_install_plan` build specs.
//!
//! The plan kind answers each object as a build spec so user values keep
//! their objects and key order; this walks those specs over the request it
//! was sent, as `_Builder` in `opencode_install_plan.py` did:
//!
//! - `["value", v]`: a string, bool, null or list of strings Guard chose;
//! - `["ref", path]`: the request value at `path` (keys and list indices);
//! - `["object", [[key, spec], ...]]`: a new dict, assigned in that order;
//! - `["merge", [spec, ...]]`: a new dict updated with each dict in turn;
//! - `["launch", server, "companion" | "override"]`: the request server's
//!   proxy argv, without or with the workspace.

use serde_json::Value;

use super::files::Doc;
use super::{Failure, Step};
use crate::pyjson::PyVal;

fn malformed(detail: &str) -> Failure {
    Failure::Refusal(format!(
        "the native OpenCode install plan was malformed: {detail}"
    ))
}

/// `repr()` of a JSON string or list, as the malformed messages quote it.
fn repr(value: &Value) -> String {
    match value {
        Value::String(text) => {
            let quote = if text.contains('\'') && !text.contains('"') {
                '"'
            } else {
                '\''
            };
            let mut out = String::from(quote);
            for character in text.chars() {
                match character {
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    _ if character == quote => {
                        out.push('\\');
                        out.push(character);
                    }
                    _ => out.push(character),
                }
            }
            out.push(quote);
            out
        }
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(repr).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        other => other.to_string(),
    }
}

/// A JSON integer as Python's `type(x) is int` sees it.
fn integer(value: &Value) -> Option<i128> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .map(i128::from)
            .or_else(|| number.as_u64().map(i128::from)),
        _ => None,
    }
}

pub(super) struct Builder<'a> {
    pub(super) request: &'a PyVal,
    /// Each request server's `[companion, override]` proxy argv.
    pub(super) launches: &'a [[PyVal; 2]],
}

impl Builder<'_> {
    pub(super) fn build(&self, spec: &Value) -> Step<PyVal> {
        let Some((Value::String(tag), body)) =
            spec.as_array().and_then(|parts| parts.split_first())
        else {
            return Err(malformed("a build spec is not a tagged list"));
        };
        if tag == "launch" {
            return self.launch(body);
        }
        if body.len() != 1 {
            return Err(malformed(&format!(
                "a {} spec has {} parts",
                repr(&Value::String(tag.clone())),
                body.len() + 1
            )));
        }
        let body = &body[0];
        match tag.as_str() {
            "value" => literal(body),
            "ref" => self.resolve(body),
            "object" => {
                let mut built = Doc::default();
                for (key, item) in pairs(body)? {
                    built.set(key, self.build(item)?);
                }
                Ok(built.value())
            }
            "merge" => {
                let parts = body
                    .as_array()
                    .ok_or_else(|| malformed("merge parts are not a list"))?;
                let mut merged = Doc::default();
                for part in parts {
                    merged.spread(&self.object(part)?);
                }
                Ok(merged.value())
            }
            _ => Err(malformed(&format!(
                "unknown spec tag {}",
                repr(&Value::String(tag.clone()))
            ))),
        }
    }

    pub(super) fn object(&self, spec: &Value) -> Step<Vec<(String, PyVal)>> {
        match self.build(spec)? {
            PyVal::Dict(entries) => Ok(entries),
            _ => Err(malformed("a spec that must build an object did not")),
        }
    }

    fn resolve(&self, path: &Value) -> Step<PyVal> {
        let steps = path
            .as_array()
            .ok_or_else(|| malformed("a reference path is not a list"))?;
        let mut current = self.request;
        for step in steps {
            let next = match (step, current) {
                (Value::String(key), PyVal::Dict(_)) => current.get(key),
                (_, PyVal::List(items)) => integer(step)
                    .and_then(|index| usize::try_from(index).ok())
                    .and_then(|index| items.get(index)),
                _ => None,
            };
            current = next.ok_or_else(|| {
                malformed(&format!(
                    "reference {} does not name a request value",
                    repr(path)
                ))
            })?;
        }
        Ok(current.clone())
    }

    fn launch(&self, body: &[Value]) -> Step<PyVal> {
        let shape = || malformed("a launch spec is not [launch, server, companion|override]");
        let [index, launch] = body else {
            return Err(shape());
        };
        let index = integer(index).ok_or_else(shape)?;
        let slot = match launch.as_str() {
            Some("companion") => 0,
            Some("override") => 1,
            _ => return Err(shape()),
        };
        usize::try_from(index)
            .ok()
            .and_then(|index| self.launches.get(index))
            .map(|launches| launches[slot].clone())
            .ok_or_else(|| malformed("a launch names no request server"))
    }
}

fn literal(value: &Value) -> Step<PyVal> {
    let refused = || malformed("a literal is not a string, bool, null or list of strings");
    Ok(match value {
        Value::Null => PyVal::Null,
        Value::Bool(flag) => PyVal::Bool(*flag),
        Value::String(text) => PyVal::Str(text.clone()),
        Value::Array(items) => PyVal::List(
            items
                .iter()
                .map(|item| item.as_str().map(|text| PyVal::Str(text.to_owned())))
                .collect::<Option<_>>()
                .ok_or_else(refused)?,
        ),
        _ => return Err(refused()),
    })
}

fn pairs(body: &Value) -> Step<Vec<(&str, &Value)>> {
    body.as_array()
        .ok_or_else(|| malformed("object pairs are not a list"))?
        .iter()
        .map(|pair| match pair.as_array().map(Vec::as_slice) {
            Some([Value::String(key), spec]) => Ok((key.as_str(), spec)),
            _ => Err(malformed("an object pair is not [key, spec]")),
        })
        .collect()
}

/// `_managed`: strictly increasing positions in the request's server list.
pub(super) fn managed(value: &Value, count: usize) -> Step<Vec<usize>> {
    let items = value
        .as_array()
        .filter(|items| items.iter().all(|item| integer(item).is_some()))
        .ok_or_else(|| malformed("managed is not a list of server indices"))?;
    let mut previous: i128 = -1;
    let mut indices = Vec::with_capacity(items.len());
    for index in items.iter().filter_map(integer) {
        if index <= previous || index >= count as i128 {
            return Err(malformed(
                "managed indices are not increasing request positions",
            ));
        }
        previous = index;
        indices.push(index as usize);
    }
    Ok(indices)
}

/// `_strings`: a list of strings.
pub(super) fn strings(value: &Value, field: &str) -> Step<Vec<String>> {
    value
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .map(|item| item.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| malformed(&format!("{field} is not a list of strings")))
}
