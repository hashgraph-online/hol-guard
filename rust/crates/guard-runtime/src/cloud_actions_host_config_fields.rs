//! The fields of the entry Guard writes into an AI tool's settings, and the
//! check that an existing entry is Guard's own. Split from
//! `cloud_actions_host_config` as a `#[path]` child module.

use serde_json::{json, Map, Value};

use super::{Tool, BRIDGE_ARGS};

/// The fields of an entry Guard writes: the bridge launch, or the
/// address-only entry an earlier alpha wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Fields {
    Url(String),
    Bridge { command: String, args: Vec<String> },
}

impl Fields {
    pub(super) fn from_request(entry: &Value) -> Option<Self> {
        let entry = entry.as_object()?;
        let keys: Vec<&str> = entry.keys().map(String::as_str).collect();
        match keys.as_slice() {
            ["url"] => Some(Self::Url(entry["url"].as_str()?.to_owned())),
            ["args", "command"] => Some(Self::Bridge {
                command: entry["command"].as_str()?.to_owned(),
                args: strings(&entry["args"])?,
            }),
            _ => None,
        }
    }

    /// The fields as an object, without the transport type.
    pub(super) fn value(&self) -> Value {
        Value::Object(
            self.entry(None)
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        )
    }

    /// The entry in writing order, typed for an AI tool that wants a type.
    pub(super) fn entry(&self, tool: Option<&Tool>) -> Vec<(&'static str, Value)> {
        let mut entry = Vec::new();
        if tool.is_some_and(|tool| tool.typed) {
            let kind = if matches!(self, Self::Url(_)) {
                "http"
            } else {
                "stdio"
            };
            entry.push(("type", json!(kind)));
        }
        match self {
            Self::Url(url) => entry.push(("url", json!(url))),
            Self::Bridge { command, args } => {
                entry.push(("command", json!(command)));
                entry.push(("args", json!(args)));
            }
        }
        entry
    }

    pub(super) fn wanted(&self, tool: &Tool) -> Value {
        Value::Object(
            self.entry(Some(tool))
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect(),
        )
    }
}

fn strings(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

pub(super) fn guard_fields(tool: &Tool, entry: &Map<String, Value>) -> Option<Fields> {
    let has_url = entry.contains_key("url");
    match (tool.typed, entry.get("type")) {
        (true, kind) => {
            let wanted = if has_url { "http" } else { "stdio" };
            if kind.and_then(Value::as_str) != Some(wanted) {
                return None;
            }
        }
        (false, Some(_)) => return None,
        (false, None) => {}
    }
    let keys: Vec<&str> = entry
        .keys()
        .map(String::as_str)
        .filter(|key| *key != "type")
        .collect();
    match keys.as_slice() {
        ["url"] => Some(Fields::Url(entry["url"].as_str()?.to_owned())),
        ["args", "command"] => {
            let command = entry["command"].as_str()?.to_owned();
            let args = strings(&entry["args"])?;
            let bridge = [BRIDGE_ARGS[0], BRIDGE_ARGS[1], tool.slug];
            let bridged = args.windows(3).any(|window| window == bridge);
            bridged.then_some(Fields::Bridge { command, args })
        }
        _ => None,
    }
}
