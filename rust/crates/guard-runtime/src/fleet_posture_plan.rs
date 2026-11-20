//! Transmission planning for `fleet_posture_inventory`: what each send
//! carries against the snapshot Guard Cloud last accepted, and the patch that
//! turns that snapshot into the next one.

use std::collections::{BTreeMap, HashSet};

use serde_json::{json, Map, Value};

use super::selection::{item_fingerprint, timestamp};
use super::{field, FULL_REFRESH_AFTER_MICROS};

fn tracked(item: &Map<String, Value>) -> Value {
    json!({
        "k": item.get("kind"),
        "n": item.get("name"),
        "h": item.get("harness"),
        "x": item.get("hash"),
        "f": item_fingerprint(item),
    })
}

/// What a removal entry can name: the contract carries no path hash.
fn identity(kind: Value, harness: Value, name: Value, hash: Value) -> String {
    Value::Array(vec![kind, harness, name, hash]).to_string()
}

pub(super) struct Plan {
    pub(super) mode: &'static str,
    pub(super) items: Vec<Value>,
    pub(super) removed: Vec<Value>,
    pub(super) next_items: Map<String, Value>,
    /// A chunked full refresh still has items or removals left to send.
    pub(super) streaming: bool,
    /// This send finished a full refresh.
    pub(super) full_complete: bool,
}

pub(super) struct Request<'a> {
    pub(super) current: &'a BTreeMap<String, Map<String, Value>>,
    pub(super) previous: Option<Map<String, Value>>,
    pub(super) last: Option<&'a Map<String, Value>>,
    pub(super) force_full: bool,
    pub(super) detail: bool,
    pub(super) now: i64,
}

impl Request<'_> {
    fn streaming(&self) -> bool {
        self.last
            .and_then(|last| last.get("fullStreaming"))
            .and_then(Value::as_bool)
            == Some(true)
    }

    /// A full inventory is due on first send, on request, or after a week.
    fn needs_full(&self) -> bool {
        let full_sent_at = self.last.and_then(|last| timestamp(last.get("fullSentAt")));
        match full_sent_at {
            Some(sent) if self.previous.is_some() && !self.force_full => {
                self.now - sent > FULL_REFRESH_AFTER_MICROS
            }
            _ => true,
        }
    }

    pub(super) fn digest_only(&self) -> Plan {
        Plan {
            mode: "digest_only",
            items: Vec::new(),
            removed: Vec::new(),
            next_items: self.previous.clone().unwrap_or_default(),
            streaming: self.streaming(),
            full_complete: false,
        }
    }

    /// `plan_inventory`: a refresh that does not fit one request streams as
    /// successive deltas. The tracked snapshot keeps every item and removal
    /// not yet sent, so a later request continues the stream instead of
    /// restarting it or forgetting pending removals.
    pub(super) fn plan(&self, limit: usize) -> Plan {
        let resuming = self.streaming();
        if !self.detail {
            return self.digest_only();
        }
        let refreshing = resuming || self.needs_full();
        if refreshing && !resuming && self.current.len() <= limit {
            return Plan {
                mode: "full",
                items: self.current.values().cloned().map(Value::Object).collect(),
                removed: Vec::new(),
                next_items: self
                    .current
                    .iter()
                    .map(|(key, item)| (key.clone(), tracked(item)))
                    .collect(),
                streaming: false,
                full_complete: true,
            };
        }
        let prior = self.previous.clone().unwrap_or_default();
        // Starting a refresh treats every current item as unknown to Guard Cloud.
        let baseline: Map<String, Value> = if resuming || !refreshing {
            prior
        } else {
            prior
                .into_iter()
                .filter(|(key, _)| !self.current.contains_key(key))
                .collect()
        };
        let changed: Vec<&String> = self
            .current
            .iter()
            .filter(|(key, item)| {
                baseline
                    .get(*key)
                    .and_then(|entry| entry.get("f"))
                    .and_then(Value::as_str)
                    != Some(item_fingerprint(item).as_str())
            })
            .map(|(key, _)| key)
            .collect();
        let mut gone: Vec<&String> = baseline
            .keys()
            .filter(|key| !self.current.contains_key(*key))
            .collect();
        gone.sort();
        let sent_changed = &changed[..changed.len().min(limit)];
        let sent_gone = &gone[..gone.len().min(limit)];
        let present: HashSet<String> = self
            .current
            .values()
            .map(|item| {
                identity(
                    item.get("kind").cloned().unwrap_or_default(),
                    item.get("harness").cloned().unwrap_or_default(),
                    item.get("name").cloned().unwrap_or_default(),
                    item.get("hash").cloned().unwrap_or_default(),
                )
            })
            .collect();
        let removed = sent_gone
            .iter()
            .map(|key| &baseline[key.as_str()])
            .filter(|entry| {
                !present.contains(&identity(
                    field(entry, "k"),
                    field(entry, "h"),
                    field(entry, "n"),
                    field(entry, "x"),
                ))
            })
            .map(|entry| {
                json!({
                    "kind": field(entry, "k"),
                    "name": field(entry, "n"),
                    "harness": field(entry, "h"),
                    "hash": field(entry, "x"),
                })
            })
            .collect();
        let mut next_items = baseline.clone();
        for key in sent_gone {
            next_items.remove(key.as_str());
        }
        for key in sent_changed {
            next_items.insert((*key).clone(), tracked(&self.current[key.as_str()]));
        }
        let unfinished = changed.len() > limit || gone.len() > limit;
        Plan {
            mode: "delta",
            items: sent_changed
                .iter()
                .map(|key| Value::Object(self.current[key.as_str()].clone()))
                .collect(),
            removed,
            next_items,
            streaming: refreshing && unfinished,
            full_complete: refreshing && !unfinished,
        }
    }
}

/// The tracked items of the last accepted send, as stored. A large snapshot
/// arrives as a list of objects, each within the request parser's width
/// limit, that join back into one.
pub(super) fn stored_items(last: Option<&Map<String, Value>>) -> Option<Map<String, Value>> {
    let chunks: Vec<&Map<String, Value>> = match last?.get("items")? {
        Value::Object(items) => vec![items],
        Value::Array(chunks) => chunks.iter().filter_map(Value::as_object).collect(),
        _ => return None,
    };
    Some(
        chunks
            .into_iter()
            .flatten()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

/// `previous_items`: the stored items that are tracked entries.
pub(super) fn previous_items(stored: Option<&Map<String, Value>>) -> Option<Map<String, Value>> {
    Some(
        stored?
            .iter()
            .filter(|(_, value)| value.is_object())
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

/// The change from the stored items to the next tracked snapshot. The
/// snapshot tracks every installed item, so the reply carries only this
/// patch: at most one plan's worth of entries to set, plus the keys to drop.
pub(super) fn items_patch(stored: Option<&Map<String, Value>>, next: &Map<String, Value>) -> Value {
    let empty = Map::new();
    let stored = stored.unwrap_or(&empty);
    let set: Map<String, Value> = next
        .iter()
        .filter(|(key, value)| stored.get(*key) != Some(*value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let remove: Vec<&String> = stored
        .keys()
        .filter(|key| !next.contains_key(*key))
        .collect();
    json!({ "set": set, "remove": remove })
}
