//! Bounded prepared observations, never delivery, currentness or execution
//! receipts. Only native-validated briefs enter this memory-only history.
use guard_context_assistance::{AdmittedFile, ContextBrief};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const MAX_ENTRIES: usize = 8;
pub(crate) const MAX_BYTES: usize = 512 * 1024;
const MAX_ENTRY_BYTES: usize = 256 * 1024;

#[derive(Clone, Serialize)]
pub(crate) struct SourceVersion {
    pub(crate) source_id: String,
    pub(crate) path: String,
    pub(crate) sha256: String,
}
#[derive(Clone, Serialize)]
pub(crate) struct Entry {
    pub(crate) history_id: String,
    pub(crate) prepared_at_ms: String,
    pub(crate) brief: ContextBrief,
    pub(crate) sources: Vec<SourceVersion>,
    pub(crate) association: Option<Value>,
    sdk_version: String,
    worker_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    producer: Option<Value>,
}
impl Entry {
    pub(crate) fn metadata(&self) -> Value {
        let mut value = json!({"history_id":self.history_id,"prepared_at_ms":self.prepared_at_ms,
            "snapshot_id":self.brief.snapshot_id,"policy_revision":self.brief.policy_revision,
            "graph_revision":self.brief.graph_revision,"rendered_tokens":self.brief.rendered_tokens,
            "citations":self.brief.citations,"sources":self.sources,"association":self.association,
            "sdk_version":self.sdk_version,"worker_fingerprint":self.worker_fingerprint,
            "historical":true,"text_retained":true,"observation":"prepared_not_delivery_or_execution"});
        if let Some(producer) = &self.producer {
            value["producer"] = producer.clone();
        }
        value
    }
}
#[derive(Clone)]
struct Held {
    at: Instant,
    bytes: usize,
    entry: Entry,
}
#[derive(Clone, Default)]
pub(crate) struct History {
    entries: VecDeque<Held>,
    bytes: usize,
    dropped: u64,
    next: u64,
    current_producer: Option<Value>,
}
impl History {
    pub(crate) fn set_current_producer(
        &mut self,
        producer: &guard_context_assistance::EvidenceUpgradeProducer,
    ) {
        self.current_producer = Some(producer.describe());
    }
    /// Preserve original timestamps, SDK labels and already-known producers.
    /// Newly attached provenance still counts toward the original byte bounds.
    pub(crate) fn for_upgrade(
        mut self,
        producer: &guard_context_assistance::EvidenceUpgradeProducer,
        sdk: &str,
        worker: &str,
    ) -> Self {
        let origin = producer.describe();
        for held in &mut self.entries {
            if held.entry.producer.is_none()
                && held.entry.sdk_version == sdk
                && held.entry.worker_fingerprint == worker
            {
                held.entry.producer = Some(origin.clone());
            }
            held.bytes = serde_json::to_vec(&held.entry).map_or(MAX_ENTRY_BYTES + 1, |v| v.len());
        }
        let before = self.entries.len();
        self.entries.retain(|h| h.bytes <= MAX_ENTRY_BYTES);
        self.dropped = self
            .dropped
            .saturating_add((before - self.entries.len()) as u64);
        self.bytes = self.entries.iter().map(|h| h.bytes).sum();
        while self.bytes > MAX_BYTES {
            self.remove(0);
            self.dropped = self.dropped.saturating_add(1);
        }
        self
    }
    fn remove(&mut self, index: usize) {
        if let Some(held) = self.entries.remove(index) {
            self.bytes -= held.bytes;
        }
    }
    pub(crate) fn expire(&mut self, retention_hours: u32) {
        let ttl = Duration::from_secs(u64::from(retention_hours) * 3600);
        while self
            .entries
            .front()
            .is_some_and(|held| held.at.elapsed() >= ttl)
        {
            self.remove(0);
        }
    }
    #[cfg(test)]
    pub(crate) fn record(
        &mut self,
        brief: ContextBrief,
        sources: &BTreeMap<String, AdmittedFile>,
        association: Option<Value>,
        sdk_version: &str,
        worker_fingerprint: &str,
    ) {
        self.record_with_dependencies(
            brief,
            sources,
            association,
            sdk_version,
            worker_fingerprint,
            &BTreeSet::new(),
        );
    }
    pub(crate) fn record_with_dependencies(
        &mut self,
        brief: ContextBrief,
        sources: &BTreeMap<String, AdmittedFile>,
        association: Option<Value>,
        sdk_version: &str,
        worker_fingerprint: &str,
        dependencies: &BTreeSet<String>,
    ) {
        self.next = self.next.saturating_add(1);
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let entry = Entry {
            history_id: format!("history:{}", self.next),
            prepared_at_ms: at.to_string(),
            sources: sources
                .values()
                .filter(|source| {
                    dependencies.contains(&source.source_id)
                        || brief
                            .citations
                            .iter()
                            .any(|c| c["source"] == source.source_id)
                })
                .map(|source| SourceVersion {
                    source_id: source.source_id.clone(),
                    path: source.relative_path.clone(),
                    sha256: source.sha256.clone(),
                })
                .collect(),
            brief,
            association,
            sdk_version: sdk_version.into(),
            worker_fingerprint: worker_fingerprint.into(),
            producer: self.current_producer.clone(),
        };
        let Ok(encoded) = serde_json::to_vec(&entry) else {
            self.dropped = self.dropped.saturating_add(1);
            return;
        };
        if encoded.len() > MAX_ENTRY_BYTES {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        // Identical observations replace their prior copy; queries and raw SDK
        // traces are not retained. The IDs remain selectors inside a scope.
        if let Some(index) = self.entries.iter().position(|held| {
            held.entry.brief.snapshot_id == entry.brief.snapshot_id
                && held.entry.association == entry.association
        }) {
            self.remove(index);
        }
        while self.entries.len() >= MAX_ENTRIES || self.bytes + encoded.len() > MAX_BYTES {
            self.remove(0);
            self.dropped = self.dropped.saturating_add(1);
        }
        self.bytes += encoded.len();
        self.entries.push_back(Held {
            at: Instant::now(),
            bytes: encoded.len(),
            entry,
        });
    }
    pub(crate) fn get(&self, id: &str) -> Option<Entry> {
        self.entries
            .iter()
            .find(|held| held.entry.history_id == id)
            .map(|held| held.entry.clone())
    }
    pub(crate) fn list(&self, decision_id: Option<&str>) -> Vec<Value> {
        self.entries
            .iter()
            .rev()
            .filter(|held| {
                decision_id.is_none_or(|id| {
                    held.entry
                        .association
                        .as_ref()
                        .is_some_and(|a| a["decision_id"] == id)
                })
            })
            .map(|held| held.entry.metadata())
            .collect()
    }
    pub(crate) fn summary(&self) -> Value {
        json!({"entries":self.entries.len(),"encoded_bytes":self.bytes,"dropped":self.dropped.to_string(),
            "max_entries":MAX_ENTRIES,"max_encoded_bytes":MAX_BYTES,"storage":"memory"})
    }
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
        self.dropped = 0;
    }
}

#[cfg(test)]
#[path = "context_assistance_history_tests.rs"]
mod tests;
