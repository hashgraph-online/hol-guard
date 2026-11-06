//! Explicit native-host broker. Public handles contain no SDK credentials.
//! Callers must bind these capabilities to current authenticated Guard grants.
#[path = "broker_domain.rs"]
mod domain;
use crate::process::JsonProcess;
use crate::{
    BrokerStorage, ContextAssistanceConfig, ContextBrief, ContextDocument, Limits, RuntimeError,
    StorageMode, VerifiedRuntime,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[path = "broker_clients.rs"]
mod clients;
#[path = "broker_execution.rs"]
mod execution;
#[path = "broker_note_transfer.rs"]
mod note_transfer;
pub use note_transfer::EphemeralReviewedNotes;
#[path = "broker_proposals.rs"]
mod proposals;
#[path = "broker_resume.rs"]
mod resume;
#[path = "broker_revision.rs"]
mod revision_codec;
pub use execution::{
    BrokerAnswerClaim, BrokerAnswerPolicy, BrokerBoundExecution, BrokerClaimReview,
    BrokerExecutionHandoff, BrokerExecutionReview, BrokerReviewVerdict, BrokerSubmission,
};

const TIMEOUT: Duration = Duration::from_secs(4);
const MAX_CLIENTS: usize = 8;
static EPOCH: AtomicU64 = AtomicU64::new(1);

#[derive(Clone)]
pub struct BrokerDomainHandle {
    epoch: u64,
    id: String,
    domain_epoch: String,
}
#[derive(Clone)]
pub struct BrokerClientHandle {
    epoch: u64,
    id: String,
    domain: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BrokerRevision {
    pub epoch: String,
    pub version: String,
}

#[derive(Clone, Serialize)]
pub struct BrokerProposal {
    pub proposal_id: String,
    pub client_id: String,
    pub request_key: String,
    pub source: String,
    pub expected: BrokerRevision,
    pub documents: Vec<ContextDocument>,
    pub basis_snapshot: String,
    pub basis: BTreeMap<String, BrokerRevision>,
    pub data_role: bool,
}

/// The SDK ticket stays inside native memory. An ID or brief is not authority.
pub struct RetainedBrokerContext {
    client: BrokerClientHandle,
    retention_id: u64,
    brief: ContextBrief,
}
impl RetainedBrokerContext {
    pub fn brief(&self) -> &ContextBrief {
        &self.brief
    }
}

struct Source {
    revision: BrokerRevision,
    documents: BTreeMap<String, ContextDocument>,
    basis: BTreeMap<String, BrokerRevision>,
}
struct Domain {
    epoch: String,
    limits: Limits,
    retention_hours: u32,
    sources: BTreeMap<String, Source>,
    proposals: BTreeMap<String, Pending>,
    storage: Option<BrokerStorage>,
    restored: bool,
    execution_handoff: bool,
    private_execution: bool,
}
struct Pending {
    proposal: BrokerProposal,
    expires: Instant,
    status: &'static str,
}
struct HeldContext {
    ticket: String,
    versions: BTreeMap<String, BrokerRevision>,
    context_id: String,
}
struct Client {
    domain: String,
    process: JsonProcess,
    sources: BTreeSet<String>,
    writable: BTreeSet<String>,
    policy_revision: String,
    expires: Instant,
    contexts: BTreeMap<u64, HeldContext>,
}
pub(crate) struct Registry {
    epoch: u64,
    next_client: u64,
    next_context: u64,
    domains: BTreeMap<String, Domain>,
    clients: BTreeMap<String, Client>,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            epoch: EPOCH.fetch_add(1, Ordering::Relaxed),
            next_client: 0,
            next_context: 0,
            domains: BTreeMap::new(),
            clients: BTreeMap::new(),
        }
    }
}
impl Registry {
    pub(crate) fn close(&mut self) {
        self.clients.clear();
        self.domains.clear();
    }
    fn domain(&self, handle: &BrokerDomainHandle) -> Result<&Domain, RuntimeError> {
        if handle.epoch != self.epoch {
            return Err(RuntimeError::ScopeDenied);
        }
        let domain = self
            .domains
            .get(&handle.id)
            .filter(|d| d.epoch == handle.domain_epoch)
            .ok_or(RuntimeError::ScopeDenied)?;
        if let Some(storage) = &domain.storage {
            storage.revalidate()?;
        }
        Ok(domain)
    }
    fn client(&self, handle: &BrokerClientHandle) -> Result<&Client, RuntimeError> {
        if handle.epoch != self.epoch {
            return Err(RuntimeError::ScopeDenied);
        }
        let client = self
            .clients
            .get(&handle.id)
            .filter(|c| c.domain == handle.domain && c.expires > Instant::now())
            .ok_or(RuntimeError::ScopeDenied)?;
        if let Some(storage) = self
            .domains
            .get(&client.domain)
            .and_then(|d| d.storage.as_ref())
        {
            storage.revalidate()?;
        }
        Ok(client)
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_:-".contains(&b))
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
fn provenance(
    domain: &Domain,
    documents: &[ContextDocument],
    origin: &str,
) -> Result<Value, RuntimeError> {
    let encoded = serde_json::to_vec(documents).map_err(|_| RuntimeError::RequestInvalid)?;
    let now = now_ms();
    let until = (origin == "reviewed_proposal")
        .then_some(now.saturating_add(u64::from(domain.retention_hours) * 3_600_000));
    Ok(
        json!({"authority":"hol_guard_native","upstream_revision":format!("{:x}",Sha256::digest(encoded)),
        "origin":origin,"observed_at_ms":now,"valid_until_ms":until,"derived_from":[]}),
    )
}
pub(crate) fn documents(
    values: Vec<ContextDocument>,
    max_bytes: usize,
) -> Result<BTreeMap<String, ContextDocument>, RuntimeError> {
    if values.len() > 1024 {
        return Err(RuntimeError::ResourceLimit);
    }
    let mut result = BTreeMap::new();
    let mut bytes = 0_usize;
    let deadline = Instant::now() + Duration::from_millis(100);
    for document in values {
        bytes = bytes
            .checked_add(document.text.len())
            .ok_or(RuntimeError::ResourceLimit)?;
        if !valid_id(&document.id)
            || document.start_line == 0
            || document.text.is_empty()
            || document.text.len() > 65536
            || bytes > max_bytes
            || document
                .text
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        {
            return Err(RuntimeError::RequestInvalid);
        }
        let scan = guard_scanner::scan_text(&document.text, true, false, 65536, Some(deadline));
        if scan.budget_exhausted
            || scan.bytes_scanned != document.text.len()
            || !scan.matches.is_empty()
        {
            return Err(RuntimeError::ScopeDenied);
        }
        if result.insert(document.id.clone(), document).is_some() {
            return Err(RuntimeError::RequestInvalid);
        }
    }
    Ok(result)
}
fn wire_documents(source: &str, values: &BTreeMap<String, ContextDocument>) -> Vec<Value> {
    values
        .values()
        .map(|d| json!({"id":d.id,"source":source,"text":d.text,"start_line":d.start_line}))
        .collect()
}
fn revision(value: &Value, epoch: &str) -> Result<BrokerRevision, RuntimeError> {
    let value: BrokerRevision =
        serde_json::from_value(value.clone()).map_err(|_| RuntimeError::TransportFailed)?;
    value.validate()?;
    if value.epoch != epoch {
        return Err(RuntimeError::TransportFailed);
    }
    Ok(value)
}

impl VerifiedRuntime {
    pub fn broker_cached_revision(
        &self,
        handle: &BrokerDomainHandle,
        source: &str,
    ) -> Result<BrokerRevision, RuntimeError> {
        self.brokers
            .domain(handle)?
            .sources
            .get(source)
            .map(|s| s.revision.clone())
            .ok_or(RuntimeError::ScopeDenied)
    }
    /// Memory-only sharing. Base runtime verification and default graph mode
    /// do not import or create a broker.
    pub fn open_broker_domain(
        &mut self,
        id: &str,
        config: &ContextAssistanceConfig,
    ) -> Result<BrokerDomainHandle, RuntimeError> {
        self.open_domain(id, config, None, false)
    }
    /// Explicit native storage capability; recovery restores evidence only.
    /// Product source grants and its native catalog must be rebuilt separately.
    pub fn open_persistent_broker_domain(
        &mut self,
        id: &str,
        config: &ContextAssistanceConfig,
        storage: BrokerStorage,
    ) -> Result<BrokerDomainHandle, RuntimeError> {
        self.open_domain(id, config, Some(storage), false)
    }
    pub fn broker_storage_status(
        &self,
        handle: &BrokerDomainHandle,
    ) -> Result<Value, RuntimeError> {
        let domain = self.brokers.domain(handle)?;
        Ok(
            json!({"mode":if domain.storage.is_some(){"sqlite-checkpoint.v1"}else{"memory"},"restored":domain.restored}),
        )
    }
    pub fn broker_source_revision(
        &mut self,
        handle: &BrokerDomainHandle,
        source: &str,
    ) -> Result<BrokerRevision, RuntimeError> {
        let domain = self.brokers.domain(handle)?;
        if !valid_id(source) {
            return Err(RuntimeError::RequestInvalid);
        }
        let epoch = domain.epoch.clone();
        let result = self.rpc(
            json!({"op":"broker_revision","domain":handle.id,"source":source}),
            TIMEOUT,
        )?;
        match revision(&result, &epoch) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.close();
                Err(error)
            }
        }
    }

    pub fn broker_replace_source(
        &mut self,
        handle: &BrokerDomainHandle,
        source: &str,
        expected: &BrokerRevision,
        values: Vec<ContextDocument>,
    ) -> Result<BrokerRevision, RuntimeError> {
        let domain = self.brokers.domain(handle)?;
        if !valid_id(source) || expected.epoch != domain.epoch {
            return Err(RuntimeError::ScopeDenied);
        }
        expected
            .validate()
            .map_err(|_| RuntimeError::RequestInvalid)?;
        let docs = documents(values, 4194304)?;
        let retained: usize = domain
            .sources
            .iter()
            .filter(|(id, _)| *id != source)
            .flat_map(|(_, s)| s.documents.values())
            .map(|d| d.text.len())
            .sum();
        if retained + docs.values().map(|d| d.text.len()).sum::<usize>() > 4194304
            || (domain.sources.len() >= 128 && !domain.sources.contains_key(source))
        {
            return Err(RuntimeError::ResourceLimit);
        }
        if docs.keys().any(|id| {
            domain
                .sources
                .iter()
                .any(|(key, s)| key != source && s.documents.contains_key(id))
        }) {
            return Err(RuntimeError::ScopeDenied);
        }
        let values: Vec<_> = docs.values().cloned().collect();
        let provenance = provenance(domain, &values, "host")?;
        let epoch = domain.epoch.clone();
        let result = self.rpc(json!({"op":"broker_replace","domain":handle.id,"source":source,"expected":expected,"documents":wire_documents(source,&docs),"provenance":provenance}),TIMEOUT)?;
        let current = match revision(&result["revision"], &epoch) {
            Ok(value) => value,
            Err(error) => {
                self.close();
                return Err(error);
            }
        };
        self.brokers
            .domains
            .get_mut(&handle.id)
            .ok_or(RuntimeError::ScopeDenied)?
            .sources
            .insert(
                source.into(),
                Source {
                    revision: current.clone(),
                    documents: docs,
                    basis: BTreeMap::new(),
                },
            );
        Ok(current)
    }

    pub fn close_broker_domain(&mut self, handle: &BrokerDomainHandle) -> Result<(), RuntimeError> {
        self.brokers.domain(handle)?;
        self.brokers
            .clients
            .retain(|_, client| client.domain != handle.id);
        self.rpc(json!({"op":"broker_close","domain":handle.id}), TIMEOUT)?;
        self.brokers.domains.remove(&handle.id);
        Ok(())
    }
}

#[cfg(test)]
#[path = "broker_tests.rs"]
mod tests;
