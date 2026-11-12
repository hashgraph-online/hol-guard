//! Rebuild the native validation catalog from freshly authorized host data.
//! SDK recovery itself never creates a native view or revives a source grant.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Dependency {
    pub(super) source: String,
    pub(super) revision: BrokerRevision,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Provenance {
    pub(super) authority: String,
    pub(super) upstream_revision: String,
    pub(super) observed_at_ms: u64,
    pub(super) valid_until_ms: Option<u64>,
    pub(super) origin: String,
    pub(super) derived_from: Vec<Dependency>,
}
impl VerifiedRuntime {
    /// Metadata for native recovery coordination. This does not populate the
    /// source catalog or grant a view, and deliberately omits stored text.
    pub fn broker_source_digest(
        &mut self,
        handle: &BrokerDomainHandle,
        source: &str,
    ) -> Result<(BrokerRevision, Option<String>), RuntimeError> {
        let expected = self.broker_source_revision(handle, source)?;
        if expected.version == "0" {
            return Ok((expected, None));
        }
        let value = self.rpc(
            json!({"op":"broker_provenance","domain":handle.id,"source":source}),
            TIMEOUT,
        )?;
        let p: Provenance =
            serde_json::from_value(value).map_err(|_| RuntimeError::ContextStale)?;
        if p.authority != "hol_guard_native"
            || !matches!(p.origin.as_str(), "host" | "reviewed_proposal")
            || !digest(&p.upstream_revision)
            || self.broker_source_revision(handle, source)? != expected
        {
            return Err(RuntimeError::ContextStale);
        }
        Ok((expected, Some(p.upstream_revision)))
    }

    /// The caller must freshly admit these exact documents through current
    /// app/workspace/file permission. The saved SDK digest is compared with
    /// that native copy; this method does not open a document path.
    pub fn resume_broker_source(
        &mut self,
        handle: &BrokerDomainHandle,
        source: &str,
        values: Vec<ContextDocument>,
    ) -> Result<BrokerRevision, RuntimeError> {
        let domain = self.brokers.domain(handle)?;
        if domain.storage.is_none() || !domain.restored || !valid_id(source) {
            return Err(RuntimeError::ScopeDenied);
        }
        let docs = documents(values, 4194304)?;
        let retained: usize = domain
            .sources
            .iter()
            .filter(|(key, _)| *key != source)
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
        let expected = self.broker_source_revision(handle, source)?;
        let value = self.rpc(
            json!({"op":"broker_provenance","domain":handle.id,"source":source}),
            TIMEOUT,
        )?;
        let p: Provenance =
            serde_json::from_value(value).map_err(|_| RuntimeError::ContextStale)?;
        let encoded = serde_json::to_vec(&docs.values().collect::<Vec<_>>())
            .map_err(|_| RuntimeError::RequestInvalid)?;
        if p.authority != "hol_guard_native"
            || !matches!(p.origin.as_str(), "host" | "reviewed_proposal")
            || p.upstream_revision != format!("{:x}", Sha256::digest(encoded))
            || p.observed_at_ms > now_ms()
            || p.valid_until_ms
                .is_some_and(|t| t <= now_ms() || t <= p.observed_at_ms)
            || (p.origin == "reviewed_proposal" && p.valid_until_ms.is_none())
            || p.derived_from.len() > 32
            || expected.version == "0"
        {
            return Err(RuntimeError::ContextStale);
        }
        let domain = self.brokers.domain(handle)?;
        let mut basis = BTreeMap::new();
        for d in p.derived_from {
            d.revision.validate()?;
            if !valid_id(&d.source)
                || d.source == source
                || d.revision.epoch != expected.epoch
                || domain
                    .sources
                    .get(&d.source)
                    .is_none_or(|s| s.revision != d.revision)
                || basis.insert(d.source, d.revision).is_some()
            {
                return Err(RuntimeError::ContextStale);
            }
        }
        if self.broker_source_revision(handle, source)? != expected {
            return Err(RuntimeError::ContextStale);
        }
        self.brokers
            .domains
            .get_mut(&handle.id)
            .ok_or(RuntimeError::ScopeDenied)?
            .sources
            .insert(
                source.into(),
                Source {
                    revision: expected.clone(),
                    documents: docs,
                    basis,
                },
            );
        Ok(expected)
    }
}
