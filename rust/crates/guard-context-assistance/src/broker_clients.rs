use super::*;
use crate::graph::brief::{validate, BriefScope};

const CLIENT_BRIDGE: &str = include_str!("../../../../integrations/cigar/broker_client.py");

// Intentionally private, without Debug, Clone or a public export. This value
// travels only from the host SDK pipe to the native-owned client SDK pipe.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Connection {
    schema: String,
    host: String,
    port: u16,
    epoch: String,
    secret: String,
}

impl VerifiedRuntime {
    pub fn broker_client_is_live(&self, handle: &BrokerClientHandle) -> bool {
        self.status().active && self.brokers.client(handle).is_ok()
    }
    pub fn grant_broker_client(
        &mut self,
        domain: &BrokerDomainHandle,
        sources: BTreeSet<String>,
        writable: BTreeSet<String>,
        policy_revision: &str,
        lease: Duration,
    ) -> Result<BrokerClientHandle, RuntimeError> {
        self.grant_broker_client_with_deadline(
            domain,
            sources,
            writable,
            policy_revision,
            lease,
            None,
        )
    }
    /// Preparation has no SDK grant. Absolute native caller deadlines still
    /// cap the issued lease; slow setup cannot extend an agent session.
    pub fn grant_broker_client_with_deadline(
        &mut self,
        domain: &BrokerDomainHandle,
        sources: BTreeSet<String>,
        writable: BTreeSet<String>,
        policy_revision: &str,
        lease: Duration,
        deadline: Option<Instant>,
    ) -> Result<BrokerClientHandle, RuntimeError> {
        let record = self.brokers.domain(domain)?;
        if sources.len() > 128
            || !writable.is_subset(&sources)
            || writable.iter().any(|source| source != "guard:notes")
            || sources
                .iter()
                .any(|source| !record.sources.contains_key(source))
            || sources.iter().any(|source| {
                record
                    .sources
                    .get(source)
                    .is_some_and(|s| s.basis.keys().any(|required| !sources.contains(required)))
            })
            || policy_revision.is_empty()
            || policy_revision.len() > 256
            || !(100..=300_000).contains(&lease.as_millis())
        {
            return Err(RuntimeError::ScopeDenied);
        }
        self.brokers
            .clients
            .retain(|_, client| client.expires > Instant::now());
        if self.brokers.clients.len() >= MAX_CLIENTS {
            return Err(RuntimeError::ResourceLimit);
        }
        if deadline.is_some_and(|end| end <= Instant::now()) {
            return Err(RuntimeError::ContextStale);
        }
        let mut process = self.spawn_private_client(CLIENT_BRIDGE)?;
        if process.rpc(json!({"op":"prepare"}), TIMEOUT)? != json!({"ready":true}) {
            return Err(RuntimeError::HandshakeFailed);
        }
        self.recheck_artifacts()?;
        let id = self
            .brokers
            .next_client
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        self.brokers.next_client = id;
        let id = format!("client:{id}");
        let epoch = self.brokers.domain(domain)?.epoch.clone();
        let tokens = self.brokers.domain(domain)?.limits.context_tokens;
        let expires = deadline.map_or(Instant::now() + lease, |end| {
            end.min(Instant::now() + lease)
        });
        let remaining = expires.saturating_duration_since(Instant::now());
        if remaining.as_millis() < 100 {
            return Err(RuntimeError::ContextStale);
        }
        let raw=self.rpc(json!({"op":"broker_grant","domain":domain.id,
            "view":{"id":id,"allowed_sources":sources,"writable_sources":writable,"policy_revision":policy_revision},
            "limits":{"max_tokens":tokens,"max_tickets":8,"max_proposals":4,"max_retained_bytes":1048576,
                "max_proposal_bytes":16384,"max_proposal_documents":32,"ticket_lifetime_ms":300_000,"proposal_lifetime_ms":300_000},
            "queue":{"max_jobs":1,"max_bytes":524288},"lease_ms":remaining.as_millis()}),TIMEOUT)?;
        let connection = serde_json::from_value::<Connection>(raw);
        let connection = match connection {
            Ok(value)
                if value.schema == "cigar.broker-client.v1"
                    && value.host == "127.0.0.1"
                    && value.port != 0
                    && value.epoch == epoch
                    && digest(&value.secret) =>
            {
                value
            }
            _ => {
                self.close();
                return Err(RuntimeError::HandshakeFailed);
            }
        };
        let result = (|| {
            if process.rpc(json!({"op":"initialize","connection":connection}), TIMEOUT)?
                != json!({"initialized":true})
            {
                return Err(RuntimeError::HandshakeFailed);
            }
            if Instant::now() >= expires {
                return Err(RuntimeError::ContextStale);
            }
            self.recheck_artifacts()?;
            if Instant::now() >= expires {
                return Err(RuntimeError::ContextStale);
            }
            self.brokers.clients.insert(
                id.clone(),
                Client {
                    domain: domain.id.clone(),
                    process,
                    sources,
                    writable,
                    policy_revision: policy_revision.into(),
                    expires,
                    contexts: BTreeMap::new(),
                },
            );
            Ok(BrokerClientHandle {
                epoch: self.brokers.epoch,
                id: id.clone(),
                domain: domain.id.clone(),
            })
        })();
        if result.is_err() {
            // A failed delivery never leaves a usable orphan grant.
            let revoked = self.rpc(
                json!({"op":"broker_revoke","domain":domain.id,"client":id}),
                TIMEOUT,
            );
            if revoked.is_err() {
                self.close();
            }
        }
        result
    }

    pub(super) fn broker_client_rpc(
        &mut self,
        handle: &BrokerClientHandle,
        request: Value,
    ) -> Result<Value, RuntimeError> {
        self.brokers.client(handle)?;
        let result = self
            .brokers
            .clients
            .get_mut(&handle.id)
            .ok_or(RuntimeError::ScopeDenied)?
            .process
            .rpc(request, TIMEOUT);
        if matches!(
            result,
            Err(RuntimeError::TransportFailed
                | RuntimeError::DeadlineExceeded
                | RuntimeError::Cancelled
                | RuntimeError::RuntimeClosed)
        ) {
            // Unknown SDK outcomes invalidate the generation. No automatic
            // proposal, source mutation or compile retry is made.
            self.close();
        }
        let result = result?;
        self.brokers.client(handle)?;
        Ok(result)
    }

    pub fn compile_broker_context(
        &mut self,
        handle: &BrokerClientHandle,
        query: &str,
        required: Vec<String>,
    ) -> Result<RetainedBrokerContext, RuntimeError> {
        self.compile_broker_context_inner(handle, query, required, None)
    }

    /// A private native consumer may narrow its token request, never broaden
    /// the domain/client limit selected during explicit runtime activation.
    pub fn compile_broker_context_limited(
        &mut self,
        handle: &BrokerClientHandle,
        query: &str,
        required: Vec<String>,
        limits: &Limits,
    ) -> Result<RetainedBrokerContext, RuntimeError> {
        self.compile_broker_context_inner(handle, query, required, Some(limits))
    }

    fn compile_broker_context_inner(
        &mut self,
        handle: &BrokerClientHandle,
        query: &str,
        required: Vec<String>,
        requested: Option<&Limits>,
    ) -> Result<RetainedBrokerContext, RuntimeError> {
        let retention_id = self
            .brokers
            .next_context
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        let client = self.brokers.client(handle)?;
        let domain = self
            .brokers
            .domains
            .get(&handle.domain)
            .ok_or(RuntimeError::ScopeDenied)?;
        if query.len() > 4096 || required.len() > 64 {
            return Err(RuntimeError::RequestInvalid);
        }
        let mut limits = domain.limits.clone();
        if let Some(requested) = requested {
            limits.context_tokens = limits.context_tokens.min(requested.context_tokens);
            limits.reserve_tokens = limits.reserve_tokens.max(requested.reserve_tokens);
        }
        if !(64..=16_384).contains(&limits.context_tokens)
            || limits.reserve_tokens >= limits.context_tokens
        {
            return Err(RuntimeError::RequestInvalid);
        }
        if required.iter().any(|id| {
            !client
                .sources
                .iter()
                .any(|source| domain.sources[source].documents.contains_key(id))
        }) {
            return Err(RuntimeError::ScopeDenied);
        }
        if client.sources.iter().any(|source| {
            domain.sources[source]
                .basis
                .keys()
                .any(|required| !client.sources.contains(required))
        }) {
            return Err(RuntimeError::ScopeDenied);
        }
        let versions = client
            .sources
            .iter()
            .map(|source| (source.clone(), domain.sources[source].revision.clone()))
            .collect();
        let request = json!({"query":query,"required":required,"max_tokens":limits.context_tokens,"reserve_tokens":limits.reserve_tokens,
            "policy_revision":client.policy_revision,"max_candidates":64,"max_blocks":16,"graph_depth":4,"excerpt_mode":"full"});
        let evict = if client.contexts.len() >= 8 {
            client
                .contexts
                .iter()
                .next()
                .map(|(id, c)| (*id, c.ticket.clone()))
        } else {
            None
        };
        if let Some((id, ticket)) = evict {
            match self.broker_client_rpc(handle, json!({"op":"forget_ticket","ticket":ticket})) {
                Ok(_) | Err(RuntimeError::ScopeDenied | RuntimeError::ContextStale) => {}
                Err(error) => return Err(error),
            }
            self.brokers
                .clients
                .get_mut(&handle.id)
                .ok_or(RuntimeError::ScopeDenied)?
                .contexts
                .remove(&id);
        }
        let raw = self.broker_client_rpc(handle, json!({"op":"compile","request":request}))?;
        let client = self.brokers.client(handle)?;
        let domain = self
            .brokers
            .domains
            .get(&handle.domain)
            .ok_or(RuntimeError::ScopeDenied)?;
        let brief = validate(
            &raw,
            &BriefScope {
                domain: &handle.domain,
                view_id: &handle.id,
                policy_revision: &client.policy_revision,
                sources: &client.sources,
                limits: &limits,
            },
            |source, node| domain.sources.get(source)?.documents.get(node),
        );
        let (brief, ticket) = match (
            brief,
            raw["ticket"].as_str().filter(|v| {
                !v.is_empty() && v.len() <= 256 && v.bytes().all(|b| b.is_ascii_graphic())
            }),
        ) {
            (Ok(brief), Some(ticket)) => (brief, ticket.to_owned()),
            _ => {
                self.close();
                return Err(RuntimeError::TransportFailed);
            }
        };
        self.brokers.next_context = retention_id;
        self.brokers
            .clients
            .get_mut(&handle.id)
            .ok_or(RuntimeError::ScopeDenied)?
            .contexts
            .insert(
                retention_id,
                HeldContext {
                    ticket,
                    versions,
                    context_id: raw["context"]["id"]
                        .as_str()
                        .ok_or(RuntimeError::TransportFailed)?
                        .into(),
                },
            );
        Ok(RetainedBrokerContext {
            client: handle.clone(),
            retention_id,
            brief,
        })
    }

    pub(super) fn broker_context_ticket(
        &self,
        context: &RetainedBrokerContext,
    ) -> Result<String, RuntimeError> {
        let client = self.brokers.client(&context.client)?;
        let domain = self
            .brokers
            .domains
            .get(&context.client.domain)
            .ok_or(RuntimeError::ScopeDenied)?;
        let held = client
            .contexts
            .get(&context.retention_id)
            .ok_or(RuntimeError::ContextStale)?;
        if held.versions.iter().any(|(source, version)| {
            domain
                .sources
                .get(source)
                .is_none_or(|s| &s.revision != version)
        }) {
            return Err(RuntimeError::ContextStale);
        }
        Ok(held.ticket.clone())
    }

    pub fn explain_broker_context(
        &mut self,
        context: &RetainedBrokerContext,
    ) -> Result<Value, RuntimeError> {
        let ticket = self.broker_context_ticket(context)?;
        self.broker_client_rpc(&context.client, json!({"op":"revalidate","ticket":ticket}))?;
        let result =
            self.broker_client_rpc(&context.client, json!({"op":"explain","ticket":ticket}))?;
        self.broker_context_ticket(context)?;
        Ok(result)
    }

    /// Cited sources plus their inherited provenance dependencies. This lets
    /// native history preserve file-access checks even when only a note was
    /// rendered. SDK revisions stay lossless strings.
    pub fn broker_context_sources(
        &self,
        context: &RetainedBrokerContext,
    ) -> Result<BTreeMap<String, BrokerRevision>, RuntimeError> {
        self.broker_context_ticket(context)?;
        let client = self.brokers.client(&context.client)?;
        let domain = self
            .brokers
            .domains
            .get(&client.domain)
            .ok_or(RuntimeError::ScopeDenied)?;
        let mut versions = BTreeMap::new();
        for citation in &context.brief.citations {
            let source = citation["source"]
                .as_str()
                .ok_or(RuntimeError::ContextStale)?;
            let record = domain
                .sources
                .get(source)
                .ok_or(RuntimeError::ContextStale)?;
            versions.insert(source.to_owned(), record.revision.clone());
            for (dependency, revision) in &record.basis {
                if !client.sources.contains(dependency)
                    || domain
                        .sources
                        .get(dependency)
                        .is_none_or(|s| &s.revision != revision)
                {
                    return Err(RuntimeError::ContextStale);
                }
                versions.insert(dependency.clone(), revision.clone());
            }
        }
        Ok(versions)
    }

    pub fn revoke_broker_client(
        &mut self,
        handle: &BrokerClientHandle,
    ) -> Result<(), RuntimeError> {
        // Revocation also accepts expired local handles for explicit cleanup.
        if handle.epoch != self.brokers.epoch
            || self
                .brokers
                .clients
                .get(&handle.id)
                .is_none_or(|c| c.domain != handle.domain)
        {
            return Err(RuntimeError::ScopeDenied);
        }
        self.brokers.clients.remove(&handle.id);
        self.rpc(
            json!({"op":"broker_revoke","domain":handle.domain,"client":handle.id}),
            TIMEOUT,
        )?;
        if let Some(domain) = self.brokers.domains.get_mut(&handle.domain) {
            domain
                .proposals
                .retain(|_, p| p.proposal.client_id != handle.id);
        }
        Ok(())
    }
}
