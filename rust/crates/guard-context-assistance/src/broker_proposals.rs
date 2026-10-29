use super::*;

fn retain_notes_basis(
    sources: &BTreeMap<String, Source>,
    docs: &BTreeMap<String, ContextDocument>,
    allowed: &BTreeSet<String>,
    basis: &mut BTreeMap<String, BrokerRevision>,
) -> Result<(), RuntimeError> {
    // A replacement can carry old notes even when the new planning snapshot
    // did not render them. Preserve those notes' original dependencies.
    if let Some(previous) = sources.get("guard:notes") {
        if docs.keys().any(|id| previous.documents.contains_key(id)) {
            for (source, revision) in &previous.basis {
                if !allowed.contains(source)
                    || sources.get(source).is_none_or(|s| &s.revision != revision)
                    || basis.get(source).is_some_and(|current| current != revision)
                {
                    return Err(RuntimeError::ContextStale);
                }
                basis.insert(source.clone(), revision.clone());
            }
        }
    }
    Ok(())
}

impl VerifiedRuntime {
    pub fn broker_proposal_records(
        &self,
        domain: &BrokerDomainHandle,
    ) -> Result<Vec<(&BrokerProposal, &'static str)>, RuntimeError> {
        Ok(self
            .brokers
            .domain(domain)?
            .proposals
            .values()
            .filter(|p| p.expires > Instant::now())
            .map(|p| (&p.proposal, p.status))
            .collect())
    }
    /// Client material is quarantined. Only the separate native host admission
    /// method can make it visible to any context view.
    pub fn propose_broker_evidence(
        &mut self,
        context: &RetainedBrokerContext,
        key: &str,
        expected: BrokerRevision,
        values: Vec<ContextDocument>,
    ) -> Result<Value, RuntimeError> {
        let ticket = self.broker_context_ticket(context)?;
        let client = &context.client;
        self.broker_client_rpc(client, json!({"op":"revalidate","ticket":ticket}))?;
        let owner = self.brokers.client(client)?;
        if !valid_id(key) || !owner.writable.contains("guard:notes") {
            return Err(RuntimeError::ScopeDenied);
        }
        let expires = owner.expires.min(Instant::now() + Duration::from_secs(300));
        let domain = self
            .brokers
            .domains
            .get(&client.domain)
            .ok_or(RuntimeError::ScopeDenied)?;
        let mut basis = self.broker_context_sources(context)?;
        basis.remove("guard:notes");
        expected
            .validate()
            .map_err(|_| RuntimeError::RequestInvalid)?;
        if expected.epoch != domain.epoch {
            return Err(RuntimeError::ContextStale);
        }
        if values.len() > 32 || values.iter().any(|d| !d.id.starts_with("note:")) {
            return Err(RuntimeError::RequestInvalid);
        }
        let docs = documents(values, 16384)?;
        retain_notes_basis(&domain.sources, &docs, &owner.sources, &mut basis)?;
        if basis.len() > 32 {
            return Err(RuntimeError::ResourceLimit);
        }
        if docs.keys().any(|id| {
            domain
                .sources
                .iter()
                .any(|(source, s)| source != "guard:notes" && s.documents.contains_key(id))
        }) {
            return Err(RuntimeError::ScopeDenied);
        }
        let existing = domain
            .proposals
            .values()
            .find(|p| p.proposal.client_id == client.id && p.proposal.request_key == key);
        if let Some(existing) = existing {
            if existing.proposal.expected != expected
                || existing.proposal.documents != docs.values().cloned().collect::<Vec<_>>()
                || existing.proposal.basis != basis
                || existing.proposal.basis_snapshot != context.brief.snapshot_id
            {
                return Err(RuntimeError::ContextConflict);
            }
            return self.broker_proposal_status(client, key);
        }
        if domain.proposals.len() >= 32
            || domain
                .proposals
                .values()
                .filter(|p| p.proposal.client_id == client.id)
                .count()
                >= 4
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let result=self.broker_client_rpc(client,json!({"op":"propose","source":"guard:notes","request_key":key,"expected":expected,"documents":wire_documents("guard:notes",&docs)}))?;
        let id = result["proposal_id"].as_str().filter(|id| valid_id(id));
        if id.is_none() || result["request_key"] != key || result["outcome"]["status"] != "pending"
        {
            self.close();
            return Err(RuntimeError::TransportFailed);
        }
        let id = id.ok_or(RuntimeError::TransportFailed)?.to_owned();
        let proposal = BrokerProposal {
            proposal_id: id.clone(),
            client_id: client.id.clone(),
            request_key: key.into(),
            source: "guard:notes".into(),
            expected,
            documents: docs.into_values().collect(),
            basis_snapshot: context.brief.snapshot_id.clone(),
            basis,
            data_role: true,
        };
        self.brokers
            .domains
            .get_mut(&client.domain)
            .ok_or(RuntimeError::ScopeDenied)?
            .proposals
            .insert(
                id,
                Pending {
                    proposal,
                    expires,
                    status: "pending",
                },
            );
        Ok(result)
    }

    pub fn broker_proposal_status(
        &mut self,
        client: &BrokerClientHandle,
        key: &str,
    ) -> Result<Value, RuntimeError> {
        self.brokers.client(client)?;
        let domain = self
            .brokers
            .domains
            .get(&client.domain)
            .ok_or(RuntimeError::ScopeDenied)?;
        let pending = domain
            .proposals
            .values()
            .find(|p| {
                p.proposal.client_id == client.id
                    && p.proposal.request_key == key
                    && p.expires > Instant::now()
            })
            .ok_or(RuntimeError::ScopeDenied)?;
        let id = pending.proposal.proposal_id.clone();
        let status = pending.status;
        let result =
            self.broker_client_rpc(client, json!({"op":"proposal_status","request_key":key}))?;
        if result["proposal_id"] != id
            || result["request_key"] != key
            || result["outcome"]["status"] != status
        {
            self.close();
            return Err(RuntimeError::TransportFailed);
        }
        Ok(result)
    }

    pub fn list_broker_proposals(
        &mut self,
        domain: &BrokerDomainHandle,
    ) -> Result<Vec<BrokerProposal>, RuntimeError> {
        self.brokers.domain(domain)?;
        let live: BTreeSet<_> = self
            .brokers
            .clients
            .iter()
            .filter(|(_, c)| c.expires > Instant::now())
            .map(|(id, _)| id.clone())
            .collect();
        let record = self
            .brokers
            .domains
            .get_mut(&domain.id)
            .ok_or(RuntimeError::ScopeDenied)?;
        record
            .proposals
            .retain(|_, p| p.expires > Instant::now() && live.contains(&p.proposal.client_id));
        Ok(record
            .proposals
            .values()
            .filter(|p| p.status == "pending")
            .map(|p| p.proposal.clone())
            .collect())
    }

    pub fn inspect_broker_proposal(
        &mut self,
        domain: &BrokerDomainHandle,
        id: &str,
    ) -> Result<BrokerProposal, RuntimeError> {
        let record = self.brokers.domain(domain)?;
        let proposal = record
            .proposals
            .get(id)
            .filter(|p| p.status == "pending" && p.expires > Instant::now())
            .ok_or(RuntimeError::ScopeDenied)?
            .proposal
            .clone();
        let result = self.rpc(
            json!({"op":"broker_proposal","domain":domain.id,"proposal":id}),
            TIMEOUT,
        )?;
        let docs: BTreeMap<_, _> = proposal
            .documents
            .iter()
            .map(|d| (d.id.clone(), d.clone()))
            .collect();
        if result["source"] != proposal.source
            || result["expected"]
                != serde_json::to_value(&proposal.expected)
                    .map_err(|_| RuntimeError::TransportFailed)?
            || result["documents"] != json!(wire_documents(&proposal.source, &docs))
        {
            self.close();
            return Err(RuntimeError::TransportFailed);
        }
        Ok(proposal)
    }

    /// Host-only admission. This is evidence data, never a command approval.
    /// The product caller must obtain separate operator proof before calling.
    pub fn admit_broker_proposal(
        &mut self,
        domain: &BrokerDomainHandle,
        id: &str,
    ) -> Result<BrokerRevision, RuntimeError> {
        let proposal = self.inspect_broker_proposal(domain, id)?;
        let docs = documents(proposal.documents.clone(), 16384)?;
        let record = self.brokers.domain(domain)?;
        if proposal.basis.iter().any(|(source, version)| {
            record
                .sources
                .get(source)
                .is_none_or(|s| &s.revision != version)
        }) {
            return Err(RuntimeError::ContextStale);
        }
        let used: usize = record
            .sources
            .iter()
            .filter(|(source, _)| *source != "guard:notes")
            .flat_map(|(_, s)| s.documents.values())
            .map(|d| d.text.len())
            .sum();
        if used + docs.values().map(|d| d.text.len()).sum::<usize>() > 4194304 {
            return Err(RuntimeError::ResourceLimit);
        }
        let mut provenance = provenance(record, &proposal.documents, "reviewed_proposal")?;
        provenance["derived_from"] = json!(proposal
            .basis
            .iter()
            .map(|(source, revision)| json!({"source":source,"revision":revision}))
            .collect::<Vec<_>>());
        let epoch = record.epoch.clone();
        let result = self.rpc(
            json!({"op":"broker_admit","domain":domain.id,"proposal":id,"provenance":provenance}),
            TIMEOUT,
        )?;
        let current = match revision(&result["revision"], &epoch) {
            Ok(value) => value,
            Err(error) => {
                self.close();
                return Err(error);
            }
        };
        let record = self
            .brokers
            .domains
            .get_mut(&domain.id)
            .ok_or(RuntimeError::ScopeDenied)?;
        record.sources.insert(
            proposal.source,
            Source {
                revision: current.clone(),
                documents: docs,
                basis: proposal.basis,
            },
        );
        record
            .proposals
            .get_mut(id)
            .ok_or(RuntimeError::ScopeDenied)?
            .status = "admitted";
        Ok(current)
    }

    pub fn reject_broker_proposal(
        &mut self,
        domain: &BrokerDomainHandle,
        id: &str,
    ) -> Result<(), RuntimeError> {
        let record = self.brokers.domain(domain)?;
        record
            .proposals
            .get(id)
            .filter(|p| p.status == "pending" && p.expires > Instant::now())
            .ok_or(RuntimeError::ScopeDenied)?;
        self.rpc(
            json!({"op":"broker_reject","domain":domain.id,"proposal":id}),
            TIMEOUT,
        )?;
        self.brokers
            .domains
            .get_mut(&domain.id)
            .ok_or(RuntimeError::ScopeDenied)?
            .proposals
            .get_mut(id)
            .ok_or(RuntimeError::ScopeDenied)?
            .status = "rejected";
        Ok(())
    }

    pub fn forget_broker_proposal(
        &mut self,
        client: &BrokerClientHandle,
        key: &str,
    ) -> Result<(), RuntimeError> {
        self.brokers.client(client)?;
        let id = self
            .brokers
            .domains
            .get(&client.domain)
            .ok_or(RuntimeError::ScopeDenied)?
            .proposals
            .values()
            .find(|p| p.proposal.client_id == client.id && p.proposal.request_key == key)
            .ok_or(RuntimeError::ScopeDenied)?
            .proposal
            .proposal_id
            .clone();
        self.broker_client_rpc(client, json!({"op":"forget_proposal","request_key":key}))?;
        self.brokers
            .domains
            .get_mut(&client.domain)
            .ok_or(RuntimeError::ScopeDenied)?
            .proposals
            .remove(&id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carried_notes_cannot_launder_omitted_foreign_or_stale_file_dependencies() {
        let revision = BrokerRevision {
            epoch: "a".repeat(64),
            version: "1".into(),
        };
        let doc = |id: &str| ContextDocument {
            id: id.into(),
            text: "Retained reviewed guidance.".into(),
            start_line: 1,
        };
        let old = BTreeMap::from([("note:old".into(), doc("note:old"))]);
        let mut sources = BTreeMap::from([
            (
                "file:upstream".into(),
                Source {
                    revision: revision.clone(),
                    documents: BTreeMap::new(),
                    basis: BTreeMap::new(),
                },
            ),
            (
                "guard:notes".into(),
                Source {
                    revision: revision.clone(),
                    documents: old.clone(),
                    basis: BTreeMap::from([("file:upstream".into(), revision.clone())]),
                },
            ),
        ]);
        let allowed = BTreeSet::from(["file:upstream".into(), "guard:notes".into()]);
        let mut basis = BTreeMap::new();
        retain_notes_basis(&sources, &old, &allowed, &mut basis).unwrap();
        assert_eq!(
            basis.get("file:upstream"),
            Some(&revision),
            "upstream remains required even when absent from the new snapshot"
        );
        assert_eq!(
            retain_notes_basis(
                &sources,
                &old,
                &BTreeSet::from(["guard:notes".into()]),
                &mut BTreeMap::new()
            ),
            Err(RuntimeError::ContextStale)
        );
        sources.get_mut("file:upstream").unwrap().revision.version = "2".into();
        assert_eq!(
            retain_notes_basis(&sources, &old, &allowed, &mut BTreeMap::new()),
            Err(RuntimeError::ContextStale)
        );
        let replacement = BTreeMap::from([("note:new".into(), doc("note:new"))]);
        let mut fresh = BTreeMap::new();
        retain_notes_basis(&sources, &replacement, &BTreeSet::new(), &mut fresh).unwrap();
        assert!(
            fresh.is_empty(),
            "replacing every prior note need not inherit removed content's dependencies"
        );
    }
}
