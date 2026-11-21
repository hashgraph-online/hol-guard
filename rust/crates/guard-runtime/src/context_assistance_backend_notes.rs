use super::*;

impl Backend {
    pub(in super::super) fn clear_notes(
        &mut self,
        runtime: &mut VerifiedRuntime,
    ) -> Result<(), RuntimeError> {
        if self.access.read || self.has_cache() {
            self.note_basis.clear();
            self.note_expires = None;
            self.notes.clear();
            self.proposal_owners.clear();
            self.replace_source(runtime, "guard:notes", Vec::new())?;
            for view in self.views.values_mut() {
                if let View::Shared { client, .. } = view {
                    if let Some(handle) = client.take() {
                        match runtime.revoke_broker_client(&handle) {
                            Ok(()) | Err(RuntimeError::ScopeDenied) => {}
                            Err(error) => return Err(error),
                        }
                    }
                }
            }
        }
        Ok(())
    }
    pub(in super::super) fn expire_notes(
        &mut self,
        runtime: &mut VerifiedRuntime,
    ) -> Result<bool, RuntimeError> {
        if self.note_expires.is_some_and(|t| t <= Instant::now()) {
            self.clear_notes(runtime)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    pub(in super::super) fn propose(
        &mut self,
        runtime: &mut VerifiedRuntime,
        context: &Context,
        owner: &str,
        key: &str,
        text: &str,
    ) -> Result<Value, RuntimeError> {
        if !self.access.propose || text.is_empty() || text.len() > 4096 {
            return Err(RuntimeError::ScopeDenied);
        }
        let (Some(Mode::Shared(domain)), Context::Shared(context)) = (&self.mode, context) else {
            return Err(RuntimeError::ScopeDenied);
        };
        let expected = runtime.broker_cached_revision(domain, "guard:notes")?;
        let mut docs = self.notes.clone();
        let id = format!("note:{:x}", Sha256::digest(format!("{owner}\0{key}")));
        // Stable keys never replace an admitted note silently.
        if docs.iter().any(|d| d.id == id) {
            return Err(RuntimeError::ContextConflict);
        }
        docs.push(ContextDocument {
            id,
            text: text.into(),
            start_line: 1,
        });
        let raw = runtime.propose_broker_evidence(context, key, expected, docs)?;
        let id = raw["proposal_id"]
            .as_str()
            .ok_or(RuntimeError::TransportFailed)?
            .to_owned();
        let status = raw["outcome"]["status"]
            .as_str()
            .filter(|s| matches!(*s, "pending" | "admitted" | "rejected"))
            .ok_or(RuntimeError::TransportFailed)?;
        self.proposal_owners.insert(id.clone(), owner.into());
        Ok(json!({"proposal_id":id,"request_key":key,"outcome":{"status":status},"data_role":true}))
    }
    pub(in super::super) fn proposal_status(
        &self,
        runtime: &mut VerifiedRuntime,
        view: &str,
        key: &str,
        forget: bool,
    ) -> Result<Value, RuntimeError> {
        let Some(View::Shared {
            client: Some(client),
            ..
        }) = self.views.get(view)
        else {
            return Err(RuntimeError::ContextStale);
        };
        if forget {
            runtime.forget_broker_proposal(client, key)?;
            return Ok(json!({"request_key":key,"status":"forgotten","data_role":true}));
        }
        let raw = runtime.broker_proposal_status(client, key)?;
        let outcome = &raw["outcome"];
        let status = outcome["status"]
            .as_str()
            .filter(|s| matches!(*s, "pending" | "admitted" | "rejected"))
            .ok_or(RuntimeError::TransportFailed)?;
        Ok(
            json!({"proposal_id":raw["proposal_id"],"request_key":key,"outcome":{"status":status},"data_role":true}),
        )
    }
    pub(in super::super) fn proposals(
        &self,
        runtime: &VerifiedRuntime,
    ) -> Result<Value, RuntimeError> {
        self.check_cache_read()?;
        let Some(Mode::Shared(domain)) = &self.mode else {
            return Err(RuntimeError::ScopeDenied);
        };
        Ok(json!(runtime.broker_proposal_records(domain)?.into_iter().map(|(p,state)|json!({"proposal_id":p.proposal_id,
            "connection_id":self.proposal_owners.get(&p.proposal_id),"state":state,"basis_snapshot":p.basis_snapshot,
            "expected":p.expected,"documents":p.documents.len(),"bytes":p.documents.iter().map(|d|d.text.len()).sum::<usize>(),
            "basis":p.basis,"data_role":true})).collect::<Vec<_>>()))
    }
    pub(in super::super) fn proposal_detail(
        &self,
        runtime: &VerifiedRuntime,
        id: &str,
    ) -> Result<Value, RuntimeError> {
        let Some(Mode::Shared(domain)) = &self.mode else {
            return Err(RuntimeError::ScopeDenied);
        };
        let records = runtime.broker_proposal_records(domain)?;
        let (p, state) = records
            .into_iter()
            .find(|(p, _)| p.proposal_id == id)
            .ok_or(RuntimeError::ContextStale)?;
        Ok(
            json!({"proposal_id":id,"state":state,"connection_id":self.proposal_owners.get(id),"basis_snapshot":p.basis_snapshot,
            "expected":p.expected,"basis":p.basis,"documents":p.documents,"data_role":true,"approval_grant":false,
            "current_documents":if self.note_revision.as_ref()==Some(&p.expected) {Some(&self.notes)}else{None},
            "current_revision":self.note_revision}),
        )
    }
    pub(in super::super) fn decide_proposal(
        &mut self,
        runtime: &mut VerifiedRuntime,
        id: &str,
        admit: bool,
    ) -> Result<Value, RuntimeError> {
        self.check_cache()?;
        let Some(Mode::Shared(domain)) = &self.mode else {
            return Err(RuntimeError::ScopeDenied);
        };
        if admit {
            let proposal = runtime.inspect_broker_proposal(domain, id)?;
            self.stage_notes(runtime, &proposal.expected.version, &proposal.documents)?;
            let Some(Mode::Shared(domain)) = &self.mode else {
                return Err(RuntimeError::ScopeDenied);
            };
            let revision = runtime.admit_broker_proposal(domain, id)?;
            self.commit_notes(
                runtime,
                &revision.version,
                Some((
                    proposal.documents.clone(),
                    proposal.basis.keys().cloned().collect(),
                )),
            )?;
            self.notes = proposal.documents;
            self.note_basis = proposal.basis.into_keys().collect();
            self.note_revision = Some(revision.clone());
            self.note_expires = Some(
                Instant::now()
                    + Duration::from_secs(u64::from(self.config.storage.retention_hours) * 3600),
            );
            self.digests.insert(
                "guard:notes".into(),
                format!(
                    "{:x}",
                    Sha256::digest(
                        serde_json::to_vec(&self.notes)
                            .map_err(|_| RuntimeError::RequestInvalid)?
                    )
                ),
            );
            Ok(
                json!({"proposal_id":id,"state":"admitted","revision":revision,"data_role":true,"approval_grant":false}),
            )
        } else {
            runtime.reject_broker_proposal(domain, id)?;
            Ok(json!({"proposal_id":id,"state":"rejected","data_role":true}))
        }
    }
}
