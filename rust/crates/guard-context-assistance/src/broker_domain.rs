//! Explicit private execution domains never imply sharing or saved storage.
use super::*;

impl VerifiedRuntime {
    pub fn open_execution_broker_domain(
        &mut self,
        id: &str,
        config: &ContextAssistanceConfig,
    ) -> Result<BrokerDomainHandle, RuntimeError> {
        if !config.features.execution_context || !config.sources.native_policy_facts {
            return Err(RuntimeError::ScopeDenied);
        }
        let mut private = config.clone();
        private.storage.mode = StorageMode::Memory;
        private.features.agent_context = false;
        private.features.shared_agents = false;
        self.open_domain(id, &private, None, true)
    }

    pub(super) fn open_domain(
        &mut self,
        id: &str,
        config: &ContextAssistanceConfig,
        mut storage: Option<BrokerStorage>,
        private_execution: bool,
    ) -> Result<BrokerDomainHandle, RuntimeError> {
        config
            .validate()
            .map_err(|_| RuntimeError::RequestInvalid)?;
        if !self.status().active
            || !config.enabled
            || (storage.is_some() != (config.storage.mode == StorageMode::Sqlite))
            || (private_execution
                && (storage.is_some()
                    || !config.features.execution_context
                    || !config.sources.native_policy_facts))
            || (storage.is_none()
                && !private_execution
                && (!config.features.agent_context || !config.features.shared_agents))
        {
            return Err(RuntimeError::ScopeDenied);
        }
        if !valid_id(id) || self.brokers.domains.contains_key(id) {
            return Err(RuntimeError::RequestInvalid);
        }
        let same_kind = self
            .brokers
            .domains
            .values()
            .filter(|domain| domain.private_execution == private_execution)
            .count();
        if (private_execution && same_kind >= 1)
            || (!private_execution && same_kind >= config.limits.max_active_workspaces as usize)
        {
            return Err(RuntimeError::ResourceLimit);
        }
        self.recheck_artifacts()?;
        let restored = storage
            .as_ref()
            .map(BrokerStorage::existed)
            .transpose()?
            .unwrap_or(false);
        let mut request = json!({"op":"broker_open","domain":id,
            "graph_limits":{"max_documents":1024,"max_document_bytes":65536,"max_total_bytes":4194304,"max_edges_per_document":16,"max_edges":4096,"cache_entries":1024,"cache_text_bytes":2097152},
            "retention":{"max_agents":8,"max_sources":128,"max_tickets":64,"max_proposals":32,"max_retained_bytes":8388608,"max_provenance_bytes":131072,"max_relation_bytes":1048576},
            "queues":{"max_agents":8,"max_agent_jobs":2,"max_agent_bytes":1048576,"max_host_jobs":2,"max_host_bytes":2097152,"max_wait_ms":500},
            "transport":{"max_connections":16,"max_connections_per_agent":2,"max_inbound_bytes":2097152,"max_outbound_bytes":8388608,"frame_timeout_ms":1000,"write_timeout_ms":1000,"response_timeout_ms":3000}});
        if let Some(storage) = &storage {
            request["storage"] = storage.wire();
        }
        let cap = self.rpc(request, TIMEOUT)?;
        let valid = cap["protocol"] == self.broker_protocol()
            && cap["core_version"] == self.status().core_version
            && cap["max_frame_bytes"] == 2 * 1024 * 1024
            && cap["max_response_bytes"] == 8 * 1024 * 1024
            && cap["host_max_frame_bytes"] == 32 * 1024 * 1024
            && cap["host_max_response_bytes"] == 64 * 1024 * 1024
            && cap["port"]
                .as_u64()
                .is_some_and(|port| (1..=65535).contains(&port))
            && cap["host"] == "127.0.0.1"
            && cap["requires_hol_services"] == false
            && cap["execution"] == "single-owner-fair-dispatch"
            && cap["epoch"].as_str().is_some_and(digest)
            && cap["storage"]
                == json!({"mode":if storage.is_some(){"sqlite-checkpoint.v1"}else{"memory"},"restored":restored})
            && cap["capabilities"]
                .as_array()
                .is_some_and(|f| f.len() <= 64 && f.iter().any(|f| f == "mutual_grant_proof.v1"));
        if !valid {
            self.close();
            return Err(RuntimeError::HandshakeFailed);
        }
        if let Some(storage) = storage.as_mut() {
            if let Err(error) = storage.seal() {
                self.close();
                return Err(error);
            }
        }
        // The broker module is imported lazily by the private SDK bridge.
        // Its first handshake must also preserve the enrolled package bytes.
        self.recheck_artifacts()?;
        self.brokers.domains.insert(
            id.into(),
            Domain {
                epoch: cap["epoch"]
                    .as_str()
                    .ok_or(RuntimeError::HandshakeFailed)?
                    .into(),
                limits: config.limits.clone(),
                retention_hours: config.storage.retention_hours,
                sources: BTreeMap::new(),
                proposals: BTreeMap::new(),
                storage,
                restored,
                private_execution,
                execution_handoff: cap["capabilities"].as_array().is_some_and(|values| {
                    values.iter().any(|value| value == "execution_handoff.v1")
                }),
            },
        );
        Ok(BrokerDomainHandle {
            epoch: self.brokers.epoch,
            id: id.into(),
            domain_epoch: self.brokers.domains[id].epoch.clone(),
        })
    }
}
