use super::*;
use crate::context_assistance_history::{Entry, MAX_BYTES, MAX_ENTRIES};

impl Engine {
    pub(super) fn history_request(
        &mut self,
        runtime: &mut VerifiedRuntime,
        request: Request,
    ) -> Result<Value, RuntimeError> {
        if matches!(&request, Request::Data | Request::ForgetHistory) {
            for scope in self.scopes.values_mut() {
                if !scope.revoked {
                    match policy_current(&self.home, scope, runtime) {
                        Ok(()) | Err(RuntimeError::ScopeDenied) => {}
                        Err(error) => return Err(error),
                    }
                }
                scope.history.expire(scope.policy.storage.retention_hours);
                if matches!(&request, Request::ForgetHistory) {
                    scope.history.clear();
                }
            }
            let active: Vec<_> = self
                .scopes
                .values()
                .filter(|scope| !scope.revoked)
                .collect();
            let sums = |field: &str| {
                active
                    .iter()
                    .map(|scope| scope.history.summary()[field].as_u64().unwrap_or(0))
                    .sum::<u64>()
            };
            return Ok(
                json!({"schema":"guard-cigar-data-summary.v2","storage":"memory","history_storage":"memory","data_role":true,
                "active_scopes":active.len(),"selected_files":active.iter().map(|s| s.sources.len()).sum::<usize>(),
                "current_contexts":active.iter().map(|s| s.context_count()).sum::<usize>(),
                "history_entries":sums("entries"),"history_encoded_bytes":sums("encoded_bytes"),
                "agent_sessions":self.agents.metadata(std::time::Instant::now()).as_array().map_or(0,Vec::len),
                "max_history_entries_per_scope":MAX_ENTRIES,"max_history_encoded_bytes_per_scope":MAX_BYTES,
                "saved_context":"unavailable","saved_evidence":self.saved_data(),"cleared_saved":false,
                "cleared_history":matches!(&request, Request::ForgetHistory)}),
            );
        }
        let id = match &request {
            Request::History { scope_id, .. } | Request::HistoryDetail { scope_id, .. } => scope_id,
            _ => return Err(RuntimeError::RequestInvalid),
        };
        let scope = self.scopes.get_mut(id).ok_or(RuntimeError::ScopeDenied)?;
        policy_current(&self.home, scope, runtime)?;
        if (scope.app == "dashboard" && !scope.policy.features.review_briefs)
            || (scope.app != "dashboard" && !scope.policy.features.agent_context)
        {
            return Err(RuntimeError::ScopeDenied);
        }
        scope.history.expire(scope.policy.storage.retention_hours);
        let result = match &request {
            Request::History { decision_id, .. } => {
                if decision_id.as_deref().is_some_and(|id| {
                    id.len() != 64
                        || !id
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                }) {
                    return Err(RuntimeError::RequestInvalid);
                }
                json!({"history_schema":"guard-cigar-history.v1","scope":metadata(id,scope),
                    "entries":scope.history.list(decision_id.as_deref()),"summary":scope.history.summary(),
                    "historical":true,"current":false})
            }
            Request::HistoryDetail { history_id, .. } => {
                let entry = scope
                    .history
                    .get(history_id)
                    .ok_or(RuntimeError::ContextStale)?;
                let before = source_states(scope, &entry)?;
                policy_current(&self.home, scope, runtime)?;
                let after = source_states(scope, &entry)?;
                if before != after {
                    return Err(RuntimeError::ContextStale);
                }
                let permitted = !after.iter().any(|state| state["state"] == "unavailable");
                json!({"history_schema":"guard-cigar-history.v1","scope":metadata(id,scope),"entry":entry.metadata(),
                    "brief":permitted.then_some(&entry.brief),"source_states":after,
                    "historical":true,"current":false,"source_access":if permitted {"available"} else {"unavailable"}})
            }
            _ => return Err(RuntimeError::RequestInvalid),
        };
        policy_current(&self.home, scope, runtime)?;
        Ok(result)
    }
}

fn source_states(scope: &Scope, entry: &Entry) -> Result<Vec<Value>, RuntimeError> {
    entry.sources.iter().map(|source| {
        if scope.sources.get(&source.source_id).is_none_or(|grant| grant.relative_path != source.path) {
            return Err(RuntimeError::ScopeDenied);
        }
        let current = scope.root.read(&source.path).ok().map(|file| file.sha256);
        let state = match current.as_deref() {
            Some(hash) if hash == source.sha256 => "unchanged",
            Some(_) => "changed",
            None => "unavailable",
        };
        Ok(json!({"source_id":source.source_id,"recorded_sha256":source.sha256,"current_sha256":current,"state":state}))
    }).collect()
}
