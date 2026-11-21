use super::*;

impl Engine {
    pub(super) fn proposal_request(
        &mut self,
        runtime: &mut VerifiedRuntime,
        request: Request,
    ) -> Result<Value, RuntimeError> {
        let id = match &request {
            Request::Proposals { scope_id }
            | Request::Proposal { scope_id, .. }
            | Request::AdmitProposal { scope_id, .. }
            | Request::RejectProposal { scope_id, .. }
            | Request::ClearNotes { scope_id } => scope_id.clone(),
            _ => return Err(RuntimeError::RequestInvalid),
        };
        let scope = self.scopes.get_mut(&id).ok_or(RuntimeError::ScopeDenied)?;
        policy_current(&self.home, scope, runtime)?;
        if !scope.graph.is_shared() || !scope.graph.access().read {
            return Err(RuntimeError::ScopeDenied);
        }
        if matches!(request, Request::ClearNotes { .. }) {
            let scope = self.reset_scope(runtime, &id, None)?;
            return Ok(json!({"scope":scope,"cleared_notes":true,"data_role":true}));
        }
        let result = match request {
            Request::Proposals { .. } => {
                json!({"scope":metadata(&id,scope),"proposals":scope.graph.proposals(runtime)?,"data_role":true})
            }
            Request::Proposal { proposal_id, .. } => {
                let mut detail = scope.graph.proposal_detail(runtime, &proposal_id)?;
                let before = proposal_source_states(scope, &detail)?;
                policy_current(&self.home, scope, runtime)?;
                let states = proposal_source_states(scope, &detail)?;
                if before != states {
                    return Err(RuntimeError::ContextStale);
                }
                let available = !states.iter().any(|state| state["state"] == "unavailable");
                if !available {
                    detail["documents"] = Value::Null;
                    detail["current_documents"] = Value::Null;
                }
                detail["source_access"] = json!(if available {
                    "available"
                } else {
                    "unavailable"
                });
                detail["source_states"] = json!(states);
                json!({"scope":metadata(&id,scope),"proposal":detail,"data_role":true})
            }
            Request::AdmitProposal { proposal_id, .. } => {
                current_sources(scope)?;
                let result = scope.graph.decide_proposal(runtime, &proposal_id, true)?;
                scope.clear_contexts();
                current_sources(scope)?;
                result
            }
            Request::RejectProposal { proposal_id, .. } => {
                scope.graph.decide_proposal(runtime, &proposal_id, false)?
            }
            Request::ClearNotes { .. } => {
                scope.graph.clear_notes(runtime)?;
                scope.clear_contexts();
                scope.history.clear();
                json!({"scope":metadata(&id,scope),"cleared_notes":true,"data_role":true})
            }
            _ => return Err(RuntimeError::RequestInvalid),
        };
        policy_current(&self.home, scope, runtime)?;
        Ok(result)
    }
}

fn proposal_source_states(scope: &Scope, detail: &Value) -> Result<Vec<Value>, RuntimeError> {
    let basis = detail["basis"]
        .as_object()
        .ok_or(RuntimeError::ContextStale)?;
    let permitted = allowed(&scope.sources, &scope.policy);
    if basis.keys().any(|id| !permitted.contains(id)) {
        return Err(RuntimeError::ScopeDenied);
    }
    scope.sources.values().filter(|s|basis.contains_key(&s.source_id)).map(|source| {
        let current=scope.root.read(&source.relative_path).ok().map(|f|f.sha256);
        Ok(json!({"source_id":source.source_id,"path":source.relative_path,"current_sha256":current,
            "state":if current.as_ref()==Some(&source.sha256){"unchanged"}else if current.is_some(){"changed"}else{"unavailable"}}))
    }).collect()
}
