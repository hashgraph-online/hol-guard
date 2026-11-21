use super::*;
use crate::context_assistance_agents::Input;
use std::time::Instant;

impl Engine {
    pub(crate) fn agent(
        &mut self,
        runtime: &mut VerifiedRuntime,
        input: Input,
        policy: Option<crate::context_assistance_action_facts::Policy>,
    ) -> Result<Value, RuntimeError> {
        self.expire_notes(runtime)?;
        let now = Instant::now();
        let result = match input {
            Input::Discover {} => return Err(RuntimeError::RequestInvalid),
            Input::Begin {} => self.agents.begin(now)?,
            input => {
                let credential = match &input {
                    Input::Status { credential, .. }
                    | Input::Compile { credential, .. }
                    | Input::Explain { credential, .. }
                    | Input::ReviewAction { credential, .. }
                    | Input::ProposeNote { credential, .. }
                    | Input::ProposalStatus { credential, .. }
                    | Input::ForgetProposal { credential, .. }
                    | Input::Close { credential } => credential,
                    _ => return Err(RuntimeError::RequestInvalid),
                };
                let (id, scope_id) = self.agents.authenticate(credential, now)?;
                let closing = matches!(&input, Input::Close { .. });
                let result = if closing {
                    self.revoke_agent(runtime, &id)?;
                    json!({"phase":"closed", "tools":[]})
                } else if let Some(scope_id) = scope_id {
                    let scope = self
                        .scopes
                        .get_mut(&scope_id)
                        .ok_or(RuntimeError::ScopeDenied)?;
                    if scope.app == "dashboard" || !scope.policy.features.agent_context {
                        return Err(RuntimeError::ScopeDenied);
                    }
                    policy_current(&self.home, scope, runtime)?;
                    let shared = scope.graph.is_shared();
                    match input {
                        Input::Status { .. } => {
                            let mut tools = vec![
                                "get_context_status",
                                "get_guard_context",
                                "explain_guard_context",
                            ];
                            if scope.policy.sources.native_policy_facts {
                                tools.push("explain_guard_action");
                            }
                            if shared && scope.graph.access().propose {
                                tools.extend([
                                    "propose_guard_context_note",
                                    "get_guard_context_proposal_status",
                                    "forget_guard_context_proposal",
                                ]);
                            }
                            json!({"phase":"authorized", "session_id":id, "scope_id":scope_id,
                            "app":scope.app,"identity_binding":"human_paired_mcp_process", "harness_route_qualification":"not_established",
                            "tools":tools,"sharing":scope.graph.metadata()})
                        }
                        Input::Compile { arguments, .. } => {
                            let context = if shared {
                                self.shared_agent_context(
                                    runtime,
                                    &id,
                                    &scope_id,
                                    arguments.query,
                                    None,
                                )?
                            } else {
                                self.execute(
                                    runtime,
                                    Request::Compile {
                                        scope_id,
                                        query: arguments.query,
                                    },
                                )?
                            };
                            let snapshot = context["result"]["brief"]["snapshot_id"]
                                .as_str()
                                .ok_or(RuntimeError::ContextStale)?;
                            self.agents.retain_snapshot(&id, snapshot.into())?;
                            context
                        }
                        Input::Explain { arguments, .. } => {
                            self.agents.require_snapshot(&id, &arguments.snapshot_id)?;
                            if shared {
                                self.shared_agent_context(
                                    runtime,
                                    &id,
                                    &scope_id,
                                    String::new(),
                                    Some(arguments.snapshot_id),
                                )?
                            } else {
                                self.execute(
                                    runtime,
                                    Request::Explain {
                                        scope_id,
                                        snapshot_id: arguments.snapshot_id,
                                    },
                                )?
                            }
                        }
                        Input::ReviewAction { arguments, .. } => {
                            if let Some(snapshot) = &arguments.snapshot_id {
                                self.agents.require_snapshot(&id, snapshot)?;
                            }
                            let context = self.action(
                                runtime,
                                &scope_id,
                                &arguments.decision_id,
                                arguments.snapshot_id.as_deref(),
                                policy.as_ref().ok_or(RuntimeError::ScopeDenied)?,
                            )?;
                            let snapshot = context["result"]["brief"]["snapshot_id"]
                                .as_str()
                                .ok_or(RuntimeError::ContextStale)?;
                            self.agents.retain_snapshot(&id, snapshot.into())?;
                            context
                        }
                        Input::ProposeNote { arguments, .. } => {
                            self.agents.require_snapshot(&id, &arguments.snapshot_id)?;
                            current_sources(scope)?;
                            let context = scope
                                .agent_contexts
                                .get(&id)
                                .and_then(|c| c.get(&arguments.snapshot_id))
                                .ok_or(RuntimeError::ContextStale)?;
                            let result = scope.graph.propose(
                                runtime,
                                context,
                                &id,
                                &arguments.request_key,
                                &arguments.text,
                            )?;
                            current_sources(scope)?;
                            policy_current(&self.home, scope, runtime)?;
                            result
                        }
                        Input::ProposalStatus { arguments, .. } => scope.graph.proposal_status(
                            runtime,
                            &id,
                            &arguments.request_key,
                            false,
                        )?,
                        Input::ForgetProposal { arguments, .. } => scope.graph.proposal_status(
                            runtime,
                            &id,
                            &arguments.request_key,
                            true,
                        )?,
                        _ => return Err(RuntimeError::RequestInvalid),
                    }
                } else if matches!(input, Input::Status { .. }) {
                    json!({"phase":"pending","session_id":id,"tools":["get_context_status"]})
                } else {
                    return Err(RuntimeError::ScopeDenied);
                };
                if !closing {
                    self.agents.require_live(&id, Instant::now())?;
                }
                result
            }
        };
        Ok(json!({"schema":"guard-cigar-agent-data.v1","data_role":true,"result":result}))
    }

    pub(super) fn authorize_agent(
        &mut self,
        runtime: &mut VerifiedRuntime,
        session_id: String,
        scope_id: String,
    ) -> Result<Value, RuntimeError> {
        let scope = self
            .scopes
            .get_mut(&scope_id)
            .ok_or(RuntimeError::ScopeDenied)?;
        if scope.app == "dashboard" || !scope.policy.features.agent_context {
            return Err(RuntimeError::ScopeDenied);
        }
        policy_current(&self.home, scope, runtime)?;
        let shared = scope.graph.is_shared();
        self.agents
            .authorize_mode(&session_id, &scope_id, Instant::now(), shared)?;
        if shared {
            let prepared = (|| {
                scope.graph.create_view(
                    runtime,
                    &session_id,
                    allowed(&scope.sources, &scope.policy),
                    &scope.revision,
                    true,
                )?;
                scope.graph.prepare_view(
                    runtime,
                    &session_id,
                    Some(self.agents.expires(&session_id)?),
                )?;
                self.agents.require_live(&session_id, Instant::now())
            })();
            if let Err(error) = prepared {
                if scope.graph.remove_view(runtime, &session_id).is_err() {
                    runtime.close();
                }
                let _ = self.agents.revoke(&session_id);
                return Err(error);
            }
        }
        Ok(
            json!({"session_id":session_id,"scope_id":scope_id,"authorized":true,"lease_seconds":if shared{300}else{3600}}),
        )
    }
    pub(super) fn revoke_agent(
        &mut self,
        runtime: &mut VerifiedRuntime,
        id: &str,
    ) -> Result<(), RuntimeError> {
        for scope in self.scopes.values_mut() {
            if !scope.revoked {
                scope.graph.remove_view(runtime, id)?;
            }
            scope.agent_contexts.remove(id);
        }
        self.agents.revoke(id)
    }
    fn shared_agent_context(
        &mut self,
        runtime: &mut VerifiedRuntime,
        id: &str,
        scope_id: &str,
        query: String,
        snapshot: Option<String>,
    ) -> Result<Value, RuntimeError> {
        self.drain_receipts(runtime)?;
        let expires = self.agents.expires(id)?;
        let scope = self
            .scopes
            .get_mut(scope_id)
            .ok_or(RuntimeError::ScopeDenied)?;
        policy_current(&self.home, scope, runtime)?;
        current_sources(scope)?;
        let (brief, explanation) = if let Some(snapshot) = snapshot {
            let context = scope
                .agent_contexts
                .get(id)
                .and_then(|c| c.get(&snapshot))
                .ok_or(RuntimeError::ContextStale)?;
            (
                context.brief().clone(),
                Some(scope.graph.explain(runtime, context)?),
            )
        } else {
            scope.reserve_context();
            let required = if scope.policy.sources.native_policy_facts {
                vec!["guard-policy-facts".into()]
            } else {
                vec![]
            };
            let context = scope
                .graph
                .compile(runtime, id, &query, required, Some(expires))?;
            let brief = context.brief().clone();
            let dependencies = context.dependencies(runtime)?;
            scope.history.expire(scope.policy.storage.retention_hours);
            scope.history.record_with_dependencies(
                brief.clone(),
                &scope.sources,
                None,
                &runtime.status().package_version,
                &runtime.status().worker_fingerprint,
                &dependencies,
            );
            scope
                .agent_contexts
                .entry(id.into())
                .or_default()
                .insert(brief.snapshot_id.clone(), context);
            (brief, None)
        };
        current_sources(scope)?;
        policy_current(&self.home, scope, runtime)?;
        let value = json!({"schema":"guard-cigar-workspace-result.v1","data_role":true,"result":{
            "brief":brief,"explanation":explanation,"scope":metadata(scope_id,scope),"sharing":scope.graph.metadata(),"current":true}});
        self.receipts_current(Some(scope_id))?;
        Ok(value)
    }
}
