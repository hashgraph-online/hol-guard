//! Actor-owned, memory-only workspace grants. Optional saved evidence never
//! restores a grant. Operator choices select sources;
//! agent-facing consumers must bind a native caller to an existing app grant.
use crate::context_assistance_notifications::{Epoch, Notifications, ReceiptFact};
use backend::{Backend, Context, NotesAccess};
use guard_context_assistance::{
    AdmittedFile, ContextAssistanceConfig, ContextDocument, RuntimeError, SourceRoot,
    VerifiedRuntime,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

#[path = "context_assistance_backend.rs"]
mod backend;
#[path = "context_assistance_engine_grants.rs"]
mod grants;
#[path = "context_assistance_engine_proposals.rs"]
mod proposals;
#[cfg(unix)]
#[path = "context_assistance_engine_upgrade.rs"]
mod upgrade;
#[cfg(unix)]
pub(crate) use upgrade::UpgradeBoundary;
#[cfg(all(test, target_os = "macos"))]
pub(crate) use upgrade::{
    upgrade_admit, upgrade_memory_summary, upgrade_reviewed_summary, UpgradeFixture,
};

#[path = "context_assistance_engine_actions.rs"]
mod actions;
#[path = "context_assistance_engine_agents.rs"]
mod agents;
#[path = "context_assistance_engine_cache.rs"]
mod cache;
#[path = "context_assistance_engine_policy.rs"]
mod policy;
use policy::{allowed, current_sources, effective, policy_current, policy_document, revision};
#[cfg(target_os = "macos")]
#[path = "context_assistance_engine_execution.rs"]
mod execution;
#[path = "context_assistance_engine_history.rs"]
mod history;
#[path = "context_assistance_engine_receipts.rs"]
mod receipts;
#[cfg(target_os = "macos")]
pub(crate) use execution::Lane as ExecutionLane;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Request {
    List,
    ListAgents,
    Data,
    ForgetHistory,
    ForgetSaved,
    ResumeErasure,
    Proposals {
        scope_id: String,
    },
    Proposal {
        scope_id: String,
        proposal_id: String,
    },
    AdmitProposal {
        scope_id: String,
        proposal_id: String,
    },
    RejectProposal {
        scope_id: String,
        proposal_id: String,
    },
    ClearNotes {
        scope_id: String,
    },
    History {
        scope_id: String,
        #[serde(default)]
        decision_id: Option<String>,
    },
    HistoryDetail {
        scope_id: String,
        history_id: String,
    },
    Grant {
        workspace: PathBuf,
        app: String,
        sources: Vec<String>,
        #[serde(default)]
        shared_notes: NotesAccess,
    },
    Refresh {
        scope_id: String,
    },
    Withdraw {
        scope_id: String,
        source_id: String,
    },
    Revoke {
        scope_id: String,
    },
    Compile {
        scope_id: String,
        query: String,
    },
    Explain {
        scope_id: String,
        snapshot_id: String,
    },
    Action {
        scope_id: String,
        decision_id: String,
        #[serde(default)]
        snapshot_id: Option<String>,
    },
    Clear,
    AuthorizeAgent {
        session_id: String,
        scope_id: String,
    },
    RevokeAgent {
        session_id: String,
    },
}

struct Scope {
    root: SourceRoot,
    app: String,
    policy: ContextAssistanceConfig,
    revision: String,
    graph: Backend,
    sources: BTreeMap<String, AdmittedFile>,
    contexts: BTreeMap<String, Context>,
    agent_contexts: BTreeMap<String, BTreeMap<String, Context>>,
    action_context: Option<actions::ActionContext>,
    history: crate::context_assistance_history::History,
    revoked: bool,
    epoch: guard_context_assistance::ContextEpoch,
    receipts: VecDeque<ReceiptFact>,
    receipts_dropped: u64,
}

impl Scope {
    fn context_count(&self) -> usize {
        self.contexts.len()
            + usize::from(self.action_context.is_some())
            + self
                .agent_contexts
                .values()
                .map(BTreeMap::len)
                .sum::<usize>()
    }
    fn clear_contexts(&mut self) {
        self.epoch.invalidate();
        self.contexts.clear();
        self.action_context = None;
        self.agent_contexts.clear();
    }
    fn reserve_context(&mut self) {
        if self.context_count() >= 8 {
            self.clear_contexts();
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
#[path = "context_assistance_engine_cleanup_test.rs"]
mod cleanup_test;

pub(crate) struct Engine {
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) cleanup_test: cleanup_test::Hook,
    home: PathBuf,
    runtime_id: String,
    storage_mode: guard_context_assistance::StorageMode,
    retention_hours: u32,
    limits: guard_context_assistance::Limits,
    scopes: BTreeMap<String, Scope>,
    notifications: Option<Arc<Notifications>>,
    receipt_epoch: Epoch,
    agents: crate::context_assistance_agents::Sessions,
    #[cfg(target_os = "macos")]
    execution_lane: Option<execution::Lane>,
    #[cfg(unix)]
    cache: Option<guard_context_assistance::EvidenceCache>,
    #[cfg(unix)]
    producer: Option<guard_context_assistance::EvidenceUpgradeProducer>,
    #[cfg(unix)]
    data_generation: Option<Arc<guard_context_assistance::PreparedEvidenceGeneration>>,
}

impl Engine {
    fn expire_notes(&mut self, runtime: &mut VerifiedRuntime) -> Result<(), RuntimeError> {
        #[cfg(unix)]
        crate::policy_store::context_assistance_registry::switching::DataRemoval::check_clear(
            &self.home,
        )?;
        let live = self.agents.sweep(std::time::Instant::now());
        for scope in self.scopes.values_mut().filter(|s| !s.revoked) {
            if scope.graph.expire_cache(runtime)? {
                scope.revoked = true;
                scope.clear_contexts();
                scope.history.clear();
                scope.sources.clear();
                scope.receipts.clear();
                continue;
            }
            scope.history.expire(scope.policy.storage.retention_hours);
            scope.graph.prune_agents(runtime, &live)?;
            scope.agent_contexts.retain(|id, _| live.contains(id));
            if scope.graph.expire_notes(runtime)? {
                scope.clear_contexts();
                scope.history.clear();
            }
        }
        self.sweep_saved()?;
        Ok(())
    }
    pub(crate) fn maintenance(
        runtime: &mut VerifiedRuntime,
        engine: &mut Self,
    ) -> Result<(), RuntimeError> {
        engine.expire_notes(runtime)?;
        #[cfg(target_os = "macos")]
        engine.maintain_execution_lane(runtime)?;
        Ok(())
    }
    pub(crate) fn new(
        home: PathBuf,
        config: &ContextAssistanceConfig,
        notifications: Option<Arc<Notifications>>,
    ) -> Self {
        Self {
            #[cfg(all(test, target_os = "macos"))]
            cleanup_test: Default::default(),
            home,
            runtime_id: config.runtime_id.clone(),
            storage_mode: config.storage.mode,
            retention_hours: config.storage.retention_hours,
            limits: config.limits.clone(),
            scopes: BTreeMap::new(),
            notifications,
            receipt_epoch: Epoch::default(),
            agents: Default::default(),
            #[cfg(target_os = "macos")]
            execution_lane: None,
            #[cfg(unix)]
            cache: None,
            #[cfg(unix)]
            producer: None,
            #[cfg(unix)]
            data_generation: None,
        }
    }

    pub(crate) fn execute(
        &mut self,
        runtime: &mut VerifiedRuntime,
        request: Request,
    ) -> Result<Value, RuntimeError> {
        if !matches!(&request, Request::Clear | Request::ForgetSaved) {
            self.expire_notes(runtime)?;
        }
        let reads = matches!(
            &request,
            Request::Compile { .. } | Request::Explain { .. } | Request::List
        );
        let read_scope = match &request {
            Request::Compile { scope_id, .. } | Request::Explain { scope_id, .. } => {
                Some(scope_id.clone())
            }
            _ => None,
        };
        if reads {
            self.drain_receipts(runtime)?;
        }
        let result = match request {
            Request::ListAgents => {
                Ok(json!({"agent_sessions":self.agents.metadata(std::time::Instant::now())}))
            }
            Request::Data
            | Request::ForgetHistory
            | Request::History { .. }
            | Request::HistoryDetail { .. } => self.history_request(runtime, request),
            Request::Proposals { .. }
            | Request::Proposal { .. }
            | Request::AdmitProposal { .. }
            | Request::RejectProposal { .. }
            | Request::ClearNotes { .. } => self.proposal_request(runtime, request),
            Request::List => {
                for scope in self.scopes.values_mut().filter(|scope| !scope.revoked) {
                    match policy_current(&self.home, scope, runtime) {
                        Ok(()) | Err(RuntimeError::ScopeDenied) => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(
                    json!({"scopes":self.scopes.iter().map(|(id, scope)| metadata(id,scope)).collect::<Vec<_>>(),
                    "agent_sessions":self.agents.metadata(std::time::Instant::now())}),
                )
            }
            Request::Grant {
                workspace,
                app,
                sources,
                shared_notes,
            } => self.grant(runtime, workspace, app, sources, shared_notes),
            Request::Clear | Request::ForgetSaved => {
                #[cfg(unix)]
                let removal = crate::policy_store::context_assistance_registry::switching::DataRemoval::acquire(&self.home)?;
                // A failed close leaves this generation unavailable, never a
                // partially cleared graph eligible for later compilation.
                for scope in self.scopes.values_mut() {
                    scope.clear_contexts();
                    close_graph(runtime, &mut scope.graph)?;
                }
                #[cfg(target_os = "macos")]
                self.close_execution_lane(runtime)?;
                self.scopes.clear();
                #[cfg(unix)]
                self.forget_saved(removal)?;
                #[cfg(not(unix))]
                self.forget_saved()?;
                self.agents = Default::default();
                if let Some(notifications) = &self.notifications {
                    notifications.clear()?;
                }
                Ok(json!({"scopes":[], "cleared":true}))
            }
            Request::AuthorizeAgent {
                session_id,
                scope_id,
            } => self.authorize_agent(runtime, session_id, scope_id),
            Request::RevokeAgent { session_id } => {
                self.revoke_agent(runtime, &session_id)?;
                Ok(json!({"session_id":session_id,"revoked":true}))
            }
            Request::Revoke { scope_id } => {
                let scope = self
                    .scopes
                    .get_mut(&scope_id)
                    .ok_or(RuntimeError::ScopeDenied)?;
                scope.clear_contexts();
                close_graph(runtime, &mut scope.graph)?;
                self.scopes.remove(&scope_id);
                Ok(json!({"revoked":true, "scope_id":scope_id}))
            }
            other => self.scoped(runtime, other),
        }?;
        if reads {
            self.receipts_current(read_scope.as_deref())?;
        }
        Ok(json!({"schema":"guard-cigar-workspace-result.v1", "data_role":true, "result":result}))
    }

    fn scoped(
        &mut self,
        runtime: &mut VerifiedRuntime,
        request: Request,
    ) -> Result<Value, RuntimeError> {
        let scope_id = match &request {
            Request::Refresh { scope_id }
            | Request::Withdraw { scope_id, .. }
            | Request::Compile { scope_id, .. }
            | Request::Explain { scope_id, .. } => scope_id,
            _ => return Err(RuntimeError::RequestInvalid),
        };
        if let Request::Withdraw { source_id, .. } = &request {
            return self.reset_scope(runtime, scope_id, Some(source_id));
        }
        let scope = self
            .scopes
            .get_mut(scope_id)
            .ok_or(RuntimeError::ScopeDenied)?;
        policy_current(&self.home, scope, runtime)?;
        match request {
            Request::Refresh { scope_id } => {
                let mut updated = BTreeMap::new();
                for source in scope.sources.values() {
                    let fresh = scope.root.read(&source.relative_path)?;
                    scope.graph.replace_source(
                        runtime,
                        &fresh.source_id,
                        fresh.documents.clone(),
                    )?;
                    updated.insert(fresh.source_id.clone(), fresh);
                }
                scope.clear_contexts();
                scope.sources = updated;
                Ok(metadata(&scope_id, scope))
            }
            Request::Withdraw {
                scope_id,
                source_id,
            } => {
                if !scope.sources.contains_key(&source_id) {
                    return Err(RuntimeError::ScopeDenied);
                }
                scope
                    .graph
                    .replace_source(runtime, &source_id, Vec::new())?;
                scope.sources.remove(&source_id);
                scope.clear_contexts();
                scope
                    .graph
                    .narrow_sources(runtime, allowed(&scope.sources, &scope.policy))?;
                scope.graph.create_view(
                    runtime,
                    "app",
                    allowed(&scope.sources, &scope.policy),
                    &scope.revision,
                    false,
                )?;
                scope.history.clear();
                Ok(metadata(&scope_id, scope))
            }
            Request::Compile { scope_id, query } => {
                if scope.app == "dashboard" && !scope.policy.features.review_briefs {
                    return Err(RuntimeError::ScopeDenied);
                }
                current_sources(scope)?;
                let required = if scope.policy.sources.native_policy_facts {
                    vec!["guard-policy-facts".into()]
                } else {
                    Vec::new()
                };
                scope.reserve_context();
                let context = scope
                    .graph
                    .compile(runtime, "app", &query, required, None)?;
                current_sources(scope)?;
                policy_current(&self.home, scope, runtime)?;
                let brief = context.brief().clone();
                let dependencies = context.dependencies(runtime)?;
                scope.contexts.insert(brief.snapshot_id.clone(), context);
                scope.history.expire(scope.policy.storage.retention_hours);
                scope.history.record_with_dependencies(
                    brief.clone(),
                    &scope.sources,
                    None,
                    &runtime.status().package_version,
                    &runtime.status().worker_fingerprint,
                    &dependencies,
                );
                Ok(json!({"brief":brief, "scope":metadata(&scope_id, scope), "current":true}))
            }
            Request::Explain { snapshot_id, .. } => {
                current_sources(scope)?;
                let context = scope
                    .contexts
                    .get(&snapshot_id)
                    .ok_or(RuntimeError::ContextStale)?;
                let explanation = scope.graph.explain(runtime, context)?;
                let brief = context.brief().clone();
                current_sources(scope)?;
                policy_current(&self.home, scope, runtime)?;
                Ok(json!({"brief":brief, "explanation":explanation, "current":true}))
            }
            _ => Err(RuntimeError::RequestInvalid),
        }
    }
}

fn close_graph(runtime: &mut VerifiedRuntime, graph: &mut Backend) -> Result<(), RuntimeError> {
    if let Err(error) = graph.forget(runtime) {
        runtime.close();
        return Err(error);
    }
    Ok(())
}

fn metadata(id: &str, scope: &Scope) -> Value {
    json!({"scope_id":id, "workspace":scope.root.path(), "app":scope.app, "policy_revision":scope.revision,
        "sources":scope.sources.values().map(|source| json!({"source_id":source.source_id,
            "path":source.relative_path, "sha256":source.sha256, "documents":source.documents.len()})).collect::<Vec<_>>(),
        "retained_contexts":scope.context_count(), "revoked":scope.revoked,"sharing":scope.graph.metadata(),
        "native_policy_facts":scope.policy.sources.native_policy_facts,
        "receipt_window":{"enabled":scope.policy.sources.sanitized_receipt_facts, "retained":scope.receipts.len(),
            "dropped":scope.receipts_dropped.to_string(), "coverage":"bounded_recent_native_receipts"}})
}

#[cfg(all(test, unix))]
#[path = "context_assistance_persistence_tests.rs"]
mod persistence_tests;
