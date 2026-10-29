//! One SDK graph or broker per granted scope. File and native-policy fences
//! remain in the owning engine; these capabilities never cross a wire.
use guard_context_assistance::{
    BrokerClientHandle, BrokerDomainHandle, BrokerRevision, ContextAssistanceConfig, ContextBrief,
    ContextDocument, RetainedBrokerContext, RetainedContext, RuntimeError, VerifiedRuntime,
    ViewHandle, WorkspaceHandle,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

#[cfg(unix)]
#[path = "context_assistance_backend_memory_upgrade.rs"]
mod memory_upgrade;
#[path = "context_assistance_backend_notes.rs"]
mod notes;
#[path = "context_assistance_backend_persistence.rs"]
mod persistence;
#[cfg(unix)]
#[path = "context_assistance_backend_upgrade.rs"]
mod upgrade;

#[derive(Clone, Copy, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct NotesAccess {
    pub(crate) read: bool,
    pub(crate) propose: bool,
}

enum Mode {
    Private(WorkspaceHandle),
    Shared(BrokerDomainHandle),
}
enum View {
    Private(ViewHandle),
    Shared {
        client: Option<BrokerClientHandle>,
        sources: BTreeSet<String>,
        writable: BTreeSet<String>,
        policy: String,
    },
}
pub(super) enum Context {
    Private(RetainedContext),
    Shared(RetainedBrokerContext),
}
impl Context {
    pub(super) fn brief(&self) -> &ContextBrief {
        match self {
            Self::Private(c) => c.brief(),
            Self::Shared(c) => c.brief(),
        }
    }
    pub(super) fn dependencies(
        &self,
        runtime: &VerifiedRuntime,
    ) -> Result<BTreeSet<String>, RuntimeError> {
        match self {
            Self::Private(_) => Ok(BTreeSet::new()),
            Self::Shared(c) => Ok(runtime.broker_context_sources(c)?.into_keys().collect()),
        }
    }
}

pub(super) struct Backend {
    mode: Option<Mode>,
    views: BTreeMap<String, View>,
    digests: BTreeMap<String, String>,
    config: ContextAssistanceConfig,
    access: NotesAccess,
    notes: Vec<ContextDocument>,
    note_basis: BTreeSet<String>,
    note_revision: Option<BrokerRevision>,
    note_expires: Option<Instant>,
    proposal_owners: BTreeMap<String, String>,
    #[cfg(unix)]
    cache: Option<guard_context_assistance::EvidenceSlot>,
    restored: bool,
    #[cfg(unix)]
    deferred_scope: Option<(
        std::sync::Arc<guard_context_assistance::PreparedEvidenceGeneration>,
        guard_context_assistance::EvidenceScope,
        guard_context_assistance::EvidenceUpgradeProducer,
    )>,
}
impl Backend {
    pub(super) fn open(
        runtime: &mut VerifiedRuntime,
        id: &str,
        config: &ContextAssistanceConfig,
        access: NotesAccess,
    ) -> Result<Self, RuntimeError> {
        if config.storage.mode != guard_context_assistance::StorageMode::Memory {
            return Err(RuntimeError::ScopeDenied);
        }
        Self::validate_open(runtime, config, access)?;
        let mode = if config.features.shared_agents {
            Mode::Shared(runtime.open_broker_domain(id, config)?)
        } else {
            Mode::Private(runtime.open_workspace(id, &config.limits)?)
        };
        Ok(Self::from_mode(mode, config, access))
    }
    fn validate_open(
        runtime: &VerifiedRuntime,
        config: &ContextAssistanceConfig,
        access: NotesAccess,
    ) -> Result<(), RuntimeError> {
        if (access.propose && !access.read) || (access.read && !config.features.shared_agents) {
            return Err(RuntimeError::ScopeDenied);
        }
        if config.features.shared_agents && !runtime.status().shared_compile_verified {
            return Err(RuntimeError::HandshakeFailed);
        }
        Ok(())
    }
    fn from_mode(mode: Mode, config: &ContextAssistanceConfig, access: NotesAccess) -> Self {
        Self {
            mode: Some(mode),
            views: BTreeMap::new(),
            digests: BTreeMap::new(),
            config: config.clone(),
            access,
            notes: Vec::new(),
            note_basis: BTreeSet::new(),
            note_revision: None,
            note_expires: None,
            proposal_owners: BTreeMap::new(),
            #[cfg(unix)]
            cache: None,
            restored: false,
            #[cfg(unix)]
            deferred_scope: None,
        }
    }
    pub(super) fn is_shared(&self) -> bool {
        self.config.features.shared_agents
    }
    pub(super) fn access(&self) -> NotesAccess {
        self.access
    }
    pub(super) fn include_notes(&self, mut sources: BTreeSet<String>) -> BTreeSet<String> {
        if self.access.read {
            sources.insert("guard:notes".into());
        }
        sources
    }
    pub(super) fn metadata(&self) -> Value {
        json!({"mode":if self.is_shared(){"shared_broker"}else if self.has_cache(){"private_broker"}else{"private_graph"},
            "notes":{"read":self.access.read,"propose":self.access.propose,"documents":self.notes.len(),"revision":self.note_revision},
            "client_lease_seconds":if self.is_shared(){Some(300)}else{None::<u32>}})
    }
    pub(super) fn prune_agents(
        &mut self,
        runtime: &mut VerifiedRuntime,
        live: &BTreeSet<String>,
    ) -> Result<(), RuntimeError> {
        self.check_cache()?;
        let names: Vec<_> = self
            .views
            .keys()
            .filter(|n| n.starts_with("agent:") && !live.contains(*n))
            .cloned()
            .collect();
        for name in names {
            self.remove_view(runtime, &name)?;
        }
        if let Some(Mode::Shared(domain)) = &self.mode {
            let ids: BTreeSet<_> = runtime
                .broker_proposal_records(domain)?
                .into_iter()
                .map(|(p, _)| p.proposal_id.clone())
                .collect();
            self.proposal_owners.retain(|id, _| ids.contains(id));
        }
        Ok(())
    }
    pub(super) fn replace_source(
        &mut self,
        runtime: &mut VerifiedRuntime,
        source: &str,
        docs: Vec<ContextDocument>,
    ) -> Result<(), RuntimeError> {
        self.check_cache()?;
        let hash = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&docs).map_err(|_| RuntimeError::RequestInvalid)?)
        );
        if self.digests.get(source) == Some(&hash) {
            return Ok(());
        }
        match self.mode.as_ref().ok_or(RuntimeError::ScopeDenied)? {
            Mode::Private(graph) => {
                runtime.replace_source(graph, source, docs)?;
            }
            Mode::Shared(domain) => {
                let previous = runtime.broker_source_revision(domain, source)?;
                if self.restored
                    && !matches!(source, "guard:notes" | "guard:receipts" | "guard:action")
                    && previous.version != "0"
                {
                    match runtime.resume_broker_source(domain, source, docs.clone()) {
                        Ok(_) => {
                            self.digests.insert(source.into(), hash);
                            return Ok(());
                        }
                        Err(RuntimeError::ContextStale) => {}
                        Err(error) => return Err(error),
                    }
                }
                if source == "guard:notes" {
                    if !docs.is_empty() {
                        return Err(RuntimeError::ScopeDenied);
                    }
                    self.stage_notes(runtime, &previous.version, &docs)?;
                }
                let Some(Mode::Shared(domain)) = &self.mode else {
                    return Err(RuntimeError::ScopeDenied);
                };
                let current = runtime.broker_replace_source(domain, source, &previous, docs)?;
                if source == "guard:notes" {
                    self.commit_notes(runtime, &current.version, None)?;
                    self.note_revision = Some(current);
                }
            }
        }
        self.digests.insert(source.into(), hash);
        if self.note_basis.contains(source) {
            self.clear_notes(runtime)?;
        }
        Ok(())
    }
    pub(super) fn create_view(
        &mut self,
        runtime: &mut VerifiedRuntime,
        name: &str,
        sources: BTreeSet<String>,
        revision: &str,
        proposals: bool,
    ) -> Result<(), RuntimeError> {
        self.remove_view(runtime, name)?;
        let view = match self.mode.as_ref().ok_or(RuntimeError::ScopeDenied)? {
            Mode::Private(graph) => {
                View::Private(runtime.create_view(graph, name, sources, revision)?)
            }
            Mode::Shared(_) => View::Shared {
                client: None,
                sources: self.include_notes(sources),
                writable: if proposals && self.access.propose {
                    BTreeSet::from(["guard:notes".into()])
                } else {
                    BTreeSet::new()
                },
                policy: revision.into(),
            },
        };
        self.views.insert(name.into(), view);
        Ok(())
    }
    pub(super) fn remove_view(
        &mut self,
        runtime: &mut VerifiedRuntime,
        name: &str,
    ) -> Result<(), RuntimeError> {
        if let Some(view) = self.views.remove(name) {
            match view {
                View::Private(view) => {
                    runtime.revoke_view(&view)?;
                }
                View::Shared {
                    client: Some(client),
                    ..
                } => match runtime.revoke_broker_client(&client) {
                    Ok(()) | Err(RuntimeError::ScopeDenied) => {}
                    Err(error) => return Err(error),
                },
                _ => {}
            }
        }
        Ok(())
    }
    /// Explicit human pairing prepares a shared connection before its first
    /// read enters the actor queue. Capacity refusal leaves no usable grant.
    pub(super) fn prepare_view(
        &mut self,
        runtime: &mut VerifiedRuntime,
        view: &str,
        expires: Option<Instant>,
    ) -> Result<(), RuntimeError> {
        self.check_cache()?;
        let slot = self.views.get_mut(view).ok_or(RuntimeError::ScopeDenied)?;
        match slot {
            View::Private(_) => Ok(()),
            View::Shared {
                client,
                sources,
                writable,
                policy,
            } => {
                let Some(Mode::Shared(domain)) = &self.mode else {
                    return Err(RuntimeError::ScopeDenied);
                };
                if client
                    .as_ref()
                    .is_none_or(|c| !runtime.broker_client_is_live(c))
                {
                    if let Some(old) = client.take() {
                        match runtime.revoke_broker_client(&old) {
                            Ok(()) | Err(RuntimeError::ScopeDenied) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    let lease = expires
                        .map(|t| t.saturating_duration_since(Instant::now()))
                        .unwrap_or(Duration::from_secs(300))
                        .min(Duration::from_secs(300));
                    *client = Some(runtime.grant_broker_client_with_deadline(
                        domain,
                        sources.clone(),
                        writable.clone(),
                        policy,
                        lease,
                        expires,
                    )?);
                }
                Ok(())
            }
        }
    }
    pub(super) fn compile(
        &mut self,
        runtime: &mut VerifiedRuntime,
        view: &str,
        query: &str,
        required: Vec<String>,
        expires: Option<Instant>,
    ) -> Result<Context, RuntimeError> {
        self.prepare_view(runtime, view, expires)?;
        match self.views.get(view).ok_or(RuntimeError::ScopeDenied)? {
            View::Private(handle) => Ok(Context::Private(
                runtime.compile_context(handle, query, required)?,
            )),
            View::Shared { client, .. } => Ok(Context::Shared(runtime.compile_broker_context(
                client.as_ref().ok_or(RuntimeError::ScopeDenied)?,
                query,
                required,
            )?)),
        }
    }
    pub(super) fn explain(
        &self,
        runtime: &mut VerifiedRuntime,
        context: &Context,
    ) -> Result<Value, RuntimeError> {
        self.check_cache_read()?;
        match context {
            Context::Private(c) => runtime.explain_context(c),
            Context::Shared(c) => runtime.explain_broker_context(c),
        }
    }
    pub(super) fn narrow_sources(
        &mut self,
        runtime: &mut VerifiedRuntime,
        allowed: BTreeSet<String>,
    ) -> Result<(), RuntimeError> {
        let allowed = self.include_notes(allowed);
        let names: Vec<_> = self.views.keys().cloned().collect();
        for name in names {
            match self.views.get_mut(&name) {
                Some(View::Shared {
                    client, sources, ..
                }) => {
                    if let Some(handle) = client.take() {
                        match runtime.revoke_broker_client(&handle) {
                            Ok(()) | Err(RuntimeError::ScopeDenied) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    sources.retain(|s| {
                        allowed.contains(s) || (name == "action" && s == "guard:action")
                    });
                }
                Some(View::Private(_)) => {
                    self.remove_view(runtime, &name)?;
                }
                None => {}
            }
        }
        Ok(())
    }
    pub(super) fn close(&mut self, runtime: &mut VerifiedRuntime) -> Result<(), RuntimeError> {
        if let Some(mode) = self.mode.take() {
            self.views.clear();
            #[cfg(unix)]
            {
                self.deferred_scope = None;
            }
            self.notes.clear();
            self.note_basis.clear();
            self.digests.clear();
            self.note_revision = None;
            self.proposal_owners.clear();
            let result = match mode {
                Mode::Private(graph) => runtime.close_workspace(&graph),
                Mode::Shared(domain) => runtime.close_broker_domain(&domain),
            };
            if let Err(error) = result {
                runtime.close();
                return Err(error);
            }
        }
        Ok(())
    }
}
