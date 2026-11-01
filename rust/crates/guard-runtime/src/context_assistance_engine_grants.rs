use super::*;

impl Engine {
    pub(super) fn grant(
        &mut self,
        runtime: &mut VerifiedRuntime,
        workspace: PathBuf,
        app: String,
        paths: Vec<String>,
        shared_notes: NotesAccess,
    ) -> Result<Value, RuntimeError> {
        if self.scopes.len() >= self.limits.max_active_workspaces as usize || paths.len() > 32 {
            return Err(RuntimeError::ResourceLimit);
        }
        if app != "dashboard"
            && crate::guard_config_harness::canonical_harness_id(&app) != Some(app.as_str())
        {
            return Err(RuntimeError::ScopeDenied);
        }
        let root = SourceRoot::inspect(&workspace)?;
        if root.path().starts_with(&self.home) {
            return Err(RuntimeError::ScopeDenied);
        }
        let policy = effective(&self.home, &root)?;
        if self.scopes.len() >= policy.limits.max_active_workspaces as usize {
            return Err(RuntimeError::ResourceLimit);
        }
        if app != "dashboard"
            && !policy.features.agent_context
            && !(cfg!(target_os = "macos")
                && policy.features.execution_context
                && policy.sources.native_policy_facts
                && matches!(app.as_str(), "pi" | "omp"))
        {
            return Err(RuntimeError::ScopeDenied);
        }
        if !paths.is_empty() && !policy.sources.workspace_documents {
            return Err(RuntimeError::ScopeDenied);
        }
        if self
            .scopes
            .values()
            .any(|scope| scope.root.path() == root.path() && scope.app == app)
        {
            return Err(RuntimeError::ScopeDenied);
        }
        let mut sources = BTreeMap::new();
        for path in paths {
            let source = root.read(&path)?;
            if sources.insert(source.source_id.clone(), source).is_some() {
                return Err(RuntimeError::RequestInvalid);
            }
        }
        let revision = revision(&policy)?;
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| RuntimeError::ResourceLimit)?;
        let id = format!("scope:{:x}", Sha256::digest(nonce));
        let mut graph = self.open_backend(runtime, &id, &root, &app, &policy, shared_notes)?;
        let result = (|| {
            cache::initialize_graph(runtime, &mut graph, &sources, &policy, &revision)?;
            if effective(&self.home, &root)? != policy {
                return Err(RuntimeError::ContextStale);
            }
            Ok(())
        })();
        if let Err(error) = result {
            let _ = graph.close(runtime);
            return Err(error);
        }
        let scope = Scope {
            root,
            app,
            policy,
            revision,
            graph,
            sources,
            contexts: BTreeMap::new(),
            agent_contexts: BTreeMap::new(),
            action_context: None,
            history: Default::default(),
            revoked: false,
            epoch: Default::default(),
            receipts: VecDeque::new(),
            receipts_dropped: 0,
        };
        let data = metadata(&id, &scope);
        self.scopes.insert(id, scope);
        Ok(data)
    }
}
