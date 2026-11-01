use super::*;
use crate::context_assistance_action_facts::{Fact, Policy};

pub(super) struct ActionContext {
    fact: Fact,
    context: Context,
}

impl Engine {
    pub(crate) fn workspace(
        &mut self,
        runtime: &mut VerifiedRuntime,
        request: Request,
        policy: Option<Policy>,
    ) -> Result<Value, RuntimeError> {
        if !matches!(&request, Request::Clear | Request::ForgetSaved) {
            self.expire_notes(runtime)?;
        }
        match request {
            Request::Action {
                scope_id,
                decision_id,
                snapshot_id,
            } => self.action(
                runtime,
                &scope_id,
                &decision_id,
                snapshot_id.as_deref(),
                policy.as_ref().ok_or(RuntimeError::ScopeDenied)?,
            ),
            other => self.execute(runtime, other),
        }
    }

    pub(super) fn action(
        &mut self,
        runtime: &mut VerifiedRuntime,
        scope_id: &str,
        decision_id: &str,
        snapshot_id: Option<&str>,
        policy: &Policy,
    ) -> Result<Value, RuntimeError> {
        self.drain_receipts(runtime)?;
        let notifications = self
            .notifications
            .as_ref()
            .ok_or(RuntimeError::ScopeDenied)?
            .clone();
        let fact = notifications.actions.get(decision_id)?;
        let scope = self
            .scopes
            .get_mut(scope_id)
            .ok_or(RuntimeError::ScopeDenied)?;
        policy_current(&self.home, scope, runtime)?;
        if !scope.policy.sources.native_policy_facts
            || (scope.app == "dashboard" && !scope.policy.features.review_briefs)
            || (scope.app != "dashboard" && !scope.policy.features.agent_context)
        {
            return Err(RuntimeError::ScopeDenied);
        }
        fact.require_scope(scope.root.path(), &scope.app, policy)?;
        current_sources(scope)?;
        let (brief, explanation, dependencies) = if let Some(snapshot_id) = snapshot_id {
            let retained = scope
                .action_context
                .as_ref()
                .filter(|retained| {
                    retained.fact == fact && retained.context.brief().snapshot_id == snapshot_id
                })
                .ok_or(RuntimeError::ContextStale)?;
            (
                retained.context.brief().clone(),
                Some(scope.graph.explain(runtime, &retained.context)?),
                retained.context.dependencies(runtime)?,
            )
        } else {
            // The ordinary view never includes this source. One dedicated
            // action view and retained snapshot per scope bound memory and
            // prevent a generic selection explanation bypassing this fence.
            scope.reserve_context();
            scope.action_context = None;
            scope.contexts.clear();
            scope
                .graph
                .replace_source(runtime, "guard:action", vec![fact.document()])?;
            let mut sources = allowed(&scope.sources, &scope.policy);
            sources.insert("guard:action".into());
            scope
                .graph
                .create_view(runtime, "action", sources, &scope.revision, false)?;
            let context = scope.graph.compile(
                runtime,
                "action",
                &fact.query(),
                vec!["guard-action-facts".into(), "guard-policy-facts".into()],
                None,
            )?;
            let brief = context.brief().clone();
            let dependencies = context.dependencies(runtime)?;
            scope.action_context = Some(ActionContext {
                fact: fact.clone(),
                context,
            });
            (brief, None, dependencies)
        };
        current_sources(scope)?;
        policy_current(&self.home, scope, runtime)?;
        if notifications.actions.get(decision_id)? != fact {
            scope.action_context = None;
            return Err(RuntimeError::ContextStale);
        }
        let scope = metadata(scope_id, scope);
        self.receipts_current(Some(scope_id))?;
        if snapshot_id.is_none() {
            let scope = self
                .scopes
                .get_mut(scope_id)
                .ok_or(RuntimeError::ScopeDenied)?;
            scope.history.expire(scope.policy.storage.retention_hours);
            scope.history.record_with_dependencies(
                brief.clone(),
                &scope.sources,
                Some(fact.association()),
                &runtime.status().package_version,
                &runtime.status().worker_fingerprint,
                &dependencies,
            );
        }
        Ok(
            json!({"schema":"guard-cigar-workspace-result.v1","data_role":true,
            "result":{"brief":brief,"scope":scope,"association":fact.association(),
            "explanation":explanation,"current":true}}),
        )
    }
}
