use super::*;
use crate::context_assistance_notifications::{ReceiptFact, WINDOW};

impl Engine {
    /// Coalesce native notifications on this existing actor lane. The native
    /// writer never waits here, and no notification creates an SDK process.
    pub(super) fn drain_receipts(
        &mut self,
        runtime: &mut VerifiedRuntime,
    ) -> Result<(), RuntimeError> {
        let Some(notifications) = &self.notifications else {
            return Ok(());
        };
        let batch = notifications.drain()?;
        self.receipt_epoch = batch.epoch;
        if batch.facts.is_empty() && batch.dropped == 0 {
            return Ok(());
        }
        for scope in self.scopes.values_mut() {
            if scope.revoked || !scope.policy.sources.sanitized_receipt_facts {
                continue;
            }
            match policy_current(&self.home, scope, runtime) {
                Ok(()) => {}
                Err(RuntimeError::ScopeDenied) => continue,
                Err(error) => return Err(error),
            }
            let mut changed = batch.dropped > 0;
            if changed {
                scope.receipts.clear();
                scope.receipts_dropped = scope.receipts_dropped.saturating_add(batch.dropped);
            }
            let matching: Vec<_> = batch
                .facts
                .iter()
                .filter(|fact| matches_scope(scope, fact))
                .cloned()
                .collect();
            for fact in matching {
                scope
                    .receipts
                    .retain(|old| old.decision_id != fact.decision_id);
                scope.receipts.push_back(fact);
                if scope.receipts.len() > WINDOW {
                    scope.receipts.pop_front();
                }
                changed = true;
            }
            if changed {
                scope.clear_contexts();
                scope.graph.replace_source(
                    runtime,
                    "guard:receipts",
                    scope.receipts.iter().map(ReceiptFact::document).collect(),
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn receipts_current(&self, scope_id: Option<&str>) -> Result<(), RuntimeError> {
        let Some(notifications) = &self.notifications else {
            return Ok(());
        };
        let scope = scope_id
            .map(|id| self.scopes.get(id).ok_or(RuntimeError::ScopeDenied))
            .transpose()?;
        if scope.is_some_and(|scope| !scope.policy.sources.sanitized_receipt_facts) {
            return Ok(());
        }
        notifications.current(
            self.receipt_epoch,
            scope.map(|scope| (scope.root.path(), scope.app.as_str())),
        )
    }
}

fn matches_scope(scope: &Scope, fact: &ReceiptFact) -> bool {
    fact.workspace == scope.root.path() && (scope.app == "dashboard" || scope.app == fact.harness)
}
