//! Host-only reviewed context preconditions. These APIs never approve or send
//! an effect. A real Guard executor must independently bind and authorize it.
use super::*;
#[path = "broker_execution_types.rs"]
mod types;
pub use types::{
    BrokerAnswerClaim, BrokerAnswerPolicy, BrokerBoundExecution, BrokerClaimReview,
    BrokerExecutionHandoff, BrokerExecutionReview, BrokerReviewVerdict, BrokerSubmission,
};
use types::{WireBinding, WireSubmission};

fn intent(value: &str) -> bool {
    value.len() == 68 && value.starts_with("1220") && digest(&value[4..])
}
fn same_client(a: &BrokerClientHandle, b: &BrokerClientHandle) -> bool {
    a.epoch == b.epoch && a.id == b.id && a.domain == b.domain
}
fn review(value: &BrokerExecutionReview) -> Result<(), RuntimeError> {
    let mut keys = BTreeSet::new();
    if !valid_id(&value.authority_revision)
        || value.reviews.len() > 16
        || value
            .policy
            .min_sources
            .is_some_and(|v| !(1..=128).contains(&v))
        || value.policy.high_confidence_bps.is_some_and(|v| v > 10_000)
        || value.reviews.iter().any(|r| {
            !digest(&r.claim_key)
                || !keys.insert(&r.claim_key)
                || r.reviewed_counterevidence.len() > 64
                || r.reviewed_counterevidence.iter().any(|id| !valid_id(id))
        })
    {
        return Err(RuntimeError::RequestInvalid);
    }
    Ok(())
}

impl VerifiedRuntime {
    fn execution_ticket(&self, context: &RetainedBrokerContext) -> Result<String, RuntimeError> {
        let ticket = self.broker_context_ticket(context)?;
        if !self
            .brokers
            .domains
            .get(&context.client.domain)
            .is_some_and(|d| d.execution_handoff)
        {
            return Err(RuntimeError::HandshakeFailed);
        }
        Ok(ticket)
    }
    fn bad_execution_reply(&mut self) -> RuntimeError {
        self.close();
        RuntimeError::TransportFailed
    }

    /// Submit bounded draft data. The native caller must independently review
    /// the exact complete submission; submission alone grants no authority.
    pub fn submit_broker_answer(
        &mut self,
        context: &RetainedBrokerContext,
        claims: Vec<BrokerAnswerClaim>,
    ) -> Result<BrokerSubmission, RuntimeError> {
        let ticket = self.execution_ticket(context)?;
        let cited: BTreeSet<_> = context
            .brief
            .citations
            .iter()
            .filter_map(|v| v["node_id"].as_str())
            .collect();
        let mut bytes = 0_usize;
        if claims.is_empty()
            || claims.len() > 16
            || claims.iter().any(|claim| {
                bytes = bytes.saturating_add(claim.text.len());
                claim.text.is_empty()
                    || claim.text.len() > 4096
                    || bytes > 16_384
                    || claim.confidence_bps.is_some_and(|v| v > 10_000)
                    || claim.citations.is_empty()
                    || claim.citations.len() > 64
                    || claim
                        .citations
                        .iter()
                        .any(|id| !cited.contains(id.as_str()))
                    || claim.citations.iter().collect::<BTreeSet<_>>().len()
                        != claim.citations.len()
            })
        {
            return Err(RuntimeError::RequestInvalid);
        }
        documents(
            claims
                .iter()
                .enumerate()
                .map(|(i, c)| ContextDocument {
                    id: format!("claim:{i}"),
                    text: c.text.clone(),
                    start_line: 1,
                })
                .collect(),
            16_384,
        )?;
        let draft =
            json!({"snapshot_id":context.brief.snapshot_id,"claims":claims,"abstain":false});
        let id = self.broker_client_rpc(
            &context.client,
            json!({"op":"submit_answer","ticket":ticket,"draft":draft}),
        )?;
        let Some(id) = id.as_str().filter(|id| digest(id)).map(str::to_owned) else {
            return Err(self.bad_execution_reply());
        };
        let raw = self.rpc(
            json!({"op":"broker_submission","domain":context.client.domain,"ticket":ticket}),
            TIMEOUT,
        )?;
        let Ok(observed) = serde_json::from_value::<WireSubmission>(raw) else {
            return Err(self.bad_execution_reply());
        };
        if observed.submission_id != id
            || observed.draft.snapshot_id != context.brief.snapshot_id
            || observed.draft.claims != claims
            || observed.draft.abstain
            || observed.review_keys.is_empty()
            || observed.review_keys.len() > claims.len()
            || observed.review_keys.iter().any(|key| !digest(key))
            || observed.review_keys.iter().collect::<BTreeSet<_>>().len()
                != observed.review_keys.len()
        {
            return Err(self.bad_execution_reply());
        }
        self.execution_ticket(context)?;
        Ok(BrokerSubmission {
            client: context.client.clone(),
            retention_id: context.retention_id,
            id,
            keys: observed.review_keys,
        })
    }

    /// Bind current host-reviewed data to an execution authority's pre-existing
    /// opaque effect ID and semantic intent. This does not authorize execution.
    pub fn bind_broker_execution(
        &mut self,
        context: &RetainedBrokerContext,
        submission: &BrokerSubmission,
        effect_id: &str,
        intent_digest: &str,
        host_review: &BrokerExecutionReview,
    ) -> Result<BrokerBoundExecution, RuntimeError> {
        let ticket = self.execution_ticket(context)?;
        review(host_review)?;
        if !same_client(&context.client, &submission.client)
            || context.retention_id != submission.retention_id
        {
            return Err(RuntimeError::ScopeDenied);
        }
        if !valid_id(effect_id) || !intent(intent_digest) {
            return Err(RuntimeError::RequestInvalid);
        }
        let checked = self.rpc(
            json!({"op":"broker_check_answer","domain":context.client.domain,
            "ticket":ticket,"submission_id":submission.id,"reviews":host_review.reviews,
            "policy":host_review.policy}),
            TIMEOUT,
        )?;
        // The SDK submission ID is a nonce; the draft ID commits to content.
        // Preserve both and bind the take assessment to the checked digest.
        if checked["context_id"]
            != self.brokers.client(&context.client)?.contexts[&context.retention_id].context_id
            || checked["assessment"]["snapshot_id"] != context.brief.snapshot_id
            || !checked["assessment"]["draft_id"]
                .as_str()
                .is_some_and(digest)
            || !matches!(
                checked["assessment"]["decision"].as_str(),
                Some("release" | "abstain")
            )
        {
            return Err(self.bad_execution_reply());
        }
        if checked["assessment"]["decision"] != "release" {
            return Err(RuntimeError::ScopeDenied);
        }
        let draft_id = checked["assessment"]["draft_id"]
            .as_str()
            .ok_or(RuntimeError::TransportFailed)?
            .to_owned();
        let raw = self.rpc(
            json!({"op":"broker_bind_execution","domain":context.client.domain,
            "ticket":ticket,"submission_id":submission.id,"effect_id":effect_id,
            "intent_digest":intent_digest,"review":host_review}),
            TIMEOUT,
        )?;
        let Ok(wire) = serde_json::from_value::<WireBinding>(raw) else {
            return Err(self.bad_execution_reply());
        };
        let held = self
            .brokers
            .client(&context.client)?
            .contexts
            .get(&context.retention_id)
            .ok_or(RuntimeError::ContextStale)?;
        let domain = &self.brokers.domains[&context.client.domain];
        if wire.schema != "cigar.context-execution-binding.v1"
            || !digest(&wire.id)
            || wire.epoch != domain.epoch
            || wire.ticket != ticket
            || wire.submission_id != submission.id
            || wire.context_id != held.context_id
            || wire.snapshot_id != context.brief.snapshot_id
            || !digest(&wire.source_authority_digest)
            || !digest(&wire.review_digest)
            || wire.effect_id != effect_id
            || wire.intent_digest != intent_digest
        {
            return Err(self.bad_execution_reply());
        }
        self.execution_ticket(context)?;
        Ok(BrokerBoundExecution {
            client: context.client.clone(),
            retention_id: context.retention_id,
            wire,
            draft_id,
        })
    }

    /// Consume the native handle for one attempt, including error/unknown
    /// outcomes. Never retry take/send automatically. The receipt observes only
    /// this context check; effect reconciliation belongs to the real executor.
    pub fn take_broker_execution(
        &mut self,
        context: &RetainedBrokerContext,
        binding: BrokerBoundExecution,
        current_host_review: &BrokerExecutionReview,
    ) -> Result<BrokerExecutionHandoff, RuntimeError> {
        self.execution_ticket(context)?;
        review(current_host_review)?;
        if !same_client(&context.client, &binding.client)
            || context.retention_id != binding.retention_id
        {
            return Err(RuntimeError::ScopeDenied);
        }
        let raw = self.rpc(
            json!({"op":"broker_take_execution","domain":context.client.domain,
            "binding":binding.wire,"review":current_host_review}),
            TIMEOUT,
        )?;
        let checked = &raw["checked"];
        if raw.as_object().is_none_or(|v| v.len() != 2)
            || raw["binding"]
                != serde_json::to_value(&binding.wire).map_err(|_| RuntimeError::TransportFailed)?
            || checked["context_id"] != binding.wire.context_id
            || checked["assessment"]["snapshot_id"] != binding.wire.snapshot_id
            || checked["assessment"]["draft_id"] != binding.draft_id
            || checked["assessment"]["decision"] != "release"
        {
            return Err(self.bad_execution_reply());
        }
        self.execution_ticket(context)?;
        Ok(BrokerExecutionHandoff {
            effect_id: binding.wire.effect_id,
            intent_digest: binding.wire.intent_digest,
            snapshot_id: binding.wire.snapshot_id,
        })
    }
}

#[cfg(test)]
#[path = "broker_execution_tests.rs"]
mod tests;
