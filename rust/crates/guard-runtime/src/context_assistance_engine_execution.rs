//! Dedicated private SDK view for captured native facts only. It shares no
//! documents, notes, receipt stream or client with operator/agent retrieval.
use super::*;
use crate::context_assistance_execution::Checked;
use crate::native_exact_action_op::bash_context::Facts;
use guard_context_assistance::{
    BrokerAnswerClaim, BrokerAnswerPolicy, BrokerClaimReview, BrokerClientHandle,
    BrokerDomainHandle, BrokerExecutionReview, BrokerReviewVerdict,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(crate) struct Lane {
    domain: BrokerDomainHandle,
    client: Option<BrokerClientHandle>,
    policy: ContextAssistanceConfig,
    pub(crate) ready: Arc<AtomicBool>,
    renew_at: Instant,
}
impl Drop for Lane {
    fn drop(&mut self) {
        self.ready.store(false, Ordering::Release);
    }
}
impl Lane {
    fn renew(&mut self, runtime: &mut VerifiedRuntime) -> Result<(), RuntimeError> {
        self.ready.store(false, Ordering::Release);
        if let Some(client) = self.client.take() {
            match runtime.revoke_broker_client(&client) {
                Ok(()) | Err(RuntimeError::ScopeDenied) => {}
                Err(error) => return Err(error),
            }
        }
        self.client = Some(runtime.grant_broker_client(
            &self.domain,
            BTreeSet::from(["guard:action".into()]),
            BTreeSet::new(),
            &revision(&self.policy)?,
            Duration::from_secs(300),
        )?);
        self.renew_at = Instant::now() + Duration::from_secs(240);
        self.ready.store(true, Ordering::Release);
        Ok(())
    }
}

impl Engine {
    /// Explicit background activation owns expensive artifact/client work.
    /// The actual command path only uses an already prepared private client.
    pub(crate) fn prewarm_execution(
        runtime: &mut VerifiedRuntime,
        policy: &ContextAssistanceConfig,
    ) -> Result<Lane, RuntimeError> {
        if !runtime.status().execution_handoff_verified {
            return Err(RuntimeError::HandshakeFailed);
        }
        let domain = runtime.open_execution_broker_domain("guard:native-executor", policy)?;
        let mut lane = Lane {
            domain,
            client: None,
            policy: policy.clone(),
            ready: Arc::new(AtomicBool::new(false)),
            renew_at: Instant::now(),
        };
        let prepared = (|| {
            let version = runtime.broker_source_revision(&lane.domain, "guard:action")?;
            runtime.broker_replace_source(&lane.domain, "guard:action", &version, vec![ContextDocument {
                id:"guard-execution-facts".into(), start_line:1,
                text:"Private execution context is prepared. No workspace access or execution authority has been granted.".into(),
            }])?;
            lane.renew(runtime)
        })();
        if let Err(error) = prepared {
            if runtime.close_broker_domain(&lane.domain).is_err() {
                runtime.close();
            }
            return Err(error);
        }
        Ok(lane)
    }
    pub(crate) fn set_execution_lane(&mut self, lane: Option<Lane>) {
        self.execution_lane = lane;
    }

    pub(super) fn maintain_execution_lane(
        &mut self,
        runtime: &mut VerifiedRuntime,
    ) -> Result<(), RuntimeError> {
        if let Some(lane) = &mut self.execution_lane {
            if Instant::now() >= lane.renew_at {
                match lane.renew(runtime) {
                    Ok(()) => {}
                    Err(RuntimeError::ResourceLimit | RuntimeError::Busy) => {
                        lane.renew_at = Instant::now() + Duration::from_secs(1);
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    pub(crate) fn execution(
        &mut self,
        runtime: &mut VerifiedRuntime,
        facts: Facts,
    ) -> Result<Checked, RuntimeError> {
        if !matches!(facts.harness.as_str(), "pi" | "omp") {
            return Err(RuntimeError::ScopeDenied);
        }
        if !runtime.status().execution_handoff_verified || Instant::now() >= facts.expires {
            return Err(RuntimeError::ContextStale);
        }
        let (scope_id, policy, epoch) = {
            let (id, scope) = self
                .scopes
                .iter_mut()
                .find(|(_, scope)| {
                    !scope.revoked
                        && scope.app == facts.harness
                        && scope.root.path() == facts.workspace
                })
                .ok_or(RuntimeError::ScopeDenied)?;
            policy_current(&self.home, scope, runtime)?;
            if !scope.policy.features.execution_context || !scope.policy.sources.native_policy_facts
            {
                return Err(RuntimeError::ScopeDenied);
            }
            (id.clone(), scope.policy.clone(), scope.epoch.fence())
        };
        let lane = self.execution_lane.as_mut().ok_or(RuntimeError::Busy)?;
        if !lane.ready.load(Ordering::Acquire)
            || lane
                .client
                .as_ref()
                .is_none_or(|c| !runtime.broker_client_is_live(c))
        {
            return Err(RuntimeError::Busy);
        }
        let version = runtime.broker_source_revision(&lane.domain, "guard:action")?;
        runtime.broker_replace_source(
            &lane.domain,
            "guard:action",
            &version,
            vec![ContextDocument {
                id: "guard-execution-facts".into(),
                text: facts.text.clone(),
                start_line: 1,
            }],
        )?;
        let context = runtime.compile_broker_context_limited(
            lane.client.as_ref().ok_or(RuntimeError::ScopeDenied)?,
            "native captured Bash execution observation",
            vec!["guard-execution-facts".into()],
            &policy.limits,
        )?;
        let citations = context
            .brief()
            .citations
            .iter()
            .filter(|c| c["source"] == "guard:action")
            .filter_map(|c| c["node_id"].as_str().map(str::to_owned))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let submission = runtime.submit_broker_answer(
            &context,
            vec![BrokerAnswerClaim {
                text: facts.text.clone(),
                citations,
                confidence_bps: Some(10_000),
            }],
        )?;
        // Only this exact fixed native observation is supported. Agent model
        // text, retrieved documents and proposed notes never enter this review.
        let review = BrokerExecutionReview {
            authority_revision: facts.sdk_intent[4..].into(),
            reviews: submission
                .review_keys()
                .iter()
                .map(|key| BrokerClaimReview {
                    claim_key: key.clone(),
                    verdict: BrokerReviewVerdict::Supported,
                    reviewed_counterevidence: vec![],
                })
                .collect(),
            policy: BrokerAnswerPolicy::default(),
        };
        let bound = runtime.bind_broker_execution(
            &context,
            &submission,
            &facts.effect_id,
            &facts.sdk_intent,
            &review,
        )?;
        let handoff = runtime.take_broker_execution(&context, bound, &review)?;
        let scope = self
            .scopes
            .get_mut(&scope_id)
            .ok_or(RuntimeError::ScopeDenied)?;
        policy_current(&self.home, scope, runtime)?;
        if !epoch.is_current() || Instant::now() >= facts.expires {
            return Err(RuntimeError::ContextStale);
        }
        Ok(Checked {
            facts,
            handoff,
            scope_id,
            scope: epoch,
        })
    }

    pub(super) fn close_execution_lane(
        &mut self,
        runtime: &mut VerifiedRuntime,
    ) -> Result<(), RuntimeError> {
        if let Some(lane) = self.execution_lane.take() {
            if let Err(error) = runtime.close_broker_domain(&lane.domain) {
                runtime.close();
                return Err(error);
            }
        }
        Ok(())
    }
}
