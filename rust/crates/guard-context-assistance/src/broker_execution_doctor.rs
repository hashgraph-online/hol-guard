//! Synthetic SDK qualification, independent of agent sharing and saved data.
//! This never advertises or qualifies an external app's execution adapter.
use crate::{
    BrokerAnswerClaim, BrokerAnswerPolicy, BrokerClaimReview, BrokerExecutionReview,
    BrokerReviewVerdict, ContextAssistanceConfig, ContextDocument, RuntimeError, VerifiedRuntime,
};
use std::collections::BTreeSet;
use std::time::Duration;

impl VerifiedRuntime {
    pub fn verify_execution_handoff(
        &mut self,
        config: &ContextAssistanceConfig,
    ) -> Result<(), RuntimeError> {
        self.set_execution_verified(false);
        if !config.features.execution_context || !config.sources.native_policy_facts {
            return Err(RuntimeError::ScopeDenied);
        }
        let mut config = config.clone();
        // An explicit recheck may use synthetic facts while global consent is
        // off. It restores no user scope, app grant or execution authority.
        config.enabled = true;
        let domain = self.open_execution_broker_domain("execution:qualification", &config)?;
        let result = (|| {
            let text =
                "Synthetic native observation for SDK qualification; no command was executed.";
            let version = self.broker_source_revision(&domain, "guard:action")?;
            self.broker_replace_source(
                &domain,
                "guard:action",
                &version,
                vec![ContextDocument {
                    id: "execution-qualification".into(),
                    text: text.into(),
                    start_line: 1,
                }],
            )?;
            let client = self.grant_broker_client(
                &domain,
                BTreeSet::from(["guard:action".into()]),
                BTreeSet::new(),
                "execution-qualification-policy",
                Duration::from_secs(30),
            )?;
            let context = self.compile_broker_context(
                &client,
                "native execution observation",
                vec!["execution-qualification".into()],
            )?;
            let submission = self.submit_broker_answer(
                &context,
                vec![BrokerAnswerClaim {
                    text: text.into(),
                    citations: vec!["execution-qualification".into()],
                    confidence_bps: Some(10_000),
                }],
            )?;
            let review = BrokerExecutionReview {
                authority_revision: "execution-qualification-review".into(),
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
            let intent = format!("1220{}", "e".repeat(64));
            let bound = self.bind_broker_execution(
                &context,
                &submission,
                "execution:qualification-effect",
                &intent,
                &review,
            )?;
            let taken = self.take_broker_execution(&context, bound, &review)?;
            if taken.effect_id() != "execution:qualification-effect"
                || taken.intent_digest() != intent
            {
                return Err(RuntimeError::HandshakeFailed);
            }
            self.recheck_artifacts()
        })();
        let cleanup = self.close_broker_domain(&domain);
        result?;
        cleanup?;
        self.set_execution_verified(true);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires the explicitly approved actual CPython 3.14/CIGAR 0.14.1 candidate"]
    fn actual_execution_doctor_uses_private_memory_without_agent_or_storage_consent() {
        let selection = serde_json::from_slice(
            &std::fs::read(
                std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit selection"),
            )
            .unwrap(),
        )
        .unwrap();
        let approval = serde_json::from_slice(
            &std::fs::read(
                std::env::var_os("GUARD_CIGAR_TEST_APPROVAL").expect("explicit approval"),
            )
            .unwrap(),
        )
        .unwrap();
        let mut runtime = VerifiedRuntime::start(selection, &approval).unwrap();
        let mut config = ContextAssistanceConfig {
            runtime_id: "explicit-test-selection".into(),
            ..Default::default()
        };
        config.features.execution_context = true;
        assert!(!config.enabled);
        assert!(!config.features.agent_context && !config.features.shared_agents);
        assert!(!runtime.status().execution_handoff_verified);
        runtime.verify_execution_handoff(&config).unwrap();
        assert!(runtime.status().execution_handoff_verified);
        assert!(!runtime.status().shared_compile_verified);
        assert!(!runtime.status().persistence_compile_verified);
        // Reopening the exact name through the public boundary proves cleanup
        // without widening the private registry for a test.
        let mut active = config.clone();
        active.enabled = true;
        active.limits.max_active_workspaces = 1;
        let reopened = runtime
            .open_execution_broker_domain("execution:qualification", &active)
            .unwrap();
        assert_eq!(
            runtime.broker_storage_status(&reopened).unwrap(),
            serde_json::json!({"mode":"memory","restored":false})
        );
        assert_eq!(
            runtime
                .open_execution_broker_domain("execution:second-private", &active)
                .err(),
            Some(RuntimeError::ResourceLimit)
        );
        let mut sharing = active.clone();
        sharing.features.agent_context = true;
        sharing.features.shared_agents = true;
        let workspace = runtime
            .open_broker_domain("sharing:one-workspace", &sharing)
            .unwrap();
        assert_eq!(
            runtime
                .open_broker_domain("sharing:second-workspace", &sharing)
                .err(),
            Some(RuntimeError::ResourceLimit),
            "the private domain cannot expand workspace capacity"
        );
        runtime.close_broker_domain(&workspace).unwrap();
        runtime.close_broker_domain(&reopened).unwrap();
        config.features.execution_context = false;
        assert_eq!(
            runtime.verify_execution_handoff(&config),
            Err(RuntimeError::ScopeDenied)
        );
        assert!(!runtime.status().execution_handoff_verified);
        assert!(runtime.status().active);
        runtime.close();
    }
}
