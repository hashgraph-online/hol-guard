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
