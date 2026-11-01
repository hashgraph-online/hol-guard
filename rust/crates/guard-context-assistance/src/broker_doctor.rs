//! Explicit background qualification uses synthetic data and fresh authority.
use crate::{ContextAssistanceConfig, ContextDocument, RuntimeError, VerifiedRuntime};
use std::collections::BTreeSet;
use std::time::Duration;

impl VerifiedRuntime {
    pub fn verify_shared_compile(
        &mut self,
        config: &ContextAssistanceConfig,
    ) -> Result<(), RuntimeError> {
        self.set_shared_verified(false);
        if !config.features.shared_agents || !config.features.agent_context {
            return Err(RuntimeError::ScopeDenied);
        }
        let mut config = config.clone();
        // An explicit off-state recheck may inspect the synthetic transport;
        // it grants no app, workspace or user document permission.
        config.enabled = true;
        config.storage.mode = crate::StorageMode::Memory;
        let domain = self.open_broker_domain("broker:qualification", &config)?;
        let result = (|| {
            let revision = self.broker_source_revision(&domain, "qualification")?;
            self.broker_replace_source(
                &domain,
                "qualification",
                &revision,
                vec![ContextDocument {
                    id: "qualification-document".into(),
                    text: "Synthetic shared context qualification evidence.".into(),
                    start_line: 1,
                }],
            )?;
            let client = self.grant_broker_client(
                &domain,
                BTreeSet::from(["qualification".into()]),
                BTreeSet::new(),
                "qualification-policy",
                Duration::from_secs(30),
            )?;
            let brief = self.compile_broker_context(
                &client,
                "shared context qualification",
                vec!["qualification-document".into()],
            )?;
            self.explain_broker_context(&brief)?;
            self.recheck_artifacts()
        })();
        let cleanup = self.close_broker_domain(&domain);
        result?;
        cleanup?;
        self.set_shared_verified(true);
        Ok(())
    }
}
