//! Explicit synthetic durability qualification. No user data or permission is
//! read, and the scratch namespace cannot remove saved project evidence.
use crate::{ContextAssistanceConfig, RuntimeError, StorageMode, VerifiedRuntime};
use std::path::Path;

impl VerifiedRuntime {
    pub fn verify_persistence_compile(
        &mut self,
        home: &Path,
        config: &ContextAssistanceConfig,
    ) -> Result<(), RuntimeError> {
        self.set_persistence_verified(false);
        if config.storage.mode != StorageMode::Sqlite {
            return Err(RuntimeError::ScopeDenied);
        }
        if !self.status().active || self.cancel.load(std::sync::atomic::Ordering::Acquire) {
            return Err(RuntimeError::Cancelled);
        }
        #[cfg(unix)]
        {
            qualify(self, home, config)?;
            self.set_persistence_verified(true);
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = home;
            Err(RuntimeError::PlatformUnqualified)
        }
    }
}

#[cfg(unix)]
fn qualify(
    runtime: &mut VerifiedRuntime,
    home: &Path,
    config: &ContextAssistanceConfig,
) -> Result<(), RuntimeError> {
    use crate::EvidenceCache;
    use sha2::{Digest, Sha256};
    let cache = EvidenceCache::qualification(home)?;
    // Only synthetic stores live here. Interrupted checks may leave a store;
    // its actual SQLite owner must be closed before this bounded removal.
    cache.forget_all()?;
    let key = format!(
        "{:x}",
        Sha256::digest(b"guard-private-storage-qualification.v1")
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| RuntimeError::StorageRepairRequired)?
        .as_millis()
        .try_into()
        .map_err(|_| RuntimeError::StorageRepairRequired)?;
    let slot = cache.open_slot(&key, 1, now)?;
    let mut config = config.clone();
    config.enabled = true;
    let mut opened = None;
    let result = roundtrip(runtime, &config, &slot, &mut opened);
    if let Some(handle) = opened.take() {
        if runtime.close_broker_domain(&handle).is_err() {
            runtime.close();
        }
    }
    if let Err(error) = slot.remove() {
        runtime.close();
        return Err(error);
    }
    result?;
    runtime.recheck_artifacts()
}

#[cfg(unix)]
fn roundtrip(
    runtime: &mut VerifiedRuntime,
    config: &ContextAssistanceConfig,
    slot: &crate::EvidenceSlot,
    opened: &mut Option<crate::BrokerDomainHandle>,
) -> Result<(), RuntimeError> {
    use crate::ContextDocument;
    use std::collections::BTreeSet;
    use std::time::Duration;
    let domain = runtime.open_persistent_broker_domain(
        &slot.domain_name(),
        config,
        slot.broker_storage()?,
    )?;
    *opened = Some(domain.clone());
    if runtime.broker_storage_status(&domain)?["restored"] != false {
        return Err(RuntimeError::HandshakeFailed);
    }
    let docs = vec![ContextDocument {
        id: "storage-qualification-document".into(),
        start_line: 1,
        text: "Synthetic saved evidence requires a fresh native grant after recovery.".into(),
    }];
    let empty = runtime.broker_source_revision(&domain, "qualification")?;
    let first = runtime.broker_replace_source(&domain, "qualification", &empty, docs.clone())?;
    let client = runtime.grant_broker_client(
        &domain,
        BTreeSet::from(["qualification".into()]),
        BTreeSet::new(),
        "qualification-policy",
        Duration::from_secs(30),
    )?;
    let old = runtime.compile_broker_context(
        &client,
        "saved evidence recovery",
        vec!["storage-qualification-document".into()],
    )?;
    runtime.explain_broker_context(&old)?;
    runtime.close_broker_domain(&domain)?;
    *opened = None;
    let fresh = runtime.open_persistent_broker_domain(
        &slot.domain_name(),
        config,
        slot.broker_storage()?,
    )?;
    *opened = Some(fresh.clone());
    let second = runtime.broker_source_revision(&fresh, "qualification")?;
    if runtime.broker_storage_status(&fresh)?["restored"] != true
        || first.epoch == second.epoch
        || first.version != second.version
        || !matches!(
            runtime.grant_broker_client(
                &fresh,
                BTreeSet::from(["qualification".into()]),
                BTreeSet::new(),
                "qualification-policy",
                Duration::from_secs(30)
            ),
            Err(RuntimeError::ScopeDenied)
        )
        || !matches!(
            runtime.explain_broker_context(&old),
            Err(RuntimeError::ScopeDenied | RuntimeError::ContextStale)
        )
    {
        return Err(RuntimeError::HandshakeFailed);
    }
    runtime.resume_broker_source(&fresh, "qualification", docs)?;
    let client = runtime.grant_broker_client(
        &fresh,
        BTreeSet::from(["qualification".into()]),
        BTreeSet::new(),
        "qualification-policy",
        Duration::from_secs(30),
    )?;
    let context = runtime.compile_broker_context(
        &client,
        "saved evidence recovery",
        vec!["storage-qualification-document".into()],
    )?;
    runtime.explain_broker_context(&context)?;
    runtime.close_broker_domain(&fresh)?;
    *opened = None;
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "broker_persistence_doctor_tests.rs"]
mod tests;
