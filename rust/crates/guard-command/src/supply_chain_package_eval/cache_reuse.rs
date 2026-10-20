//! Stored evaluations are lookup hints, never independent decision authority.

use super::bundle_transitive::lockfile_dependency_versions;
use super::evaluation::cached_eval_has_reason_code;
use super::*;

pub(super) struct CacheContext<'a, 'deps> {
    pub deps: &'a SupplyChainEvalDeps<'deps>,
    pub artifact: &'a GuardArtifact,
    pub store: &'a dyn SupplyChainStore,
    pub workspace_dir: Option<&'a Path>,
    pub workspace_id: &'a str,
    pub fingerprint: Option<&'a str>,
    pub intent_hash: &'a str,
    pub bundle: &'a SupplyChainBundleResponse,
    pub meta: &'a BTreeMap<String, String>,
    pub targets: &'a [Map<String, Value>],
    pub now: Option<f64>,
}

impl CacheContext<'_, '_> {
    pub(super) fn reuse(
        &self,
        cached: &Map<String, Value>,
    ) -> EvalResult<Option<PackageEvalResult>> {
        if cached_eval_has_reason_code(cached, "cloud_validation_error") {
            // Only a current saved block can retain this restriction. Rebuild
            // the response; no cached action, entitlement or text is authority.
            return match saved_policy_keeps_cached_error(
                self.deps,
                self.store,
                self.artifact,
                self.workspace_dir,
            ) {
                SavedPolicyOutcome::Keep => Ok(Some(self.saved_block())),
                SavedPolicyOutcome::Retry => Ok(None),
                SavedPolicyOutcome::Probe => Err(EvalError::SavedPolicyProbeRequired(Box::new(
                    self.saved_block()
                        .to_dict()
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                ))),
            };
        }
        let sync_keyring = self.store.get_sync_payload("supply_chain_bundle_keyring");
        let Ok(synced_version) = self.synced_bundle_version() else {
            return Ok(None);
        };
        let Ok(has_sync_keyring) = self.deps.bundle.validate_cached_supply_chain_bundle(
            self.bundle,
            self.workspace_id,
            self.now,
            sync_keyring.as_ref(),
            synced_version.as_deref(),
        ) else {
            return Ok(None);
        };
        let Some(resolved_targets) = self.locally_resolved_targets() else {
            return Ok(None);
        };
        let Some(mut draft) = evaluate_with_bundle(
            self.deps,
            self.artifact,
            self.targets,
            self.bundle,
            self.workspace_dir,
            Some(self.workspace_id),
            self.now,
        ) else {
            return Ok(None);
        };
        if draft.refresh_required
            || !resolved_targets.iter().all(|target| {
                let identity = result_package_identity(self.deps, target);
                draft
                    .packages
                    .iter()
                    .any(|package| result_package_identity(self.deps, package) == identity)
            })
        {
            return Ok(None);
        }
        let account_current = self.account_authority_current();
        if draft.decision != "block"
            && (!account_current || !has_sync_keyring || synced_version.is_none())
        {
            return Ok(None);
        }
        if !account_current {
            // Pairing alone is not a subscription or a current signed-in
            // session. A verified finding can still restrict the request.
            draft.entitlement_state = "unknown".into();
        }
        // Every field is derived again from the current verified bundle. A
        // matching cache key never authenticates decision_json or its user copy.
        let mut result = finalize_evaluation(self.deps, &draft, self.intent_hash, self.fingerprint);
        result.cache_status = "hit".into();
        Ok(Some(result))
    }

    fn synced_bundle_version(&self) -> Result<Option<String>, ()> {
        let Some(payload) = self
            .store
            .get_sync_payload("supply_chain_bundle_entitlement")
        else {
            return Ok(None);
        };
        if payload.get("workspace_id").and_then(Value::as_str) != Some(self.workspace_id) {
            return Err(());
        }
        optional_string(payload.get("bundle_version"))
            .map(Some)
            .ok_or(())
    }

    fn locally_resolved_targets(&self) -> Option<Vec<Map<String, Value>>> {
        if self.targets.is_empty() {
            return None;
        }
        let versions = lockfile_dependency_versions(
            self.deps,
            self.workspace_dir,
            self.artifact,
            self.targets,
        );
        // Reusing a pinned assessment must not resolve a future registry payload
        // or fetch metadata on every ordinary cache hit.
        self.targets
            .iter()
            .map(|target| {
                let version = optional_string(target.get("version"))
                    .or_else(|| {
                        lockfile_target_key(target).and_then(|key| versions.get(&key).cloned())
                    })
                    .or_else(|| {
                        optional_string(target.get("range")).and_then(|range| exact_version(&range))
                    })?;
                let mut resolved = target.clone();
                resolved.insert("resolvedVersion".into(), Value::String(version));
                Some(resolved)
            })
            .collect()
    }

    fn saved_block(&self) -> PackageEvalResult {
        let mut result = cloud_fail_closed_evaluation_full(
            self.deps,
            "cloud_validation_error",
            "Your saved block remains active. The cached Cloud assessment is not verified intelligence.",
            self.artifact,
            self.targets,
            self.workspace_dir,
            self.fingerprint,
            Some(self.meta),
            "block",
        );
        result.enforcement = "policy_override".into();
        result.entitlement_state = "unknown".into();
        result.refresh_required = true;
        result.bundle_version = None;
        result.policy_version = "local:none".into();
        result
    }

    fn account_authority_current(&self) -> bool {
        let Ok(auth) = self
            .deps
            .guard_sync
            .resolve_guard_sync_auth_context(self.store, false, false)
        else {
            return false;
        };
        let Some(sync_url) = optional_string(auth.get("sync_url")) else {
            return false;
        };
        if optional_string(auth.get("access_token")).is_none()
            || self
                .deps
                .guard_sync
                .validate_guard_sync_url(&sync_url, optional_string(auth.get("issuer")).as_deref())
                .is_err()
        {
            return false;
        }
        self.deps
            .entitlement
            .resolve_package_firewall_entitlement_with_refresh(self.store)
            .is_ok_and(|state| state.get("allowed") == Some(&Value::Bool(true)))
    }
}
