//! Current source identity is an admission/decision fence, separate from the
//! snapshot MAC and retained binding floor. No provider or actor authority.

use super::policy_store_command_authority::open_mutation_lock;
use super::policy_store_persistence::read_private_json;
use super::PolicySnapshotStore;
use guard_policy_snapshot::business_source_anchor::{
    verify_business_source_anchor, BusinessSourcePhase, MAX_BUSINESS_SOURCE_ANCHOR_BYTES,
};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes, PolicySnapshotV3};
use std::fs::File;

pub(crate) struct BusinessSourceLease {
    _file: File,
}

const MARKER_FILE: &str = "business-source-anchor.v1.json";

impl PolicySnapshotStore {
    pub(crate) fn business_source_lease(
        &self,
        snapshot: &PolicySnapshotV3,
    ) -> Result<Option<BusinessSourceLease>, String> {
        let marker_path = self.state_base.join(MARKER_FILE);
        let private_root = crate::resident_state::private_root_for_state_base(&self.state_base)?;
        let lock_path = private_root.join("extension-control-authority.lock");
        super::policy_store_validation::validate_private_directory(&private_root)?;
        // Only a genuinely absent marker permits an unarmed legacy policy.
        // Dangling links, inaccessible state and malformed files stay closed.
        match std::fs::symlink_metadata(&marker_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Even the first legacy decision must materialize and retain
                // the common lease before first activation can close a marker.
                if snapshot.business_policy.is_none() && snapshot.command_extensions.is_none() {
                    // CREATE_NEW never repairs/truncates an existing lock. A
                    // creation race proceeds through the strict reader below.
                    match crate::resident_state::private_file(&lock_path, true, &private_root) {
                        Ok(file) => drop(file),
                        Err(_) if std::fs::symlink_metadata(&lock_path).is_ok() => {}
                        Err(_) => return Err("native_business_source_authority_invalid".to_owned()),
                    }
                } else if snapshot.business_policy.is_some()
                    && std::fs::symlink_metadata(&lock_path)
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
                {
                    return Err("native_business_source_authority_missing".to_owned());
                }
            }
            Err(_) => return Err("native_business_source_authority_invalid".to_owned()),
            Ok(_) => {}
        }
        let file = open_mutation_lock(&lock_path, &private_root)?;
        fs2::FileExt::try_lock_shared(&file)
            .map_err(|_| "native_business_source_mutation_in_progress".to_owned())?;
        let record = read_private_json(
            &marker_path,
            MAX_BUSINESS_SOURCE_ANCHOR_BYTES as u64,
            "business_source_authority",
            &private_root,
        )
        .map_err(|_| "native_business_source_authority_invalid".to_owned())?;
        let Some((_, bytes)) = record else {
            return if snapshot.business_policy.is_none() {
                Ok(Some(BusinessSourceLease { _file: file }))
            } else {
                Err("native_business_source_authority_missing".to_owned())
            };
        };
        let marker = verify_business_source_anchor(&bytes, &self.verifier_key)
            .map_err(|_| "native_business_source_authority_invalid".to_owned())?;
        if marker.phase() != BusinessSourcePhase::Committed {
            return Err("native_business_source_authority_not_current".to_owned());
        }
        let binding = snapshot
            .business_policy
            .as_ref()
            .ok_or_else(|| "native_business_policy_removal_requires_authority".to_owned())?;
        if snapshot.mode != "enforce" {
            return Err("native_business_source_enforce_required".to_owned());
        }
        let value = serde_json::to_value(binding)
            .map_err(|_| "native_business_source_authority_invalid".to_owned())?;
        let binding_bytes = canonical_json_bytes(&value)
            .map_err(|_| "native_business_source_authority_invalid".to_owned())?;
        if marker.floor().business_policy_digest() != digest_bytes(&binding_bytes)
            || value
                .get("sourceDocumentDigest")
                .and_then(serde_json::Value::as_str)
                != Some(marker.floor().source_digest())
        {
            return Err("native_business_source_authority_not_current".to_owned());
        }
        Ok(Some(BusinessSourceLease { _file: file }))
    }
}
