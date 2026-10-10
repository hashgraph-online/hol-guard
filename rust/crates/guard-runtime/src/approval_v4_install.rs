use super::*;

pub(crate) fn install_record(state_base: &Path, record_path: &Path) -> Result<(), String> {
    super::super::approval_enrollment::with_transition_lock(state_base, || {
        super::super::validate_private_directory(state_base)?;
        let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
        let Some((candidate, bytes)) = read_record(record_path, &private_root)? else {
            return Err("native_approval_v4_authority_missing".into());
        };
        let target = state_base.join(AUTHORITY_FILE_NAME);
        let current = read_record(&target, &private_root)?;
        let state = read_secure_state_record(state_base)?;
        let (credential_id, cose_public_key) = validate_record(&candidate)?;
        let candidate_digest = guard_policy_snapshot::digest_bytes(&bytes);
        if let Some((current, current_bytes)) = current.as_ref() {
            if *current_bytes == bytes {
                let state = state
                    .as_ref()
                    .ok_or("native_approval_v4_secure_state_unavailable")?;
                if !secure_state_matches_record(
                    state,
                    current,
                    &candidate_digest,
                    &credential_id,
                    &cose_public_key,
                ) {
                    return Err("native_approval_v4_authority_provenance_mismatch".into());
                }
                return Ok(());
            }
            if current.status == "revoked" {
                return Err("native_approval_v4_authority_revoked".into());
            }
            if candidate.enrollment_generation <= current.enrollment_generation
                || (candidate.status == "active"
                    && candidate.previous_key_id.as_deref() != Some(current.key_id.as_str()))
                || (candidate.status == "revoked"
                    && (candidate.key_id != current.key_id || candidate.previous_key_id.is_some()))
            {
                return Err("native_approval_v4_authority_generation_rollback".into());
            }
            if candidate.device_binding != current.device_binding
                || candidate.installation_binding != current.installation_binding
                || candidate.rp_id != current.rp_id
                || candidate.origin != current.origin
            {
                return Err("native_approval_v4_authority_provenance_mismatch".into());
            }
        }
        if let Some(enrollment) = super::super::approval_enrollment::load_unlocked(state_base)? {
            if enrollment.device_binding != candidate.device_binding
                || enrollment.installation_binding != candidate.installation_binding
            {
                return Err("native_approval_v4_authority_provenance_mismatch".into());
            }
            if enrollment.status == "revoked" {
                return Err("native_approval_authority_revoked".into());
            }
        } else {
            return Err("native_approval_v4_authority_provenance_mismatch".into());
        }

        let (sign_count, mut enrollment_lineage) = match state {
            Some(state) => {
                if state.status == "revoked" {
                    return Err("native_approval_v4_authority_revoked".into());
                }
                if secure_state_matches_record(
                    &state,
                    &candidate,
                    &candidate_digest,
                    &credential_id,
                    &cose_public_key,
                ) {
                    // Resume only this exact Root-signed candidate after a secure-state
                    // commit interrupted before the public authority file was replaced.
                    (state.sign_count, state.enrollment_lineage)
                } else {
                    let (current, current_bytes) = current
                        .as_ref()
                        .ok_or("native_approval_v4_authority_provenance_mismatch")?;
                    let (current_credential, current_cose) = validate_record(current)?;
                    if !secure_state_matches_record(
                        &state,
                        current,
                        &guard_policy_snapshot::digest_bytes(current_bytes),
                        &current_credential,
                        &current_cose,
                    ) {
                        return Err("native_approval_v4_authority_provenance_mismatch".into());
                    }
                    if candidate.status == "active" {
                        if candidate.credential_id == current.credential_id
                            || state.enrollment_lineage.iter().any(|ancestor| {
                                ancestor.record.key_id == candidate.key_id
                                    || ancestor.record.credential_id == candidate.credential_id
                            })
                        {
                            return Err("native_approval_v4_authority_generation_rollback".into());
                        }
                        let fingerprint =
                            super::super::policy_store_authority::authority_fingerprint(&target)
                                .ok_or("native_approval_v4_authority_invalid")?;
                        let mut lineage = state.enrollment_lineage;
                        lineage.push(lineage::EnrollmentAncestor {
                            fingerprint,
                            record: current.clone(),
                        });
                        (0, lineage)
                    } else {
                        // A revocation is a durable floor, never an active lineage edge.
                        (state.sign_count, Vec::new())
                    }
                }
            }
            None => {
                if current.is_some() {
                    return Err("native_approval_v4_secure_state_unavailable".into());
                }
                if candidate.enrollment_generation != 1 || candidate.previous_key_id.is_some() {
                    return Err("native_approval_v4_authority_generation_rollback".into());
                }
                (0, Vec::new())
            }
        };
        if candidate.status == "revoked" {
            enrollment_lineage.clear();
        }
        let authority = ApprovalV4Authority {
            credential_id,
            cose_public_key,
            algorithm: candidate.algorithm,
            rp_id: candidate.rp_id.clone(),
            origin: candidate.origin.clone(),
            key_id: candidate.key_id.clone(),
            device_binding: candidate.device_binding.clone(),
            installation_binding: candidate.installation_binding.clone(),
            enrollment_generation: candidate.enrollment_generation,
            previous_key_id: candidate.previous_key_id.clone(),
            enrollment_lineage: Arc::new(enrollment_lineage),
            status: candidate.status.clone(),
            path: target.clone(),
            fingerprint: String::new(),
            record_digest: candidate_digest,
            state_base: state_base.to_owned(),
            sign_count: Arc::new(Mutex::new(sign_count)),
            assertions: Arc::new(Mutex::new(HashMap::new())),
        };
        lineage::validate(&authority)?;
        let encoded_state = secure_state_value(&authority, sign_count)?;
        super::super::approval_v4_secure_state::store(state_base, &encoded_state)?;
        super::super::policy_store_persistence::persist_private_bytes(
            &target,
            &bytes,
            AUTHORITY_MAX_BYTES,
            "approval_authority_v4",
            &private_root,
        )?;
        Ok(())
    })
}
