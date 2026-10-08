//! Native owned-send boundary. No RPC, actor registry or custody claim.
use super::super::super::{workspace_review_authority, PolicySnapshotStore};
use super::{ClaimedBusinessReview, PreparedGoogleBusinessRequest};
use guard_command::business_input::PreparedBusinessInputV1;
use guard_contracts::{
    BusinessDispatchAttemptV1, BusinessDispatchJournalV1, BusinessDispatchRetryAuthorityV1,
    BusinessProviderEffectV1, NativeBusinessDispatchReceiptV1, WorkspaceReviewDecisionEnvelopeV1,
    NATIVE_BUSINESS_DISPATCH_RECEIPT_V1_SCHEMA,
};
use guard_google_identity::dispatch::{GoogleDispatchError, GoogleSendAttempt};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};

pub(super) struct Lease {
    envelope_digest: String,
    snapshot_digest: String,
    authority_digest: String,
    claimed_at_ms: u64,
    expires_at_ms: u64,
}

pub(crate) struct Outcome {
    pub(crate) attempt: GoogleSendAttempt,
    pub(crate) journal_recorded: bool,
    decision_binding: String,
    input_binding: String,
}

impl Outcome {
    /// Project only finite metadata. A projection error never changes the
    /// transport observation into a refusal or permission to send again.
    pub(crate) fn receipt(&self) -> Result<NativeBusinessDispatchReceiptV1, &'static str> {
        let (attempt, acknowledgement_binding) = match &self.attempt {
            GoogleSendAttempt::ApiAccepted { message_binding } => (
                BusinessDispatchAttemptV1::ApiAccepted,
                Some(message_binding.clone()),
            ),
            GoogleSendAttempt::Unconfirmed => (BusinessDispatchAttemptV1::OutcomeUnknown, None),
        };
        let receipt = NativeBusinessDispatchReceiptV1 {
            schema: NATIVE_BUSINESS_DISPATCH_RECEIPT_V1_SCHEMA.into(),
            version: 1,
            decision_binding: self.decision_binding.clone(),
            input_binding: self.input_binding.clone(),
            attempt,
            journal: if self.journal_recorded {
                BusinessDispatchJournalV1::Recorded
            } else {
                BusinessDispatchJournalV1::Unconfirmed
            },
            provider_effect: BusinessProviderEffectV1::NotChecked,
            retry_authority: BusinessDispatchRetryAuthorityV1::None,
            acknowledgement_binding,
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

// There is no authenticated worker admission implementation yet. An empty
// proof type makes accidental activation impossible: native review approval
// alone cannot supply worker identity, first-party floors or credential custody.
// A future registered-worker owner must implement this authority boundary;
// no model payload, boolean, deserializer or reload constructor can mint it.
pub(crate) enum RegisteredWorkerAdmission {}

fn require_supported_durability() -> Result<(), String> {
    if !cfg!(unix) {
        return Err("native_business_dispatch_durability_unavailable".into());
    }
    Ok(())
}

fn now_ms() -> Result<u64, String> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_millis();
    u64::try_from(time).map_err(|_| "native_resident_clock_invalid".into())
}

fn snapshot_digest(store: &PolicySnapshotStore) -> Result<String, String> {
    let value = serde_json::to_value(store.current_snapshot()?)
        .map_err(|_| "native_business_dispatch_invalid".to_owned())?;
    Ok(digest_bytes(&canonical_json_bytes(&value).map_err(
        |_| "native_business_dispatch_invalid".to_owned(),
    )?))
}

impl Lease {
    // Called only after the native signed decision has been consumed, under
    // its transition lock. This metadata alone grants no dispatch authority;
    // the claimed handle retains the native verifier result separately.
    pub(super) fn capture(
        store: &PolicySnapshotStore,
        decision: &[u8],
        claimed_at_ms: u64,
    ) -> Result<Self, String> {
        let envelope: WorkspaceReviewDecisionEnvelopeV1 =
            serde_json::from_value(crate::strict_json_value(decision)?)
                .map_err(|_| "native_business_dispatch_invalid".to_owned())?;
        let authority =
            workspace_review_authority::read_installed_record(store.state_base(), claimed_at_ms)?
                .ok_or_else(|| "native_business_dispatch_authority_unavailable".to_owned())?;
        if authority.record_digest != envelope.authority_record_digest
            || claimed_at_ms >= envelope.expires_at_ms
        {
            return Err("native_business_dispatch_expired".into());
        }
        Ok(Self {
            envelope_digest: digest_bytes(decision),
            snapshot_digest: snapshot_digest(store)?,
            authority_digest: authority.record_digest,
            claimed_at_ms,
            expires_at_ms: envelope
                .expires_at_ms
                .min(store.current_snapshot()?.expires_at_ms)
                .min(authority.expires_at_ms),
        })
    }

    pub(super) fn seal_clock(mut self, observed_at_ms: u64) -> Result<Self, String> {
        if observed_at_ms < self.claimed_at_ms {
            return Err("native_business_dispatch_clock_rollback".into());
        }
        self.claimed_at_ms = observed_at_ms;
        Ok(self)
    }

    fn check(
        &self,
        store: &PolicySnapshotStore,
        input: &PreparedBusinessInputV1,
        time: u64,
    ) -> Result<(), String> {
        if time < self.claimed_at_ms {
            return Err("native_business_dispatch_clock_rollback".into());
        }
        if time >= self.expires_at_ms {
            return Err("native_business_dispatch_expired".into());
        }
        if snapshot_digest(store)? != self.snapshot_digest {
            return Err("native_business_dispatch_policy_changed".into());
        }
        let authority =
            workspace_review_authority::read_installed_record(store.state_base(), time)?
                .ok_or_else(|| "native_business_dispatch_authority_unavailable".to_owned())?;
        if authority.record_digest != self.authority_digest {
            return Err("native_business_dispatch_authority_changed".into());
        }
        // Budget declarations remain refused until a verified actor registry
        // and reservations are integrated. An approval cannot waive them.
        crate::policy_enforcement::ensure_business_review_permitted(
            &store.current_snapshot()?,
            input.facts(),
            "review",
        )
    }
}

impl ClaimedBusinessReview<PreparedGoogleBusinessRequest> {
    pub(crate) fn dispatch(
        self,
        store: &PolicySnapshotStore,
        _admission: RegisteredWorkerAdmission,
    ) -> Result<Outcome, String> {
        self.dispatch_with(
            store,
            PreparedGoogleBusinessRequest::is_current,
            PreparedGoogleBusinessRequest::dispatch_owned,
            now_ms,
        )
    }
}

impl<T> ClaimedBusinessReview<T> {
    fn dispatch_with(
        self,
        store: &PolicySnapshotStore,
        current: impl Fn(&T) -> bool,
        send: impl FnOnce(T, PreparedBusinessInputV1) -> Result<GoogleSendAttempt, GoogleDispatchError>,
        mut clock: impl FnMut() -> Result<u64, String>,
    ) -> Result<Outcome, String> {
        require_supported_durability()?;
        super::super::super::approval_enrollment::with_transition_lock(store.state_base(), || {
            if self.verified.decision != "allow"
                || self.verified.replayed
                || self.verified.envelope_digest != self.lease.envelope_digest
                || self.verified.authority_record_digest != self.lease.authority_digest
            {
                return Err("native_business_dispatch_claim_invalid".into());
            }
            let first = clock()?;
            self.lease.check(store, &self.owned, first)?;
            if !current(&self.input) {
                return Err("native_business_dispatch_resolution_expired".into());
            }
            let journal = self.journal.start_unlocked(store)?;
            let admission = (|| {
                let last = clock()?;
                if last < first {
                    return Err("native_business_dispatch_clock_rollback".into());
                }
                self.lease.check(store, &self.owned, last)?;
                if !current(&self.input) {
                    return Err("native_business_dispatch_resolution_expired".into());
                }
                Ok(())
            })();
            if let Err(error) = admission {
                return if journal.refuse_unlocked(store).is_ok() {
                    Err(error)
                } else {
                    Err("native_business_dispatch_spent_admission_and_journal_unavailable".into())
                };
            }
            // Hold the same native transition lock through the bounded fixed
            // SDK call: a policy/authority update cannot race admission.
            let decision_binding = self.lease.envelope_digest.clone();
            let input_binding = self.owned.binding().to_owned();
            let attempt = send(self.input, self.owned);
            match attempt {
                Ok(attempt) => {
                    let acknowledgement = match &attempt {
                        GoogleSendAttempt::ApiAccepted { message_binding } => {
                            Some(message_binding.clone())
                        }
                        GoogleSendAttempt::Unconfirmed => None,
                    };
                    let journal_recorded = journal.finish_unlocked(store, acknowledgement).is_ok();
                    Ok(Outcome {
                        attempt,
                        journal_recorded,
                        decision_binding,
                        input_binding,
                    })
                }
                // SDK errors are pre-I/O refusals; HTTP/provider uncertainty
                // is represented by Unconfirmed above. Never conflate them.
                Err(_) => {
                    if journal.refuse_unlocked(store).is_ok() {
                        Err("native_business_dispatch_spent_input_unavailable".into())
                    } else {
                        Err("native_business_dispatch_spent_input_and_journal_unavailable".into())
                    }
                }
            }
        })
    }
}

#[cfg(all(test, unix))]
#[path = "workspace_review_business_dispatch_tests.rs"]
mod tests;

#[cfg(all(test, not(unix)))]
#[test]
fn unsupported_journal_durability_refuses_transport() {
    assert_eq!(
        require_supported_durability().unwrap_err(),
        "native_business_dispatch_durability_unavailable"
    );
}
