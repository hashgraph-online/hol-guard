//! Exact saved consent claimed by the native owner at its launch barrier.
//! No caller-supplied subject or digest can substitute for captured inputs.

use std::io;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use guard_contained_process::{CapturedOutput, SourceLaunchGate};
use guard_contracts::{
    ClaimApprovalReuseDecisionsRequestV1, ContextDigestComponentsV1, GuardHookEnvelopeV2,
    NativeBashAuthorizationKindV1, NativeBashAuthorizationV1, NativeBashCaptureV1,
    NativeBashOperationV1, NativeBashReviewLineageV1, NativeBashSubjectV1,
};
use serde_json::json;

use crate::policy_enforcement::AdmittedPolicySnapshot;
use crate::policy_store::{
    policy_store_approval::bash_journal::BashOperationJournal,
    policy_store_approval::launch_fence::LaunchPolicyFence, PolicySnapshotStore,
};

pub(super) const ARTIFACT: &str = guard_contracts::NATIVE_BASH_ARTIFACT_ID;

#[derive(Debug)]
pub(crate) struct LaunchFailure {
    pub(crate) error: io::Error,
    pub(crate) grant_claimed: bool,
    pub(crate) dispatch_acknowledged: bool,
    pub(crate) operation: Option<Box<NativeBashOperationV1>>,
    pub(crate) code: Option<&'static str>,
    pub(crate) review_lineage: Option<Box<NativeBashReviewLineageV1>>,
}

impl From<io::Error> for LaunchFailure {
    fn from(error: io::Error) -> Self {
        Self {
            error,
            grant_claimed: false,
            dispatch_acknowledged: false,
            operation: None,
            code: None,
            review_lineage: None,
        }
    }
}

impl From<io::ErrorKind> for LaunchFailure {
    fn from(kind: io::ErrorKind) -> Self {
        io::Error::from(kind).into()
    }
}

pub(crate) struct LaunchOutput {
    pub(crate) output: Option<CapturedOutput>,
    pub(crate) grant_claimed: bool,
    pub(crate) dispatch_acknowledged: bool,
    pub(crate) operation: NativeBashOperationV1,
    pub(crate) replayed: bool,
}

pub(crate) fn binding(
    subject: &NativeBashSubjectV1,
    snapshot: &AdmittedPolicySnapshot,
) -> Result<String, &'static str> {
    let controls = snapshot.snapshot().command_extensions.as_ref();
    crate::context_digest::build_context_token(&ContextDigestComponentsV1 {
        identity: serde_json::to_value(&subject.context)
            .map_err(|_| "bash_grant_identity_invalid")?,
        content: json!({"subject_sha256":subject.identity_sha256()?}),
        capabilities: json!({"profile":ARTIFACT,"argv":subject.argv,"outputs":subject.outputs}),
        policy: json!({
            "rule_digest":snapshot.rule_digest,
            "effective_policy":snapshot.effective_policy,
            "mode":snapshot.mode,
            "command_program":controls.map(|value| &value.program_digest),
            "command_catalog":controls.map(|value| &value.catalog_digest),
            "command_trust":controls.map(|value| &value.trust_digest),
            "business_policy":snapshot.business_policy,
        }),
        sandbox: json!({"assurance":subject.execution_assurance}),
        extension_control_digest: controls
            .map(|value| value.effective_digest.clone())
            .unwrap_or_else(|| {
                guard_policy_snapshot::digest_bytes(b"hol.guard.bash.no-command-controls.v1")
            }),
    })
}

/// Internal owning entry point. Host adapters must still authenticate their
/// final execution context before invoking it; no RPC capability is advertised.
#[cfg(test)]
pub(crate) fn execute_saved(
    request: &NativeBashCaptureV1,
    envelope: &GuardHookEnvelopeV2,
    store: &PolicySnapshotStore,
    claim: &ClaimApprovalReuseDecisionsRequestV1,
    operation_id: &str,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<LaunchOutput, LaunchFailure> {
    execute_authorized(
        request,
        envelope,
        store,
        &NativeBashAuthorizationV1::SavedGrant {
            claim: Box::new(claim.clone()),
        },
        (operation_id, None),
        deadline,
        cancel,
    )
}

pub(crate) fn execute_authorized(
    request: &NativeBashCaptureV1,
    envelope: &GuardHookEnvelopeV2,
    store: &PolicySnapshotStore,
    authorization: &NativeBashAuthorizationV1,
    operation: (&str, Option<&str>),
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<LaunchOutput, LaunchFailure> {
    let refuse = |_| io::Error::from(io::ErrorKind::PermissionDenied);
    store
        .require_guard_home(&request.guard_home)
        .map_err(refuse)?;
    let claim = match authorization {
        NativeBashAuthorizationV1::SavedGrant { claim } => {
            store
                .require_guard_home(&claim.guard_home)
                .map_err(refuse)?;
            Some(claim.as_ref())
        }
        NativeBashAuthorizationV1::CurrentPolicy { .. } => None,
    };
    store
        .require_store_path(authorization.store_path())
        .map_err(refuse)?;
    if !context_matches(request, envelope) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let fence = store.fence_for_launch(envelope).map_err(refuse)?;
    let captured = super::bash_capture::capture_for_launch(request, fence.snapshot())
        .map_err(|_| io::ErrorKind::PermissionDenied)?;
    let expected = binding(&captured.subject, fence.snapshot())
        .map_err(|_| io::ErrorKind::PermissionDenied)?;
    let allocator =
        BashOperationJournal::open(store, authorization.store_path(), operation.0, &expected)
            .map_err(refuse)?;
    let (operation_id, invocation) = allocator
        .allocate_invocation(&request.harness, &request.workspace, operation.1)
        .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?;
    let _activity_alias = store
        .bash_launches()
        .alias(operation.0, &operation_id)
        .map_err(refuse)?;
    let mut journal =
        BashOperationJournal::open(store, authorization.store_path(), &operation_id, &expected)
            .map_err(refuse)?;
    journal.attach_invocation(invocation);
    if let Some(operation) = journal
        .read()
        .map_err(|_| io::ErrorKind::PermissionDenied)?
    {
        return Ok(LaunchOutput {
            output: None,
            grant_claimed: operation.authorization == NativeBashAuthorizationKindV1::SavedGrant,
            dispatch_acknowledged: operation.dispatch_acknowledged,
            operation,
            replayed: true,
        });
    }
    match journal.review_kept_blocked() {
        Ok(false) => {}
        refusal => {
            let mut failure: LaunchFailure = io::ErrorKind::PermissionDenied.into();
            failure.code = Some(if refusal.is_ok() {
                "native_bash_operation_kept_blocked"
            } else {
                "native_bash_review_lineage_unavailable"
            });
            return Err(failure);
        }
    }
    if let Some(claim) = claim {
        if !matches_grant(claim, &captured.subject, &request.harness, &expected) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    } else if !captured
        .policy
        .as_ref()
        .is_some_and(|policy| policy.allows_without_consent())
    {
        let mut failure: LaunchFailure = io::ErrorKind::PermissionDenied.into();
        failure.code = Some("native_bash_consent_required");
        failure.review_lineage = Some(Box::new(
            journal
                .pending_review(&request.harness, &captured.subject.context.project)
                .map_err(|_| io::ErrorKind::PermissionDenied)?,
        ));
        return Err(failure);
    }
    let claim = claim.cloned().map(|mut claim| {
        claim.consume_local_once = true;
        claim
    });
    let mut gate = Gate {
        fence: Some(fence),
        claim,
        claimed: false,
        dispatched: false,
        journal: &journal,
        harness: request.harness.clone(),
        project: captured.subject.context.project.clone(),
        saved_authority_refused: false,
    };
    match super::bash_launch::execute(captured, deadline, cancel, &mut gate) {
        Ok(output) => {
            let operation = journal.completed(&output).map_err(|_| LaunchFailure {
                error: io::ErrorKind::Other.into(),
                grant_claimed: gate.grant_claimed(),
                dispatch_acknowledged: gate.dispatched,
                operation: None,
                code: Some("native_bash_completion_record_unavailable"),
                review_lineage: None,
            })?;
            Ok(LaunchOutput {
                output: Some(output),
                grant_claimed: gate.grant_claimed(),
                dispatch_acknowledged: gate.dispatched,
                operation,
                replayed: false,
            })
        }
        Err(error) => {
            let mut code = gate
                .saved_authority_refused
                .then_some("native_bash_saved_authority_changed");
            let operation = if gate.claimed {
                match journal.uncertain(gate.dispatched) {
                    Ok(operation) => Some(Box::new(operation)),
                    Err(_) => {
                        eprintln!("native_bash_uncertain_record_unavailable");
                        code = Some("native_bash_uncertain_record_unavailable");
                        None
                    }
                }
            } else {
                None
            };
            Err(LaunchFailure {
                error,
                grant_claimed: gate.grant_claimed(),
                dispatch_acknowledged: gate.dispatched,
                operation,
                code,
                review_lineage: None,
            })
        }
    }
}

pub(super) fn context_matches(
    request: &NativeBashCaptureV1,
    envelope: &GuardHookEnvelopeV2,
) -> bool {
    !(envelope.schema != guard_contracts::GUARD_HOOK_ENVELOPE_V2_SCHEMA
        || envelope.recording_only
        || envelope.event != "PreToolUse"
        || envelope.harness != request.harness
        || envelope.source.home_dir != request.home_dir
        || envelope.source.cwd.as_deref() != Some(request.cwd.as_str())
        || envelope.source.execution_environment.as_ref() != Some(&request.execution_environment)
        || envelope
            .raw_payload
            .get("tool_name")
            .and_then(|value| value.as_str())
            != Some("bash")
        || envelope
            .raw_payload
            .pointer("/tool_input/command")
            .and_then(|value| value.as_str())
            != Some(request.command.as_str()))
}

fn matches_grant(
    claim: &ClaimApprovalReuseDecisionsRequestV1,
    subject: &NativeBashSubjectV1,
    harness: &str,
    expected: &str,
) -> bool {
    let [decision] = claim.decisions.as_slice() else {
        return false;
    };
    let text = |key| decision.get(key).and_then(|value| value.as_str());
    let once = text("approval_id").is_some_and(|value| !value.is_empty());
    let persistent = decision
        .get("decision_id")
        .and_then(|value| value.as_i64())
        .is_some();
    let project_matches = crate::policy_decision_lookup_op::workspace_policy_key(text("workspace"))
        == crate::policy_decision_lookup_op::computed_workspace_policy_key(Some(
            subject.context.project.as_str(),
        ));
    // Existing artifact-scope rows have workspace=null. Their expected native
    // context token still binds the exact captured project/host/cwd/home; a
    // global or different project's token cannot match it. Artifact-scope
    // inbox resolutions also use null for once rows; the same expected token
    // binds their project and the authenticated claim still spends them once.
    let workspace_matches =
        project_matches || decision.get("workspace") == Some(&serde_json::Value::Null);
    once != persistent
        && text("action") == Some("allow")
        && text("harness") == Some(harness)
        && text("artifact_id") == Some(ARTIFACT)
        && text("artifact_hash") == Some(expected)
        && workspace_matches
        && (once || text("scope") == Some("artifact") && text("source") == Some("approval-gate"))
}

struct Gate<'store, 'journal> {
    fence: Option<LaunchPolicyFence<'store>>,
    claim: Option<ClaimApprovalReuseDecisionsRequestV1>,
    claimed: bool,
    dispatched: bool,
    journal: &'journal BashOperationJournal<'journal>,
    harness: String,
    project: String,
    saved_authority_refused: bool,
}

impl Gate<'_, '_> {
    fn grant_claimed(&self) -> bool {
        self.claimed && self.claim.is_some()
    }
    fn authorize(&mut self) -> io::Result<()> {
        self.fence
            .as_ref()
            .ok_or(io::ErrorKind::PermissionDenied)?
            .require_current()
            .map_err(|_| io::ErrorKind::PermissionDenied)?;
        if !self.claimed {
            let reserved = if let Some(claim) = &self.claim {
                self.journal
                    .reserve(claim)
                    .map_err(|_| io::ErrorKind::PermissionDenied)?
            } else {
                match self.journal.reserve_allowed(&self.harness, &self.project) {
                    Ok(reserved) => reserved,
                    Err(_) => {
                        self.saved_authority_refused = true;
                        return Err(io::ErrorKind::PermissionDenied.into());
                    }
                }
            };
            if !reserved {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            self.claimed = true;
        }
        self.fence
            .as_ref()
            .ok_or(io::ErrorKind::PermissionDenied)?
            .require_current()
            .map_err(|_| io::ErrorKind::PermissionDenied.into())
    }
}

impl SourceLaunchGate for Gate<'_, '_> {
    fn prepare_effects(&mut self) -> io::Result<()> {
        self.authorize()
    }
    fn commit(&mut self) -> io::Result<()> {
        self.authorize()
    }
    fn released(&mut self) -> io::Result<()> {
        if !self.claimed || self.fence.is_none() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.dispatched = true;
        // S was observed even if the durable update fails; never erase that
        // fact or release a retry. The claimed row already blocks execution.
        self.journal
            .dispatched()
            .map_err(|_| io::ErrorKind::Other)?;
        self.fence.take();
        Ok(())
    }
}
