//! Share one bounded verifier while retaining separate authenticated proofs
//! for first selection and a disabled selection with a previous SDK/data pair.
use super::*;
use guard_cigar_release::SelectionPointer;

pub(super) enum RecoveryTarget {
    Initial {
        target: Box<switching::InitialTarget>,
        proof: Box<switching::EmptyDataProof>,
    },
    Selected(Box<switching::DisabledTarget>),
}
impl RecoveryTarget {
    pub(super) fn admit(
        owner: &mut switching::Owner,
        job: &SwitchJob,
        generation: u64,
    ) -> Result<(Self, SwitchJob), String> {
        if job.is_initial() {
            let (target, proof, job) = owner.begin_initial_recovery(job, generation)?;
            Ok((
                Self::Initial {
                    target: Box::new(target),
                    proof: Box::new(proof),
                },
                job,
            ))
        } else {
            let (target, job) = owner.begin_disabled_recovery(job, generation)?;
            Ok((Self::Selected(Box::new(target)), job))
        }
    }
    pub(super) fn settings(&self) -> &crate::guard_config_load::AssistanceSettings {
        match self {
            Self::Initial { target, .. } => target.settings(),
            Self::Selected(target) => target.settings(),
        }
    }
    pub(super) fn pointer(&self) -> &SelectionPointer {
        match self {
            Self::Initial { target, .. } => target.pointer(),
            Self::Selected(target) => target.pointer(),
        }
    }
    pub(super) fn rules(&self) -> &guard_cigar_release::UpdatePreferences {
        match self {
            Self::Initial { target, .. } => target.rules(),
            Self::Selected(target) => target.rules(),
        }
    }
    pub(super) fn check(&self) -> Result<(), String> {
        match self {
            Self::Initial { target, .. } => target.check(),
            Self::Selected(target) => target.check(),
        }
    }
    pub(super) fn recover(
        &self,
        owner: &mut switching::Owner,
        job: &SwitchJob,
        measured: &SelectionPointer,
    ) -> Result<(), String> {
        match self {
            Self::Initial { target, proof } => {
                owner.recover_initial_target(&job.request.job_id, target, proof, measured)
            }
            Self::Selected(target) => owner.recover_disabled_target(job, target, measured),
        }
    }
    pub(super) fn healthy(&self, owner: &mut switching::Owner, id: &str) -> Result<(), String> {
        match self {
            Self::Initial { .. } => owner.mark_initial_healthy(id),
            Self::Selected(_) => owner.mark_healthy(id),
        }
    }
    pub(super) fn complete(&self, owner: &mut switching::Owner, id: &str) -> Result<(), String> {
        match self {
            Self::Initial { .. } => owner.complete_initial(id),
            Self::Selected(_) => owner.complete_publication(id),
        }
    }
    pub(super) fn reconcile_job(
        &self,
        owner: &switching::Owner,
        job: &SwitchJob,
    ) -> Result<(), String> {
        match self {
            Self::Initial { .. } => owner.reconcile_initial_job(job),
            Self::Selected(_) => owner.reconcile_job(job),
        }
    }
    pub(super) fn commit_code(&self) -> &'static str {
        match self {
            Self::Initial { .. } => "reconciling_initial_target",
            Self::Selected(_) => "reconciling_disabled_target",
        }
    }
    pub(super) fn failure_code(&self) -> &'static str {
        match self {
            Self::Initial { .. } => "initial_verification_recovery_required",
            Self::Selected(_) => "disabled_verification_recovery_required",
        }
    }
    pub(super) fn conflict_code(&self) -> &'static str {
        match self {
            Self::Initial { .. } => "initial_selection_conflict",
            Self::Selected(_) => "switch_selection_conflict",
        }
    }
}
