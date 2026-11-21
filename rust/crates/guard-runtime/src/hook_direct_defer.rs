//! Why the resident leaves a hook to the daemon: each reason is reported to
//! the bridge and counted, so the drain shows how often each one happens.

use super::cursor;
use crate::policy_store::policy_store_direct_lane::DirectLaneDefer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookDirectDefer {
    HarnessUnsupported,
    HarnessUnmanaged,
    EventUnsupported,
    PayloadUnsupported,
    TransitionProbe,
    WorkspaceMissing,
    WorkspaceInvalid,
    Lane(DirectLaneDefer),
    Cursor(cursor::CursorDefer),
    BindingIncomplete,
    HomeMismatch,
    LocalCliRules,
    PromptNotice,
    PermissionNotice,
    ExecutionEnvironmentInvalid,
    EvidenceUndrained,
    EvidenceFull,
    ContainedRouteFailed,
    EdgeFailed,
    NotAllow,
    SavedDecision,
    ReviewQueue,
    /// A Git read the edge held for review because it could not settle the
    /// checkout's configuration inside the resident's short budget.
    GitContextReview,
    /// A command the edge held for review because its extension check ran
    /// out of the resident's short budget.
    ExtensionTimedOut,
    RuntimeSuperseded,
    /// An Oh My Pi `PostToolUse` whose managed-policy view the binding does
    /// not carry, or does not carry readably: only the daemon can resolve
    /// what its structured output requires.
    StructuredMediation,
    /// A hook the bridge asked about under the emergency-safe profile that
    /// the profile does not continue, so the bridge pauses it as it would
    /// have without asking.
    EmergencySafeProfile,
}

impl HookDirectDefer {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::HarnessUnsupported => "direct_hook_harness_unsupported",
            Self::HarnessUnmanaged => "direct_hook_harness_unmanaged",
            Self::EventUnsupported => "direct_hook_event_unsupported",
            Self::PayloadUnsupported => "direct_hook_payload_unsupported",
            Self::TransitionProbe => "direct_hook_transition_probe",
            Self::WorkspaceMissing => "direct_hook_workspace_missing",
            Self::WorkspaceInvalid => "direct_hook_workspace_invalid",
            Self::Lane(defer) => defer.code(),
            Self::Cursor(defer) => defer.code(),
            Self::BindingIncomplete => "direct_hook_binding_incomplete",
            Self::HomeMismatch => "direct_hook_home_mismatch",
            Self::LocalCliRules => "direct_hook_local_cli_rules",
            Self::PromptNotice => "direct_hook_prompt_notice",
            Self::PermissionNotice => "direct_hook_permission_notice",
            Self::ExecutionEnvironmentInvalid => "direct_hook_execution_environment_invalid",
            Self::EvidenceUndrained => "direct_hook_evidence_undrained",
            Self::EvidenceFull => "direct_hook_evidence_full",
            Self::ContainedRouteFailed => "direct_hook_contained_route_failed",
            Self::EdgeFailed => "direct_hook_edge_failed",
            Self::NotAllow => "direct_hook_not_allow",
            Self::SavedDecision => "direct_hook_saved_decision",
            Self::ReviewQueue => "direct_hook_review_queue",
            Self::GitContextReview => "direct_hook_git_context_review",
            Self::ExtensionTimedOut => "direct_hook_extension_timed_out",
            Self::RuntimeSuperseded => "direct_hook_runtime_superseded",
            Self::StructuredMediation => "direct_hook_structured_mediation",
            Self::EmergencySafeProfile => "direct_hook_emergency_safe_profile",
        }
    }
}
