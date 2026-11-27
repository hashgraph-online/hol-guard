//! Guard home and store path bindings for resident operations.

use crate::resident_protocol::ResidentOperationV1;

/// The Guard home an operation acts on, for operations that open per-home state.
pub(super) fn operation_guard_home(operation: &ResidentOperationV1) -> Option<&str> {
    match operation {
        ResidentOperationV1::ContextAssistance(request) => Some(&request.query.guard_home),
        ResidentOperationV1::Swarm(request) => Some(&request.query.guard_home),
        ResidentOperationV1::ContextAgent(request) => Some(&request.query.guard_home),
        ResidentOperationV1::CloudCatalog(request) => {
            if request["action"] == "begin" || request["action"] == "reuse" {
                request["observation"]["guard_home"].as_str()
            } else {
                request["guard_home"].as_str()
            }
        }
        ResidentOperationV1::CatalogReadV2(request) => request.guard_home.to_str(),
        ResidentOperationV1::CatalogPrepareV1(request) => request.guard_home.to_str(),
        ResidentOperationV1::CatalogReadPreparedV1(request) => request.guard_home.to_str(),
        ResidentOperationV1::WindowsPrivateState(request) => Some(&request.guard_home),
        // Pinned even when the field is missing or not text: a request the
        // resident cannot bind to its own home is refused, never loaded.
        ResidentOperationV1::GuardConfigLoad(request) => {
            Some(request["guard_home"].as_str().unwrap_or(""))
        }
        ResidentOperationV1::NativeBashPrepare(request) => Some(&request.capture.guard_home),
        ResidentOperationV1::NativeBashExecute(request) => Some(&request.capture.guard_home),
        ResidentOperationV1::NativeBashCancel(request) => Some(&request.guard_home),
        ResidentOperationV1::NativeBashActivity(request) => Some(&request.guard_home),
        ResidentOperationV1::NativeBashAck(request) => Some(&request.guard_home),
        ResidentOperationV1::NativeBashReviewCheck(request) => Some(&request.guard_home),
        ResidentOperationV1::ArchiveAcquisition(request) => Some(&request.guard_home),
        ResidentOperationV1::DirectoryTrust(request) => Some(&request.guard_home),
        ResidentOperationV1::HookDirect(request) => Some(&request.guard_home),
        ResidentOperationV1::HookDirectEvidenceDrain(request) => Some(&request.guard_home),
        ResidentOperationV1::HookDirectEvidenceCommit(request) => Some(&request.guard_home),
        ResidentOperationV1::McpRelayDecide(request) => Some(&request.guard_home),
        ResidentOperationV1::McpRelayCommit(request) => Some(&request.guard_home),
        ResidentOperationV1::McpRelayReady(request) => Some(&request.guard_home),
        ResidentOperationV1::McpRelayClaim(request) => Some(&request.guard_home),
        ResidentOperationV1::McpRelayServerReport(request) => Some(&request.guard_home),
        ResidentOperationV1::ApprovalReuseDiagnostic(request) => Some(&request.guard_home),
        ResidentOperationV1::ClaimApprovalReuseDecisions(request) => Some(&request.guard_home),
        ResidentOperationV1::GuardStore(request) => Some(&request.guard_home),
        ResidentOperationV1::HookEvidenceWriter(request) => Some(&request.guard_home),
        ResidentOperationV1::ApprovalGate(request) => Some(&request.guard_home),
        ResidentOperationV1::SupplyChainEval(request) => Some(&request.guard_home),
        ResidentOperationV1::ApplyStoredPackagePolicy(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageAuthorityDecide(request) => Some(&request.guard_home),
        ResidentOperationV1::CursorObserverProof(request) => Some(&request.guard_home),
        ResidentOperationV1::HookAuthorityState(request) => Some(&request.guard_home),
        ResidentOperationV1::ExtensionControlAuthority(request) => Some(&request.guard_home),
        ResidentOperationV1::CommandPackRecord(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageAdvisoryIds(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageEvaluationCompose(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageReviewPlan(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageApprovalHash(request) => Some(&request.guard_home),
        ResidentOperationV1::PackagePolicyResolve(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageProtectFinalize(request) => Some(&request.guard_home),
        ResidentOperationV1::PackagePosture(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageAuditProjection(request) => Some(&request.guard_home),
        ResidentOperationV1::WorkspaceInventory(request) => Some(&request.guard_home),
        ResidentOperationV1::PolicyDecisionLookup(request) => Some(&request.guard_home),
        ResidentOperationV1::ContainedNodeExecute(request) => Some(&request.guard_home),
        ResidentOperationV1::ContainedTypescriptExecute(request) => Some(&request.guard_home),
        ResidentOperationV1::ContainedPackageScriptExecute(request) => Some(&request.guard_home),
        ResidentOperationV1::ContainedWorkspaceWriteExecute(request) => Some(&request.guard_home),
        ResidentOperationV1::ContainedExecute(request) => Some(&request.guard_home),
        ResidentOperationV1::ContainmentHealthProbe(request) => Some(&request.guard_home),
        ResidentOperationV1::ShimAdmin(request) => Some(&request.guard_home),
        ResidentOperationV1::PackageContextBuild(request) => Some(&request.guard_home),
        ResidentOperationV1::McpStdioProbe(request) => Some(&request.guard_home),
        ResidentOperationV1::PromptAnalyze(request) => Some(&request.guard_home),
        ResidentOperationV1::McpRuntimeEvidence(request) => Some(&request.guard_home),
        ResidentOperationV1::RuntimeDetectorRun(request) => Some(&request.guard_home),
        ResidentOperationV1::RunnerAuthority(request) => Some(&request.guard_home),
        ResidentOperationV1::LocalCliGrantDecide(request) => Some(&request.guard_home),
        ResidentOperationV1::LocalCliHook(request) => Some(&request.guard_home),
        ResidentOperationV1::HookLocalCliRule(request) => Some(&request.guard_home),
        ResidentOperationV1::ConnectorSetupContext(request) => Some(&request.guard_home),
        ResidentOperationV1::McpToolEvidence(request) => Some(&request.guard_home),
        ResidentOperationV1::LocalMcpGrantDecide(request) => Some(&request.guard_home),
        ResidentOperationV1::ContributedMcpDecide(request) => Some(&request.guard_home),
        ResidentOperationV1::RichCommandModel(request) => Some(&request.guard_home),
        ResidentOperationV1::RequestContextBuild(request) => Some(&request.guard_home),
        ResidentOperationV1::SkillDirectoryIdentity(request) => Some(&request.guard_home),
        #[cfg(unix)]
        ResidentOperationV1::CodexBindingCapture(request) => Some(&request.guard_home),
        ResidentOperationV1::ProtectRequest(request) => Some(&request.guard_home),
        ResidentOperationV1::CodexRequestResume(request) => Some(&request.guard_home),
        // Only the review responses read a file (the daemon token that signs
        // their review link), so only they name the home they read.
        ResidentOperationV1::HookDecide(request) => match &request.query {
            guard_contracts::HookDecisionQueryV1::SilentReviewBlock { inputs } => {
                Some(&inputs.guard_home)
            }
            guard_contracts::HookDecisionQueryV1::PausedReview { inputs } => {
                Some(&inputs.guard_home)
            }
            _ => None,
        },
        ResidentOperationV1::PolicyIntegrityRows(request) => request
            .generation
            .as_ref()
            .map(|generation| generation.guard_home.as_str()),
        _ => None,
    }
}

/// The store an operation opens, for operations that carry an explicit path.
pub(super) fn operation_store_path(operation: &ResidentOperationV1) -> Option<&str> {
    match operation {
        ResidentOperationV1::NativeBashExecute(request) => Some(request.authorization.store_path()),
        ResidentOperationV1::NativeBashReviewCheck(request) => Some(&request.store_path),
        ResidentOperationV1::NativeBashAck(request) => Some(&request.store_path),
        ResidentOperationV1::ApprovalReuseDiagnostic(request) => Some(&request.store_path),
        ResidentOperationV1::ClaimApprovalReuseDecisions(request) => Some(&request.store_path),
        ResidentOperationV1::GuardStore(request) => Some(&request.store_path),
        ResidentOperationV1::SupplyChainEval(request) => Some(&request.store_path),
        ResidentOperationV1::ApplyStoredPackagePolicy(request) => Some(&request.store_path),
        ResidentOperationV1::PackageAuthorityDecide(request) => Some(&request.store_path),
        ResidentOperationV1::PackageAdvisoryIds(request) => Some(&request.store_path),
        ResidentOperationV1::PackageApprovalHash(request) => request.store_path.as_deref(),
        ResidentOperationV1::PackageAuditProjection(request) => match &request.query {
            guard_contracts::PackageAuditQueryV1::Receipt(query) => query.store_path.as_deref(),
            guard_contracts::PackageAuditQueryV1::Aliases(query) => Some(&query.store_path),
            guard_contracts::PackageAuditQueryV1::CloudPayload(query) => Some(&query.store_path),
            _ => None,
        },
        ResidentOperationV1::PolicyDecisionLookup(request) => Some(&request.store_path),
        ResidentOperationV1::LocalCliGrantDecide(request) => Some(&request.store_path),
        ResidentOperationV1::LocalCliHook(request) => Some(&request.store_path),
        ResidentOperationV1::HookLocalCliRule(request) => Some(&request.store_path),
        ResidentOperationV1::ConnectorSetupContext(request) => Some(&request.store_path),
        ResidentOperationV1::LocalMcpGrantDecide(request) => Some(&request.store_path),
        ResidentOperationV1::ContributedMcpDecide(request) => Some(&request.store_path),
        ResidentOperationV1::HookAuthorityState(request) => Some(&request.store_path),
        ResidentOperationV1::ExtensionControlAuthority(request) => Some(&request.store_path),
        ResidentOperationV1::CommandPackRecord(request) => Some(&request.store_path),
        ResidentOperationV1::ProtectRequest(request) => request.store_path.as_deref(),
        ResidentOperationV1::CodexRequestResume(request) => Some(&request.store_path),
        ResidentOperationV1::PolicyIntegrityRows(request) => request
            .generation
            .as_ref()
            .map(|generation| generation.store_path.as_str()),
        _ => None,
    }
}
