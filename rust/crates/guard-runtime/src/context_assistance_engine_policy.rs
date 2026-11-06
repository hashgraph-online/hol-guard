//! Current native policy and protected source fences, independent of storage.
use super::*;

pub(super) fn effective(
    home: &std::path::Path,
    root: &SourceRoot,
) -> Result<ContextAssistanceConfig, RuntimeError> {
    crate::policy_store::context_assistance_registry::switching::DataRemoval::check_clear(home)?;
    root.revalidate()?;
    let settings = crate::guard_config_load::context_assistance_for_workspace(home, root.path())
        .map_err(|_| RuntimeError::ScopeDenied)?;
    if !settings.requested.enabled
        || !settings.effective.enabled
        || !settings.verification_permitted
        || settings.diagnostic.is_some()
    {
        return Err(RuntimeError::ScopeDenied);
    }
    Ok(settings.effective)
}
pub(super) fn revision(policy: &ContextAssistanceConfig) -> Result<String, RuntimeError> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(policy).map_err(|_| RuntimeError::RequestInvalid)?)
    ))
}
pub(super) fn allowed(
    sources: &BTreeMap<String, AdmittedFile>,
    policy: &ContextAssistanceConfig,
) -> BTreeSet<String> {
    let mut allowed: BTreeSet<_> = sources.keys().cloned().collect();
    if policy.sources.native_policy_facts {
        allowed.insert("guard:policy".into());
    }
    if policy.sources.sanitized_receipt_facts {
        allowed.insert("guard:receipts".into());
    }
    allowed
}
pub(super) fn current_sources(scope: &Scope) -> Result<(), RuntimeError> {
    for source in scope.sources.values() {
        if scope.root.read(&source.relative_path)?.sha256 != source.sha256 {
            return Err(RuntimeError::ContextStale);
        }
    }
    Ok(())
}
pub(super) fn policy_current(
    home: &std::path::Path,
    scope: &mut Scope,
    runtime: &mut VerifiedRuntime,
) -> Result<(), RuntimeError> {
    if scope.revoked {
        return Err(RuntimeError::ScopeDenied);
    }
    if effective(home, &scope.root).is_ok_and(|config| config == scope.policy) {
        return Ok(());
    }
    scope.revoked = true;
    scope.clear_contexts();
    scope.history.clear();
    scope.sources.clear();
    scope.receipts.clear();
    close_graph(runtime, &mut scope.graph)?;
    Err(RuntimeError::ScopeDenied)
}
pub(super) fn policy_document() -> ContextDocument {
    ContextDocument { id:"guard-policy-facts".into(), start_line:1,
        text:"Guard provides Allow once and Always allow for supported executable reviews. Context assistance supplies data and grants no command approval.".into() }
}
