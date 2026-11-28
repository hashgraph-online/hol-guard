//! Provider finding rows for the browser card (BP-T134, PRD 6.8).
//!
//! A row is built from one cached `ProviderSignalV1` and the compiled manifest of the provider that
//! answered. The name and every reason label come from the manifest; a reason code the capability
//! does not declare, or one without a declared label, is left off. Nothing the provider sent reaches
//! the card as text.

use guard_contracts::{
    BrowserCardProviderFindingV1, ProviderSignalV1, BROWSER_CARD_MAX_REASON_LABELS,
};

use crate::provider_integration_compile::CompiledProviderIntegrationV1;

/// The card row for `signal`, or `None` when the signal is malformed, comes from another provider
/// or names a capability the manifest does not declare.
pub fn provider_finding_row(
    provider: &CompiledProviderIntegrationV1,
    signal: &ProviderSignalV1,
) -> Option<BrowserCardProviderFindingV1> {
    signal.validate_shape().ok()?;
    if signal.provider_id != provider.id {
        return None;
    }
    let capability = provider
        .capabilities
        .iter()
        .find(|declared| declared.capability == signal.capability)?;
    let mut reason_labels: Vec<String> = Vec::new();
    if let Some(codes) = &capability.reason_codes {
        for code in &signal.reason_codes {
            if reason_labels.len() == BROWSER_CARD_MAX_REASON_LABELS {
                break;
            }
            if !codes.allow.contains(code) {
                continue;
            }
            if let Some(label) = codes.labels.get(code) {
                if !reason_labels.contains(label) {
                    reason_labels.push(label.clone());
                }
            }
        }
    }
    Some(BrowserCardProviderFindingV1 {
        provider_id: provider.id.clone(),
        provider_name: provider.name.clone(),
        capability: signal.capability,
        verdict: signal.verdict,
        state: signal.state,
        reason_labels,
        observed_at_ms: signal.observed_at_ms,
        // The discovery feed carries the paid flag (BP-T140); until then no listing is sponsored.
        sponsored: false,
    })
}

#[cfg(test)]
#[path = "browser_card_provider_tests.rs"]
mod tests;
