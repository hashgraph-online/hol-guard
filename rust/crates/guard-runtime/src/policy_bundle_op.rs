//! Resident transport adapter for the policy-bundle authority.

use guard_contracts::PolicyBundleAuthorityRequestV1;

pub(crate) fn evaluate_policy_bundle_authority_request(
    request: &PolicyBundleAuthorityRequestV1,
) -> Result<Vec<u8>, String> {
    crate::encode_response(&guard_policy_bundle::evaluate(request))
}
