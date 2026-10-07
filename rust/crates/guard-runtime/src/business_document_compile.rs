//! Offline document compilation through the runtime's strict JSON boundary.
//! This operation never reads or writes policy state and supplies no authority.

use guard_policy_snapshot::business_policy_document::{
    compile_business_document, BusinessDocumentError, MAX_BUSINESS_POLICY_DOCUMENT_BYTES,
};
use serde_json::{json, Value};

pub(crate) fn compile_bytes(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > MAX_BUSINESS_POLICY_DOCUMENT_BYTES {
        return Err("native_business_document_bounds".into());
    }
    let source = crate::strict_json::parse(bytes)?;
    let compiled = compile_business_document(&source).map_err(|error| {
        match error {
            BusinessDocumentError::Bounds => "native_business_document_bounds",
            BusinessDocumentError::InvalidDocument => "native_business_document_invalid",
            BusinessDocumentError::DuplicateRule => "native_business_document_duplicate_rule",
            BusinessDocumentError::UnsupportedDefaults => {
                "native_business_document_unsupported_defaults"
            }
            BusinessDocumentError::UnsupportedRule => "native_business_document_unsupported_rule",
            BusinessDocumentError::UnsupportedLifetime => {
                "native_business_document_unsupported_lifetime"
            }
            BusinessDocumentError::UnsupportedExtension => {
                "native_business_document_unsupported_extension"
            }
        }
        .to_owned()
    })?;
    Ok(json!({
        "schema": "guard.business-policy-document-compile.v1",
        "source_digest": compiled.source_digest(),
        "source_id": source["metadata"]["id"],
        "source_revision": source["metadata"]["revision"],
        "business_policy": compiled.binding(),
        "authority": "unverified_source",
        "installed": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> Value {
        json!({
            "apiVersion": "guard.hashgraphonline.com/v1alpha1", "kind": "GuardPolicy",
            "metadata": {"id": "policy.test", "name": "Test", "revision": 9},
            "spec": {"defaults": {"mode": "enforce", "defaultAction": "block"},
            "rules": [{"id": "rule.test", "enabled": true, "effect": "review",
                "match": {"business": {"schema": "guard.business-policy-match.v1",
                    "version": 1, "services": ["google_gmail"], "operations": ["mail_send"]}},
                "lifetime": {"mode": "permanent"},
                "provenance": {"source": "local", "createdAt": "2026-07-15T00:00:00Z"}}]}
        })
    }

    #[test]
    fn response_binds_complete_source_without_claiming_authority() {
        let source = source();
        let response = compile_bytes(&serde_json::to_vec(&source).unwrap()).unwrap();
        assert_eq!(response["source_revision"], 9);
        assert_eq!(response["installed"], false);
        assert_eq!(response["authority"], "unverified_source");
        assert_eq!(
            response["source_digest"],
            compile_business_document(&source).unwrap().source_digest()
        );
        assert!(response.get("canonical_source").is_none());
    }

    #[test]
    fn until_transport_retains_exact_expiry_without_installing_policy() {
        let mut document = source();
        document["spec"]["rules"][0]["lifetime"] =
            json!({"mode":"until", "expiresAt":"2026-07-16T00:00:00.000000001Z"});
        let response = compile_bytes(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert_eq!(
            response["business_policy"]["rules"][0]["expiresAt"],
            "2026-07-16T00:00:00.000000001Z"
        );
        assert_eq!(response["installed"], false);
        assert_eq!(response["authority"], "unverified_source");
        assert_eq!(
            response["source_digest"],
            compile_business_document(&document)
                .unwrap()
                .source_digest()
        );
    }

    #[test]
    fn duplicate_members_and_trailing_values_are_rejected_before_compilation() {
        for input in [
            br#"{"kind":"GuardPolicy","kind":"GuardPolicy"}"#.as_slice(),
            br#"{"spec":{"rules":[],"rules":[]}}"#,
            br#"{"kind":"GuardPolicy","k\u0069nd":"GuardPolicy"}"#,
            br#"{} {}"#,
        ] {
            assert!(compile_bytes(input).is_err());
        }
    }

    #[test]
    fn oversized_input_and_invalid_utf8_are_rejected() {
        assert_eq!(
            compile_bytes(&vec![b' '; MAX_BUSINESS_POLICY_DOCUMENT_BYTES + 1]).unwrap_err(),
            "native_business_document_bounds"
        );
        assert!(compile_bytes(&[0xff]).is_err());
    }

    #[test]
    fn unrepresented_scope_returns_a_constant_error_without_source_content() {
        let mut source = source();
        source["spec"]["rules"][0]["match"]["actors"] = json!(["private-synthetic-marker"]);
        assert_eq!(
            compile_bytes(&serde_json::to_vec(&source).unwrap()).unwrap_err(),
            "native_business_document_unsupported_rule"
        );
    }
}
