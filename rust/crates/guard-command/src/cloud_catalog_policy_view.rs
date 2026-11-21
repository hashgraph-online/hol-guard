//! Session/discovery binding for policy consumers of a completed local view.
//! Inputs come from authenticated local adapters, never a policy response.
use super::*;

type PolicyResult = std::result::Result<Value, (&'static str, &'static str)>;

fn assemble(request: &Value) -> PolicyResult {
    let summary = &request["runtime_summary"];
    let identity = &summary["policyMetadataIdentity"];
    let fields = ["ownerUserId", "workspaceId", "deviceId", "runtimeId"];
    if identity
        .as_object()
        .is_none_or(|o| o.len() != fields.len() || fields.iter().any(|key| !o.contains_key(*key)))
    {
        return Err((
            "policy_observation_identity_missing",
            "Authenticated policy observation identity is unavailable.",
        ));
    }
    if identity["runtimeId"] != summary["runtime_credential_id"]
        || identity["deviceId"] != summary["runtime_device_id"]
    {
        return Err((
            "policy_observation_identity_mismatch",
            "Policy observation session identity changed.",
        ));
    }
    // Present only for callers that bind the view to a signed policy envelope.
    if let Some(workspace) = request
        .as_object()
        .and_then(|o| o.get("policy_workspace_id"))
    {
        if identity["workspaceId"] != *workspace {
            return Err((
                "policy_observation_identity_mismatch",
                "Policy workspace identity changed.",
            ));
        }
    }
    let observed_at = &summary["policyMetadataObservedAt"];
    if observed_at.as_str().is_none_or(str::is_empty) {
        return Err((
            "policy_completed_observation_missing",
            "Authenticated completed observation time is unavailable.",
        ));
    }
    let view = &request["view"];
    let discovery = &request["discovery"];
    if view["discovery_root"] != discovery["root"]
        || view["discovery_authority"] != discovery["authority"]
    {
        return Err((
            "policy_local_view_invalid",
            "Policy discovery observation changed.",
        ));
    }
    let manifest = &view["manifest"];
    if manifest["enforcementCatalogDigest"] != request["enforcement_catalog_digest"] {
        return Err((
            "policy_enforcement_digest_mismatch",
            "Policy enforcement state changed.",
        ));
    }
    Ok(json!({
        "guard_home":request["guard_home"], "token":view["token"],
        "view_digest":manifest["catalogDigest"], "identity":identity,
        "observed_at":observed_at, "now":request["now"],
        "observation":{
            "guard_home":request["guard_home"], "discovery_root":discovery["root"],
            "discovery_authority":discovery["authority"],
            "enforcement_catalog_digest":request["enforcement_catalog_digest"],
            "guard_version":manifest["guardVersion"], "generated_at":manifest["generatedAt"]
        }
    }))
}

pub(super) fn evaluate(request: &Value) -> Value {
    let result = assemble(request).and_then(|local| {
        let home = local["guard_home"].as_str().ok_or((
            "policy_local_view_invalid",
            "Authenticated local catalog view is unavailable.",
        ))?;
        completion::validate(Path::new(home), &local).map_err(|_| {
            (
                "policy_local_view_invalid",
                "Authenticated completed catalog view is unavailable.",
            )
        })?;
        Ok(local)
    });
    match result {
        Ok(payload) => json!({"schema":"guard-cloud-catalog-result.v2","payload":payload}),
        Err((code, message)) => json!({"schema":"guard-cloud-catalog-result.v2",
            "payload":{"policy_error":code,"message":message}}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Value {
        json!({"guard_home":"/unused-policy-view", "now":"2026-10-19T00:00:00Z",
            "runtime_summary":{
                "policyMetadataIdentity":{"ownerUserId":"owner","workspaceId":"workspace",
                    "deviceId":"device","runtimeId":"runtime"},
                "runtime_credential_id":"runtime","runtime_device_id":"device",
                "policyMetadataObservedAt":"2026-10-19T00:00:00Z"},
            "view":{"token":"a".repeat(64), "discovery_root":"b".repeat(64),
                "discovery_authority":"c".repeat(64), "manifest":{
                    "catalogDigest":"d".repeat(64),"enforcementCatalogDigest":"e".repeat(64),
                    "guardVersion":"3.49.0","generatedAt":"2026-10-19T00:00:00Z"}},
            "discovery":{"root":"b".repeat(64),"authority":"c".repeat(64)},
            "enforcement_catalog_digest":"e".repeat(64)})
    }

    #[test]
    fn local_view_binds_session_discovery_and_enforcement() {
        let input = request();
        let local = assemble(&input).unwrap();
        assert_eq!(
            local["identity"],
            input["runtime_summary"]["policyMetadataIdentity"]
        );
        assert_eq!(
            local["observation"]["discovery_root"],
            input["discovery"]["root"]
        );
        assert_eq!(
            local["observation"]["enforcement_catalog_digest"],
            input["enforcement_catalog_digest"]
        );
        assert_eq!(
            local["view_digest"],
            input["view"]["manifest"]["catalogDigest"]
        );
        assert_eq!(local["token"], input["view"]["token"]);
        assert_eq!(
            local["observed_at"],
            input["runtime_summary"]["policyMetadataObservedAt"]
        );
    }

    #[test]
    fn bound_policy_workspace_must_match_the_observed_identity() {
        let mut input = request();
        input["policy_workspace_id"] = json!("workspace");
        assert!(assemble(&input).is_ok());
        for value in [json!("other"), Value::Null] {
            input["policy_workspace_id"] = value;
            assert_eq!(
                assemble(&input).unwrap_err().0,
                "policy_observation_identity_mismatch"
            );
        }
    }

    #[test]
    fn changed_local_bindings_fail_with_stable_policy_errors() {
        for (path, value, code) in [
            (
                "/runtime_summary/policyMetadataIdentity",
                json!({}),
                "policy_observation_identity_missing",
            ),
            (
                "/runtime_summary/runtime_credential_id",
                json!("other"),
                "policy_observation_identity_mismatch",
            ),
            (
                "/runtime_summary/runtime_device_id",
                json!("other"),
                "policy_observation_identity_mismatch",
            ),
            (
                "/runtime_summary/policyMetadataObservedAt",
                json!(""),
                "policy_completed_observation_missing",
            ),
            (
                "/discovery/root",
                json!("f".repeat(64)),
                "policy_local_view_invalid",
            ),
            (
                "/discovery/authority",
                json!("f".repeat(64)),
                "policy_local_view_invalid",
            ),
            (
                "/enforcement_catalog_digest",
                json!("f".repeat(64)),
                "policy_enforcement_digest_mismatch",
            ),
        ] {
            let mut input = request();
            *input.pointer_mut(path).unwrap() = value;
            assert_eq!(evaluate(&input)["payload"]["policy_error"], code, "{path}");
        }
    }

    #[test]
    fn session_summary_cannot_replace_native_completion() {
        let home = tempfile::tempdir().unwrap();
        let mut input = request();
        input["guard_home"] = json!(home.path());
        assert_eq!(
            evaluate(&input)["payload"]["policy_error"],
            "policy_local_view_invalid"
        );
    }
}
