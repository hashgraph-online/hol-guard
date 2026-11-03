//! The scope op replayed against the cases
//! `approval_scope_support.package_request_{portable,runtime}_workspace_scope`
//! used to answer: a portable context, a non-portable one, the artifacts that
//! are not package requests, the hashes that carry no identity, and the
//! evidence shapes the op must read as "no context" rather than as a refusal.

use guard_command::package_execution_context::{
    digest_json, PackageExecutionContext, PackageExecutionContextComponent,
    PACKAGE_EXECUTION_CONTEXT_VERSION,
};
use guard_contracts::{
    PACKAGE_WORKSPACE_SCOPE_REQUEST_SCHEMA, PACKAGE_WORKSPACE_SCOPE_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use super::*;

const ARTIFACT_ID: &str = "codex:package-request:npm:left-pad";
const ARTIFACT_HASH: &str = "11111111111111111111111111111111111111111111111111111111111111ab";

fn context(portable: bool) -> PackageExecutionContext {
    let components = vec![PackageExecutionContextComponent {
        name: "workspace_identity".to_owned(),
        digest: "22222222222222222222222222222222222222222222222222222222222222cd".to_owned(),
    }];
    let digest = digest_json(&json!({
        "components": components
            .iter()
            .map(|item| json!({"name": item.name, "digest": item.digest}))
            .collect::<Vec<_>>(),
        "portable": portable,
        "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
    }));
    PackageExecutionContext {
        digest,
        portable,
        components,
        non_portable_reason: if portable {
            None
        } else {
            Some("workspace_configuration".to_owned())
        },
    }
}

fn request(
    artifact_id: Option<&str>,
    artifact_hash: Option<&str>,
    artifact_type: Option<&str>,
    execution_context: Option<Value>,
) -> PackageWorkspaceScopeRequestV1 {
    PackageWorkspaceScopeRequestV1 {
        schema: PACKAGE_WORKSPACE_SCOPE_REQUEST_SCHEMA.to_owned(),
        request_id: "scope-1".to_owned(),
        artifact_id: artifact_id.map(str::to_owned),
        artifact_hash: artifact_hash.map(str::to_owned),
        artifact_type: artifact_type.map(str::to_owned),
        execution_context,
    }
}

fn scopes(request: &PackageWorkspaceScopeRequestV1) -> Value {
    let reply: Value =
        serde_json::from_slice(&evaluate_package_workspace_scope_request(request).unwrap())
            .unwrap();
    assert_eq!(reply["schema"], PACKAGE_WORKSPACE_SCOPE_RESULT_SCHEMA);
    assert_eq!(reply["request_id"], "scope-1");
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["code"], "ok");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    reply["payload"].clone()
}

#[test]
fn a_portable_context_scopes_the_approval_portably() {
    let payload = scopes(&request(
        Some(ARTIFACT_ID),
        Some(ARTIFACT_HASH),
        Some("package_request"),
        Some(context(true).to_evidence()),
    ));
    let portable = payload["portable"].as_str().unwrap();
    assert!(
        portable.starts_with("package-request-workspace:v2:"),
        "{portable}"
    );
    assert_eq!(payload["runtime"].as_str().unwrap(), portable);
}

#[test]
fn a_non_portable_context_scopes_the_approval_to_that_context() {
    let payload = scopes(&request(
        Some(ARTIFACT_ID),
        Some(ARTIFACT_HASH),
        Some("package_request"),
        Some(context(false).to_evidence()),
    ));
    assert_eq!(payload["portable"], Value::Null);
    let runtime = payload["runtime"].as_str().unwrap();
    assert!(
        runtime.starts_with("package-request-workspace-exact:v2:"),
        "{runtime}"
    );
}

#[test]
fn an_artifact_that_is_not_a_package_request_has_no_scope() {
    let payload = scopes(&request(
        Some("codex:command:npm-install"),
        Some(ARTIFACT_HASH),
        Some("command_request"),
        Some(context(true).to_evidence()),
    ));
    assert_eq!(payload["portable"], Value::Null);
    assert_eq!(payload["runtime"], Value::Null);
}

#[test]
fn an_artifact_hash_that_carries_no_identity_has_no_scope() {
    for hash in [Some("unknown"), Some("   "), None] {
        let payload = scopes(&request(
            Some(ARTIFACT_ID),
            hash,
            Some("package_request"),
            Some(context(true).to_evidence()),
        ));
        assert_eq!(payload["portable"], Value::Null, "{hash:?}");
        assert_eq!(payload["runtime"], Value::Null, "{hash:?}");
    }
}

#[test]
fn evidence_the_runtime_cannot_read_scopes_nothing_rather_than_refusing() {
    let mut stale = context(true).to_evidence();
    stale["schema_version"] = json!(1);
    for evidence in [None, Some(json!({})), Some(stale)] {
        let payload = scopes(&request(
            Some(ARTIFACT_ID),
            Some(ARTIFACT_HASH),
            Some("package_request"),
            evidence.clone(),
        ));
        assert_eq!(payload["portable"], Value::Null, "{evidence:?}");
        assert_eq!(payload["runtime"], Value::Null, "{evidence:?}");
    }
}

#[test]
fn the_result_is_bound_to_the_request_it_answers() {
    let first: Value = serde_json::from_slice(
        &evaluate_package_workspace_scope_request(&request(
            Some(ARTIFACT_ID),
            Some(ARTIFACT_HASH),
            Some("package_request"),
            Some(context(true).to_evidence()),
        ))
        .unwrap(),
    )
    .unwrap();
    let second: Value = serde_json::from_slice(
        &evaluate_package_workspace_scope_request(&request(
            Some(ARTIFACT_ID),
            Some(ARTIFACT_HASH),
            Some("package_request"),
            Some(context(false).to_evidence()),
        ))
        .unwrap(),
    )
    .unwrap();
    assert_ne!(first["request_sha256"], second["request_sha256"]);
}

#[test]
fn a_saved_approval_s_key_is_the_one_it_was_stored_under() {
    // The scope string is a key the store already holds. These two values are
    // what `json.dumps(material, sort_keys=True, separators=(",", ":"))` under
    // plain SHA-256 produced before the derivation moved into the runtime, so
    // an "Always allow" granted then still matches now.
    let context = PackageExecutionContext {
        digest: "b".repeat(64),
        portable: true,
        components: Vec::new(),
        non_portable_reason: None,
    };
    let artifact_id = "guard-cli:project:package-request:fixture";
    let artifact_hash = "a".repeat(64);

    assert_eq!(
        guard_command::local_supply_chain::package_request_portable_workspace_scope(
            Some(artifact_id),
            Some(&artifact_hash),
            Some("package_request"),
            Some(&context),
        ),
        Some(
            "package-request-workspace:v2:\
             3788a9ec1ac4fec542cbd04b3507241f093bca5933cae58d0183bf43e40a7e5b"
                .to_owned()
        )
    );

    let non_portable = PackageExecutionContext {
        portable: false,
        non_portable_reason: Some("workspace_configuration".to_owned()),
        ..context
    };
    assert_eq!(
        guard_command::local_supply_chain::package_request_runtime_workspace_scope(
            Some(artifact_id),
            Some(&artifact_hash),
            Some("package_request"),
            &non_portable,
        ),
        Some(
            "package-request-workspace-exact:v2:\
             af0831550d718fd14904ab837c144672a2a6b8f5bfa3a996b80167f47022378c"
                .to_owned()
        )
    );
}

#[test]
fn a_request_under_another_schema_is_refused_rather_than_answered() {
    let mut other = request(
        Some(ARTIFACT_ID),
        Some(ARTIFACT_HASH),
        Some("package_request"),
        Some(context(true).to_evidence()),
    );
    other.schema = "guard-package-authority-request.v1".to_owned();

    assert_eq!(
        evaluate_package_workspace_scope_request(&other).unwrap_err(),
        "native_package_workspace_scope_schema_mismatch"
    );
}

#[test]
fn a_request_with_no_id_is_refused_rather_than_answered_with_an_empty_one() {
    let mut anonymous = request(
        Some(ARTIFACT_ID),
        Some(ARTIFACT_HASH),
        Some("package_request"),
        Some(context(true).to_evidence()),
    );
    anonymous.request_id = String::new();

    assert_eq!(
        evaluate_package_workspace_scope_request(&anonymous).unwrap_err(),
        "native_package_workspace_scope_invalid"
    );
}
