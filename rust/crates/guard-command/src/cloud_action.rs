//! Native decision authority for hosted cloud actions.
//!
//! A hosting service asks one question per action: may this exact action be
//! dispatched now, and if not, why. The evaluator is stateless per request.
//! It holds the admitted binding set and the activation verification key from
//! startup, and reads the packaged command program for catalog MCP
//! contributions. Identity, consent claims, budgets and revocation live with
//! the caller, which must treat every error as "do not dispatch".
//!
//! Order: binding → connection → arguments → workspace policy (or the
//! effect floor) → catalog MCP tightening → target capabilities → saved
//! consent. A saved consent answers only a review; it never lowers a block or
//! a sandbox requirement.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::cloud_action_activation::{
    is_utc_timestamp, verify_activation, ActivationContext, SignedActivation, VerifiedActivation,
};
use crate::cloud_action_binding::{
    valid_label, AdapterKind, AdmittedBinding, BindingSet, TargetCapability,
};
use crate::cloud_action_canonical::{canonical_arguments, domain_digest, parse_strict};
use crate::cloud_action_policy::{decide_policy, validate_rules, CloudPolicyRule, PolicySubject};
use crate::contributed_mcp_decision::{
    contributions, decide_active_contribution, matching_contribution, ContributedMcpInput,
};
use crate::effect_decision::GuardAction;
use crate::native_command_program::{packaged_command_program, NativeCommandProgram};

pub const REQUEST_SCHEMA: &str = "guard.cloud-action-evaluation.v1";
pub const RESULT_SCHEMA: &str = "guard.cloud-action-evaluation-result.v1";
pub const MAX_SAVED_CONSENTS: usize = 256;
const IDENTITY_DOMAIN: &str = "guard.cloud-action-identity.v1";
const PROVENANCE_DOMAIN: &str = "guard.cloud-action-evaluation-provenance.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(rename = "schema")]
    _schema: String,
    request_id: String,
    evaluated_at: String,
    binding_set_digest: String,
    principal: Principal,
    connection: Connection,
    action: RequestedAction,
    target_capabilities: Vec<TargetCapability>,
    policy: Policy,
    saved_consents: Vec<SavedConsent>,
    activation: Option<SignedActivation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Principal {
    workspace_id: String,
    subject_id: String,
    client_grant_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Connection {
    connection_id: String,
    provider: String,
    account_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestedAction {
    action_id: String,
    arguments: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    snapshot_id: String,
    rules: Vec<CloudPolicyRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ConsentKind {
    Once,
    Always,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedConsent {
    consent_id: String,
    kind: ConsentKind,
    action_identity_sha256: String,
}

/// The long-lived evaluator state fixed at startup.
pub struct CloudActionEvaluator {
    bindings: BindingSet,
    activation_key: Option<[u8; 32]>,
}

impl CloudActionEvaluator {
    pub fn new(bindings: BindingSet, activation_key: Option<[u8; 32]>) -> Self {
        Self {
            bindings,
            activation_key,
        }
    }

    pub fn binding_set_digest(&self) -> &str {
        &self.bindings.digest
    }

    /// Answer one request line. Never panics on caller input.
    pub fn evaluate(&self, line: &[u8]) -> Value {
        let parsed = match parse_strict(line) {
            Ok(value) => value,
            Err(error) => return error_result(None, error.code()),
        };
        let request_id = parsed
            .get("request_id")
            .and_then(Value::as_str)
            .filter(|id| valid_label(id))
            .map(str::to_owned);
        if parsed.get("schema").and_then(Value::as_str) != Some(REQUEST_SCHEMA) {
            return error_result(request_id.as_deref(), "unsupported_version");
        }
        let request: Request = match serde_json::from_value(parsed) {
            Ok(request) => request,
            Err(_) => return error_result(request_id.as_deref(), "invalid_request"),
        };
        let program = match packaged_command_program() {
            Ok(program) => program,
            Err(_) => return error_result(request_id.as_deref(), "program_unavailable"),
        };
        match self.decide(&request, &program) {
            Ok(result) => result,
            Err(code) => error_result(Some(&request.request_id), code),
        }
    }

    fn decide(
        &self,
        request: &Request,
        program: &NativeCommandProgram,
    ) -> Result<Value, &'static str> {
        validate_request(request)?;
        if request.binding_set_digest != self.bindings.digest {
            return Err("binding_unavailable");
        }
        let admitted = self
            .bindings
            .get(&request.action.action_id)
            .ok_or("action_unknown")?;
        let binding = &admitted.binding;
        if request.connection.provider != binding.adapter.provider {
            return Err("connection_mismatch");
        }
        let arguments =
            canonical_arguments(&request.action.arguments).map_err(|error| error.code())?;
        let resource_id = resource_id(admitted, &request.action.arguments)?;
        let activation = verify_activation(
            request.activation.as_ref(),
            self.activation_key.as_ref(),
            &ActivationContext {
                workspace_id: &request.principal.workspace_id,
                catalog_digest: &program.catalog_digest,
                now: &request.evaluated_at,
            },
        )?;

        let policy = decide_policy(
            &request.policy.rules,
            &PolicySubject {
                action_id: &binding.action_id,
                connection_id: &request.connection.connection_id,
                resource_id: resource_id.as_deref(),
            },
            binding.effect,
        );
        let mut action = policy.action;
        let mut reason_codes = vec![policy.reason_code];
        if let Some(tightened) = catalog_tightening(admitted, program, &activation, action) {
            action = tightened;
            reason_codes.push("catalog_mcp_extension");
        }
        let missing: Vec<&'static str> = binding
            .required_capabilities
            .iter()
            .filter(|needed| !request.target_capabilities.contains(needed))
            .map(|capability| capability.as_str())
            .collect();
        if !missing.is_empty() && action.severity() < GuardAction::SandboxRequired.severity() {
            action = GuardAction::SandboxRequired;
            reason_codes.push("capability_unavailable");
        }

        let identity = domain_digest(
            IDENTITY_DOMAIN,
            &[
                request.principal.workspace_id.as_bytes(),
                request.connection.connection_id.as_bytes(),
                request.connection.account_digest.as_bytes(),
                binding.action_id.as_bytes(),
                admitted.execution_identity_digest.as_bytes(),
                &arguments,
            ],
        );
        let review_eligible =
            matches!(action, GuardAction::Review | GuardAction::RequireReapproval);
        let mut consent: Option<&SavedConsent> = None;
        if review_eligible {
            consent = request
                .saved_consents
                .iter()
                .filter(|saved| saved.action_identity_sha256 == identity)
                .max_by_key(|saved| saved.kind == ConsentKind::Always);
            if let Some(saved) = consent {
                action = GuardAction::Allow;
                reason_codes.push(match saved.kind {
                    ConsentKind::Once => "saved_consent_once",
                    ConsentKind::Always => "saved_consent_always",
                });
            }
        }
        let provenance = domain_digest(
            PROVENANCE_DOMAIN,
            &[
                program.program_digest.as_bytes(),
                self.bindings.digest.as_bytes(),
                request.policy.snapshot_id.as_bytes(),
                activation.digest.as_deref().unwrap_or("").as_bytes(),
            ],
        );
        Ok(json!({
            "schema": RESULT_SCHEMA,
            "request_id": request.request_id,
            "action": action.as_str(),
            "dispatch_permitted": matches!(action, GuardAction::Allow | GuardAction::Warn),
            "review_eligible": review_eligible && consent.is_none(),
            "reason_codes": reason_codes,
            "matched_rule_ids": policy.matched_rule_id.into_iter().collect::<Vec<_>>(),
            "required_capabilities": binding.required_capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
            "missing_capabilities": missing,
            "consent_applied": consent.map_or("none", |saved| match saved.kind {
                ConsentKind::Once => "once",
                ConsentKind::Always => "always",
            }),
            "consent_id": consent.map(|saved| saved.consent_id.as_str()),
            "action_identity_sha256": identity,
            "execution_identity_digest": admitted.execution_identity_digest,
            "evaluation_provenance_digest": provenance,
            "engine": {"version": env!("CARGO_PKG_VERSION"), "contract": REQUEST_SCHEMA},
        }))
    }
}

fn validate_request(request: &Request) -> Result<(), &'static str> {
    let labels = [
        request.request_id.as_str(),
        request.principal.workspace_id.as_str(),
        request.principal.subject_id.as_str(),
        request.principal.client_grant_id.as_str(),
        request.connection.connection_id.as_str(),
        request.connection.provider.as_str(),
        request.policy.snapshot_id.as_str(),
    ];
    if !labels.into_iter().all(valid_label)
        || !is_sha256_hex(&request.connection.account_digest)
        || !is_utc_timestamp(&request.evaluated_at)
    {
        return Err("invalid_request");
    }
    if request.saved_consents.len() > MAX_SAVED_CONSENTS {
        return Err("limit");
    }
    if !request
        .saved_consents
        .iter()
        .all(|saved| valid_label(&saved.consent_id) && is_sha256_hex(&saved.action_identity_sha256))
    {
        return Err("invalid_request");
    }
    validate_rules(&request.policy.rules)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The resource the binding names, read from the exact arguments.
fn resource_id(
    admitted: &AdmittedBinding,
    arguments: &Value,
) -> Result<Option<String>, &'static str> {
    let Some(resource) = &admitted.binding.resource else {
        return Ok(None);
    };
    match arguments.get(&resource.argument).and_then(Value::as_str) {
        Some(id) if valid_label(id) => Ok(Some(id.to_owned())),
        _ => Err("invalid_request"),
    }
}

/// Catalog MCP contributions may only tighten a remote MCP action here: the
/// one relaxing path in the shared decision requires a local package launcher.
fn catalog_tightening(
    admitted: &AdmittedBinding,
    program: &NativeCommandProgram,
    activation: &VerifiedActivation,
    current: GuardAction,
) -> Option<GuardAction> {
    let binding = &admitted.binding;
    if binding.adapter.kind != AdapterKind::RemoteMcp {
        return None;
    }
    let remote = binding.remote_mcp.as_ref()?;
    let mut identity = serde_json::Map::new();
    identity.insert("transport".into(), Value::from("http"));
    identity.insert("command".into(), Value::from(remote.url.as_str()));
    let tool_name = Value::from(remote.tool_name.as_str());
    let input = ContributedMcpInput {
        current_action: current.as_str(),
        server_identity: Some(&identity),
        artifact_transport: None,
        server_name: None,
        tool_name: Some(&tool_name),
        layers: &[],
    };
    let all = contributions(program);
    let contribution = matching_contribution(&all, &input)?;
    if contribution.trust_class == "external"
        && !activation.external_enabled(contribution.catalog_id)
    {
        return None;
    }
    let outcome = decide_active_contribution(contribution, &input, activation.global_lockdown)?;
    let tightened = match outcome.action {
        "block" => GuardAction::Block,
        "review" => GuardAction::Review,
        _ => return None,
    };
    (tightened.severity() > current.severity()).then_some(tightened)
}

/// The one error shape: a block that can never be dispatched.
pub fn error_result(request_id: Option<&str>, code: &str) -> Value {
    json!({
        "schema": RESULT_SCHEMA,
        "request_id": request_id,
        "action": "block",
        "dispatch_permitted": false,
        "error": {"code": code},
    })
}
