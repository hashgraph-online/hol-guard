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
use crate::cloud_action_policy::{
    decide_policy, rules_digest, validate_rules, CloudPolicyRule, PolicySubject,
};
use crate::contributed_mcp_decision::{
    contributions, decide_active_contribution, matching_contribution, ContributedMcpInput,
    Contribution,
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
pub(crate) struct Principal {
    pub(crate) workspace_id: String,
    pub(crate) subject_id: String,
    pub(crate) client_grant_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Connection {
    pub(crate) connection_id: String,
    pub(crate) provider: String,
    pub(crate) account_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestedAction {
    pub(crate) action_id: String,
    pub(crate) arguments: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    snapshot_id: String,
    rules: Vec<CloudPolicyRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ConsentKind {
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

/// What a decision reads from the command program: its digests and its
/// catalog MCP contributions.
pub(crate) struct ProgramView<'a> {
    pub(crate) program_digest: &'a str,
    pub(crate) catalog_digest: &'a str,
    pub(crate) catalog: Vec<Contribution<'a>>,
}

impl<'a> ProgramView<'a> {
    pub(crate) fn of(program: &'a NativeCommandProgram) -> Self {
        Self {
            program_digest: &program.program_digest,
            catalog_digest: &program.catalog_digest,
            catalog: contributions(program),
        }
    }
}

/// The long-lived evaluator state fixed at startup.
pub struct CloudActionEvaluator {
    pub(crate) bindings: BindingSet,
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
        let schema = parsed.get("schema").and_then(Value::as_str);
        if schema == Some(crate::cloud_action_v2::REQUEST_SCHEMA_V2) {
            return crate::cloud_action_v2::evaluate_v2(self, parsed, request_id.as_deref());
        }
        if schema != Some(REQUEST_SCHEMA) {
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
        match self.decide(&request, &ProgramView::of(&program)) {
            Ok(result) => result,
            Err(code) => error_result(request_id.as_deref(), code),
        }
    }

    /// `evaluate` against a given program view instead of the packaged one,
    /// so parity fixtures can supply their own catalog contributions.
    #[cfg(test)]
    pub(crate) fn evaluate_with(&self, line: &[u8], program: &ProgramView<'_>) -> Value {
        let request: Request = match parse_strict(line).map(serde_json::from_value) {
            Ok(Ok(request)) => request,
            _ => return error_result(None, "invalid_request"),
        };
        self.decide(&request, program)
            .unwrap_or_else(|code| error_result(Some(&request.request_id), code))
    }

    fn decide(&self, request: &Request, program: &ProgramView<'_>) -> Result<Value, &'static str> {
        let envelope = request.envelope();
        validate_request(request)?;
        let admission = self.admit(&envelope, program)?;
        let binding = &admission.admitted.binding;
        let policy = decide_policy(
            &request.policy.rules,
            &PolicySubject {
                action_id: &binding.action_id,
                connection_id: &request.connection.connection_id,
                resource_id: admission.resource_id.as_deref(),
            },
            binding.effect,
        );
        let mut action = policy.action;
        let mut reason_codes = vec![policy.reason_code];
        let missing = harden(
            &admission,
            &envelope,
            program,
            &mut action,
            &mut reason_codes,
        );

        let identity = action_identity(&envelope, &admission);
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
        let rules = rules_digest(&request.policy.rules);
        let provenance = domain_digest(
            PROVENANCE_DOMAIN,
            &[
                program.program_digest.as_bytes(),
                self.bindings.digest.as_bytes(),
                request.policy.snapshot_id.as_bytes(),
                rules.as_bytes(),
                admission
                    .activation
                    .digest
                    .as_deref()
                    .unwrap_or("")
                    .as_bytes(),
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
            "execution_identity_digest": admission.admitted.execution_identity_digest,
            "evaluation_provenance_digest": provenance,
            "engine": {"version": env!("CARGO_PKG_VERSION"), "contract": REQUEST_SCHEMA},
        }))
    }

    /// Binding, connection, arguments, resource and activation: everything a
    /// decision needs before any policy runs. Shared by both request versions.
    pub(crate) fn admit<'s>(
        &'s self,
        envelope: &Envelope<'_>,
        program: &ProgramView<'_>,
    ) -> Result<Admission<'s>, &'static str> {
        if envelope.binding_set_digest != self.bindings.digest {
            return Err("binding_unavailable");
        }
        let admitted = self
            .bindings
            .get(&envelope.action.action_id)
            .ok_or("action_unknown")?;
        if envelope.connection.provider != admitted.binding.adapter.provider {
            return Err("connection_mismatch");
        }
        let arguments =
            canonical_arguments(&envelope.action.arguments).map_err(|error| error.code())?;
        let resource_id = resource_id(admitted, &envelope.action.arguments)?;
        let activation = verify_activation(
            envelope.activation,
            self.activation_key.as_ref(),
            &ActivationContext {
                workspace_id: &envelope.principal.workspace_id,
                catalog_digest: program.catalog_digest,
                now: envelope.evaluated_at,
            },
        )?;
        Ok(Admission {
            admitted,
            arguments,
            resource_id,
            activation,
        })
    }
}

/// The parts every request version shares.
pub(crate) struct Envelope<'r> {
    pub(crate) request_id: &'r str,
    pub(crate) evaluated_at: &'r str,
    pub(crate) binding_set_digest: &'r str,
    pub(crate) principal: &'r Principal,
    pub(crate) connection: &'r Connection,
    pub(crate) action: &'r RequestedAction,
    pub(crate) target_capabilities: &'r [TargetCapability],
    pub(crate) snapshot_id: &'r str,
    pub(crate) activation: Option<&'r SignedActivation>,
}

impl Request {
    fn envelope(&self) -> Envelope<'_> {
        Envelope {
            request_id: &self.request_id,
            evaluated_at: &self.evaluated_at,
            binding_set_digest: &self.binding_set_digest,
            principal: &self.principal,
            connection: &self.connection,
            action: &self.action,
            target_capabilities: &self.target_capabilities,
            snapshot_id: &self.policy.snapshot_id,
            activation: self.activation.as_ref(),
        }
    }
}

/// What admission established.
pub(crate) struct Admission<'s> {
    pub(crate) admitted: &'s AdmittedBinding,
    pub(crate) arguments: Vec<u8>,
    pub(crate) resource_id: Option<String>,
    pub(crate) activation: VerifiedActivation,
}

/// Catalog tightening, global lockdown and target capabilities, applied after
/// policy. Each can only raise `action`. Returns the missing capabilities.
pub(crate) fn harden(
    admission: &Admission<'_>,
    envelope: &Envelope<'_>,
    program: &ProgramView<'_>,
    action: &mut GuardAction,
    reason_codes: &mut Vec<&'static str>,
) -> Vec<&'static str> {
    let binding = &admission.admitted.binding;
    if let Some(tightened) = catalog_tightening(
        admission.admitted,
        &program.catalog,
        &admission.activation,
        *action,
    ) {
        *action = tightened;
        reason_codes.push("catalog_mcp_extension");
    }
    if admission.activation.global_lockdown && *action != GuardAction::Block {
        *action = GuardAction::Block;
        reason_codes.push("global_lockdown");
    }
    let missing: Vec<&'static str> = binding
        .required_capabilities
        .iter()
        .filter(|needed| !envelope.target_capabilities.contains(needed))
        .map(|capability| capability.as_str())
        .collect();
    if !missing.is_empty() && action.severity() < GuardAction::SandboxRequired.severity() {
        *action = GuardAction::SandboxRequired;
        reason_codes.push("capability_unavailable");
    }
    missing
}

/// The exact-call identity an `exact` consent is bound to.
pub(crate) fn action_identity(envelope: &Envelope<'_>, admission: &Admission<'_>) -> String {
    domain_digest(
        IDENTITY_DOMAIN,
        &[
            envelope.principal.workspace_id.as_bytes(),
            envelope.connection.connection_id.as_bytes(),
            envelope.connection.account_digest.as_bytes(),
            admission.admitted.binding.action_id.as_bytes(),
            admission.admitted.execution_identity_digest.as_bytes(),
            &admission.arguments,
        ],
    )
}

pub(crate) fn validate_envelope(envelope: &Envelope<'_>) -> Result<(), &'static str> {
    let labels = [
        envelope.request_id,
        envelope.principal.workspace_id.as_str(),
        envelope.principal.subject_id.as_str(),
        envelope.principal.client_grant_id.as_str(),
        envelope.connection.connection_id.as_str(),
        envelope.connection.provider.as_str(),
        envelope.snapshot_id,
    ];
    if !labels.into_iter().all(valid_label)
        || !is_sha256_hex(&envelope.connection.account_digest)
        || !is_utc_timestamp(envelope.evaluated_at)
    {
        return Err("invalid_request");
    }
    Ok(())
}

fn validate_request(request: &Request) -> Result<(), &'static str> {
    validate_envelope(&request.envelope())?;
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

pub(crate) fn is_sha256_hex(value: &str) -> bool {
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
pub(crate) fn catalog_tightening(
    admitted: &AdmittedBinding,
    catalog: &[Contribution<'_>],
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
    let contribution = matching_contribution(catalog, &input)?;
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
