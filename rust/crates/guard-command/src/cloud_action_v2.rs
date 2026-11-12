//! Version 2 of the cloud action request: action facts, fact rules, usage
//! windows, session flow, obligations and scoped consent.
//!
//! Admission, catalog tightening, lockdown and capabilities are shared with
//! version 1. What changes is the policy step:
//!
//! 1. The effect floor is the stricter of the binding's effect and the effect
//!    the facts' action class implies. Admin is an intrinsic block.
//! 2. Version 1 rules decide as before and give the default.
//! 3. Fact rules whose action pattern matches join that default. With `D` the
//!    rules whose selector definitely matches and `U` those whose answer
//!    depends on an unknown fact, the outcome is the stricter of
//!    `outcome(D)` and `outcome(D ∪ U)`. `outcome(S)` is the strictest action
//!    in `S` plus any matched version 1 rule, or the default when that is
//!    empty. So a fact rule may lower a default, an unknown fact never lowers
//!    anything, and rule order never matters.
//! 4. Obligations from `D ∪ U` the caller cannot fulfil turn the decision
//!    into a block.
//! 5. Saved consent answers only a review, as in version 1.

use std::collections::BTreeMap;

use guard_contracts::{
    valid_fact_token, ActionClassV2, ActionFactsErrorV2, ActionFactsV2, FactSelectorV2,
    FactSubjectV2, Match3, SessionFlowV2, MAX_ACTION_FACTS_BYTES, MAX_USAGE_WINDOWS,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::cloud_action::{
    action_identity, harden, is_sha256_hex, validate_envelope, Admission, CloudActionEvaluator,
    Connection, Envelope, Principal, ProgramView, RequestedAction, MAX_SAVED_CONSENTS,
};
use crate::cloud_action_activation::SignedActivation;
use crate::cloud_action_binding::{ActionEffect, TargetCapability};
use crate::cloud_action_canonical::{canonical_bytes, domain_digest};
use crate::cloud_action_policy::{
    decide_policy, effect_floor, rules_digest, specificity, valid_match, validate_rules,
    CloudPolicyMatch, CloudPolicyRule, PolicyOutcome, PolicySubject, MAX_POLICY_RULES,
};
use crate::cloud_action_v2_consent::{find_consent, validate_consent, SavedConsentV2};
use crate::effect_decision::GuardAction;
use crate::native_command_program::packaged_command_program;

pub const REQUEST_SCHEMA_V2: &str = "guard.cloud-action-evaluation.v2";
pub const RESULT_SCHEMA_V2: &str = "guard.cloud-action-evaluation-result.v2";
const PROVENANCE_DOMAIN_V2: &str = "guard.cloud-action-evaluation-provenance.v2";
const FACTS_DOMAIN: &str = "guard.action-facts.v2";
const FACT_RULES_DOMAIN: &str = "guard.cloud-action-fact-rules.v2";
const INPUTS_DOMAIN: &str = "guard.cloud-action-flow-inputs.v2";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestV2 {
    #[serde(rename = "schema")]
    _schema: String,
    request_id: String,
    evaluated_at: String,
    binding_set_digest: String,
    principal: Principal,
    connection: Connection,
    action: RequestedAction,
    target_capabilities: Vec<TargetCapability>,
    /// Obligations the caller can carry out for this action.
    supported_obligations: Vec<Obligation>,
    policy: PolicyV2,
    facts: ActionFactsV2,
    /// Authenticated usage per named window before this call.
    usage_windows: BTreeMap<String, u64>,
    /// `null` when the caller keeps no session journal; flags then read as unknown.
    session_flow: Option<SessionFlowV2>,
    saved_consents: Vec<SavedConsentV2>,
    activation: Option<SignedActivation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyV2 {
    snapshot_id: String,
    /// Digest of the policy pack the rules were compiled from, if any.
    pack_digest: Option<String>,
    rules: Vec<CloudPolicyRule>,
    fact_rules: Vec<CloudFactRule>,
}

/// A policy rule that also selects on action facts.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudFactRule {
    pub rule_id: String,
    pub action: GuardAction,
    #[serde(rename = "match")]
    pub matcher: CloudPolicyMatch,
    pub facts: FactSelectorV2,
    #[serde(default)]
    pub obligations: Vec<Obligation>,
}

/// Work the caller must do around dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Obligation {
    /// Count the affected records with a provider read before dispatch.
    CountReadback,
    /// Show the exact change to the person before dispatch.
    PreviewRequired,
    /// Replace detected secrets in the result before delivering it.
    RedactResultSecrets,
    /// Deliver the result wrapped and labelled as untrusted data.
    AnnotateUntrustedResult,
}

impl Obligation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CountReadback => "count_readback",
            Self::PreviewRequired => "preview_required",
            Self::RedactResultSecrets => "redact_result_secrets",
            Self::AnnotateUntrustedResult => "annotate_untrusted_result",
        }
    }
}

const MAX_OBLIGATIONS: usize = 4;

impl RequestV2 {
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

/// Canonical digests of inputs taken exactly as the caller sent them.
struct InputDigests {
    facts: String,
    fact_rules: String,
    flow: String,
}

fn input_digests(parsed: &Value) -> Result<InputDigests, &'static str> {
    let bytes = |value: &Value| canonical_bytes(value).map_err(|_| "invalid_request");
    let facts = bytes(&parsed["facts"])?;
    if facts.len() > MAX_ACTION_FACTS_BYTES {
        return Err("facts_limit");
    }
    let windows = bytes(&parsed["usage_windows"])?;
    let session = bytes(&parsed["session_flow"])?;
    Ok(InputDigests {
        facts: domain_digest(FACTS_DOMAIN, &[&facts]),
        fact_rules: domain_digest(
            FACT_RULES_DOMAIN,
            &[&bytes(&parsed["policy"]["fact_rules"])?],
        ),
        flow: domain_digest(INPUTS_DOMAIN, &[&windows, &session]),
    })
}

/// Answer one version 2 request already parsed by `evaluate`.
pub(crate) fn evaluate_v2(
    evaluator: &CloudActionEvaluator,
    parsed: Value,
    request_id: Option<&str>,
) -> Value {
    let digests = match input_digests(&parsed) {
        Ok(digests) => digests,
        Err(code) => return error_result_v2(request_id, code),
    };
    // Facts decode on their own first so a bad fact reports a facts code,
    // not a generic request error.
    if let Some(facts) = parsed.get("facts") {
        let checked = serde_json::to_vec(facts)
            .map_err(|_| ActionFactsErrorV2::Invalid)
            .and_then(|bytes| ActionFactsV2::from_bounded_json(&bytes));
        if let Err(error) = checked {
            return error_result_v2(request_id, error.code());
        }
    }
    let request: RequestV2 = match serde_json::from_value(parsed) {
        Ok(request) => request,
        Err(_) => return error_result_v2(request_id, "invalid_request"),
    };
    let program = match packaged_command_program() {
        Ok(program) => program,
        Err(_) => return error_result_v2(request_id, "program_unavailable"),
    };
    decide_v2(evaluator, &request, &digests, &ProgramView::of(&program))
        .unwrap_or_else(|code| error_result_v2(request_id, code))
}

fn validate_v2(request: &RequestV2) -> Result<(), &'static str> {
    validate_envelope(&request.envelope())?;
    request.facts.validate().map_err(|error| error.code())?;
    let policy = &request.policy;
    if policy.rules.len() + policy.fact_rules.len() > MAX_POLICY_RULES
        || request.usage_windows.len() > MAX_USAGE_WINDOWS
        || request.saved_consents.len() > MAX_SAVED_CONSENTS
        || request.supported_obligations.len() > MAX_OBLIGATIONS
    {
        return Err("limit");
    }
    validate_rules(&policy.rules)?;
    let fact_rules_ok = policy.fact_rules.iter().all(|rule| {
        crate::cloud_action_binding::valid_label(&rule.rule_id)
            && valid_match(&rule.matcher)
            && rule.facts.validate().is_ok()
            && rule.obligations.len() <= MAX_OBLIGATIONS
    });
    if !fact_rules_ok
        || !request
            .usage_windows
            .keys()
            .all(|name| valid_fact_token(name))
        || !policy.pack_digest.as_deref().is_none_or(is_sha256_hex)
    {
        return Err("invalid_request");
    }
    request.saved_consents.iter().try_for_each(validate_consent)
}

pub(crate) const fn effect_rank(effect: ActionEffect) -> u8 {
    match effect {
        ActionEffect::Read => 0,
        ActionEffect::Write => 1,
        ActionEffect::Destructive => 2,
        ActionEffect::Admin => 3,
    }
}

/// The effect an action class implies on its own.
pub const fn class_effect(class: ActionClassV2) -> ActionEffect {
    match class {
        ActionClassV2::Read => ActionEffect::Read,
        ActionClassV2::Draft
        | ActionClassV2::Send
        | ActionClassV2::Share
        | ActionClassV2::Export
        | ActionClassV2::Update
        | ActionClassV2::Execute
        | ActionClassV2::Pay => ActionEffect::Write,
        ActionClassV2::Delete => ActionEffect::Destructive,
        ActionClassV2::Admin => ActionEffect::Admin,
    }
}

/// The fact rules joined with the version 1 outcome.
pub(crate) struct FactJoin<'r> {
    pub(crate) action: GuardAction,
    pub(crate) reason_codes: Vec<&'static str>,
    pub(crate) matched: Vec<&'r str>,
    pub(crate) unknown: Vec<&'r str>,
    pub(crate) obligations: Vec<Obligation>,
}

pub(crate) fn join_fact_rules<'r>(
    rules: &'r [CloudFactRule],
    policy_subject: &PolicySubject<'_>,
    subject: &FactSubjectV2<'_>,
    policy: &PolicyOutcome,
) -> FactJoin<'r> {
    let mut join = FactJoin {
        action: policy.action,
        reason_codes: Vec::new(),
        matched: Vec::new(),
        unknown: Vec::new(),
        obligations: Vec::new(),
    };
    if policy.reason_code == "admin_effect_unsupported" {
        return join;
    }
    let mut definite = Vec::new();
    let mut uncertain = Vec::new();
    for rule in rules {
        if specificity(&rule.matcher, policy_subject).is_none() {
            continue;
        }
        match rule.facts.matches(subject) {
            Match3::Yes => definite.push(rule),
            Match3::Unknown => uncertain.push(rule),
            Match3::No => {}
        }
    }
    let base = policy.action;
    let base_matched = policy.matched_rule_id.is_some();
    let outcome = |set: &[&CloudFactRule]| -> GuardAction {
        set.iter()
            .map(|rule| rule.action)
            .chain(base_matched.then_some(base))
            .max_by_key(|action| action.severity())
            .unwrap_or(base)
    };
    let sure = outcome(&definite);
    let all: Vec<&CloudFactRule> = definite.iter().chain(&uncertain).copied().collect();
    let worst = outcome(&all);
    join.action = if worst.severity() > sure.severity() {
        worst
    } else {
        sure
    };
    if !definite.is_empty() {
        join.reason_codes.push("fact_rule");
    }
    if worst.severity() > sure.severity() {
        join.reason_codes.push("fact_unknown");
    }
    join.matched = definite.iter().map(|rule| rule.rule_id.as_str()).collect();
    join.unknown = uncertain.iter().map(|rule| rule.rule_id.as_str()).collect();
    join.obligations = all
        .iter()
        .flat_map(|rule| rule.obligations.iter().copied())
        .collect();
    join.obligations.sort_unstable();
    join.obligations.dedup();
    join
}

fn decide_v2(
    evaluator: &CloudActionEvaluator,
    request: &RequestV2,
    digests: &InputDigests,
    program: &ProgramView<'_>,
) -> Result<Value, &'static str> {
    validate_v2(request)?;
    let envelope = request.envelope();
    let admission: Admission<'_> = evaluator.admit(&envelope, program)?;
    let binding = &admission.admitted.binding;
    let implied = class_effect(request.facts.class);
    let effect = if effect_rank(implied) > effect_rank(binding.effect) {
        implied
    } else {
        binding.effect
    };
    let policy_subject = PolicySubject {
        action_id: &binding.action_id,
        connection_id: &request.connection.connection_id,
        resource_id: admission.resource_id.as_deref(),
    };
    let mut policy = decide_policy(&request.policy.rules, &policy_subject, effect);
    let mut reason_codes = vec![policy.reason_code];
    if effect != binding.effect {
        reason_codes.push("facts_effect");
        // A version 1 rule was written for the binding's declared effect. When
        // the facts raise it, the rule cannot decide below the raised floor.
        let floor = effect_floor(effect);
        if policy.matched_rule_id.is_some() && policy.action.severity() < floor.severity() {
            policy.action = floor;
            reason_codes.push("facts_effect_floor");
        }
    }
    let subject = FactSubjectV2 {
        provider: &request.connection.provider,
        facts: &request.facts,
        session: request.session_flow.as_ref(),
        windows: &request.usage_windows,
    };
    let join = join_fact_rules(
        &request.policy.fact_rules,
        &policy_subject,
        &subject,
        &policy,
    );
    let mut action = join.action;
    reason_codes.extend(&join.reason_codes);
    let missing = harden(
        &admission,
        &envelope,
        program,
        &mut action,
        &mut reason_codes,
    );
    let missing_obligations: Vec<&'static str> = join
        .obligations
        .iter()
        .filter(|needed| !request.supported_obligations.contains(needed))
        .map(|obligation| obligation.as_str())
        .collect();
    if !missing_obligations.is_empty() && action != GuardAction::Block {
        action = GuardAction::Block;
        reason_codes.push("capability_unavailable");
    }

    let identity = action_identity(&envelope, &admission);
    let review_eligible = matches!(action, GuardAction::Review | GuardAction::RequireReapproval);
    let consent = find_consent(
        &request.saved_consents,
        &crate::cloud_action_v2_consent::ConsentContext {
            identity: &identity,
            action_id: &binding.action_id,
            connection_id: &request.connection.connection_id,
            resource_id: admission.resource_id.as_deref(),
            subject: &subject,
            action,
        },
    )
    .filter(|_| review_eligible);
    if let Some(applied) = &consent {
        action = GuardAction::Allow;
        reason_codes.push(applied.reason_code());
    }
    let options = if review_eligible && consent.is_none() {
        crate::cloud_action_v2_consent::consent_options(
            admission.resource_id.is_some(),
            action,
            &request.facts,
        )
    } else {
        Vec::new()
    };
    let pack_digest = request.policy.pack_digest.as_deref();
    let provenance = domain_digest(
        PROVENANCE_DOMAIN_V2,
        &[
            program.program_digest.as_bytes(),
            evaluator.bindings.digest.as_bytes(),
            request.policy.snapshot_id.as_bytes(),
            rules_digest(&request.policy.rules).as_bytes(),
            digests.fact_rules.as_bytes(),
            pack_digest.unwrap_or("").as_bytes(),
            admission
                .activation
                .digest
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
            digests.facts.as_bytes(),
            digests.flow.as_bytes(),
        ],
    );
    let matched_rule_ids: Vec<&str> = policy
        .matched_rule_id
        .as_deref()
        .into_iter()
        .chain(join.matched.iter().copied())
        .collect();
    Ok(json!({
        "schema": RESULT_SCHEMA_V2,
        "request_id": request.request_id,
        "action": action.as_str(),
        "dispatch_permitted": matches!(action, GuardAction::Allow | GuardAction::Warn),
        "review_eligible": review_eligible && consent.is_none(),
        "reason_codes": reason_codes,
        "matched_rule_ids": matched_rule_ids,
        "unknown_fact_rule_ids": join.unknown,
        "required_capabilities": binding.required_capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
        "missing_capabilities": missing,
        "obligations": join.obligations.iter().map(|o| o.as_str()).collect::<Vec<_>>(),
        "missing_obligations": missing_obligations,
        "consent_applied": consent.as_ref().map_or("none", |applied| applied.kind_str()),
        "consent_scope": consent.as_ref().map_or("none", |applied| applied.scope_str()),
        "consent_id": consent.as_ref().map(|applied| applied.consent_id),
        "consent_options": options,
        "action_identity_sha256": identity,
        "execution_identity_digest": admission.admitted.execution_identity_digest,
        "facts_digest": digests.facts,
        "pack_digest": pack_digest,
        "evaluation_provenance_digest": provenance,
        "engine": {"version": env!("CARGO_PKG_VERSION"), "contract": REQUEST_SCHEMA_V2},
    }))
}

/// The version 2 error shape: a block that can never be dispatched.
pub fn error_result_v2(request_id: Option<&str>, code: &str) -> Value {
    json!({
        "schema": RESULT_SCHEMA_V2,
        "request_id": request_id,
        "action": "block",
        "dispatch_permitted": false,
        "error": {"code": code},
    })
}
