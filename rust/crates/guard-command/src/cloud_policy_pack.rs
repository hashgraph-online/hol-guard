//! Preset policy packs for cloud actions: Relaxed, Balanced and Strict.
//!
//! A policy pack is data (`contributions/cloud-policy-packs/*.json`). Each
//! entry pairs a fact rule in the evaluator's wire shape with the risk family
//! it encodes and a one-line summary. Loading a pack checks every rule the
//! way the evaluator would, so a pack that loads is a pack the evaluator
//! accepts; the caller passes [`PolicyPack::fact_rules`] and
//! [`PolicyPack::digest`] in the `policy` block of a version 2 request.
//!
//! The three shipped presets are compiled in ([`shipped`]), so pack fixtures
//! can state the decision each preset gives without a separate input.

use crate::cloud_action_binding::{valid_label, ActionEffect};
use crate::cloud_action_canonical::{canonical_bytes, domain_digest};
use crate::cloud_action_classifier::Proposal;
use crate::cloud_action_policy::{decide_policy, specificity, valid_match, PolicySubject};
use crate::cloud_action_v2::{join_fact_rules, CloudFactRule};
use crate::cloud_pack::PackError;
use crate::effect_decision::GuardAction;
use guard_contracts::{valid_fact_token, ActionFactsV2, FactSubjectV2, SessionFlowV2};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

const RELAXED: &str = include_str!("../../../../contributions/cloud-policy-packs/relaxed.json");
const BALANCED: &str = include_str!("../../../../contributions/cloud-policy-packs/balanced.json");
const STRICT: &str = include_str!("../../../../contributions/cloud-policy-packs/strict.json");

pub const POLICY_PACK_SCHEMA: &str = "guard.cloud-policy-pack.v1";
const DIGEST_DOMAIN: &str = "guard.cloud-policy-pack.v1.digest";
const MAX_RULES: usize = 256;
const MAX_TEXT: usize = 512;
const MAX_WINDOW_SECONDS: u64 = 30 * 24 * 3600;
const MAX_OBLIGATIONS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Preset {
    Relaxed,
    Balanced,
    Strict,
}

impl Preset {
    pub const ALL: [Self; 3] = [Self::Relaxed, Self::Balanced, Self::Strict];

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|preset| preset.as_str() == value)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Relaxed => "relaxed",
            Self::Balanced => "balanced",
            Self::Strict => "strict",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireWindow {
    id: String,
    seconds: u64,
    counts: String,
}

/// What an action with no admitted pack entry gets (PRD R16).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unclassified {
    pub action: GuardAction,
    pub destructive_name_action: GuardAction,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEntry {
    family: String,
    summary: String,
    rule: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireWorkspaceRule {
    family: String,
    needs: String,
    summary: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePack {
    schema: String,
    preset: Preset,
    title: String,
    summary: String,
    windows: Vec<WireWindow>,
    unclassified: Unclassified,
    rules: Vec<WireEntry>,
    workspace_rules: Vec<WireWorkspaceRule>,
}

/// A validated policy pack.
#[derive(Debug, Clone)]
pub struct PolicyPack {
    pub preset: Preset,
    pub unclassified: Unclassified,
    rules: Vec<Value>,
    typed: Vec<CloudFactRule>,
    windows: Vec<String>,
    digest: String,
}

static SHIPPED: LazyLock<[PolicyPack; 3]> = LazyLock::new(|| {
    // The shipped files are checked by the test suite; a broken file is a
    // build defect, not an input error.
    [RELAXED, BALANCED, STRICT].map(|text| {
        serde_json::from_str(text)
            .ok()
            .and_then(|value| policy_pack_from_value(value).ok())
            .expect("shipped cloud policy pack")
    })
});

/// One of the presets that ship with Guard.
pub fn shipped(preset: Preset) -> &'static PolicyPack {
    let index = match preset {
        Preset::Relaxed => 0,
        Preset::Balanced => 1,
        Preset::Strict => 2,
    };
    &SHIPPED[index]
}

/// What a fixture's decision is computed against: the action, its effect and
/// facts, with every declared window at zero and a clean session unless the
/// caller says otherwise.
pub struct FactCall<'a> {
    pub provider: &'a str,
    pub action_id: &'a str,
    pub effect: ActionEffect,
    /// The connection the call ran on; fixtures use `fixture`.
    pub connection_id: &'a str,
    /// The resource the call named, when it names one.
    pub resource_id: Option<&'a str>,
    pub facts: &'a ActionFactsV2,
    pub session: Option<&'a SessionFlowV2>,
    pub windows: Option<&'a BTreeMap<String, u64>>,
}

/// A policy decision and the fact rules behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleDecision {
    pub action: GuardAction,
    pub matched: Vec<String>,
    pub unknown: Vec<String>,
}

impl PolicyPack {
    /// The rules in the wire shape of a version 2 request's `fact_rules`.
    pub fn fact_rules(&self) -> &[Value] {
        &self.rules
    }

    /// Hex SHA-256 over the canonical pack, for the request's `pack_digest`.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The policy decision for one call: the effect default joined with this
    /// pack's fact rules, exactly as the evaluator joins them. Capability,
    /// obligation and consent checks come after this and are not applied.
    pub fn decide(&self, call: &FactCall<'_>) -> GuardAction {
        self.decide_with_rules(call).action
    }

    /// [`Self::decide`], with the ids of the rules that matched and of the
    /// rules that would match if every unknown fact were known.
    pub fn decide_with_rules(&self, call: &FactCall<'_>) -> RuleDecision {
        let subject = PolicySubject {
            action_id: call.action_id,
            connection_id: call.connection_id,
            resource_id: call.resource_id,
        };
        let effect = std::cmp::max_by_key(
            call.effect,
            crate::cloud_action_v2::class_effect(call.facts.class),
            |effect| crate::cloud_action_v2::effect_rank(*effect),
        );
        let policy = decide_policy(&[], &subject, effect);
        let zeroed: BTreeMap<String, u64>;
        let windows = match call.windows {
            Some(windows) => windows,
            None => {
                zeroed = self.windows.iter().map(|id| (id.clone(), 0)).collect();
                &zeroed
            }
        };
        let clean = SessionFlowV2 {
            untrusted_content_seen: false,
            sensitive_data_seen: false,
            injection_signal_seen: false,
        };
        let facts = FactSubjectV2 {
            provider: call.provider,
            facts: call.facts,
            session: Some(call.session.unwrap_or(&clean)),
            windows,
        };
        let join = join_fact_rules(&self.typed, &subject, &facts, &policy);
        RuleDecision {
            action: join.action,
            matched: join.matched.into_iter().map(str::to_owned).collect(),
            unknown: join.unknown.into_iter().map(str::to_owned).collect(),
        }
    }

    /// Which scope labels a call must carry before it can be decided: whether
    /// a rule that would otherwise cover the call is scoped to a connection
    /// the call leaves unknown, and likewise for a resource. A rule for
    /// another action, or one the call's known labels already rule out, needs
    /// neither. `resource_id` is `None` when the resource is unknown and
    /// `Some(None)` when the call names no resource.
    pub fn missing_scopes(
        &self,
        action_id: &str,
        connection_id: Option<&str>,
        resource_id: Option<Option<&str>>,
    ) -> (bool, bool) {
        let mut missing = (false, false);
        for rule in &self.typed {
            let matcher = &rule.matcher;
            let subject = PolicySubject {
                action_id,
                connection_id: connection_id
                    .or(matcher.connection_id.as_deref())
                    .unwrap_or(""),
                resource_id: resource_id.unwrap_or(matcher.resource_id.as_deref()),
            };
            if specificity(matcher, &subject).is_none() {
                continue;
            }
            missing.0 |= connection_id.is_none() && matcher.connection_id.is_some();
            missing.1 |= resource_id.is_none() && matcher.resource_id.is_some();
        }
        missing
    }

    /// The decision for an action no admitted pack describes. A name that
    /// reads as destructive gets the stricter of the two actions.
    pub fn unclassified_action(&self, proposal: &Proposal) -> GuardAction {
        if proposal.destructive {
            self.unclassified.destructive_name_action
        } else {
            self.unclassified.action
        }
    }
}

fn error(code: &'static str, pointer: impl Into<String>) -> PackError {
    PackError::new(code, pointer)
}

fn text_ok(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
}

/// Parse and validate a policy pack document.
pub fn policy_pack_from_value(value: Value) -> Result<PolicyPack, PackError> {
    let canonical = canonical_bytes(&value).map_err(|_| error("policy_pack_not_canonical", ""))?;
    let wire: WirePack =
        serde_json::from_value(value).map_err(|_| error("policy_pack_invalid", ""))?;
    if wire.schema != POLICY_PACK_SCHEMA {
        return Err(error("policy_pack_schema_unsupported", "/schema"));
    }
    for (pointer, text) in [("/title", &wire.title), ("/summary", &wire.summary)] {
        if !text_ok(text) {
            return Err(error("policy_pack_invalid", pointer));
        }
    }
    let declared = validate_windows(&wire.windows)?;
    validate_unclassified(&wire.unclassified)?;
    if wire.rules.is_empty() || wire.rules.len() > MAX_RULES {
        return Err(error("policy_pack_limit", "/rules"));
    }
    let prefix = format!("{}.", wire.preset.as_str());
    let mut ids = BTreeSet::new();
    let mut rules = Vec::with_capacity(wire.rules.len());
    let mut typed = Vec::with_capacity(wire.rules.len());
    for (index, entry) in wire.rules.into_iter().enumerate() {
        let pointer = format!("/rules/{index}");
        if !text_ok(&entry.family) || !text_ok(&entry.summary) {
            return Err(error("policy_pack_invalid", pointer));
        }
        let rule: CloudFactRule = serde_json::from_value(entry.rule.clone())
            .map_err(|_| error("policy_pack_rule_invalid", format!("{pointer}/rule")))?;
        validate_rule(&rule, &prefix, &declared)
            .map_err(|code| error(code, format!("{pointer}/rule")))?;
        if !ids.insert(rule.rule_id.clone()) {
            return Err(error(
                "policy_pack_rule_duplicate",
                format!("{pointer}/rule/rule_id"),
            ));
        }
        rules.push(entry.rule);
        typed.push(rule);
    }
    for (index, rule) in wire.workspace_rules.iter().enumerate() {
        if ![&rule.family, &rule.needs, &rule.summary]
            .into_iter()
            .all(|text| text_ok(text))
        {
            return Err(error(
                "policy_pack_invalid",
                format!("/workspace_rules/{index}"),
            ));
        }
    }
    let windows = declared.into_iter().map(str::to_owned).collect();
    Ok(PolicyPack {
        preset: wire.preset,
        unclassified: wire.unclassified,
        rules,
        typed,
        windows,
        digest: domain_digest(DIGEST_DOMAIN, &[&canonical]),
    })
}

fn validate_windows(windows: &[WireWindow]) -> Result<BTreeSet<&str>, PackError> {
    let mut ids = BTreeSet::new();
    for (index, window) in windows.iter().enumerate() {
        let ok = valid_fact_token(&window.id)
            && (1..=MAX_WINDOW_SECONDS).contains(&window.seconds)
            && text_ok(&window.counts)
            && ids.insert(window.id.as_str());
        if !ok {
            return Err(error("policy_pack_invalid", format!("/windows/{index}")));
        }
    }
    Ok(ids)
}

/// An action no pack describes is never allowed, and a destructive-looking
/// name is never treated more leniently than any other.
fn validate_unclassified(unclassified: &Unclassified) -> Result<(), PackError> {
    let base = unclassified.action.severity();
    if base < GuardAction::Review.severity()
        || unclassified.destructive_name_action.severity() < base
    {
        return Err(error("policy_pack_unclassified_lenient", "/unclassified"));
    }
    Ok(())
}

fn validate_rule(
    rule: &CloudFactRule,
    prefix: &str,
    windows: &BTreeSet<&str>,
) -> Result<(), &'static str> {
    let obligations: BTreeSet<_> = rule.obligations.iter().collect();
    let ok = valid_label(&rule.rule_id)
        && rule.rule_id.starts_with(prefix)
        && valid_match(&rule.matcher)
        && rule.facts.validate().is_ok()
        && rule.obligations.len() <= MAX_OBLIGATIONS
        && obligations.len() == rule.obligations.len();
    if !ok {
        return Err("policy_pack_rule_invalid");
    }
    let declared = rule
        .facts
        .windows
        .iter()
        .flatten()
        .all(|bound| windows.contains(bound.window.as_str()));
    if !declared {
        return Err("policy_pack_window_undeclared");
    }
    Ok(())
}
