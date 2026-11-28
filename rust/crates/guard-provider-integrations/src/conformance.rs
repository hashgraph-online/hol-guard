//! The provider conformance kit (PRD 6.12).
//!
//! A vendor's coding agent runs these five checks against its manifest before opening a pull
//! request, and CI runs them for every manifest under `contributions/provider-integrations/`:
//!
//! 1. `compile`: the manifest compiles, which includes the safe-text grammar for every label.
//! 2. `recordings`: every recorded response maps to the signal or failure it is recorded as, and
//!    each capability has a recording for every verdict it can produce plus `unknown`, and for each
//!    [`RecordedFailure`].
//! 3. `share-set`: the rendered request for each capability carries exactly its declared facts, and
//!    no undeclared fact appears anywhere in the body.
//! 4. `no-added-prompt`: the benign browser corpus decides the same with no provider as with this
//!    provider answering `ok`, `unknown` or failing.
//! 5. `bounded-prompt`: with the provider answering `caution` for every subject, the provider-caused
//!    reviews stay inside the noise caps.
//!
//! The kit decides nothing itself. The caller passes Guard's own decision for each corpus row, and
//! checks 4 and 5 run them through [`crate::noise`] exactly as the resident does.

use std::collections::BTreeMap;

use guard_command::provider_integration_compile::{
    compile_provider_integration, CompiledProviderCapabilityV1, CompiledProviderIntegrationV1,
};
use guard_contracts::{ProviderCapabilityV1, ProviderShareableFactV1, ProviderVerdictV1};
use serde_json::Value;

use crate::answer::{map_answer, AnswerMapping, MappedAnswer, ReasonCodeMapping, TtlMapping};
use crate::noise::BaselineDecision;
use crate::parse::parse_strict;
use crate::render::render_body;

/// The stable ids of the five checks, in order.
pub const CONFORMANCE_CHECKS: [&str; 5] = [
    "compile",
    "recordings",
    "share-set",
    "no-added-prompt",
    "bounded-prompt",
];

/// A failure a recording can stand for. Transport failures (timeout, TLS, redirect, wrong host)
/// never produce a body, so the client tests cover them instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordedFailure {
    /// `401` or `403`: the key was refused.
    Unauthorized,
    /// `429`.
    RateLimited,
    /// Any other status outside `2xx`.
    Status,
    /// A body over the manifest's `maxResponseBytes`.
    Oversize,
    /// A body that is not strict JSON.
    Malformed,
}

impl RecordedFailure {
    /// The failures every capability must have a recording for.
    pub const REQUIRED: [Self; 4] = [
        Self::Unauthorized,
        Self::RateLimited,
        Self::Oversize,
        Self::Malformed,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::RateLimited => "rate_limited",
            Self::Status => "status",
            Self::Oversize => "oversize",
            Self::Malformed => "malformed",
        }
    }
}

/// What a recording says the provider's answer means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedExpectation {
    Signal {
        verdict: ProviderVerdictV1,
        reason_codes: Vec<String>,
    },
    Failure(RecordedFailure),
}

/// One recorded provider response, as stored under `tests/fixtures/provider_integrations/<slug>/`.
#[derive(Debug, Clone)]
pub struct Recording<'a> {
    pub name: &'a str,
    pub capability: ProviderCapabilityV1,
    pub status: u16,
    pub body: &'a [u8],
    pub expect: RecordedExpectation,
}

/// The result of one check. `problems` names what failed and never carries a fact value or key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceCheck {
    pub id: &'static str,
    pub problems: Vec<String>,
}

impl ConformanceCheck {
    fn new(id: &'static str, problems: Vec<String>) -> Self {
        Self { id, problems }
    }

    pub fn passed(&self) -> bool {
        self.problems.is_empty()
    }
}

/// All five checks, in [`CONFORMANCE_CHECKS`] order. A manifest that does not compile fails every
/// later check with `manifest did not compile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    pub provider_id: Option<String>,
    pub checks: Vec<ConformanceCheck>,
}

impl ConformanceReport {
    pub fn passed(&self) -> bool {
        self.checks.iter().all(ConformanceCheck::passed)
    }
}

/// Run the kit. `corpus` is Guard's own decision for each row of the benign browser corpus.
pub fn run_conformance(
    manifest: &[u8],
    recordings: &[Recording<'_>],
    corpus: &[BaselineDecision],
) -> ConformanceReport {
    let compiled = compile_provider_integration(manifest, &[]);
    let Ok(compiled) = compiled else {
        let code = compiled.err().map_or("", |error| error.code());
        let mut checks = vec![ConformanceCheck::new(
            CONFORMANCE_CHECKS[0],
            vec![format!("manifest did not compile: {code}")],
        )];
        for id in &CONFORMANCE_CHECKS[1..] {
            checks.push(ConformanceCheck::new(
                id,
                vec!["manifest did not compile".to_owned()],
            ));
        }
        return ConformanceReport {
            provider_id: None,
            checks,
        };
    };
    ConformanceReport {
        provider_id: Some(compiled.id.clone()),
        checks: vec![
            ConformanceCheck::new(CONFORMANCE_CHECKS[0], Vec::new()),
            check_recordings(&compiled, recordings),
            check_share_set(&compiled),
            noise_checks::check_no_added_prompt(&compiled, corpus),
            noise_checks::check_bounded_prompt(&compiled, corpus.len()),
        ],
    }
}

fn answer_mapping(capability: &CompiledProviderCapabilityV1) -> AnswerMapping<'_> {
    AnswerMapping {
        verdict_pointer: &capability.verdict_pointer,
        verdict_map: &capability.verdict_map,
        reason_codes: capability
            .reason_codes
            .as_ref()
            .map(|codes| ReasonCodeMapping {
                pointer: &codes.pointer,
                allow: &codes.allow,
            }),
        ttl: capability.ttl.as_ref().map(|ttl| TtlMapping {
            pointer: &ttl.pointer,
            min_seconds: ttl.min_seconds,
            max_seconds: ttl.max_seconds,
        }),
    }
}

/// What the resident makes of one response: the mapped answer, or the failure it reads as.
pub fn recorded_outcome(
    capability: &CompiledProviderCapabilityV1,
    max_response_bytes: u64,
    status: u16,
    body: &[u8],
) -> Result<MappedAnswer, RecordedFailure> {
    // The transport refuses an oversized body before it reports any status.
    if body.len() as u64 > max_response_bytes {
        return Err(RecordedFailure::Oversize);
    }
    match status {
        401 | 403 => return Err(RecordedFailure::Unauthorized),
        429 => return Err(RecordedFailure::RateLimited),
        200..=299 => {}
        _ => return Err(RecordedFailure::Status),
    }
    map_answer(body, &answer_mapping(capability)).map_err(|_| RecordedFailure::Malformed)
}

pub(crate) fn check_recordings(
    compiled: &CompiledProviderIntegrationV1,
    recordings: &[Recording<'_>],
) -> ConformanceCheck {
    let mut problems = Vec::new();
    let mut seen: BTreeMap<ProviderCapabilityV1, (Vec<ProviderVerdictV1>, Vec<RecordedFailure>)> =
        BTreeMap::new();
    for recording in recordings {
        let Some(capability) = compiled
            .capabilities
            .iter()
            .find(|capability| capability.capability == recording.capability)
        else {
            problems.push(format!(
                "{}: the manifest has no {} capability",
                recording.name,
                recording.capability.as_str()
            ));
            continue;
        };
        let outcome = recorded_outcome(
            capability,
            compiled.limits.max_response_bytes,
            recording.status,
            recording.body,
        );
        let entry = seen.entry(recording.capability).or_default();
        match (&recording.expect, outcome) {
            (
                RecordedExpectation::Signal {
                    verdict,
                    reason_codes,
                },
                Ok(answer),
            ) if answer.verdict == *verdict && answer.reason_codes == *reason_codes => {
                entry.0.push(*verdict);
            }
            (RecordedExpectation::Failure(expected), Err(failure)) if failure == *expected => {
                entry.1.push(failure);
            }
            (_, outcome) => problems.push(format!(
                "{}: recorded as {}, reads as {}",
                recording.name,
                expectation_label(&recording.expect),
                outcome_label(&outcome)
            )),
        }
    }
    for capability in &compiled.capabilities {
        let (verdicts, failures) = seen
            .get(&capability.capability)
            .cloned()
            .unwrap_or_default();
        let mut needed: Vec<ProviderVerdictV1> = capability.verdict_map.values().copied().collect();
        needed.push(ProviderVerdictV1::Unknown);
        needed.sort_by_key(|verdict| verdict_name(*verdict));
        needed.dedup();
        for verdict in needed {
            if !verdicts.contains(&verdict) {
                problems.push(format!(
                    "{}: no recording answers {}",
                    capability.capability.as_str(),
                    verdict_name(verdict)
                ));
            }
        }
        for failure in RecordedFailure::REQUIRED {
            if !failures.contains(&failure) {
                problems.push(format!(
                    "{}: no recording fails as {}",
                    capability.capability.as_str(),
                    failure.code()
                ));
            }
        }
    }
    ConformanceCheck::new(CONFORMANCE_CHECKS[1], problems)
}

fn verdict_name(verdict: ProviderVerdictV1) -> &'static str {
    match verdict {
        ProviderVerdictV1::Ok => "ok",
        ProviderVerdictV1::Caution => "caution",
        ProviderVerdictV1::Danger => "danger",
        ProviderVerdictV1::Unknown => "unknown",
    }
}

fn expectation_label(expect: &RecordedExpectation) -> String {
    match expect {
        RecordedExpectation::Signal { verdict, .. } => verdict_name(*verdict).to_owned(),
        RecordedExpectation::Failure(failure) => failure.code().to_owned(),
    }
}

fn outcome_label(outcome: &Result<MappedAnswer, RecordedFailure>) -> String {
    match outcome {
        Ok(answer) => format!(
            "{} with {} reason code(s)",
            verdict_name(answer.verdict),
            answer.reason_codes.len()
        ),
        Err(failure) => failure.code().to_owned(),
    }
}

/// The wire name of a fact, such as `target.origin`.
pub fn fact_name(fact: ProviderShareableFactV1) -> String {
    serde_json::to_value(fact)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

const FACTS: [ProviderShareableFactV1; 8] = ProviderShareableFactV1::ALL;

fn canary(fact: ProviderShareableFactV1) -> String {
    format!("conformance-canary-{}", fact_name(fact))
}

/// Every shareable fact, each holding its own canary, so a value in the body names the fact it
/// came from.
fn canary_facts() -> BTreeMap<String, Value> {
    FACTS
        .iter()
        .map(|fact| {
            let value = Value::String(canary(*fact));
            let value = if *fact == ProviderShareableFactV1::PageScriptHashes {
                Value::Array(vec![value])
            } else {
                value
            };
            (fact_name(*fact), value)
        })
        .collect()
}

fn check_share_set(compiled: &CompiledProviderIntegrationV1) -> ConformanceCheck {
    let facts = canary_facts();
    let mut problems = Vec::new();
    for capability in &compiled.capabilities {
        let label = capability.capability.as_str();
        let names: Vec<(String, String)> = capability
            .request
            .body
            .iter()
            .map(|(field, fact)| (field.clone(), fact_name(*fact)))
            .collect();
        let fields: Vec<(&str, &str)> = names
            .iter()
            .map(|(field, fact)| (field.as_str(), fact.as_str()))
            .collect();
        let body = match render_body(&fields, &facts) {
            Ok(body) => body,
            Err(error) => {
                problems.push(format!(
                    "{label}: the body did not render: {}",
                    error.code()
                ));
                continue;
            }
        };
        let declared: Vec<ProviderShareableFactV1> = capability
            .request
            .body
            .iter()
            .map(|(_, fact)| *fact)
            .collect();
        for fact in FACTS {
            let carried = body.contains(&canary(fact));
            if carried && !declared.contains(&fact) {
                problems.push(format!(
                    "{label}: the body carries undeclared {}",
                    fact_name(fact)
                ));
            }
            if carried != capability.shares.contains(&fact) {
                problems.push(format!(
                    "{label}: shares and the body disagree on {}",
                    fact_name(fact)
                ));
            }
        }
        let Some(Value::Object(object)) = parse_strict(body.as_bytes()) else {
            problems.push(format!("{label}: the body is not a JSON object"));
            continue;
        };
        let keys: Vec<&String> = object.keys().collect();
        let mut expected: Vec<&String> = names.iter().map(|(field, _)| field).collect();
        expected.sort();
        let mut sorted = keys.clone();
        sorted.sort();
        if sorted != expected {
            problems.push(format!("{label}: the body has fields it does not declare"));
        }
    }
    ConformanceCheck::new(CONFORMANCE_CHECKS[2], problems)
}

#[path = "conformance_noise.rs"]
mod noise_checks;

#[cfg(test)]
#[path = "conformance_tests.rs"]
mod tests;
