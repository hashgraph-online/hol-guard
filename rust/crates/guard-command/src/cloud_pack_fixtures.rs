//! Runs the fixtures a pack ships with.
//!
//! Each fixture calls one action with recorded arguments and states what must
//! come out: the argument error it is refused with, or the facts Guard derives,
//! the exact request the executor sends, and the projection of a recorded
//! provider response, and the decision each shipped policy preset gives. A
//! pack whose fixtures fail is not compiled.

use crate::cloud_pack::{CloudActionPack, PackAction};
use crate::cloud_pack_facts::extract;
use crate::cloud_pack_request::{check_arguments, render};
use crate::cloud_pack_response::project;
use crate::cloud_policy_pack::{shipped, FactCall, Preset};
use crate::effect_decision::GuardAction;
use guard_contracts::ActionFactsV2;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureKind {
    Safe,
    Risky,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Fixture {
    pub name: String,
    pub kind: FixtureKind,
    pub arguments: Value,
    pub expect: FixtureExpect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FixtureExpect {
    /// The argument error code the call is refused with.
    pub error: Option<String>,
    /// Facts to compare by top-level key with the extracted facts.
    pub facts: Option<serde_json::Map<String, Value>>,
    /// The exact request the executor sends (`declarative-http` only).
    pub request: Option<Value>,
    /// A recorded provider response body and the projection it yields.
    pub response: Option<String>,
    pub projection: Option<Value>,
    /// The policy decision under each shipped preset, from the extracted
    /// facts with a clean session and zeroed usage windows.
    pub decisions: Option<PresetDecisions>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresetDecisions {
    pub relaxed: Option<GuardAction>,
    pub balanced: Option<GuardAction>,
    pub strict: Option<GuardAction>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureResult {
    pub action_id: String,
    pub fixture: String,
    pub kind: FixtureKind,
    pub passed: bool,
    /// The first expectation that did not hold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureReport {
    pub passed: bool,
    pub total: usize,
    pub failed: usize,
    pub results: Vec<FixtureResult>,
}

pub fn run(pack: &CloudActionPack) -> FixtureReport {
    let results: Vec<FixtureResult> = pack
        .actions
        .iter()
        .flat_map(|action| action.fixtures.iter().map(move |fixture| (action, fixture)))
        .map(|(action, fixture)| {
            let failure = check(&pack.provider.id, action, fixture).err();
            FixtureResult {
                action_id: action.action_id.clone(),
                fixture: fixture.name.clone(),
                kind: fixture.kind,
                passed: failure.is_none(),
                failure,
            }
        })
        .collect();
    let failed = results.iter().filter(|result| !result.passed).count();
    FixtureReport {
        passed: failed == 0,
        total: results.len(),
        failed,
        results,
    }
}

fn check(provider: &str, action: &PackAction, fixture: &Fixture) -> Result<(), String> {
    let expect = &fixture.expect;
    let checked = check_arguments(action, &fixture.arguments);
    if let Some(code) = &expect.error {
        let got = match &checked {
            Ok(_) => render(action, &fixture.arguments)
                .err()
                .map(|error| error.code),
            Err(error) => Some(error.code),
        };
        return match got {
            Some(got) if got == code => Ok(()),
            Some(got) => Err(format!("error: expected {code}, got {got}")),
            None => Err(format!("error: expected {code}, call was accepted")),
        };
    }
    let record = checked.map_err(|error| format!("arguments refused: {}", error.code))?;
    let derived = extract(action, record);
    if let Some(expected) = &expect.decisions {
        check_decisions(provider, action, &derived, expected)?;
    }
    if let Some(expected) = &expect.facts {
        let facts =
            serde_json::to_value(&derived).map_err(|_| "facts: unserializable".to_string())?;
        for (key, value) in expected {
            if facts.get(key) != Some(value) {
                return Err(format!(
                    "facts.{key}: expected {value}, got {}",
                    facts.get(key).unwrap_or(&Value::Null)
                ));
            }
        }
    }
    if let Some(expected) = &expect.request {
        let rendered = render(action, &fixture.arguments)
            .map_err(|error| format!("request refused: {}", error.code))?;
        let rendered =
            serde_json::to_value(rendered).map_err(|_| "request: unserializable".to_string())?;
        if &rendered != expected {
            return Err(format!("request: expected {expected}, got {rendered}"));
        }
    }
    if let (Some(body), Some(expected)) = (&expect.response, &expect.projection) {
        let projection = project(action, body.as_bytes())
            .map_err(|code| format!("projection refused: {code}"))?;
        if &projection.data != expected {
            return Err(format!(
                "projection: expected {expected}, got {}",
                projection.data
            ));
        }
    }
    Ok(())
}

fn check_decisions(
    provider: &str,
    action: &PackAction,
    facts: &ActionFactsV2,
    expected: &PresetDecisions,
) -> Result<(), String> {
    let call = FactCall {
        provider,
        action_id: &action.action_id,
        effect: action.safety.effect,
        connection_id: "fixture",
        resource_id: None,
        facts,
        session: None,
        windows: None,
        unclassified: None,
    };
    for (preset, want) in [
        (Preset::Relaxed, expected.relaxed),
        (Preset::Balanced, expected.balanced),
        (Preset::Strict, expected.strict),
    ] {
        let Some(want) = want else { continue };
        let got = shipped(preset).decide(&call);
        if got != want {
            return Err(format!(
                "decisions.{}: expected {}, got {}",
                preset.as_str(),
                want.as_str(),
                got.as_str()
            ));
        }
    }
    Ok(())
}
