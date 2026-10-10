//! Parity test: `evaluate_command` → `CompositeCommandEvaluation` vs the Python
//! oracle (`testdata/evaluate_command_oracle.json`). 36 commands: 31 with empty
//! `command_extensions` observations (floor-driven only) + 5 with real rule
//! observations (exercises controlling-match / rule-match / match payload).
//!
//! Every row asserts the FULL `to_payload` dict is byte-identical to Python's
//! `evaluation.to_dict()` — minimum_action, decision_plane (with factors /
//! controlling_reasons / proof_routes), matches, extension_observations,
//! parse_confidence, uncertainty_reason, security_identity, risk_classes.

use serde::Deserialize;

use crate::canonical_command::CanonicalCommand;
use crate::command_evaluation_compose::{evaluate_command, CommandEvaluationInput};
use crate::native_command_catalog::{packaged_command_catalog, CatalogExtension};
use crate::{CanonicalCommandV1, CommandSegmentV1, CommandSpanV1};
use guard_contracts::NativeCommandControlBindingV1;

#[derive(Deserialize)]
struct SegmentRow {
    text: String,
    tokens: Vec<String>,
    executable: Option<String>,
    arguments: Vec<String>,
    environment_names: Vec<String>,
    wrapper_chain: Vec<String>,
    path_overridden: bool,
    execution_context: String,
    pipeline_index: usize,
    span: SpanRow,
}

#[derive(Deserialize)]
struct SpanRow {
    source: String,
    start: usize,
    end: usize,
}

#[derive(Deserialize)]
struct V1Row {
    normalized_text: String,
    dialect: String,
    transport: String,
    extraction_provenance: String,
    wrapper_chain: Vec<String>,
    segments: Vec<SegmentRow>,
    confidence: String,
    uncertainty_reason: Option<String>,
    path_overridden: bool,
    exact_raw_text: Option<bool>,
    #[serde(default)]
    parser_profile: String,
    #[serde(default)]
    security_identity: String,
}

#[derive(Deserialize)]
struct ReadFactorRow {
    source: String,
    reason_code: String,
    basis: ReadBasis,
    #[serde(default)]
    operation_ref: Option<String>,
    #[serde(default)]
    producer_ref: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ReadBasis {
    action_floor: String,
    proof_route: Option<String>,
}

#[derive(Deserialize)]
struct OracleRow {
    command: String,
    evaluation: serde_json::Value,
    native: serde_json::Value,
    v1: V1Row,
    #[serde(default)]
    read_factors: Vec<ReadFactorRow>,
}
#[derive(Deserialize)]
struct Fixture {
    catalog_extensions: Vec<CatalogExtension>,
    snapshot: SnapshotRow,
    cases: Vec<OracleRow>,
}

#[derive(Deserialize)]
struct SnapshotRow {
    revision: u64,
    managed_revision: u64,
    effective_digest: String,
    health: String,
}

fn to_v1(row: &V1Row) -> CanonicalCommandV1 {
    CanonicalCommandV1 {
        exact_raw_text: row.exact_raw_text.unwrap_or(true),
        normalized_text: row.normalized_text.clone(),
        dialect: row.dialect.clone(),
        transport: row.transport.clone(),
        extraction_provenance: row.extraction_provenance.clone(),
        wrapper_chain: row.wrapper_chain.clone(),
        segments: row
            .segments
            .iter()
            .map(|s| CommandSegmentV1 {
                text: s.text.clone(),
                tokens: s.tokens.clone(),
                executable: s.executable.clone(),
                arguments: s.arguments.clone(),
                environment_names: s.environment_names.clone(),
                wrapper_chain: s.wrapper_chain.clone(),
                path_overridden: s.path_overridden,
                execution_context: s.execution_context.clone(),
                pipeline_index: s.pipeline_index,
                span: CommandSpanV1 {
                    source: s.span.source.clone(),
                    start: s.span.start,
                    end: s.span.end,
                },
            })
            .collect(),
        confidence: row.confidence.clone(),
        uncertainty_reason: row.uncertainty_reason.clone(),
        path_overridden: row.path_overridden,
        parser_profile: row.parser_profile.clone(),
        security_identity: row.security_identity.clone(),
    }
}

fn to_read_factor(row: &ReadFactorRow) -> crate::effect_decision::DecisionFactor {
    use crate::effect_decision::{
        DecisionBasis, DecisionFactor, DecisionFactorSource, GuardAction,
    };
    let source = match row.source.as_str() {
        "assurance" => DecisionFactorSource::Assurance,
        "control" => DecisionFactorSource::Control,
        "authorization" => DecisionFactorSource::Authorization,
        _ => DecisionFactorSource::Policy,
    };
    let action_floor = match row.basis.action_floor.as_str() {
        "allow" => GuardAction::Allow,
        "require-reapproval" => GuardAction::RequireReapproval,
        "block" => GuardAction::Block,
        _ => GuardAction::Review,
    };
    DecisionFactor {
        source,
        reason_code: row.reason_code.clone(),
        basis: DecisionBasis {
            action_floor,
            proof_route: None,
        },
        segment_ref: None,
        operation_ref: row.operation_ref.clone(),
        producer_ref: row.producer_ref.clone(),
        evidence_digest: None,
        assessment: None,
        proof: None,
    }
}

#[test]
fn evaluate_command_matches_python_oracle() {
    let raw = include_str!("../testdata/evaluate_command_oracle.json");
    let mut fixture: Fixture = serde_json::from_str(raw).expect("oracle parses");
    let catalog = packaged_command_catalog().expect("packaged catalog loads");
    // New, unrelated extensions rotate the catalog digest without changing
    // any oracle input. Pin every original extension's typed semantics instead:
    // removed/changed rules, permissions, defaults, aliases and trust still fail.
    assert!(
        !fixture.catalog_extensions.is_empty(),
        "oracle catalog is empty"
    );
    for expected in &fixture.catalog_extensions {
        assert_eq!(
            catalog.get(&expected.extension_id),
            Some(expected),
            "oracle catalog semantics changed for {}; regenerate the Python oracle",
            expected.extension_id
        );
    }
    // Bind observations to the live compiled identities. Full evaluation
    // payload equality below remains the Python/Rust parity gate.
    for row in &mut fixture.cases {
        if let Some(binding) = row
            .native
            .get_mut("command_extensions")
            .and_then(|ce| ce.get_mut("binding"))
            .and_then(|b| b.as_object_mut())
        {
            binding.insert(
                "program_digest".into(),
                serde_json::Value::String(catalog.program_digest.clone()),
            );
            binding.insert(
                "catalog_digest".into(),
                serde_json::Value::String(catalog.catalog_digest.clone()),
            );
        }
    }
    let snapshot = NativeCommandControlBindingV1 {
        schema: guard_contracts::NATIVE_COMMAND_CONTROL_BINDING_SCHEMA.to_owned(),
        program_digest: catalog.program_digest.clone(),
        catalog_digest: catalog.catalog_digest.clone(),
        trust_digest: catalog.catalog_digest.clone(),
        health: fixture.snapshot.health.to_lowercase().replace('_', "-"),
        revision: fixture.snapshot.revision,
        managed_revision: fixture.snapshot.managed_revision,
        effective_digest: fixture.snapshot.effective_digest.clone(),
        layers: Vec::new(),
        authority: None,
    };

    let mut mismatches = Vec::new();
    for row in &fixture.cases {
        let command = CanonicalCommand::from_v1(&to_v1(&row.v1));
        let read_factors: Vec<_> = row.read_factors.iter().map(to_read_factor).collect();
        let evaluation = evaluate_command(CommandEvaluationInput {
            command: &command,
            native_extension_evidence: &row.native,
            registry: &catalog,
            binding: &snapshot,
            compatibility_action_class: None,
            compatibility_reason: None,
            workflow_authorization: None,
            read_factors,
        });
        let mut payload = match evaluation {
            Ok(evaluation) => evaluation.to_payload(),
            Err(error) => {
                mismatches.push(format!(
                    "{} -> evaluate_command Err: {}",
                    row.command, error
                ));
                continue;
            }
        };
        // The Python oracle predates `baseline_decision`: it must be present and
        // well-formed, and every other field must still match the oracle.
        let baseline = payload
            .as_object_mut()
            .and_then(|object| object.remove("baseline_decision"));
        assert!(
            baseline
                .as_ref()
                .and_then(|decision| decision.get("action"))
                .is_some_and(serde_json::Value::is_string),
            "{} -> missing baseline_decision",
            row.command
        );
        if payload != row.evaluation {
            let expected = serde_json::to_string_pretty(&row.evaluation).unwrap_or_default();
            let got = serde_json::to_string_pretty(&payload).unwrap_or_default();
            mismatches.push(format!(
                "{} -> payload mismatch\nexpected: {}\ngot:      {}",
                row.command, expected, got
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} evaluate_command oracle mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n---\n")
    );
}
