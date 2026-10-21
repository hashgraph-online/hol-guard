//! Parity test: `verified_read_candidate_operation` vs Python oracle rows
//! (`testdata/verified_read_candidate_models.json`).

use serde::Deserialize;

use crate::canonical_command::CanonicalCommand;
use crate::command_verified_read_candidates::{
    verified_read_candidate_factor, verified_read_candidate_operation,
};
use crate::{CanonicalCommandV1, CommandSegmentV1, CommandSpanV1};

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
    #[serde(default)]
    exact_raw_text: Option<bool>,
    #[serde(default)]
    parser_profile: String,
}

#[derive(Deserialize)]
struct OracleRow {
    command: String,
    op: Option<String>,
    v1: V1Row,
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
        security_identity: String::new(),
    }
}

#[test]
fn verified_read_operation_matches_python_oracle() {
    let raw = include_str!("../testdata/verified_read_candidate_models.json");
    let rows: Vec<OracleRow> = serde_json::from_str(raw).expect("oracle parses");
    let mut mismatches = Vec::new();
    for row in &rows {
        let command = CanonicalCommand::from_v1(&to_v1(&row.v1));
        let got = verified_read_candidate_operation(&command).map(|s| s.to_owned());
        if got != row.op {
            mismatches.push(format!("{}: rust={:?} py={:?}", row.command, got, row.op));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn verified_read_factor_shape() {
    let raw = include_str!("../testdata/verified_read_candidate_models.json");
    let rows: Vec<OracleRow> = serde_json::from_str(raw).expect("oracle parses");
    for row in &rows {
        let command = CanonicalCommand::from_v1(&to_v1(&row.v1));
        let factor = verified_read_candidate_factor(&command);
        match (&row.op, &factor) {
            (None, None) => {}
            (Some(op), Some(f)) => {
                assert_eq!(f.reason_code, "verified-read-proof-required");
                assert_eq!(
                    f.operation_ref.as_deref(),
                    Some(format!("operation:{op}").as_str())
                );
                assert_eq!(
                    f.producer_ref.as_deref(),
                    Some("policy:verified-read-candidate-v1")
                );
                assert_eq!(f.basis.action_floor.as_str(), "review");
            }
            (a, b) => panic!("{}: op={:?} factor-present={}", row.command, a, b.is_some()),
        }
    }
}
