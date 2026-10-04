//! Parity test: `command_critical_floor_factors` vs Python oracle rows
//! (`testdata/critical_floors_oracle.json`).

use serde::Deserialize;

use crate::canonical_command::CanonicalCommand;
use crate::command_critical_floors::command_critical_floor_factors;
use crate::github_capability_contract::GitHubCommandCapability;
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
    exact_raw_text: Option<bool>,
    #[serde(default)]
    parser_profile: String,
}

#[derive(Deserialize)]
struct FactorRow {
    source: String,
    reason_code: String,
    action: String,
    proof_route: Option<String>,
    segment_ref: Option<String>,
}

#[derive(Deserialize)]
struct OracleRow {
    command: String,
    factors: Vec<FactorRow>,
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
#[allow(clippy::type_complexity)]
fn critical_floor_factors_match_python_oracle() {
    let raw = include_str!("../testdata/critical_floors_oracle.json");
    let rows: Vec<OracleRow> = serde_json::from_str(raw).expect("oracle parses");
    let mut mismatches = Vec::new();
    for row in &rows {
        let command = CanonicalCommand::from_v1(&to_v1(&row.v1));
        let got: Vec<(String, String, Option<String>, Option<String>, String)> =
            command_critical_floor_factors(&command, None, &[])
                .iter()
                .map(|f| {
                    (
                        f.reason_code.clone(),
                        f.basis.action_floor.as_str().to_owned(),
                        f.basis.proof_route.map(|r| r.as_str().to_owned()),
                        f.segment_ref.clone(),
                        f.source.as_str().to_owned(),
                    )
                })
                .collect();
        let expected: Vec<(String, String, Option<String>, Option<String>, String)> = row
            .factors
            .iter()
            .map(|f| {
                (
                    f.reason_code.clone(),
                    f.action.clone(),
                    f.proof_route.clone(),
                    f.segment_ref.clone(),
                    f.source.clone(),
                )
            })
            .collect();
        if got != expected {
            mismatches.push(format!(
                "{}:\n  rust={:?}\n  py  ={:?}",
                row.command, got, expected
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

/// `explicitly_allowed_github_capabilities` dedupe path.
#[test]
fn explicitly_allowed_github_capabilities_pass_through() {
    let command = CanonicalCommand::from_v1(&crate::CanonicalCommandV1 {
        exact_raw_text: true,
        normalized_text: "gh pr merge 5 --admin".to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
        wrapper_chain: vec![],
        segments: vec![CommandSegmentV1 {
            text: "gh pr merge 5 --admin".to_owned(),
            tokens: vec![
                "gh".to_owned(),
                "pr".to_owned(),
                "merge".to_owned(),
                "5".to_owned(),
                "--admin".to_owned(),
            ],
            executable: Some("gh".to_owned()),
            arguments: vec![
                "pr".to_owned(),
                "merge".to_owned(),
                "5".to_owned(),
                "--admin".to_owned(),
            ],
            environment_names: vec![],
            wrapper_chain: vec![],
            path_overridden: false,
            execution_context: "direct".to_owned(),
            pipeline_index: 0,
            span: CommandSpanV1 {
                source: "normalized".to_owned(),
                start: 0,
                end: 21,
            },
        }],
        confidence: "exact".to_owned(),
        uncertainty_reason: None,
        path_overridden: false,
        parser_profile: "posix".to_owned(),
        security_identity: String::new(),
    });
    // With AdminMergeRemote allowed, the gh factor is suppressed.
    let suppressed = command_critical_floor_factors(
        &command,
        None,
        &[GitHubCommandCapability::AdminMergeRemote],
    );
    assert!(
        suppressed
            .iter()
            .all(|f| f.reason_code != "critical.github-cli"),
        "allowed capability must suppress the github-cli floor: {suppressed:?}"
    );
    // Without the allow, it fires.
    let fired = command_critical_floor_factors(&command, None, &[]);
    assert!(fired.iter().any(|f| f.reason_code == "critical.github-cli"));
}
