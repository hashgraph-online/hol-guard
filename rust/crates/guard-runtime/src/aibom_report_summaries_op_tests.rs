use super::*;

use guard_contracts::AibomSummaryItemV1;
use serde_json::json;

fn item(kind: &str, risk: &str, drift_state: &str) -> AibomSummaryItemV1 {
    AibomSummaryItemV1 {
        item_kind: kind.to_owned(),
        risk_level: risk.to_owned(),
        drift_state: drift_state.to_owned(),
        trust_resolution: Value::Null,
        source_links: Value::Null,
        source_of_truth: Value::Null,
    }
}

fn snapshot(items: Vec<AibomSummaryItemV1>) -> AibomSummarySnapshotV1 {
    AibomSummarySnapshotV1 {
        items,
        finding_count: 0,
        source_count: 0,
        drift_states: Vec::new(),
    }
}

fn request(snapshots: Vec<AibomSummarySnapshotV1>) -> AibomReportSummariesRequestV1 {
    AibomReportSummariesRequestV1 {
        schema: AIBOM_REPORT_SUMMARIES_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        generated_at: "2026-10-22T00:00:00Z".to_owned(),
        snapshots,
    }
}

fn decode(request: &AibomReportSummariesRequestV1) -> AibomReportSummariesResultV1 {
    serde_json::from_slice(&evaluate_aibom_report_summaries(request).unwrap()).unwrap()
}

fn payload(request: &AibomReportSummariesRequestV1) -> Value {
    decode(request).payload.expect("payload")
}

#[test]
fn an_empty_report_still_names_every_layer() {
    let result = decode(&request(Vec::new()));
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    let payload = result.payload.expect("payload");
    let layers = &payload["layer_summary"];
    for key in [
        "instructions",
        "skills",
        "mcp",
        "plugins",
        "policies",
        "findings",
        "trust",
        "sources",
        "configSources",
    ] {
        assert_eq!(layers[key], json!(0), "layer {key}");
    }
    assert_eq!(layers["generatedAt"], "2026-10-22T00:00:00Z");
    assert_eq!(layers["staleSnapshot"], json!(false));
    // Nothing is eligible, so nothing is uncovered.
    assert_eq!(payload["trust"]["coverage_percent"], json!(100));
    assert_eq!(payload["trust"]["average_score"], Value::Null);
}

#[test]
fn each_item_kind_lands_in_the_layer_python_counted_it_in() {
    let items = vec![
        item("overlay", "low", "unchanged"),
        item("prompt_pack", "low", "unchanged"),
        item("skill", "low", "unchanged"),
        item("mcp_server", "low", "unchanged"),
        item("mcp_tool", "low", "unchanged"),
        item("plugin", "low", "unchanged"),
        item("daemon_plugin", "low", "unchanged"),
        item("policy", "low", "unchanged"),
        item("something_else", "low", "unchanged"),
    ];
    let layers = payload(&request(vec![snapshot(items)]))["layer_summary"].clone();
    assert_eq!(layers["instructions"], json!(2));
    assert_eq!(layers["skills"], json!(1));
    assert_eq!(layers["mcp"], json!(2));
    assert_eq!(layers["plugins"], json!(2));
    assert_eq!(layers["policies"], json!(1));
}

#[test]
fn findings_and_config_sources_are_counted_across_snapshots() {
    let request = request(vec![
        AibomSummarySnapshotV1 {
            items: Vec::new(),
            finding_count: 2,
            source_count: 1,
            drift_states: Vec::new(),
        },
        AibomSummarySnapshotV1 {
            items: Vec::new(),
            finding_count: 1,
            source_count: 0,
            drift_states: Vec::new(),
        },
    ]);
    let layers = payload(&request)["layer_summary"].clone();
    assert_eq!(layers["findings"], json!(3));
    assert_eq!(layers["configSources"], json!(1));
}

#[test]
fn a_count_beyond_the_row_bound_is_refused() {
    let request = request(vec![AibomSummarySnapshotV1 {
        items: Vec::new(),
        finding_count: AIBOM_REPORT_SUMMARIES_MAX_ROWS + 1,
        source_count: 0,
        drift_states: Vec::new(),
    }]);
    assert_eq!(
        evaluate_aibom_report_summaries(&request).unwrap_err(),
        "native_aibom_report_summaries_invalid"
    );
}

#[test]
fn the_row_bound_holds_across_snapshots_not_only_within_one() {
    let compact = |finding_count| AibomSummarySnapshotV1 {
        items: Vec::new(),
        finding_count,
        source_count: 0,
        drift_states: Vec::new(),
    };
    let half = AIBOM_REPORT_SUMMARIES_MAX_ROWS / 2;
    assert!(evaluate_aibom_report_summaries(&request(vec![compact(half), compact(half)])).is_ok());
    let over = request(vec![compact(half), compact(half), compact(1)]);
    assert_eq!(
        evaluate_aibom_report_summaries(&over).unwrap_err(),
        "native_aibom_report_summaries_invalid"
    );
    let overflow = request(vec![compact(u64::MAX), compact(1)]);
    assert_eq!(
        evaluate_aibom_report_summaries(&overflow).unwrap_err(),
        "native_aibom_report_summaries_invalid"
    );
}

#[test]
fn source_links_win_over_source_of_truth_and_count_once_each() {
    // Python returned early once an item had links, so the source of truth on
    // the same item never added a second row.
    let linked = AibomSummaryItemV1 {
        source_links: json!([{"url": "one"}, {"url": "two"}]),
        source_of_truth: json!({"url": "ignored"}),
        ..item("skill", "low", "unchanged")
    };
    let truth_only = AibomSummaryItemV1 {
        source_of_truth: json!({"url": "only"}),
        ..item("skill", "low", "unchanged")
    };
    let empty_links = AibomSummaryItemV1 {
        source_links: json!([]),
        source_of_truth: json!({"url": "fallback"}),
        ..item("skill", "low", "unchanged")
    };
    let layers = payload(&request(vec![snapshot(vec![
        linked,
        truth_only,
        empty_links,
    ])]))["layer_summary"]
        .clone();
    assert_eq!(layers["sources"], json!(4));
}

#[test]
fn trust_coverage_counts_only_the_eligible_kinds() {
    let items = vec![
        AibomSummaryItemV1 {
            trust_resolution: json!({"trustScore": 90}),
            ..item("skill", "low", "unchanged")
        },
        AibomSummaryItemV1 {
            trust_resolution: json!({"trustScore": 40}),
            ..item("plugin", "low", "unchanged")
        },
        item("mcp_server", "low", "unchanged"),
        // Not an eligible kind, so its score moves neither coverage nor the average.
        AibomSummaryItemV1 {
            trust_resolution: json!({"trustScore": 10}),
            ..item("policy", "low", "unchanged")
        },
    ];
    let payload = payload(&request(vec![snapshot(items)]));
    let trust = &payload["trust"];
    assert_eq!(trust["eligible"], json!(3));
    assert_eq!(trust["covered"], json!(2));
    assert_eq!(trust["coverage_percent"], json!(67));
    assert_eq!(trust["low_trust"], json!(1));
    assert_eq!(trust["average_score"], json!(65));
    // The layer count is every item carrying a resolution, eligible or not.
    assert_eq!(payload["layer_summary"]["trust"], json!(3));
    assert_eq!(payload["layer_summary"]["lowTrustCount"], json!(1));
}

#[test]
fn drift_totals_item_states_and_snapshot_rows_together() {
    let request = request(vec![AibomSummarySnapshotV1 {
        items: vec![
            item("skill", "high", "new"),
            item("skill", "critical", "changed"),
            item("skill", "low", "removed"),
            item("skill", "low", "unchanged"),
            item("skill", "medium", "not_a_state"),
        ],
        finding_count: 0,
        source_count: 0,
        drift_states: vec!["new".to_owned(), "not_a_state".to_owned()],
    }]);
    let payload = payload(&request);
    let drift = &payload["drift"];
    assert_eq!(drift["new"], json!(2));
    assert_eq!(drift["changed"], json!(1));
    assert_eq!(drift["removed"], json!(1));
    assert_eq!(drift["unchanged"], json!(1));
    assert_eq!(drift["high_risk"], json!(2));
    assert_eq!(drift["total"], json!(4));
    assert_eq!(payload["layer_summary"]["driftCount"], json!(4));
    assert_eq!(payload["layer_summary"]["highRiskCount"], json!(2));
}

#[test]
fn a_foreign_schema_is_refused() {
    let mut request = request(Vec::new());
    request.schema = "guard-something-else.v1".to_owned();
    assert_eq!(
        evaluate_aibom_report_summaries(&request).unwrap_err(),
        "native_aibom_report_summaries_schema_mismatch"
    );
}

#[test]
fn an_empty_request_id_is_refused() {
    let mut request = request(Vec::new());
    request.request_id = String::new();
    assert_eq!(
        evaluate_aibom_report_summaries(&request).unwrap_err(),
        "native_aibom_report_summaries_invalid"
    );
}

#[test]
fn the_reply_binds_the_digest_of_the_request_it_answered() {
    let first = request(vec![snapshot(vec![item("skill", "low", "new")])]);
    let second = request(vec![snapshot(vec![item("skill", "low", "changed")])]);
    let first_sha = decode(&first).request_sha256;
    assert_eq!(first_sha, decode(&first).request_sha256);
    assert_ne!(first_sha, decode(&second).request_sha256);
    assert_eq!(
        first_sha,
        request_digest_with_limit(&first, AIBOM_REPORT_SUMMARIES_MAX_REQUEST_BYTES).unwrap()
    );
}
