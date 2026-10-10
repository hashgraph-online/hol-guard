use super::*;
use serde_json::Value;

fn row_text(row: &Value, key: &str) -> Option<f64> {
    row.get(key).and_then(Value::as_f64)
}

#[test]
fn timestamp_vectors_match_recorded_python() {
    let rows: Vec<Value> = serde_json::from_str(include_str!(
        "../tests/fixtures/policy_bundle_timestamp_vectors.json"
    ))
    .expect("vectors");
    assert!(rows.len() > 15_000);
    let mut failures = Vec::new();
    for row in &rows {
        let value = row["value"].as_str().expect("value");
        let checks = [
            ("v1", v1_timestamp(value), row_text(row, "v1")),
            ("tc", replaced_timestamp(value), row_text(row, "tc")),
            (
                "strict",
                strict_utc_micros(value).and_then(micros_to_seconds),
                row_text(row, "strict"),
            ),
        ];
        for (name, got, want) in checks {
            if got != want {
                failures.push(format!("{name} {value:?} got {got:?} want {want:?}"));
            }
        }
        let observed = normalized_observed_at(value);
        if observed.as_deref() != row["observed"].as_str() {
            failures.push(format!(
                "observed {value:?} got {observed:?} want {:?}",
                row["observed"]
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(25)]
    );
}

#[test]
fn strict_utc_requires_a_zero_offset() {
    assert!(strict_utc_micros("2026-01-01T12:00:00Z").is_some());
    for value in [
        "2026-01-01T12:00:00+01:00:00.000000\0Z",
        "2026-01-01T12:00:00-05:00:00.000000\0Z",
    ] {
        assert_eq!(strict_utc_micros(value), None, "{value:?}");
    }
}
