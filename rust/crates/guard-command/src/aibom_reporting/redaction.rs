use super::*;

/// `_aggregate_redaction_report(snapshots)`
pub fn _aggregate_redaction_report(
    snapshots: &[GuardAgentInventorySnapshot],
) -> Map<String, Value> {
    let mut redacted_fields: BTreeSet<String> = BTreeSet::new();
    let mut raw_secrets = false;
    let mut symlink_items = 0i64;
    for snapshot in snapshots {
        let report = &snapshot.redaction_report;
        if report.get("rawSecretsIncluded").and_then(Value::as_bool) == Some(true) {
            raw_secrets = true;
        }
        if let Some(fields) = report.get("redactedFields").and_then(Value::as_array) {
            for field in fields {
                redacted_fields.insert(value_display(field));
            }
        }
        for item in &snapshot.items {
            let source_of_truth = item.metadata.get("sourceOfTruth");
            let source_links = item.metadata.get("sourceLinks");
            if source_of_truth.is_some_and(Value::is_object)
                || source_links
                    .and_then(Value::as_array)
                    .is_some_and(|l| !l.is_empty())
            {
                symlink_items += 1;
            }
        }
    }
    let mut out = Map::new();
    out.insert("rawValuesIncluded".into(), json!(raw_secrets));
    out.insert(
        "redactedFields".into(),
        json!(redacted_fields.into_iter().collect::<Vec<_>>()),
    );
    out.insert("symlinkItems".into(), json!(symlink_items));
    out.insert("snapshots".into(), json!(snapshots.len() as i64));
    out
}

/// `str(field)` — for non-string scalars Python renders `str(value)`.
pub(super) fn value_display(value: &Value) -> String {
    match value.as_str() {
        Some(s) => s.to_string(),
        None => value.to_string(),
    }
}
