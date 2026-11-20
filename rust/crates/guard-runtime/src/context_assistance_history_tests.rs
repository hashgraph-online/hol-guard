use super::*;

fn brief(index: usize, bytes: usize) -> ContextBrief {
    ContextBrief {
        schema: "guard-cigar-context-brief.v1",
        snapshot_id: format!("{index:064x}"),
        policy_revision: "a".repeat(64),
        graph_revision: 1,
        rendered: "x".repeat(bytes),
        rendered_tokens: 10,
        citations: vec![],
        excerpts: vec![],
        data_role: true,
    }
}
fn record(history: &mut History, index: usize, bytes: usize) {
    history.record(
        brief(index, bytes),
        &BTreeMap::new(),
        Some(json!({"decision_id":format!("{index:064x}")})),
        "0.14.1",
        &"f".repeat(64),
    );
}

#[test]
fn history_bounds_encoded_bytes_entries_and_replaces_identical_observations() {
    let mut history = History::default();
    for index in 0..12 {
        record(&mut history, index, 20);
    }
    assert_eq!(history.entries.len(), MAX_ENTRIES);
    assert_eq!(history.summary()["dropped"], "4");
    let id = history.entries.back().unwrap().entry.history_id.clone();
    record(&mut history, 11, 20);
    assert_eq!(history.entries.len(), MAX_ENTRIES);
    assert!(history.get(&id).is_none());
    history.clear();
    for index in 0..6 {
        record(&mut history, index, 200_000);
    }
    assert!(history.bytes <= MAX_BYTES);
    assert_eq!(history.entries.len(), 2);
    let before = history.bytes;
    record(&mut history, 10, MAX_ENTRY_BYTES + 1);
    assert_eq!(history.bytes, before);
    assert!(
        history.summary()["dropped"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            >= 5
    );
}

#[test]
fn history_is_historical_metadata_without_disclosing_brief_text_or_query() {
    let mut history = History::default();
    record(&mut history, 1, 80);
    let listed = history.list(Some(&format!("{:064x}", 1)));
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["historical"], true);
    assert_eq!(
        listed[0]["observation"],
        "prepared_not_delivery_or_execution"
    );
    assert!(listed[0].get("rendered").is_none());
    assert!(listed[0].get("query").is_none());
    assert!(history.list(Some(&format!("{:064x}", 2))).is_empty());
    assert_eq!(
        history
            .get(listed[0]["history_id"].as_str().unwrap())
            .unwrap()
            .brief
            .rendered
            .len(),
        80
    );
}

#[test]
fn expiry_and_clear_forget_text_and_history_ids_without_reusing_the_old_selector() {
    let mut history = History::default();
    record(&mut history, 1, 40);
    let id = history.entries.front().unwrap().entry.history_id.clone();
    history.entries.front_mut().unwrap().at = Instant::now() - Duration::from_secs(3600);
    history.expire(1);
    assert!(history.get(&id).is_none());
    assert_eq!(history.bytes, 0);
    record(&mut history, 2, 20);
    let id = history.entries.front().unwrap().entry.history_id.clone();
    history.clear();
    assert!(history.list(None).is_empty());
    record(&mut history, 3, 20);
    assert!(history.get(&id).is_none());
}
