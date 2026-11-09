use serde_json::json;

use super::*;

fn pairs(query: &str) -> Vec<(String, String)> {
    query_pairs(query).unwrap()
}

#[test]
fn activity_cursor_reads_the_header_before_the_query() {
    assert_eq!(activity_cursor(&pairs(""), None), Some(0));
    assert_eq!(activity_cursor(&pairs("cursor=7"), None), Some(7));
    assert_eq!(activity_cursor(&pairs("cursor=7"), Some(" 9 ")), Some(9));
    assert_eq!(activity_cursor(&pairs("cursor=7"), Some("  ")), Some(7));
}

#[test]
fn activity_cursor_leaves_errors_to_the_daemon() {
    assert_eq!(activity_cursor(&pairs("cursor=-1"), None), None);
    assert_eq!(activity_cursor(&pairs("cursor="), None), None);
    assert_eq!(activity_cursor(&pairs("cursor=1&cursor=2"), None), None);
    assert_eq!(activity_cursor(&pairs("other=1"), None), None);
    assert_eq!(
        activity_cursor(&pairs("cursor=99999999999999999999"), None),
        None
    );
}

#[test]
fn event_frames_skip_rows_without_an_integer_id() {
    let items = vec![
        json!({"event_id": 3, "kind": "a"}),
        json!({"event_id": "x"}),
        json!({"event_id": 5, "text": "caf\u{e9}"}),
    ];
    let (frames, cursor) = event_frames(&items, 1);
    assert_eq!(cursor, 5);
    let text = String::from_utf8(frames).unwrap();
    assert_eq!(text.matches("data: ").count(), 2);
    assert!(text.contains("\"caf\\u00e9\""), "{text}");
    assert!(text.ends_with("\n\n"));
}

#[test]
fn activity_frames_reset_then_invalidate() {
    let page = json!({
        "reset_required": true,
        "reset_cursor": 10,
        "items": [
            {"sequence": 11, "activity_id": "act-1"},
            {"sequence": "12", "activity_id": "act-2"},
        ],
    });
    let (frames, cursor) = activity_frames(&page, 40);
    assert_eq!(cursor, 11);
    let text = String::from_utf8(frames).unwrap();
    assert!(text.starts_with(
        "id: 10\nevent: command_activity_reset\ndata: {\"event\":\"command_activity_reset\",\"reset_required\":true}\n\n"
    ));
    assert!(text.contains("id: 11\ndata: {\"activity_id\":\"act-1\",\"event\":\"command_activity_invalidated\"}\n\n")
        || text.contains("id: 11\ndata: {\"event\":\"command_activity_invalidated\",\"activity_id\":\"act-1\"}\n\n"));
    assert!(!text.contains("act-2"));
}

#[test]
fn python_json_matches_json_dumps() {
    let value = json!({"a": [1, true, null], "b": "q\"\n\u{1f600}"});
    assert_eq!(
        python_json(&value),
        "{\"a\": [1, true, null], \"b\": \"q\\\"\\n\\ud83d\\ude00\"}"
    );
}

#[test]
fn stream_head_names_the_origin_only_when_given() {
    let plain = String::from_utf8(stream_head(None)).unwrap();
    assert!(plain.starts_with("HTTP/1.0 200 OK\r\nContent-Type: text/event-stream\r\n"));
    assert!(!plain.contains("Access-Control"));
    let hosted = String::from_utf8(stream_head(Some("https://hol.org"))).unwrap();
    assert!(hosted.contains("Access-Control-Allow-Origin: https://hol.org\r\n"));
    assert!(hosted.ends_with("\r\n\r\n"));
}

#[test]
fn activity_slots_stop_at_the_limit() {
    let held: Vec<_> = std::iter::from_fn(ActivitySlot::claim)
        .take(ACTIVITY_MAX_CLIENTS + 1)
        .collect();
    assert_eq!(held.len(), ACTIVITY_MAX_CLIENTS);
    drop(held);
    assert!(ActivitySlot::claim().is_some());
}
