use serde_json::{json, Value};

use super::*;

const CENTER: &str = "http://127.0.0.1:5474";

fn item(request_id: &str, harness: &str, artifact_id: Option<&str>, url: Option<&str>) -> Value {
    let mut item = json!({"request_id": request_id, "harness": harness});
    if let Some(artifact_id) = artifact_id {
        item["artifact_id"] = json!(artifact_id);
    }
    if let Some(url) = url {
        item["approval_url"] = json!(url);
    }
    item
}

fn primary(args: Value) -> Value {
    let mut args = args;
    args["mode"] = json!("primary");
    dispatch(&args).unwrap()
}

fn preferred(payload: Value) -> Value {
    let mut args = payload;
    args["mode"] = json!("preferred");
    args["harness"] = json!("codex");
    dispatch(&args).unwrap()["url"].clone()
}

#[test]
fn harness_selects_its_own_latest_request() {
    let queued = json!([
        item(
            "codex-req",
            "codex",
            None,
            Some("http://127.0.0.1:5474/requests/codex-req")
        ),
        item(
            "cursor-req",
            "cursor",
            None,
            Some("http://127.0.0.1:5474/requests/cursor-req")
        ),
    ]);
    let result =
        primary(json!({"queued": queued, "harness": " Cursor ", "approval_center_url": CENTER}));
    assert_eq!(result["index"], 1);
    assert_eq!(result["url"], "http://127.0.0.1:5474/requests/cursor-req");
    let claude = json!([
        item("a", "codex", None, None),
        item("b", "claude", None, None)
    ]);
    assert_eq!(
        primary(json!({"queued": claude, "harness": "claude-code"}))["index"],
        1
    );
}

#[test]
fn request_id_then_artifact_then_single_item_bind_the_request() {
    let queued = json!([
        item("older-req", "cursor", Some("shell-a"), None),
        item("newer-req", "cursor", Some("shell-b"), None),
    ]);
    let by_id = json!({"queued": queued, "harness": "cursor", "request_id": "older-req"});
    assert_eq!(primary(by_id)["index"], 0);
    let by_artifact = json!({"queued": queued, "harness": "cursor", "artifact_id": "shell-a"});
    assert_eq!(primary(by_artifact)["index"], 0);
    let missing = json!({"queued": queued, "request_id": "missing-req", "artifact_id": "shell-a"});
    assert_eq!(primary(missing)["index"], Value::Null);
    assert_eq!(primary(json!({"queued": queued}))["index"], Value::Null);
    let solo = json!({"queued": [Value::Null, item("solo", "cursor", None, None)]});
    assert_eq!(primary(solo)["index"], 1);
}

#[test]
fn malformed_items_are_skipped_and_the_url_is_built_from_the_center() {
    let queued = json!([
        null,
        {"approval_url": "  ", "harness": ""},
        {"approval_url": "http://127.0.0.1:5474/requests/req-ok", "harness": "cursor"},
    ]);
    let result =
        primary(json!({"queued": queued, "harness": "cursor", "approval_center_url": CENTER}));
    assert_eq!(result["url"], "http://127.0.0.1:5474/requests/req-ok");
    let built = primary(json!({
        "queued": [{"request_id": " req-1 ", "harness": ""}],
        "approval_center_url": " http://127.0.0.1:5474// ",
    }));
    assert_eq!(built["url"], "http://127.0.0.1:5474/requests/req-1");
    let no_center = primary(json!({"queued": [{"request_id": "req-1", "harness": ""}]}));
    assert_eq!(
        (no_center["index"].clone(), no_center["url"].clone()),
        (json!(0), Value::Null)
    );
}

#[test]
fn stale_loopback_links_move_to_the_active_center() {
    let cases = [
        (
            "http://127.0.0.1:5713/requests/r",
            CENTER,
            "http://127.0.0.1:5474/requests/r",
        ),
        (
            "http://localhost:5713/requests/r",
            CENTER,
            "http://127.0.0.1:5474/requests/r",
        ),
        (
            "http://[::1]:5713/requests/r",
            "http://[::1]:5474",
            "http://[::1]:5474/requests/r",
        ),
        (
            "HTTP://127.0.0.1:1/a;p?q#f",
            "https://localhost:2",
            "https://localhost:2/a;p?q#f",
        ),
        (
            "http://127.0.0.1:1/a;?#",
            "https://localhost:2",
            "https://localhost:2/a",
        ),
        (
            "http://127.0.0.1:1?x",
            "https://localhost:2",
            "https://localhost:2?x",
        ),
        (
            "http://127.0.0.1:1//x;y/z;w",
            "http://localhost:2",
            "http://localhost:2//x;y/z;w",
        ),
        ("http://user@::1/r", CENTER, "http://127.0.0.1:5474/r"),
        (
            " http://127.0.0.1:1/r ",
            " http://127.0.0.1:2 ",
            "http://127.0.0.1:2/r",
        ),
    ];
    for (stale, center, expected) in cases {
        assert_eq!(canonical_url(stale, Some(center)), expected, "{stale}");
    }
}

#[test]
fn other_links_are_only_stripped() {
    let unchanged = [
        ("https://guard.example/requests/r", CENTER),
        ("http://127.0.0.1:1/r", "https://guard.example"),
        ("http://127.0.0.1:1/r", "ftp://127.0.0.1:2"),
        ("ftp://127.0.0.1:1/r", CENTER),
        ("http:127.0.0.1/r", CENTER),
        ("http://LOCALHOST:1/r", CENTER),
        ("http://[::1:1/r", CENTER),
        // Python rewrites these two after dropping the tab or reading the
        // userinfo brackets; leaving them alone keeps the rewrite exact.
        ("http://[::1]@[::1]:1/r", CENTER),
        ("http://127.0.0.1:1/a\tb", CENTER),
        ("http://lócalhost:1/r", CENTER),
    ];
    for (link, center) in unchanged {
        assert_eq!(
            canonical_url(&format!(" {link} "), Some(center)),
            link,
            "{link}"
        );
    }
    assert_eq!(
        canonical_url("http://127.0.0.1:1/r", None),
        "http://127.0.0.1:1/r"
    );
    assert_eq!(
        canonical_url("http://127.0.0.1:1/r", Some("  ")),
        "http://127.0.0.1:1/r"
    );
}

#[test]
fn attach_prefers_the_artifact_over_operation_ids() {
    let queued = json!([
        item(
            "first-op-req",
            "cursor",
            Some("shell-a"),
            Some("http://127.0.0.1:5474/requests/first-op-req")
        ),
        item(
            "bound-req",
            "cursor",
            Some("shell-b"),
            Some("http://127.0.0.1:5474/requests/bound-req")
        ),
    ]);
    let args = |ids: Value| {
        json!({
            "mode": "attach",
            "queued": queued,
            "harness": "cursor",
            "approval_center_url": CENTER,
            "payload_artifact_id": "shell-b",
            "approval_request_ids": ids,
        })
    };
    for ids in [json!(["first-op-req"]), json!(["bound-req"])] {
        let result = dispatch(&args(ids)).unwrap();
        assert_eq!(result["request_id"], "bound-req");
        assert_eq!(result["url"], "http://127.0.0.1:5474/requests/bound-req");
    }
    let mut unbound = args(json!([7, "", "first-op-req"]));
    unbound["payload_artifact_id"] = Value::Null;
    assert_eq!(dispatch(&unbound).unwrap()["request_id"], "first-op-req");
    let empty = json!({"mode": "attach", "queued": null});
    assert_eq!(
        dispatch(&empty).unwrap(),
        json!({"request_id": null, "url": null})
    );
}

#[test]
fn preferred_link_repairs_and_recovers_like_the_cli() {
    let center = "http://127.0.0.1:5481";
    let stale = |id: &str| format!("http://127.0.0.1:4833/requests/{id}");
    let repaired = |id: &str| json!(format!("{center}/requests/{id}"));
    let queue = |items: Vec<Value>| Value::Array(items);

    let only_primary = json!({"approval_center_url": center, "primary_approval_url": stale("p")});
    assert_eq!(preferred(only_primary), repaired("p"));
    let external =
        json!({"approval_center_url": center, "primary_approval_url": "https://guard.example/a"});
    assert_eq!(preferred(external), "https://guard.example/a");
    let path = json!({"approval_center_url": center, "primary_approval_url": "http://127.0.0.1:4833/approvals/x"});
    assert_eq!(preferred(path), json!(format!("{center}/approvals/x")));

    let new_request = item("req-new", "codex", None, Some(&stale("req-new")));
    let stale_id = json!({
        "approval_center_url": center,
        "primary_approval_request_id": "req-old",
        "primary_approval_url": stale("req-old"),
        "queued": queue(vec![new_request.clone()]),
    });
    assert_eq!(preferred(stale_id.clone()), repaired("req-new"));

    let mut by_artifact = stale_id.clone();
    by_artifact["artifact_id"] = json!("artifact-a");
    by_artifact["queued"] = queue(vec![
        item("req-a", "codex", Some("artifact-a"), Some(&stale("req-a"))),
        item("req-b", "codex", Some("artifact-b"), Some(&stale("req-b"))),
    ]);
    assert_eq!(preferred(by_artifact.clone()), repaired("req-a"));

    by_artifact["queued"] = queue(vec![item(
        "req-b",
        "codex",
        Some("artifact-b"),
        Some(&stale("req-b")),
    )]);
    assert_eq!(preferred(by_artifact.clone()), repaired("req-old"));

    by_artifact["queued"] = queue(vec![new_request]);
    assert_eq!(preferred(by_artifact), repaired("req-new"));

    assert_eq!(
        preferred(json!({"approval_center_url": format!(" {center} ")})),
        center
    );
    assert_eq!(preferred(json!({})), Value::Null);
}

#[test]
fn invalid_arguments_are_refused() {
    for args in [
        json!({"mode": "other", "queued": []}),
        json!({"queued": []}),
        json!({"mode": "primary", "queued": {}}),
        json!({"mode": "attach", "queued": [], "approval_request_ids": "x"}),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
