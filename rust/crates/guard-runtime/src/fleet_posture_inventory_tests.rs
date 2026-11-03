use serde_json::{json, Map, Value};

use super::dispatch;

const KEY: &str = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
const NOW: &str = "2026-11-02T12:00:00.250000+00:00";

fn row(name: &str, path: Option<&str>) -> Value {
    json!({
        "artifact_type": "skill",
        "harness": "codex",
        "artifact_name": name,
        "first_seen_at": "2026-10-01T00:00:00Z",
        "last_seen_at": "2026-10-02T00:00:00+00:00",
        "config_path": path,
        "artifact_hash": "SHA256:".to_owned() + &"ab".repeat(32),
        "source_scope": "workspace",
    })
}

fn rows(count: usize) -> Vec<Value> {
    (0..count)
        .map(|index| row(&format!("skill-{index}"), Some(&format!("/p/{index}"))))
        .collect()
}

fn build_with(rows: &[Value], last: &Value, now: &str, extra: &[(&str, Value)]) -> Value {
    let mut args = json!({
        "rows": rows,
        "hash_key": KEY,
        "last": last,
        "now": now,
        "force_full": false,
        "detail": true,
        "max_payload_bytes": 65536,
        "client": {"version": "1"},
        "machine": {"hostHash": "h"},
        "policy": {"mode": "enforce"},
        "runtimes": null,
        "tools": [{"harness": "codex", "protectionState": "protected", "blindSpots": ["x"]}],
    });
    for (key, value) in extra {
        args[*key] = value.clone();
    }
    let mut built = dispatch("fleet_posture_build", &args).expect("build");
    let items = committed_items(last, &built["next_state"]["itemsPatch"]);
    built["next_state"]["items"] = items;
    built
}

/// What the caller commits: the stored items with the reply's patch applied.
fn committed_items(last: &Value, patch: &Value) -> Value {
    let mut items = Map::new();
    match &last["items"] {
        Value::Object(stored) => items.extend(stored.clone()),
        Value::Array(chunks) => {
            for chunk in chunks.iter().filter_map(Value::as_object) {
                items.extend(chunk.clone());
            }
        }
        _ => {}
    }
    for key in patch["remove"].as_array().into_iter().flatten() {
        if let Some(key) = key.as_str() {
            items.remove(key);
        }
    }
    if let Some(set) = patch["set"].as_object() {
        items.extend(set.clone());
    }
    Value::Object(items)
}

fn build(rows: &[Value], last: &Value) -> Value {
    build_with(rows, last, NOW, &[])
}

#[test]
fn selects_installed_known_rows_once_per_identity() {
    let mut removed = row("gone", None);
    removed["removed_at"] = json!("2026-10-03T00:00:00Z");
    let mut absent = row("absent", None);
    absent["present"] = json!(0);
    let mut unknown_harness = row("other", None);
    unknown_harness["harness"] = json!("nobody");
    let mut unknown_kind = row("file", None);
    unknown_kind["artifact_type"] = json!("readme");
    let mut undated = row("undated", None);
    undated["first_seen_at"] = json!(17);
    let selected = dispatch(
        "fleet_inventory_rows",
        &json!({"rows": [
            removed, absent, unknown_harness, unknown_kind, undated,
            row("  kept  ", Some("/a")), row("kept", Some("/a")), row("kept", Some("/b")),
        ]}),
    )
    .expect("rows");
    let selected = selected["rows"].as_array().expect("rows");
    let indexes: Vec<u64> = selected
        .iter()
        .filter_map(|row| row["index"].as_u64())
        .collect();
    assert_eq!(indexes, vec![5, 7]);
    assert_eq!(selected[0]["name"], "kept");
    assert_eq!(selected[0]["first_seen_at"], "2026-10-01T00:00:00Z");
    assert_eq!(selected[0]["config_path"], "/a");
}

#[test]
fn items_key_the_config_path_under_the_install_secret() {
    let items = dispatch(
        "fleet_inventory_items",
        &json!({"rows": [row("one", Some("/home/u/.codex/skills/one"))], "hash_key": KEY}),
    )
    .expect("items");
    let item = &items["items"][0];
    assert_eq!(item["kind"], "skill");
    assert_eq!(item["source"], "project");
    assert_eq!(item["hash"], format!("sha256:{}", "ab".repeat(32)));
    let path_hash = item["pathHash"].as_str().expect("path hash");
    assert_eq!(path_hash.len(), "sha256:".len() + 64);
    assert_ne!(
        path_hash,
        format!(
            "sha256:{}",
            super::selection::sha256_hex("/home/u/.codex/skills/one")
        )
    );
    let other = dispatch(
        "fleet_inventory_items",
        &json!({"rows": [row("one", Some("/home/u/.codex/skills/one"))], "hash_key": KEY.repeat(2)}),
    )
    .expect("items");
    assert_ne!(other["items"][0]["pathHash"], item["pathHash"]);
}

#[test]
fn refuses_a_short_hash_key() {
    assert!(dispatch(
        "fleet_inventory_items",
        &json!({"rows": [], "hash_key": "short"})
    )
    .is_err());
}

#[test]
fn first_send_is_full_and_a_repeat_is_an_empty_delta() {
    let inventory = rows(3);
    let first = build(&inventory, &Value::Null);
    assert_eq!(first["mode"], "full");
    assert_eq!(first["advanced_inventory"], true);
    assert_eq!(
        first["payload"]["inventory"]["items"]
            .as_array()
            .map(Vec::len),
        Some(3)
    );
    let state = &first["next_state"];
    assert_eq!(state["sentAt"], "2026-11-02T12:00:00Z");
    assert_eq!(state["fullSentAt"], "2026-11-02T12:00:00Z");
    assert_eq!(state["inventoryItemsTracked"], 3);
    assert_eq!(state["summary"]["inventory"]["items"], json!([]));
    assert_eq!(state["tools"]["codex"], "protected");
    assert_eq!(first["payload"]["aiTools"][0]["artifactCount"], 3);
    assert_eq!(
        first["payload"]["aiTools"][0]["inventoryDigest"],
        first["payload"]["inventory"]["digest"]
    );

    let repeat = build(&inventory, state);
    assert_eq!(repeat["mode"], "delta");
    assert_eq!(repeat["payload"]["inventory"]["items"], json!([]));
    assert_eq!(repeat["payload"]["inventory"]["removed"], json!([]));
    assert_eq!(repeat["next_state"]["fullSentAt"], state["fullSentAt"]);
}

#[test]
fn a_removal_waits_until_no_other_path_holds_the_item() {
    let both = [row("shared", Some("/a")), row("shared", Some("/b"))];
    let first = build(&both, &Value::Null);
    let one_left = build(&both[..1], &first["next_state"]);
    assert_eq!(one_left["mode"], "delta");
    assert_eq!(one_left["payload"]["inventory"]["removed"], json!([]));
    assert_eq!(one_left["next_state"]["inventoryItemsTracked"], 1);

    let none_left = build(&[], &one_left["next_state"]);
    let removed = &none_left["payload"]["inventory"]["removed"];
    assert_eq!(removed.as_array().map(Vec::len), Some(1));
    assert_eq!(removed[0]["name"], "shared");
    assert_eq!(removed[0]["harness"], "codex");
}

#[test]
fn a_week_old_full_send_is_refreshed() {
    let inventory = rows(2);
    let mut last = build(&inventory, &Value::Null)["next_state"].clone();
    last["fullSentAt"] = json!("2026-10-25T11:59:59Z");
    let refreshed = build(&inventory, &last);
    assert_eq!(refreshed["mode"], "full");
    assert_eq!(
        refreshed["next_state"]["fullSentAt"],
        "2026-11-02T12:00:00Z"
    );

    let forced = build_with(
        &inventory,
        &build(&inventory, &Value::Null)["next_state"],
        NOW,
        &[("force_full", json!(true))],
    );
    assert_eq!(forced["mode"], "full");
}

#[test]
fn a_large_refresh_streams_as_deltas() {
    let inventory = rows(300);
    // A roomy byte budget leaves the item cap as the only limit.
    let roomy = [("max_payload_bytes", json!(1_000_000))];
    let first = build_with(&inventory, &Value::Null, NOW, &roomy);
    assert_eq!(first["mode"], "delta");
    assert_eq!(
        first["payload"]["inventory"]["items"]
            .as_array()
            .map(Vec::len),
        Some(250)
    );
    assert_eq!(first["next_state"]["fullStreaming"], true);
    assert_eq!(first["next_state"]["fullSentAt"], Value::Null);

    let second = build_with(&inventory, &first["next_state"], NOW, &roomy);
    assert_eq!(second["mode"], "delta");
    assert_eq!(
        second["payload"]["inventory"]["items"]
            .as_array()
            .map(Vec::len),
        Some(50)
    );
    assert_eq!(second["next_state"]["fullStreaming"], false);
    assert_eq!(second["next_state"]["fullSentAt"], "2026-11-02T12:00:00Z");
    assert_eq!(second["next_state"]["inventoryItemsTracked"], 300);
}

#[test]
fn the_reply_patches_the_tracked_items_instead_of_repeating_them() {
    let inventory = rows(300);
    let roomy = [("max_payload_bytes", json!(1_000_000))];
    let first = build_with(&inventory, &Value::Null, NOW, &roomy);
    let patch = &first["next_state"]["itemsPatch"];
    assert_eq!(patch["set"].as_object().map(Map::len), Some(250));

    let second = build_with(&inventory, &first["next_state"], NOW, &roomy);
    let patch = &second["next_state"]["itemsPatch"];
    assert_eq!(patch["set"].as_object().map(Map::len), Some(50));
    assert_eq!(patch["remove"], json!([]));
    assert_eq!(
        second["next_state"]["items"].as_object().map(Map::len),
        Some(300)
    );

    let unchanged = build_with(&inventory, &second["next_state"], NOW, &roomy);
    assert_eq!(
        unchanged["next_state"]["itemsPatch"],
        json!({"set": {}, "remove": []})
    );
    let gone = build_with(&inventory[1..], &second["next_state"], NOW, &roomy);
    let patch = &gone["next_state"]["itemsPatch"];
    assert_eq!(patch["set"], json!({}));
    assert_eq!(patch["remove"].as_array().map(Vec::len), Some(1));
}

#[test]
fn the_byte_budget_trims_a_delta_below_the_item_cap() {
    let first = build(&rows(300), &Value::Null);
    let sent = first["payload"]["inventory"]["items"]
        .as_array()
        .map_or(0, Vec::len);
    assert!(sent > 0 && sent < 250, "{sent}");
    assert!(first["payload_bytes"]
        .as_u64()
        .is_some_and(|bytes| bytes <= 65536));
}

#[test]
fn rows_and_tracked_items_may_arrive_in_chunks() {
    let inventory = rows(300);
    let chunked_rows = vec![
        Value::from(inventory[..120].to_vec()),
        Value::from(inventory[120..].to_vec()),
    ];
    let flat = build(&inventory, &Value::Null);
    let chunked = build(&chunked_rows, &Value::Null);
    assert_eq!(chunked, flat);

    let mut last = flat["next_state"].clone();
    let items = last["items"].as_object().cloned().unwrap_or_default();
    let (head, tail): (Vec<_>, Vec<_>) = items
        .into_iter()
        .enumerate()
        .partition(|(index, _)| *index < 100);
    let chunk = |pairs: Vec<(usize, (String, Value))>| {
        Value::Object(pairs.into_iter().map(|(_, pair)| pair).collect())
    };
    last["items"] = json!([chunk(head), chunk(tail)]);
    assert_eq!(
        build(&chunked_rows, &last),
        build(&inventory, &flat["next_state"])
    );
}

#[test]
fn a_minimal_report_sends_only_the_digest() {
    let inventory = rows(2);
    let minimal = build_with(
        &inventory,
        &Value::Null,
        NOW,
        &[("detail", json!(false)), ("runtimes", json!({"items": []}))],
    );
    assert_eq!(minimal["mode"], "digest_only");
    assert_eq!(minimal["advanced_inventory"], false);
    assert_eq!(minimal["payload"]["inventory"]["items"], json!([]));
    assert!(minimal["payload"].get("runtimes").is_none());
    assert_eq!(
        minimal["next_state"]["itemsPatch"],
        json!({"set": {}, "remove": []})
    );
}

#[test]
fn runtimes_give_way_before_inventory_rows() {
    let inventory = rows(20);
    let without = build(&inventory, &Value::Null)["payload_bytes"]
        .as_u64()
        .expect("bytes");
    let runtimes = json!({"items": ["r".repeat(4096)]});
    let fitted = build_with(
        &inventory,
        &Value::Null,
        NOW,
        &[
            ("runtimes", runtimes.clone()),
            ("max_payload_bytes", json!(without + 16)),
        ],
    );
    assert!(fitted["payload"].get("runtimes").is_none());
    assert_eq!(fitted["mode"], "full");
    assert_eq!(
        fitted["payload"]["inventory"]["items"]
            .as_array()
            .map(Vec::len),
        Some(20)
    );

    let roomy = build_with(&inventory, &Value::Null, NOW, &[("runtimes", runtimes)]);
    assert!(roomy["payload"].get("runtimes").is_some());
}

#[test]
fn an_oversized_payload_sends_what_fits_then_falls_back_to_the_digest() {
    let inventory = rows(20);
    let full = build(&inventory, &Value::Null)["payload_bytes"]
        .as_u64()
        .expect("bytes");
    let fewer = build_with(
        &inventory,
        &Value::Null,
        NOW,
        &[("max_payload_bytes", json!(full - 100))],
    );
    assert_eq!(fewer["mode"], "delta");
    let sent = fewer["payload"]["inventory"]["items"]
        .as_array()
        .map_or(0, Vec::len);
    assert!(sent > 0 && sent < 20);
    assert!(fewer["payload_bytes"].as_u64().expect("bytes") <= full - 100);
    assert_eq!(fewer["next_state"]["fullStreaming"], true);

    let none = build_with(
        &inventory,
        &Value::Null,
        NOW,
        &[("max_payload_bytes", json!(10))],
    );
    assert_eq!(none["mode"], "digest_only");
    assert_eq!(none["payload"]["aiTools"][0]["blindSpots"], json!([]));
    assert_eq!(
        none["next_state"]["summary"]["aiTools"][0]["blindSpots"],
        json!([])
    );
}

#[test]
fn the_digest_ignores_row_order() {
    let mut inventory = rows(5);
    let forward = build(&inventory, &Value::Null)["payload"]["inventory"]["digest"].clone();
    inventory.reverse();
    let reverse = build(&inventory, &Value::Null)["payload"]["inventory"]["digest"].clone();
    assert_eq!(forward, reverse);
}

#[test]
fn refuses_an_unparseable_now() {
    let args = json!({"rows": [], "hash_key": KEY, "last": null, "now": "soon"});
    assert!(dispatch("fleet_posture_build", &args).is_err());
}
