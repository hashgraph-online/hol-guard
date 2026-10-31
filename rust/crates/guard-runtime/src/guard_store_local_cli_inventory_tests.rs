//! Paging the local CLI inventory read: a device holding more connectors than
//! one reply may frame still lists every one of them, because the caller walks
//! the offsets the pages name, each page enriches only what it lists, and a
//! list that changes mid-walk sends the caller back to the start.

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::StoreResult;
use crate::guard_store_local_cli_inventory::{inventory_page, list_items};

/// An item of roughly `kibibytes`, so that only a few fit one page.
fn bulky_item(index: usize, kibibytes: usize) -> Map<String, Value> {
    let mut item = Map::new();
    item.insert(
        "cli_id".to_owned(),
        Value::from(format!("local-cli.{index:03}")),
    );
    item.insert(
        "filler".to_owned(),
        Value::from("x".repeat(kibibytes * 1024)),
    );
    item
}

fn unchanged(_: &mut Map<String, Value>) -> StoreResult<()> {
    Ok(())
}

/// Every `cli_id` a caller sees when it reads page by page, as the Python
/// store does, how many items were enriched along the way, and how many
/// pages the walk took.
fn walk(items: &[Map<String, Value>]) -> (Vec<String>, usize, usize) {
    let mut seen = Vec::new();
    let mut enriched = 0;
    let mut pages = 0;
    let mut offset = 0;
    loop {
        pages += 1;
        let reply = inventory_page(items.to_vec(), offset, |_| {
            enriched += 1;
            Ok(())
        })
        .expect("page");
        let listed = reply["items"].as_array().expect("items").clone();
        assert!(!listed.is_empty(), "a page must advance past its offset");
        for item in &listed {
            seen.push(item["cli_id"].as_str().expect("cli_id").to_owned());
        }
        offset += listed.len();
        match reply["next_offset"].as_u64() {
            None => return (seen, enriched, pages),
            Some(next) => assert_eq!(usize::try_from(next).expect("offset"), offset),
        }
    }
}

#[test]
fn walking_the_pages_lists_every_connector() {
    let items: Vec<Map<String, Value>> = (0..80).map(|index| bulky_item(index, 64)).collect();
    // 80 items of 64 KiB are past one reply, so this really takes several
    // pages rather than proving the single-page case twice.
    assert!(
        inventory_page(items.clone(), 0, unchanged).expect("page")["next_offset"]
            .as_u64()
            .is_some()
    );
    let (walked, _, _) = walk(&items);
    assert_eq!(walked.len(), items.len());
    assert_eq!(walked.first().map(String::as_str), Some("local-cli.000"));
    assert_eq!(walked.last().map(String::as_str), Some("local-cli.079"));
}

#[test]
fn a_walk_enriches_each_connector_about_once() {
    let items: Vec<Map<String, Value>> = (0..80).map(|index| bulky_item(index, 64)).collect();
    let (walked, enriched, pages) = walk(&items);
    assert!(pages > 1, "the walk must span several pages");
    // Each page enriches what it lists plus the one item that did not fit,
    // never the whole rest of the list again.
    assert!(
        enriched < walked.len() + pages,
        "{enriched} enrichments for {} items",
        walked.len()
    );
}

#[test]
fn an_item_larger_than_one_page_still_comes_back() {
    let reply =
        inventory_page(vec![bulky_item(0, 4096), bulky_item(1, 1)], 0, unchanged).expect("page");
    assert_eq!(reply["items"].as_array().expect("items").len(), 1);
    assert_eq!(reply["next_offset"].as_u64(), Some(1));
}

#[test]
fn an_offset_past_the_last_item_ends_the_walk() {
    let reply = inventory_page(vec![bulky_item(0, 1)], 5, unchanged).expect("page");
    assert!(reply["items"].as_array().expect("items").is_empty());
    assert!(reply["next_offset"].is_null());
}

fn observed(connection: &Connection, cli_id: &str, last_seen_at: &str) {
    connection
        .execute(
            "insert into local_cli_observation (cli_id, identity_hash, kind, name, last_seen_at) \
             values (?1, 'sha256:a', 'executable', ?1, ?2)",
            [cli_id, last_seen_at],
        )
        .expect("insert");
}

fn read(connection: &Connection, offset: i64, snapshot: Option<&str>) -> Value {
    let mut args = Map::new();
    args.insert("offset".to_owned(), Value::from(offset));
    if let Some(snapshot) = snapshot {
        args.insert("snapshot".to_owned(), Value::from(snapshot));
    }
    list_items(connection, &Args(&args)).expect("list")
}

#[test]
fn a_reordered_list_sends_the_walk_back_to_the_start() {
    let connection = Connection::open_in_memory().expect("open");
    connection
        .execute(
            "create table local_cli_observation (cli_id text primary key, \
             identity_hash text, kind text, name text, last_seen_at text)",
            [],
        )
        .expect("create");
    observed(&connection, "alpha", "2026-01-02T00:00:00Z");
    observed(&connection, "beta", "2026-01-01T00:00:00Z");

    let first = read(&connection, 0, None);
    let snapshot = first["snapshot"].as_str().expect("snapshot").to_owned();
    assert!(first.get("restart").is_none());
    assert_eq!(first["items"][0]["cli_id"], "alpha");

    // Unchanged, the snapshot the first page named still reads on.
    let again = read(&connection, 1, Some(&snapshot));
    assert!(again.get("restart").is_none(), "{again}");
    assert_eq!(again["snapshot"], Value::from(snapshot.as_str()));

    // A fresh observation reorders the list; reading on at offset 1 would
    // repeat alpha and never list beta, so the reply says start over.
    connection
        .execute(
            "update local_cli_observation set last_seen_at = '2026-01-03T00:00:00Z' \
             where cli_id = 'beta'",
            [],
        )
        .expect("update");
    let moved = read(&connection, 1, Some(&snapshot));
    assert_eq!(moved["restart"], Value::Bool(true), "{moved}");
    assert!(moved.get("items").is_none());
    let current = moved["snapshot"].as_str().expect("snapshot");
    assert_ne!(current, snapshot);

    let restarted = read(&connection, 0, Some(current));
    assert!(restarted.get("restart").is_none(), "{restarted}");
    assert_eq!(restarted["items"][0]["cli_id"], "beta");
}
