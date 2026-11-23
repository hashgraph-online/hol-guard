//! A safe-alternative package block keeps its connector setup's group.

use serde_json::json;

use super::{compose, edited, reviewed, stamp, temp_home, HOME};

#[test]
fn a_connector_group_on_the_review_reaches_the_silent_row() {
    let workspace = temp_home("relay-package-connector-group");
    let group = format!("connector:{}", "a".repeat(64));
    let record = edited(reviewed(&workspace), |record| {
        record["review"]["queue_group_id"] = json!(group);
    });
    let (_, row) = compose(HOME, &record, &stamp()).expect("a plain package record composes");
    let row = row.expect("a safe-alternative block adds a row");
    assert_eq!(row["items"][0]["queue_group_id"], json!(group));
    let _ = std::fs::remove_dir_all(&workspace);
}

#[test]
fn without_a_connector_group_the_store_derives_one() {
    let workspace = temp_home("relay-package-no-connector-group");
    let (_, row) = compose(HOME, &reviewed(&workspace), &stamp()).expect("composes");
    let row = row.expect("a safe-alternative block adds a row");
    assert!(row["items"][0].get("queue_group_id").is_none());
    let _ = std::fs::remove_dir_all(&workspace);
}
