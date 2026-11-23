//! The generation a package claim verifies its rows at.

use serde_json::json;

use super::store;

/// A claim spent after the relay's own remembered allow verifies the rows at
/// the generation that write was finalized at; the published state the bound
/// check compares with the persisted one is left as it was.
#[test]
fn a_claim_after_its_own_write_reads_rows_at_that_generation() {
    let published = json!({"generation": 3, "enforcement": "enforce"});
    let mut state = published.clone();
    store::after_own_write(&mut state, 4);
    assert_eq!(state["generation"], 4);
    assert_eq!(published["generation"], 3);
    // A published generation already past the write is kept.
    let mut later = json!({"generation": 5});
    store::after_own_write(&mut later, 4);
    assert_eq!(later["generation"], 5);
    // A state that names no generation takes the write's.
    let mut unnamed = json!({});
    store::after_own_write(&mut unnamed, 1);
    assert_eq!(unnamed["generation"], 1);
}
