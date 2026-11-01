//! Replays the observed-MCP provider and catalog read vectors recorded from
//! the original Python store (see
//! `testdata/guard_store/record_mcp_provider_read_vectors.py`). Seeds,
//! payloads, errors and post-step table state all come from Python, never from
//! Rust output.

use crate::guard_store_local_cli_vectors_tests::replay_vectors;

const MCP_PROVIDER_READ_VECTORS: &str =
    include_str!("../testdata/guard_store/mcp_provider_read_vectors.json");

#[test]
fn replays_every_recorded_mcp_provider_read_scenario() {
    let compared_steps = replay_vectors(
        MCP_PROVIDER_READ_VECTORS,
        "guard-store-mcp-provider-read-vectors.v1",
    );
    assert!(compared_steps >= 39, "only {compared_steps} recorded steps");
}
