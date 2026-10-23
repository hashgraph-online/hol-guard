//! Compare public operational observations to immutable private quota prefixes.

use crate::crypto::is_sha256;
use crate::provider_quota::{invalid, visit_provider_quota_snapshots};
use crate::Result;
use serde_json::Value;
use std::path::Path;

const MAX_ROWS: usize = 30_000;

/// Compare chronological operational snapshots with exact prefixes of one
/// private Python journal and an independently pinned final journal hash.
/// This never grants inference or qualifies a benchmark result.
pub fn verify_provider_quota_observations(
    root: &Path,
    expected_config_digest: &str,
    expected_allowance_digest: Option<&str>,
    expected_final_journal_hash: &str,
    observations: &[Value],
) -> Result<Value> {
    if !is_sha256(expected_final_journal_hash)
        || observations.is_empty()
        || observations.len() > MAX_ROWS + 1
        || observations
            .iter()
            .any(|row| !row["journal_hash"].as_str().is_some_and(is_sha256))
    {
        return Err(invalid(
            "outside provider history pins and observations required",
        ));
    }
    let mut matched = 0_usize;
    let final_snapshot = visit_provider_quota_snapshots(
        root,
        expected_config_digest,
        expected_allowance_digest,
        |snapshot| {
            while matched < observations.len()
                && observations[matched]["journal_hash"] == snapshot["journal_hash"]
            {
                if observations[matched] != *snapshot {
                    return Err(invalid(
                        "provider observation differs from durable journal prefix",
                    ));
                }
                matched += 1;
            }
            Ok(())
        },
    )?;
    if matched != observations.len()
        || final_snapshot["journal_hash"] != expected_final_journal_hash
    {
        return Err(invalid(
            "provider observations omit or reorder journal prefixes",
        ));
    }
    Ok(final_snapshot)
}
