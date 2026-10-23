//! `InventoryScanFindings` — wire contract for the resident op that turns a
//! scanner run and the symlink evidence an inventory already carries into
//! findings and sources.
//!
//! Three readings decide what a scan reports: which scanner produced a run and
//! whether it was available, what severity each raw finding earns and the score
//! it moves the inventory by, and which recorded symlink states are worth a
//! finding of their own. Each is a protection decision — a `critical` that
//! normalizes to `info`, a failed scanner that reports as merely missing, or an
//! escaped symlink that reports nothing at all all understate what the scan
//! found. `guard_command::inventory_contract` already owns the grammar, so
//! Python asks for the answers instead of keeping a second copy of the rules.
//!
//! Finding text crosses a privacy boundary on the way out: scanner titles,
//! descriptions and file paths name local directories, and the same request
//! that classifies them redacts them, so no caller can publish the raw text by
//! forgetting to call the redactor first.
//!
//! A harness asks once per scan: every run and every item ride together so one
//! round trip covers the whole inventory.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Schema discriminator for the request.
pub const INVENTORY_SCAN_FINDINGS_REQUEST_SCHEMA: &str = "guard-inventory-scan-findings-request.v1";
/// Schema discriminator for the result.
pub const INVENTORY_SCAN_FINDINGS_RESULT_SCHEMA: &str = "guard-inventory-scan-findings-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const INVENTORY_SCAN_FINDINGS_FEATURE: &str = "inventory-scan-findings-v1";
/// Largest canonical request serialization the op will accept.
///
/// The transport frames at most [`crate::MAX_NATIVE_REQUEST_BYTES`], and the
/// envelope the sender builds around this request is the larger of the two, so
/// the bound sits a frame's slack under that ceiling. A larger number admits no
/// larger scan: it only moves the refusal from this op, which names the request
/// as too big, to the client, which drops an unframeable request as a runtime
/// that stopped answering.
pub const INVENTORY_SCAN_FINDINGS_MAX_BYTES: usize = crate::MAX_NATIVE_REQUEST_BYTES - 64 * 1024;
/// Most scanner runs one request may carry.
pub const INVENTORY_SCAN_FINDINGS_MAX_RUNS: usize = 256;
/// Most inventory items one request may carry.
pub const INVENTORY_SCAN_FINDINGS_MAX_ITEMS: usize = 8192;

/// One inventory item, as much of it as the finding grammar reads.
///
/// `metadata` carries `configPath`, which associates a scanner finding with the
/// artifact it belongs to, and `sourceOfTruth`, which carries the symlink
/// validation state. Nothing else about the item is used, so nothing else is
/// asked for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventoryScanFindingsItemV1 {
    /// The item's identity, which a finding attributes itself to.
    pub item_id: String,
    /// The item's published metadata.
    pub metadata: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventoryScanFindingsRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The harness the symlink findings are attributed to.
    pub harness: String,
    /// The operator home directory the redactor measures a path against.
    pub home_dir: String,
    /// The workspace directory, when the scan had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_dir: Option<String>,
    /// The directory a relative path would resolve against. The callers only
    /// pass absolute paths, so it decides nothing, but the redactor takes it
    /// rather than inventing one.
    pub cwd: String,
    /// Whether the caller's detection walked symlinks at all. A detection that
    /// did not look has no symlink evidence to report, and reporting findings
    /// from stale metadata would claim an inspection that never ran.
    ///
    /// It carries no default, and neither do the two fields below. Every
    /// caller sends all three, so a request missing one is a request that was
    /// built wrong or lost something in transit, and the three stand for the
    /// scan's protection-relevant input: a default would turn that request
    /// into an answered scan that walked no links and read no runs, which
    /// reads at the caller exactly like a clean inventory.
    pub include_symlinks: bool,
    /// The scanner runs, as the duck-typed objects the Python caller read.
    pub cisco_runs: Vec<Map<String, Value>>,
    /// The inventory items the findings attach to, in the caller's order.
    pub items: Vec<InventoryScanFindingsItemV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventoryScanFindingsResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_inventory_scan_findings_*` codes.
    pub code: String,
    /// `{"findings": [...], "sources": [...]}` — the scanner findings followed
    /// by the symlink findings, and the scanner sources, each in the order the
    /// request's runs and items were listed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
