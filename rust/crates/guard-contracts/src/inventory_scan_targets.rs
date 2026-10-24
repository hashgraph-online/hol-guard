//! `InventoryScanTargets` - wire contract for the resident op that decides
//! which MCP configurations and skill collections a Cisco inventory scan
//! reads.
//!
//! The selection is what the scan is: a configuration this answer leaves out
//! is a configuration no scanner opens, and a skill collection it misses is
//! instructions nothing reports on. Picking the targets is a walk of the
//! workspace and the home directory - `is_file`, `is_dir`, a recursive search
//! for `SKILL.md`, and `Path.resolve()` on everything that gets deduplicated
//! or labelled. That is decision-critical filesystem work, so the resident
//! does it and the caller runs the scanners against what comes back.
//!
//! One request covers a whole inventory pass. `run_cisco_inventory_scans` is
//! called once per pass, so the targets are chosen once rather than per
//! artifact.
//!
//! Every path in the request is sent as the caller holds it, relative values
//! included, and `cwd` is the directory the caller would have resolved them
//! against. The resident has its own working directory and resolving against
//! that one would answer about a directory the caller never stood in.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const INVENTORY_SCAN_TARGETS_REQUEST_SCHEMA: &str = "guard-inventory-scan-targets-request.v1";
/// Schema discriminator for the result.
pub const INVENTORY_SCAN_TARGETS_RESULT_SCHEMA: &str = "guard-inventory-scan-targets-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const INVENTORY_SCAN_TARGETS_FEATURE: &str = "inventory-scan-targets-v1";
/// Largest canonical request serialization the op will accept.
///
/// Held under [`MAX_NATIVE_REQUEST_BYTES`](crate::MAX_NATIVE_REQUEST_BYTES),
/// which the transport enforces on the frame before this op ever sees it. A
/// bound above that would be unreachable: a request between the two would be
/// refused as a malformed frame instead of being told its own size is why.
pub const INVENTORY_SCAN_TARGETS_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most detected artifacts one request may carry. A detection larger than
/// this is a detection the caller should have bounded; the op refuses rather
/// than walking an unbounded list.
pub const INVENTORY_SCAN_TARGETS_MAX_ARTIFACTS: usize = 4096;
/// Most directory entries the whole request may visit while searching for
/// skill collections.
///
/// The Python this replaces had no bound, so a deep or looping tree walked
/// until it finished. The resident answers several callers, so the walk is
/// bounded and a request that exceeds it is refused. A refusal leaves the
/// caller without targets, which skips the scan; answering with whatever the
/// walk had reached would report a clean inventory of a tree that was never
/// read.
pub const INVENTORY_SCAN_TARGETS_MAX_VISITED_ENTRIES: usize = 200_000;

/// One detected artifact, as much of it as target selection reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventoryScanTargetArtifactV1 {
    /// The native artifact category. Only `mcp_server` contributes an MCP
    /// configuration, and only `skill` and `skill_file` contribute a skill
    /// collection.
    pub artifact_type: String,
    /// The artifact's own configuration path, as the caller holds it. Absent
    /// and `null` both mean the artifact declares none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    /// `metadata["skill_root"]`, the workspace- or home-relative directory a
    /// detection recorded for a skill. Absent and `null` both mean there is
    /// none, including when the metadata held a non-string value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventoryScanTargetsRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The harness being inventoried. `hermes` keeps its own skill directory,
    /// which is preferred over the detection's artifacts when it holds any
    /// skills at all.
    pub harness: String,
    /// The directory the caller resolves its own relative paths against.
    pub cwd: String,
    /// The harness context's home directory.
    pub home_dir: String,
    /// The harness context's workspace directory, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_dir: Option<String>,
    /// The detected artifacts, in the caller's order.
    pub artifacts: Vec<InventoryScanTargetArtifactV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InventoryScanTargetsResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_inventory_scan_targets_*` codes.
    pub code: String,
    /// `{"mcp_targets": [{"root": ..., "config_path": ..., "label": ...}],
    /// "skill_roots": [...]}`. The MCP targets are in scan order and already
    /// deduplicated by what their root and configuration resolve to; the
    /// label is the configuration's workspace-relative name, or its
    /// root-relative name, or its bare file name, whichever first describes
    /// it without naming a directory outside the scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
