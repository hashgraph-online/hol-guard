//! Port of `src/codex_plugin_scanner/guard/aibom_reporting.py` (RTM-027).
//!
//! AIBOM reporting helpers preserving the public CLI dependency seams.
//!
//! TODO(deps): the Python module lazily resolves `.aibom_cli` (`api`) for
//! `extract_aibom_metadata_extensions`, `_metadata_lookup_from_snapshots`,
//! `_redact_inventory_store_item`, `_store_row_config_path`,
//! `_store_only_artifact_metadata_extensions`, `_sync_summary`, and
//! `apply_local_trust_metadata`, and `.inventory_contract` for
//! `_redact_command_value`. Until those land they sit behind the
//! `ReportingApi` + `StoreApi` + `RedactionApi` seams. `HarnessContext` is
//! mirrored locally.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

#[path = "aibom_reporting/types.rs"]
mod types;
pub use types::{
    GuardAgentInventorySnapshot, HarnessContext, InventoryDrift, InventoryItem, RedactionApi,
    ReportingApi, ReportingDeps, StoreApi,
};
#[path = "aibom_reporting/summaries.rs"]
mod summaries;
pub use summaries::{
    _metadata_lookup_from_snapshots, summarize_aibom_drift, summarize_aibom_layers,
    summarize_aibom_trust,
};
#[path = "aibom_reporting/store_rows.rs"]
mod store_rows;
pub use store_rows::_artifact_rows_from_store;

#[path = "aibom_reporting/redaction.rs"]
mod redaction;
pub use redaction::_aggregate_redaction_report;
use redaction::value_display;
#[path = "aibom_reporting/rendering.rs"]
mod rendering;
use rendering::py_round_f64;
pub use rendering::{_aibom_connection_status, _render_aibom_markdown};
