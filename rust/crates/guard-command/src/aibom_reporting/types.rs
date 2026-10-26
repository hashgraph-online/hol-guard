use super::*;

/// `adapters.base.HarnessContext` mirror.
#[derive(Debug, Clone, Default)]
pub struct HarnessContext {
    pub home_dir: PathBuf,
    pub workspace_dir: Option<PathBuf>,
    pub guard_home: PathBuf,
    pub executable_overrides: Map<String, Value>,
    pub home_override_explicit: bool,
    pub workspace_override_explicit: bool,
}

/// Duck-typed inventory-item mirror used across reporting summaries.
/// Carries `item_kind`, `metadata`, `risk_level`, `drift_state`, and `item_id`.
#[derive(Debug, Clone, Default)]
pub struct InventoryItem {
    pub item_id: String,
    pub item_kind: String,
    pub metadata: Map<String, Value>,
    pub risk_level: String,
    pub drift_state: String,
}

/// `GuardAgentInventoryDrift` mirror (only `state` is read here).
#[derive(Debug, Clone, Default)]
pub struct InventoryDrift {
    pub state: String,
}

/// `GuardAgentInventorySnapshot` mirror — only the fields reporting consumes.
#[derive(Debug, Clone, Default)]
pub struct GuardAgentInventorySnapshot {
    pub agent_id: String,
    pub agent_type: String,
    pub items: Vec<InventoryItem>,
    pub findings: Vec<Value>,
    pub drift: Vec<InventoryDrift>,
    pub sources: Vec<Value>,
    pub redaction_report: Map<String, Value>,
}

// ---------------------------------------------------------------------------
// Seams.
// ---------------------------------------------------------------------------

/// `.inventory_contract` redaction seam.
pub trait RedactionApi {
    /// `redact_local_path(path, home_dir=)`
    fn redact_local_path(&self, path: &std::path::Path, home_dir: &std::path::Path) -> String;
    /// `_redact_command_value(value, home_dir, workspace_dir)`
    fn _redact_command_value(
        &self,
        value: &str,
        home_dir: &std::path::Path,
        workspace_dir: Option<&std::path::Path>,
    ) -> String;
}

/// `aibom_cli` + inventory-contract api seam.
pub trait ReportingApi {
    /// `extract_aibom_metadata_extensions(metadata)`
    fn extract_aibom_metadata_extensions(
        &self,
        metadata: &Map<String, Value>,
    ) -> Map<String, Value>;
    /// `apply_local_trust_metadata(artifact, *, captured_at, item_kind, metadata, workspace_dir)`
    fn apply_local_trust_metadata(
        &self,
        artifact: &Map<String, Value>,
        captured_at: &str,
        item_kind: &str,
        metadata: Map<String, Value>,
        workspace_dir: Option<&std::path::Path>,
    ) -> Map<String, Value>;
    /// `_sync_summary(store)` → `{synced: bool, synced_at: Option<str>, ..}`
    fn _sync_summary(&self, store: &dyn StoreApi) -> Map<String, Value>;
}

/// `store.list_inventory()` / cloud-profile seam.
pub trait StoreApi {
    /// `store.list_inventory()` → iterable of stored artifact rows.
    fn list_inventory(&self) -> Vec<Map<String, Value>>;
    /// `store.get_cloud_sync_profile()`
    fn get_cloud_sync_profile(&self) -> Option<Value>;
    /// `store.get_cloud_workspace_id()`
    fn get_cloud_workspace_id(&self) -> Option<Value>;
}

/// Bundle of reporting seams.
pub struct ReportingDeps<'a> {
    pub api: &'a dyn ReportingApi,
    pub redaction: &'a dyn RedactionApi,
    pub store: &'a dyn StoreApi,
}
