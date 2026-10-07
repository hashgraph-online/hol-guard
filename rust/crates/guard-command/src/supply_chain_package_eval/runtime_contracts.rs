use super::*;

/// `restricted_archive_contract.RestrictedArchiveFailure` (:12) mirror — a
/// stable, non-sensitive reason the archive download stopped.
#[derive(Debug, Clone, Default)]
pub struct RestrictedArchiveFailure {
    pub code: String,
    pub message: String,
}

/// `restricted_archive_contract.RestrictedArchiveDownload` (:21) mirror — a
/// bounded archive blob whose digest was computed while reading. The temp file
/// lifecycle (`cleanup`/`__del__`) is owned by the seam implementation; this
/// mirror only carries the path.
#[derive(Debug, Clone, Default)]
pub struct RestrictedArchiveDownload {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub source_url: String,
    pub final_url: String,
}

/// `restricted_archive_contract.RestrictedArchiveDownloadResult` (:49)
/// discriminated mirror.
#[derive(Debug, Clone)]
pub enum RestrictedArchiveDownloadResult {
    Success(RestrictedArchiveDownload),
    Failure(RestrictedArchiveFailure),
}

/// `.runtime.restricted_archive_download` seam (:66-75 imports).
pub trait RestrictedArchiveApi {
    /// `download_restricted_archive(source_url, max_bytes=, max_redirects=,
    /// timeout_seconds=, temp_dir=)` (:189) — bounded public-HTTPS-only
    /// download. Policy rejections return `Failure(...)` (mirroring the Python
    /// result union), not `Err`.
    fn download_restricted_archive(
        &self,
        source_url: &str,
        max_bytes: u64,
        max_redirects: u32,
        timeout_seconds: f64,
        temp_dir: Option<&Path>,
    ) -> EvalResult<RestrictedArchiveDownloadResult>;
}

/// `.native_archive_inspection` seam (:33 import).
pub trait NativeArchiveApi {
    /// `inspect_archive_native(path, expected_sha256=, state_dir=,
    /// timeout_seconds=, max_archive_bytes=, max_files=, max_expanded_bytes=,
    /// max_member_bytes=, max_package_json_bytes=, max_memory_bytes=,
    /// max_decompression_ratio=, max_nested_archives=, max_path_depth=)`
    /// (native_archive_inspection.py:101) -> `ArchiveInspectionResult` dict
    /// mirror.
    #[allow(clippy::too_many_arguments)]
    fn inspect_archive_native(
        &self,
        path: &Path,
        expected_sha256: &str,
        state_dir: &Path,
        timeout_seconds: f64,
        max_archive_bytes: u64,
        max_files: u64,
        max_expanded_bytes: u64,
        max_member_bytes: u64,
        max_package_json_bytes: u64,
        max_memory_bytes: u64,
        max_decompression_ratio: f64,
        max_nested_archives: u64,
        max_path_depth: u64,
    ) -> EvalResult<Map<String, Value>>;
}

/// `.runtime.workspace_path_guard` read wrappers seam (:106-110 imports).
/// `resolve_path_within_workspace` is already reused from
/// `package_intent_common`; these mirror the two read helpers.
pub trait WorkspaceIoApi {
    /// `read_text_within_workspace(workspace_dir, relative_path)` -> file text
    /// or `None` on traversal/missing/decode failure.
    fn read_text(&self, workspace_dir: &Path, relative_path: &str) -> Option<String>;
    /// `read_bytes_within_workspace(workspace_dir, relative_path)` -> file
    /// bytes or `None` on traversal/missing failure.
    fn read_bytes_within_workspace(
        &self,
        workspace_dir: &Path,
        relative_path: &str,
    ) -> Option<Vec<u8>>;
}

/// `.store.GuardStore` supply-chain extras seam — the eval-cache, evidence,
/// and OAuth-health methods this module calls on `store` (:547, :705, :873,
/// :1247, :2135) that are not part of the `SupplyChainStore` trait.
pub trait StoreExtrasApi {
    /// `store.get_cached_supply_chain_evaluation(workspace_id=,
    /// package_intent_hash=, feed_snapshot_hash=, policy_hash=,
    /// scoring_version=, bundle_version=)` (store_cloud_events.py:169) ->
    /// cached `decision` dict payload (`to_cache_dict()` shape) or `None`.
    fn get_cached_supply_chain_evaluation(
        &self,
        workspace_id: &str,
        package_intent_hash: &str,
        feed_snapshot_hash: &str,
        policy_hash: &str,
        scoring_version: &str,
        bundle_version: &str,
    ) -> Option<Map<String, Value>>;
    /// `deps.store_extras.cache_supply_chain_evaluation(...)` (store_cloud_events.py:144)
    /// — persist a `PackageRequestEvaluation.to_cache_dict()` payload.
    #[allow(clippy::too_many_arguments)]
    fn cache_supply_chain_evaluation(
        &self,
        workspace_id: &str,
        package_intent_hash: &str,
        feed_snapshot_hash: &str,
        policy_hash: &str,
        scoring_version: &str,
        bundle_version: &str,
        decision: &Map<String, Value>,
        now: &str,
    );
    /// `store.add_evidence(record)` (store_evidence_facade.py:53) — the
    /// `EvidenceRecord` is passed as its dict mirror.
    fn add_evidence(&self, record: &Map<String, Value>);
    /// `store.get_oauth_local_credential_health()` (store_oauth.py:300) ->
    /// `{configured, state, backend, fallback_backend, ...}` health dict.
    fn get_oauth_local_credential_health(&self) -> Map<String, Value>;
}

/// `.local_supply_chain.resolve_package_firewall_entitlement_with_refresh`
/// seam (local_supply_chain.py:461) — resolve the package-firewall
/// entitlement, refreshing from Guard Cloud first when stale.
pub trait EntitlementRefreshApi {
    /// `resolve_package_firewall_entitlement_with_refresh(store)` -> entitlement
    /// dict (`{state, source, expires_at, ...}`).
    fn resolve_package_firewall_entitlement_with_refresh(
        &self,
        store: &dyn SupplyChainStore,
    ) -> EvalResult<Map<String, Value>>;
}

/// `..config.load_guard_config` seam (:31 import).
pub trait ConfigLoaderApi {
    /// `load_guard_config(guard_home, workspace=,
    /// require_canonical_workspace=)` -> `GuardConfig`.
    fn load_guard_config(
        &self,
        guard_home: &Path,
        workspace: Option<&Path>,
        require_canonical_workspace: bool,
    ) -> EvalResult<GuardConfig>;
}
