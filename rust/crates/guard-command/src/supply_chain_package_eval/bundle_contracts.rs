use super::*;
use crate::pep440::{SpecifierSet, Version};

/// `supply_chain_bundle_models.SupplyChainBundleResponse` (:460) mirror —
/// the signed Guard Cloud bundle response. `signed_bundle` preserves the exact
/// bundle JSON for hash/signature verification; `bundle` holds the
/// `to_dict()`-shaped parsed-bundle payload for seam consumers that only need
/// dict access (mirrors `SupplyChainBundle` without porting its dataclasses).
#[derive(Debug, Clone, Default)]
pub struct SupplyChainBundleResponse {
    pub bundle: Map<String, Value>,
    pub signed_bundle: Map<String, Value>,
    pub payload_hash: String,
    pub signature: String,
    pub signature_algorithm: String,
    /// `SupplyChainVerificationKey.to_dict()` payloads.
    pub verification_keys: Vec<Map<String, Value>>,
    /// The typed response the seam already decoded. Offline decisions reuse
    /// it instead of re-serialising and re-parsing the whole bundle per call;
    /// `None` means a caller must parse from `to_dict()`.
    pub parsed: Option<std::sync::Arc<crate::supply_chain_bundle::SupplyChainBundleResponse>>,
}

impl SupplyChainBundleResponse {
    /// `to_dict` (:470).
    pub fn to_dict(&self) -> Value {
        json!({
            "bundle": Value::Object(self.signed_bundle.clone()),
            "payloadHash": self.payload_hash,
            "signature": self.signature,
            "signatureAlgorithm": self.signature_algorithm,
            "verificationKeys": self
                .verification_keys
                .iter()
                .cloned()
                .map(Value::Object)
                .collect::<Vec<Value>>(),
        })
    }
}

/// `.runtime.supply_chain_bundle` seam (:86-96 imports) plus the module-local
/// `_bundle_meta` helper (:2324).
pub trait SupplyChainBundleApi {
    /// `load_supply_chain_bundle_response(raw_json)` (supply_chain_bundle.py /
    /// supply_chain_bundle_runtime.py:83). `raw_json` is the decoded JSON
    /// object (string callers `serde_json::from_str` first);
    /// `EvalError::Validation` maps `SupplyChainBundleMalformedError`.
    fn load_supply_chain_bundle_response(
        &self,
        raw_json: &Value,
    ) -> EvalResult<SupplyChainBundleResponse>;
    /// Parsing a stored response is not proof that its cached verdict is current.
    /// Use the native signature/key-state/freshness verifier and paired scope.
    /// The boolean reports a matching recorded sync keyring, not a new trust
    /// root. Missing sync context cannot establish a permissive cache hit.
    fn validate_cached_supply_chain_bundle(
        &self,
        response: &SupplyChainBundleResponse,
        workspace_id: &str,
        now: Option<f64>,
        sync_keyring: Option<&Value>,
        synced_bundle_version: Option<&str>,
    ) -> EvalResult<bool> {
        let decoded;
        let typed = match response.parsed.as_deref() {
            Some(typed) => typed,
            None => {
                decoded = crate::supply_chain_bundle::load_supply_chain_bundle_response(
                    &response.to_dict(),
                )
                .map_err(|error| EvalError::Validation(error.to_string()))?;
                &decoded
            }
        };
        if typed.bundle.workspace_id != workspace_id {
            return Err(EvalError::Validation(
                "Cached bundle belongs to another workspace".into(),
            ));
        }
        if sync_keyring.is_some_and(|payload| {
            payload.get("workspace_id").and_then(Value::as_str) != Some(workspace_id)
        }) {
            return Err(EvalError::Validation(
                "Cached keyring belongs to another workspace".into(),
            ));
        }
        let keys = crate::supply_chain_bundle::load_supply_chain_verification_keys(sync_keyring)
            .map_err(|error| EvalError::Validation(error.to_string()))?;
        if sync_keyring.is_some() && keys.is_empty() {
            return Err(EvalError::Validation("Cached sync keyring is empty".into()));
        }
        crate::supply_chain_bundle::verify_supply_chain_bundle_response(
            typed,
            (!keys.is_empty()).then_some(keys.as_slice()),
            synced_bundle_version,
            now,
            &crate::supply_chain_bundle::RingRsaPssVerify,
        )
        .map_err(|error| EvalError::Validation(error.to_string()))?;
        if !keys.is_empty() {
            let signer = typed
                .verification_keys
                .iter()
                .find(|key| key.key_id == typed.bundle.key_id)
                .ok_or_else(|| EvalError::Validation("Cached signing key is missing".into()))?;
            // The response can advertise an old active key after the synced
            // keyring revoked it. Both views must permit the signing key.
            // The verifier already requires a matching fingerprint. Inspect
            // every matching entry so an active alias cannot hide revocation.
            for current in keys
                .iter()
                .filter(|key| key.fingerprint_sha256 == signer.fingerprint_sha256)
            {
                let usable = match current.state.as_str() {
                    "active" => true,
                    "grace" => {
                        let clock = now.or_else(|| {
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .ok()
                                .map(|time| time.as_secs_f64())
                        });
                        let until = current
                            .valid_until_timestamp()
                            .map_err(|error| EvalError::Validation(error.to_string()))?;
                        matches!((clock, until), (Some(clock), Some(until)) if clock <= until)
                    }
                    _ => false,
                };
                if !usable {
                    return Err(EvalError::Validation(
                        "Synced signing key is not current".into(),
                    ));
                }
            }
        }
        Ok(!keys.is_empty())
    }
    /// `check_supply_chain_bundle_freshness(bundle, now=)` (:114). `now` is
    /// epoch seconds (`None` = wall clock). `EvalError::Validation` maps
    /// `SupplyChainBundleExpiredError`.
    fn check_supply_chain_bundle_freshness(
        &self,
        bundle: &Map<String, Value>,
        now: Option<f64>,
    ) -> EvalResult<()>;
    /// `evaluate_cached_supply_chain_bundle(response, package_name=,
    /// package_version=, ecosystem=, now=)` (:276) ->
    /// `OfflineSupplyChainDecision` dict mirror.
    fn evaluate_cached_supply_chain_bundle(
        &self,
        response: &SupplyChainBundleResponse,
        package_name: &str,
        package_version: Option<&str>,
        ecosystem: Option<&str>,
        now: Option<f64>,
    ) -> EvalResult<Map<String, Value>>;
    /// `_bundle_meta(bundle_payload)` (:2324) -> `{bundle_version,
    /// feed_snapshot_hash, policy_hash, scoring_version}`; keys stay snake_case
    /// like the Python return dict.
    fn supply_chain_bundle_meta(
        &self,
        bundle_payload: &Map<String, Value>,
    ) -> EvalResult<BTreeMap<String, String>>;
}

/// `packaging` + `.runtime.js_semver` seam — per-package policy version
/// resolution (:27, :3086-5038 usage sites).
pub trait JsSemverApi {
    /// `SpecifierSet(range)` — parse a PEP-440 specifier set.
    /// `EvalError::Validation` maps `InvalidSpecifier`.
    fn specifier_set(&self, range: &str) -> EvalResult<SpecifierSet>;
    /// `Version(value)` — parse a PEP-440 version.
    /// `EvalError::Validation` maps `InvalidVersion`.
    fn version(&self, value: &str) -> EvalResult<Version>;
    /// `version in specifier_set` membership test.
    fn version_in_specifier_set(&self, version: &Version, set: &SpecifierSet) -> bool;
    /// `js_semver.highest_js_version_for_selector(versions, selector)` (:156)
    /// -> highest matching version string, if any.
    fn highest_js_version_for_selector(
        &self,
        versions: &[String],
        selector: &str,
    ) -> Option<String>;
    /// `js_semver.version_matches_js_selector(version, selector)` (:130).
    fn version_matches_js_selector(&self, version: &str, selector: &str) -> bool;
}

/// `.runtime.supply_chain` seam (:85 import).
pub trait RiskDetectApi {
    /// `detect_supply_chain_risk(content, file_path=)` (supply_chain.py:115)
    /// -> `RiskSignalV2` dict mirrors (`signal_id`, `category`, `severity`,
    /// `confidence`, `message`, `file_path`, ...).
    fn detect_supply_chain_risk(
        &self,
        content: &str,
        file_path: Option<&str>,
    ) -> EvalResult<Vec<Map<String, Value>>>;
    /// Synchronous evaluate-and-collect pass over a package's risk-bearing
    /// surfaces (command text + manifest bodies); returns the merged signal
    /// list plus the highest-severity summary the evaluator folds into
    /// `reasons`/`risk_summary`.
    fn evaluate_supply_chain_risk_sync(
        &self,
        content: &str,
        file_path: Option<&str>,
    ) -> EvalResult<Vec<Map<String, Value>>>;
}

/// `.runtime.package_manifest_diff` seam (:63-65 imports).
/// `_DeadlineExceededError` (package_manifest_diff.py:33) maps to
/// `EvalError::Validation("deadline_exceeded ...")` — callers treat it the
/// same as the Python `except _DeadlineExceededError` arms.
pub trait ManifestDepsApi {
    // `manifest_dependency_targets.evaluation_targets` is implemented inline in
    // `targets::manifest_dependency_targets` — the resident trait seam was a
    // stub that never produced `manifest_unsynced`, degrading the eval to
    // `monitor` for unrecognized lockfile deps.
    /// `_dependency_map_for_path(path, text, deadline=)` (:81) — dispatches on
    /// the manifest/lockfile filename to the per-format parser. `deadline` is
    /// a monotonic deadline in seconds; expiry raises
    /// `EvalError::Validation` carrying the deadline reason.
    fn dependency_map_for_path(
        &self,
        path: &str,
        text: &str,
        deadline: f64,
    ) -> EvalResult<BTreeMap<String, String>>;
    /// `parse_manifest_dependencies(path=, text=, byte_limit=, deadline_ms=)`
    /// (:65) — swallows every parse failure into `{}` like the Python body.
    fn parse_manifest_dependencies(
        &self,
        path: &str,
        text: &str,
        byte_limit: usize,
        deadline_ms: u64,
    ) -> BTreeMap<String, String>;
}

/// `supply_chain_package_identity.CanonicalPackageIdentity` (:17) mirror.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalPackageIdentity {
    pub ecosystem: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: String,
}

impl CanonicalPackageIdentity {
    /// `qualified_name` (:26).
    pub fn qualified_name(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{ns}/{}", self.name),
            None => self.name.clone(),
        }
    }

    /// `display` (:30) — `{ecosystem}:{qualified_name}@{version}`.
    pub fn display(&self) -> String {
        format!(
            "{}:{}@{}",
            self.ecosystem,
            self.qualified_name(),
            self.version
        )
    }
}

/// `.runtime.supply_chain_package_identity` seam (:99-104 imports).
/// `PackageIdentityError` maps to `EvalError::Validation`.
pub trait PackageIdentityApi {
    /// `canonical_package_identity(ecosystem=, namespace=, name=, version=)`
    /// (:57) — build a canonical key from already-structured bundle fields.
    fn canonical_package_identity(
        &self,
        ecosystem: &str,
        namespace: Option<&str>,
        name: &str,
        version: &str,
    ) -> EvalResult<CanonicalPackageIdentity>;
    /// `parse_package_identity(ecosystem=, package_name=, version=)` (:93) —
    /// parse one target name using the selected ecosystem's syntax.
    fn parse_package_identity(
        &self,
        ecosystem: &str,
        package_name: &str,
        version: &str,
    ) -> EvalResult<CanonicalPackageIdentity>;
    /// `normalize_ecosystem(ecosystem)` (:34).
    fn normalize_ecosystem(&self, ecosystem: &str) -> EvalResult<String>;
    /// `normalize_qualified_package_name(ecosystem, package_name)` (:121).
    fn normalize_qualified_package_name(
        &self,
        ecosystem: &str,
        package_name: &str,
    ) -> EvalResult<String>;
}
