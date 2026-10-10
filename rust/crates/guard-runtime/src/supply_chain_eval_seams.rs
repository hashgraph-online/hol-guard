//! Test seams, saved-policy probe and public-registry metadata for the
//! resident's `supply_chain_eval` op.
//!
//! The test seams are honored only when the resident was started with the
//! dedicated opt-in, and only in a small known-key, bounded shape. The
//! saved-policy probe is the caller's answer to `saved_policy_probe_required`.
//! Registry metadata is fetched by the caller that owns the managed network
//! policy (`guard_command::egress_broker`); the override replaces that fetch.

use guard_command::registry_metadata_transport::fetch_registry_metadata;
use guard_command::supply_chain_package_eval::{
    RegistryDocument, RegistryMetadataApi, SavedPolicyProbe,
};
use guard_contracts::SupplyChainEvalRequestV1;
use serde_json::{Map, Value};

/// Public-registry metadata for range resolution. The fetch is the shared
/// plain-GET transport; the test override replaces it wholesale.
pub(crate) struct ResidentRegistryMetadata {
    pub(crate) metadata_override: Option<Map<String, Value>>,
}

impl RegistryMetadataApi for ResidentRegistryMetadata {
    fn fetch_registry_metadata(&self, url: &str, accept: &str) -> Option<RegistryDocument> {
        match &self.metadata_override {
            // A parsed fixture has already lost document order, so its version
            // order is the sorted key order. Only the transport sees real
            // registry order; the fixtures are a test seam.
            Some(fixtures) => {
                let object = fixtures.get(url).and_then(Value::as_object).cloned()?;
                let version_order = object
                    .get("versions")
                    .and_then(Value::as_object)
                    .map(|versions| versions.keys().cloned().collect())
                    .unwrap_or_default();
                Some(RegistryDocument {
                    object,
                    version_order,
                })
            }
            None => fetch_registry_metadata(url, accept),
        }
    }
}

/// Dedicated opt-in for the supply-chain test seams. It is deliberately not
/// `HOL_GUARD_NATIVE_DIAGNOSTIC`: diagnostics widen what the resident reports,
/// and must never also let a request supply auth, entitlement, or registry
/// fixtures. The resident only sees this variable when the spawner's isolated
/// environment allowlist forwards it.
pub(crate) const RESIDENT_TEST_SEAMS_ENV: &str = "HOL_GUARD_RESIDENT_TEST_SEAMS";

/// Whether the supply-chain test seams are enabled for this resident. Only
/// the dedicated variable counts; the lookup is injected so tests can prove
/// diagnostics alone never enable them without mutating the process env.
pub(crate) fn test_seams_enabled_from(lookup: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    lookup(RESIDENT_TEST_SEAMS_ENV).is_some()
}

pub(crate) const TEST_SEAM_MAX_BYTES: usize = 8192;
const TEST_ENTITLEMENT_KEYS: [&str; 4] = ["allowed", "reason", "tier", "upgrade_cta"];
const TEST_REGISTRY_URL_PREFIXES: [&str; 2] =
    ["https://registry.npmjs.org/", "https://pypi.org/pypi/"];
const TEST_AUTH_KEYS: [&str; 5] = [
    "sync_url",
    "access_token",
    "issuer",
    "dpop_key_material",
    "error",
];

/// A test-seam override is honored only when it is a small JSON object of known
/// keys. Anything else is refused outright rather than half-applied, so the
/// test-only path cannot carry an unbounded or unexpected shape into a request.
pub(crate) fn test_seam_overrides_are_valid(request: &SupplyChainEvalRequestV1) -> bool {
    let bounded = |value: &Value| {
        serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= TEST_SEAM_MAX_BYTES)
    };
    let auth_valid = request
        .sync_auth_context_override
        .as_ref()
        .is_none_or(|auth| {
            bounded(auth)
                && auth.as_object().is_some_and(|map| {
                    map.iter().all(|(key, value)| {
                        TEST_AUTH_KEYS.contains(&key.as_str())
                            && match key.as_str() {
                                "dpop_key_material" => value.is_null() || value.is_object(),
                                _ => value.is_string(),
                            }
                    })
                })
        });
    let entitlement_valid =
        request
            .package_entitlement_override
            .as_ref()
            .is_none_or(|entitlement| {
                bounded(entitlement)
                    && entitlement.as_object().is_some_and(|map| {
                        map.iter().all(|(key, value)| {
                            TEST_ENTITLEMENT_KEYS.contains(&key.as_str())
                                && match key.as_str() {
                                    "allowed" => value.is_boolean(),
                                    "upgrade_cta" => value.is_null() || value.is_string(),
                                    _ => value.is_string(),
                                }
                        })
                    })
            });
    let registry_valid = request
        .registry_metadata_override
        .as_ref()
        .is_none_or(|fixtures| {
            bounded(fixtures)
                && fixtures.as_object().is_some_and(|map| {
                    map.iter().all(|(url, value)| {
                        TEST_REGISTRY_URL_PREFIXES
                            .iter()
                            .any(|prefix| url.starts_with(prefix))
                            && (value.is_null() || value.is_object())
                    })
                })
        });
    auth_valid && entitlement_valid && registry_valid
}

pub(crate) const SAVED_POLICY_MAX_BYTES: usize = 65536;

/// The caller's hydrated saved-policy lookup. An absent probe asks the caller
/// for one; a present row must be a bounded JSON object, otherwise the request
/// is refused rather than treated as "no saved policy".
pub(crate) fn saved_policy_probe(request: &SupplyChainEvalRequestV1) -> Option<SavedPolicyProbe> {
    let Some(probe) = request.saved_policy_probe.as_ref() else {
        return Some(SavedPolicyProbe::Required);
    };
    match probe.decision.as_ref() {
        None | Some(Value::Null) => Some(SavedPolicyProbe::Supplied(None)),
        Some(decision @ Value::Object(_)) => serde_json::to_vec(decision)
            .is_ok_and(|bytes| bytes.len() <= SAVED_POLICY_MAX_BYTES)
            .then(|| SavedPolicyProbe::Supplied(Some(decision.clone()))),
        Some(_) => None,
    }
}
