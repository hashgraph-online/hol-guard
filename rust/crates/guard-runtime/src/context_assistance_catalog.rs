//! One catalog resolver; imported data never selects/enables an SDK or grants
//! source access. Installed receipts remain usable offline; new preparation
//! requires current signature authority. Public roots are configured separately.
use super::*;
use guard_cigar_release::{CatalogTrust, TrustedCatalog, TrustedKey};
use std::collections::BTreeSet;
#[path = "context_assistance_catalog_feed.rs"]
pub(crate) mod feed;
#[cfg(unix)]
#[path = "context_assistance_catalog_native.rs"]
mod native;
#[cfg(all(test, unix))]
#[path = "context_assistance_catalog_tests.rs"]
mod tests;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicKey {
    pub key_id: String,
    pub public_key_hex: String,
    pub not_before: u64,
    pub not_after: u64,
    pub revoked: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Authority {
    pub schema: String,
    pub keys: Vec<PublicKey>,
}
impl Authority {
    fn resolve(&self) -> Result<Vec<TrustedKey>, String> {
        let mut ids = BTreeSet::new();
        if self.schema != "guard-cigar-catalog-authority.v1" || self.keys.len() > 8 {
            return Err(error("cigar_catalog_authority_invalid"));
        }
        self.keys
            .iter()
            .map(|k| {
                if !valid_id(&k.key_id)
                    || !ids.insert(&k.key_id)
                    || !is_lower_hex(&k.public_key_hex, 64)
                    || k.not_before >= k.not_after
                {
                    return Err(error("cigar_catalog_authority_invalid"));
                }
                Ok(TrustedKey {
                    key_id: k.key_id.clone(),
                    public_key: hex::decode(&k.public_key_hex)
                        .map_err(|_| error("cigar_catalog_authority_invalid"))?
                        .try_into()
                        .map_err(|_| error("cigar_catalog_authority_invalid"))?,
                    not_before: k.not_before,
                    not_after: k.not_after,
                    revoked: k.revoked,
                })
            })
            .collect()
    }
}
pub(crate) struct Snapshot {
    pub catalog: TrustedCatalog,
    withdrawn_sdk: BTreeSet<String>,
    withdrawn_python: BTreeSet<String>,
    source: &'static str,
    feed_sha256: Option<String>,
    feed_diagnostic: Option<String>,
    key_ids: Vec<String>,
    diagnostic: Option<String>,
    trust_diagnostic: Option<String>,
}
impl Snapshot {
    fn bundled() -> Result<Self, String> {
        let catalog = TrustedCatalog::bundled().map_err(|e| error(e.code()))?;
        let withdrawn_sdk = catalog
            .document()
            .builds
            .iter()
            .filter(|b| b.withdrawn)
            .map(|b| b.identity.build_id.clone())
            .collect();
        let withdrawn_python = catalog
            .document()
            .interpreters
            .iter()
            .filter(|b| b.withdrawn)
            .map(|b| b.build_id.clone())
            .collect();
        Ok(Self {
            catalog,
            withdrawn_sdk,
            withdrawn_python,
            source: "bundled",
            feed_sha256: None,
            feed_diagnostic: None,
            key_ids: Vec::new(),
            diagnostic: None,
            trust_diagnostic: None,
        })
    }
    pub(crate) fn check_sdk(&self, id: &str) -> Result<(), String> {
        if self.withdrawn_sdk.contains(id) {
            return Err(error("cigar_build_withdrawn"));
        }
        Ok(())
    }
    pub(crate) fn check_python(&self, id: &str) -> Result<(), String> {
        if self.withdrawn_python.contains(id) {
            return Err(error("cigar_build_withdrawn"));
        }
        Ok(())
    }
    fn metadata(&self) -> Value {
        json!({"source":self.source,"checkpoint":self.catalog.checkpoint(),"fresh_for_preparation":self.diagnostic.is_none(),"diagnostic":self.diagnostic,"trust_diagnostic":self.trust_diagnostic,"trust_configured":!self.key_ids.is_empty(),"key_ids":self.key_ids,"withdrawn_sdk_builds":self.withdrawn_sdk,"withdrawn_interpreter_builds":self.withdrawn_python,"remote_feed_configured":self.feed_sha256.is_some(),"feed_sha256":self.feed_sha256,"feed_diagnostic":self.feed_diagnostic,"activation_granted":false})
    }
}
pub(crate) fn installed(home: &Path) -> Result<Snapshot, String> {
    #[cfg(unix)]
    {
        native::load(home)
    }
    #[cfg(not(unix))]
    {
        for name in [
            "cigar-catalog.json",
            "cigar-catalog.key",
            "cigar-catalog-trust.json",
            "cigar-catalog-feed.json",
            "cigar-catalog-state",
        ] {
            match fs::symlink_metadata(home.join(name)) {
                Ok(_) => return Err(error("cigar_catalog_platform_unqualified")),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(error("cigar_catalog_storage_invalid_or_changed")),
            }
        }
        Snapshot::bundled()
    }
}
pub(crate) fn fresh(home: &Path) -> Result<Snapshot, String> {
    let s = installed(home)?;
    if let Some(code) = &s.diagnostic {
        return Err(code.clone());
    }
    Ok(s)
}
pub(crate) fn releases(home: &Path) -> Result<Value, String> {
    let s = installed(home)?;
    Ok(
        json!({"schema":"guard-cigar-releases.v1","host_platform":preparation::setup_platform(),"checkpoint":s.catalog.checkpoint(),"builds":s.catalog.document().builds,"interpreter_builds":s.catalog.document().interpreters,"catalog":s.metadata()}),
    )
}
pub(crate) fn status(home: &Path) -> Result<Value, String> {
    Ok(installed(home)?.metadata())
}
pub(crate) fn configure(home: &Path, value: Authority) -> Result<Value, String> {
    value.resolve()?;
    #[cfg(unix)]
    {
        native::configure(home, value)
    }
    #[cfg(not(unix))]
    {
        let _ = (home, value);
        Err(error("cigar_catalog_platform_unqualified"))
    }
}
pub(crate) fn import(home: &Path, raw: &[u8]) -> Result<Value, String> {
    #[cfg(unix)]
    {
        native::import(home, raw)
    }
    #[cfg(not(unix))]
    {
        let _ = (home, raw);
        Err(error("cigar_catalog_platform_unqualified"))
    }
}
