//! Explicit feed configuration and a native-only lifecycle owner. A refresh
//! can change release metadata, never selection, enablement or SDK authority.
use super::*;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Feed {
    pub schema: String,
    pub url: Option<String>,
}
impl Feed {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema != "guard-cigar-catalog-feed.v1" {
            return Err(error("cigar_catalog_feed_invalid"));
        }
        if let Some(url) = &self.url {
            let d = guard_command::restricted_archive::canonical_destination(url)
                .map_err(|_| error("cigar_catalog_feed_invalid"))?;
            if url.len() > 2048
                || url.contains(['?', '#'])
                || d.port != 443
                || d.url != *url
                || !d.hostname.contains('.')
                || d.hostname.parse::<std::net::IpAddr>().is_ok()
            {
                return Err(error("cigar_catalog_feed_invalid"));
            }
        }
        Ok(())
    }
    pub(crate) fn fingerprint(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_vec(self)
            .map(|v| format!("{:x}", Sha256::digest(v)))
            .map_err(|_| error("cigar_catalog_feed_invalid"))
    }
}
#[path = "context_assistance_catalog_feed_native.rs"]
mod native;
pub(crate) use native::{begin, inspect, reconcile, Owner};
pub(crate) fn configure(home: &Path, feed: Feed) -> Result<Value, String> {
    feed.validate()?;
    native::configure(home, feed)
}
