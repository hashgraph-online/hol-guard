//! Brokered sign-in transports for cloud action packs (ADR 0016).
//!
//! A pack may name the sign-in brokers whose toolkits can carry its requests.
//! The block is data only: it grants nothing, changes no decision and no
//! rendered request. A hosted gateway may route a pack through a broker only
//! when this block names that broker; everything else about the call (exact
//! host, owner binding, headers, size) is enforced outside the engine.

use crate::cloud_pack::{AuthMode, CloudActionPack, Executor, PackError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Most brokers one pack may name.
pub const MAX_PARTNER_TRANSPORTS: usize = 4;
const MAX_TOOLKIT_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Transports {
    pub partner: Vec<PartnerTransport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartnerTransport {
    pub partner: Partner,
    pub toolkit: String,
}

/// A present `transports` key must hold a block; `null` is refused, not read as absent.
pub(crate) fn present<'de, D>(deserializer: D) -> Result<Option<Transports>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Transports::deserialize(deserializer).map(Some)
}

/// The closed list of sign-in brokers Guard knows how to route through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Partner {
    Composio,
}

impl Partner {
    pub fn as_str(self) -> &'static str {
        match self {
            Partner::Composio => "composio",
        }
    }
}

/// A broker toolkit slug: lowercase letter first, then lowercase letters,
/// digits or underscores, 2..=64 characters.
pub fn valid_toolkit(slug: &str) -> bool {
    let bytes = slug.as_bytes();
    (2..=MAX_TOOLKIT_LENGTH).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

/// Check the optional `transports` block. A pack that signs in with nothing
/// has no sign-in to broker, and a broker proxy carries only plain HTTP
/// requests, so a pack with any non-HTTP action may not declare one.
pub fn validate_transports(pack: &CloudActionPack) -> Result<(), PackError> {
    let Some(transports) = &pack.transports else {
        return Ok(());
    };
    let invalid = || PackError::new("cloud_pack_transports_invalid", "/transports");
    let http_only = pack
        .actions
        .iter()
        .all(|action| matches!(action.executor, Executor::DeclarativeHttp { .. }));
    if pack.auth.mode == AuthMode::None
        || !http_only
        || transports.partner.is_empty()
        || transports.partner.len() > MAX_PARTNER_TRANSPORTS
    {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    for (index, entry) in transports.partner.iter().enumerate() {
        if !valid_toolkit(&entry.toolkit) || !seen.insert(entry.partner) {
            return Err(PackError::new(
                "cloud_pack_transports_invalid",
                format!("/transports/partner/{index}"),
            ));
        }
    }
    Ok(())
}

/// The broker toolkit a pack names for `partner`, if any.
pub fn partner_toolkit(pack: &CloudActionPack, partner: Partner) -> Option<&str> {
    pack.transports
        .as_ref()?
        .partner
        .iter()
        .find(|entry| entry.partner == partner)
        .map(|entry| entry.toolkit.as_str())
}

/// `partner:toolkit` labels, sorted, for diffs and review text.
pub fn partner_labels(pack: &CloudActionPack) -> BTreeSet<String> {
    pack.transports
        .iter()
        .flat_map(|transports| transports.partner.iter())
        .map(|entry| format!("{}:{}", entry.partner.as_str(), entry.toolkit))
        .collect()
}
