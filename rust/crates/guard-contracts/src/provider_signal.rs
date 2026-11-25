//! Provider signal contract (ADR 0018).
//!
//! A provider answers one capability about one subject. Its answer is evidence: it can add a
//! finding or tighten a decision, never approve, grant or lower a floor. Capabilities, subject
//! kinds and verdicts are closed lists; adding a value is a contract change with tests.

use serde::{Deserialize, Serialize};

pub const PROVIDER_SIGNAL_V1_VERSION: u32 = 1;
/// Most reason codes one signal may carry.
pub const PROVIDER_SIGNAL_MAX_REASON_CODES: usize = 8;
/// Longest reason code, in bytes.
pub const PROVIDER_REASON_CODE_MAX_BYTES: usize = 64;
/// Provider id prefix reserved for the test fixture origin.
pub const PROVIDER_FIXTURE_ID_PREFIX: &str = "provider.fixture-";

/// Provider-caused reviews per subject per signal version.
pub const PROVIDER_CAUTION_REVIEWS_PER_SUBJECT_VERSION: u32 = 1;
/// Provider-caused `caution` reviews per session per provider.
pub const PROVIDER_CAUTION_REVIEWS_PER_SESSION: u32 = 3;
/// Allows through provider-caused reviews (same provider and reason) before the card offers
/// "Stop asking for this reason".
pub const PROVIDER_OVERRIDE_OFFER_THRESHOLD: u32 = 3;
/// Window for the override count, in milliseconds (seven days).
pub const PROVIDER_OVERRIDE_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Provider rows the card shows before "N more".
pub const PROVIDER_CARD_MAX_ROWS: usize = 3;

/// The closed capability list.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProviderCapabilityV1 {
    #[serde(rename = "browser.origin-reputation")]
    OriginReputation,
    #[serde(rename = "browser.script-integrity")]
    ScriptIntegrity,
    #[serde(rename = "browser.page-data-risk")]
    PageDataRisk,
    #[serde(rename = "browser.download-reputation")]
    DownloadReputation,
    #[serde(rename = "browser.site-policy")]
    SitePolicy,
}

impl ProviderCapabilityV1 {
    pub const ALL: [Self; 5] = [
        Self::OriginReputation,
        Self::ScriptIntegrity,
        Self::PageDataRisk,
        Self::DownloadReputation,
        Self::SitePolicy,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OriginReputation => "browser.origin-reputation",
            Self::ScriptIntegrity => "browser.script-integrity",
            Self::PageDataRisk => "browser.page-data-risk",
            Self::DownloadReputation => "browser.download-reputation",
            Self::SitePolicy => "browser.site-policy",
        }
    }
}

/// The closed list of facts Guard may share with a provider.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProviderShareableFactV1 {
    #[serde(rename = "target.origin")]
    TargetOrigin,
    #[serde(rename = "target.site_group")]
    TargetSiteGroup,
    #[serde(rename = "target.path_prefix")]
    TargetPathPrefix,
    #[serde(rename = "action.verb")]
    ActionVerb,
    #[serde(rename = "action.intent")]
    ActionIntent,
    #[serde(rename = "page.script_hashes")]
    PageScriptHashes,
    #[serde(rename = "download.sha256")]
    DownloadSha256,
    #[serde(rename = "guard.version")]
    GuardVersion,
}

impl ProviderShareableFactV1 {
    /// Facts that are off until the user turns them on at connect.
    pub const fn opt_in_only(self) -> bool {
        matches!(self, Self::TargetPathPrefix)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSubjectKindV1 {
    Origin,
    SiteGroup,
    PathPrefix,
    ScriptSet,
    File,
}

/// What a signal is about. Holds a digest so the cache never stores the subject itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct ProviderSubjectV1 {
    pub kind: ProviderSubjectKindV1,
    pub digest: String,
}

/// A provider's answer. There is deliberately no allow verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProviderVerdictV1 {
    Ok,
    Caution,
    Danger,
    Unknown,
}

impl ProviderVerdictV1 {
    /// Ordering for "strongest fresh verdict wins". An `ok` never cancels a `danger`.
    pub const fn strength(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Ok => 1,
            Self::Caution => 2,
            Self::Danger => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderInventoryV1 {
    /// Script inventory came from a Guard layer on this device (relay or companion extension).
    Device,
    /// The provider answered from its own knowledge of the origin.
    ProviderSide,
    None,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSignalStateV1 {
    Fresh,
    Stale,
    Unavailable,
    RateLimited,
    KeyInvalid,
    Disabled,
}

impl ProviderSignalStateV1 {
    /// Only fresh signals can change a decision.
    pub const fn is_fresh(self) -> bool {
        matches!(self, Self::Fresh)
    }
}

/// How much a provider's verdicts may change Guard's decision, per capability.
#[derive(
    Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEffectLevelV1 {
    /// Findings and would-have-reviewed receipts only.
    Observe,
    /// Default for a newly connected provider.
    #[default]
    Tighten,
    /// `danger` blocks. Never a default; a protected user or managed-policy setting.
    Enforce,
}

/// One cached provider answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSignalV1 {
    pub version: u32,
    pub provider_id: String,
    pub capability: ProviderCapabilityV1,
    pub subject: ProviderSubjectV1,
    pub verdict: ProviderVerdictV1,
    /// Codes from the manifest's allow-list. Rendered only through manifest labels.
    pub reason_codes: Vec<String>,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub inventory: ProviderInventoryV1,
    pub state: ProviderSignalStateV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderSignalShapeErrorV1 {
    WrongVersion,
    TooManyReasonCodes,
    ReasonCodeInvalid,
    ExpiresBeforeObserved,
    ProviderIdInvalid,
}

impl ProviderSignalShapeErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::WrongVersion => "provider_signal_wrong_version",
            Self::TooManyReasonCodes => "provider_signal_too_many_reason_codes",
            Self::ReasonCodeInvalid => "provider_signal_reason_code_invalid",
            Self::ExpiresBeforeObserved => "provider_signal_expires_before_observed",
            Self::ProviderIdInvalid => "provider_signal_provider_id_invalid",
        }
    }
}

/// Provider ids are `provider.<slug>` with a lowercase ASCII slug of letters, digits and `-`.
pub fn provider_id_is_valid(id: &str) -> bool {
    let Some(slug) = id.strip_prefix("provider.") else {
        return false;
    };
    !slug.is_empty()
        && slug.len() <= 64
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// Reason codes are lowercase snake case, so they can never carry free provider text.
pub fn provider_reason_code_is_valid(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= PROVIDER_REASON_CODE_MAX_BYTES
        && code.as_bytes()[0].is_ascii_lowercase()
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

impl ProviderSignalV1 {
    pub fn validate_shape(&self) -> Result<(), ProviderSignalShapeErrorV1> {
        if self.version != PROVIDER_SIGNAL_V1_VERSION {
            return Err(ProviderSignalShapeErrorV1::WrongVersion);
        }
        if !provider_id_is_valid(&self.provider_id) {
            return Err(ProviderSignalShapeErrorV1::ProviderIdInvalid);
        }
        if self.reason_codes.len() > PROVIDER_SIGNAL_MAX_REASON_CODES {
            return Err(ProviderSignalShapeErrorV1::TooManyReasonCodes);
        }
        if !self
            .reason_codes
            .iter()
            .all(|code| provider_reason_code_is_valid(code))
        {
            return Err(ProviderSignalShapeErrorV1::ReasonCodeInvalid);
        }
        if self.expires_at_ms < self.observed_at_ms {
            return Err(ProviderSignalShapeErrorV1::ExpiresBeforeObserved);
        }
        Ok(())
    }

    /// True while the signal is fresh and unexpired at `now_ms`.
    pub fn is_live_at(&self, now_ms: u64) -> bool {
        self.state.is_fresh() && now_ms < self.expires_at_ms
    }
}
