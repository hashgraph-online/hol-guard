//! Unified browser action contract (version 2) and the native approval card projection.
//!
//! `BrowserActionV2` describes one browser action regardless of the route that carried it: an
//! MCP driver, a harness built-in tool, a command-line driver or a DevTools protocol frame.
//! `BrowserAutomationIntentV1` stays readable for stored approvals.

use serde::{Deserialize, Serialize};

use crate::{BrowserIntentV1, BrowserProfileModeV1, BrowserSensitiveSurfaceV1};

/// Schema version carried in [`BrowserActionV2::version`].
pub const BROWSER_ACTION_V2_VERSION: u32 = 2;
/// Largest accepted `operation` length, in bytes.
pub const BROWSER_ACTION_OPERATION_MAX_BYTES: usize = 128;
/// Largest element name preview, in characters. Display only, never part of a grant key.
pub const BROWSER_ELEMENT_NAME_PREVIEW_MAX_CHARS: usize = 80;
/// Longest display URL an action may carry.
pub const BROWSER_URL_REDACTED_MAX_CHARS: usize = 2_048;
/// The only query value a redacted URL may carry.
pub const BROWSER_URL_REDACTED_VALUE: &str = "[redacted]";

/// True for a lowercase hex SHA-256 digest, the only digest form these contracts carry.
pub fn sha256_hex_is_valid(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// True when a display URL holds no query values and no fragment.
///
/// The runtime builds the URL; this check makes the contract refuse one that skipped redaction.
pub fn browser_url_is_redacted(url: &str) -> bool {
    if url.chars().count() > BROWSER_URL_REDACTED_MAX_CHARS || url.contains('#') {
        return false;
    }
    // Userinfo in the authority (`scheme://name:secret@host`) is a credential redaction must strip.
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme.split(['/', '?']).next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let Some((_, query)) = url.split_once('?') else {
        return true;
    };
    query.split('&').all(|field| match field.split_once('=') {
        None => true,
        Some((_, value)) => {
            value.is_empty()
                || value == BROWSER_URL_REDACTED_VALUE
                || value.eq_ignore_ascii_case("%5Bredacted%5D")
        }
    })
}

/// The route a browser action arrived on.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserDriverKindV1 {
    Mcp,
    HarnessTool,
    Cli,
    Cdp,
}

/// How far Guard trusts the driver's own description of an action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserDriverTrustClassV1 {
    /// Profile shipped with Guard and reviewed by maintainers.
    FirstParty,
    /// Community profile from `contributions/browser-drivers/`, enabled by the user.
    Contributed,
    /// No profile matched. Every operation classifies conservatively.
    Unprofiled,
}

/// The verb Guard decides on. Grants and cards key on this, never on a driver's tool name.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BrowserVerbV1 {
    Navigate,
    Read,
    Click,
    Type,
    Key,
    Select,
    Scroll,
    Screenshot,
    Upload,
    Download,
    Evaluate,
    CookieRead,
    CookieWrite,
    StorageRead,
    StorageWrite,
    Intercept,
    Permission,
    TabControl,
    Attach,
    Other,
}

/// Driver identity for one action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserDriverV2 {
    pub id: String,
    pub kind: BrowserDriverKindV1,
    pub identity_hash: Option<String>,
    pub trust_class: BrowserDriverTrustClassV1,
}

/// Session context. Holds a digest of the harness session reference, never the reference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserSessionV2 {
    pub harness: String,
    pub session_ref_digest: Option<String>,
    pub profile_mode: BrowserProfileModeV1,
}

/// Where the action lands. `url_redacted` keeps query keys but no query values: every value is
/// [`BROWSER_URL_REDACTED_VALUE`] or empty, and there is no fragment. See [`browser_url_is_redacted`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserTargetV2 {
    pub origin: Option<String>,
    pub site_group: Option<String>,
    pub path_prefix: Option<String>,
    pub is_loopback: bool,
    pub is_guard_origin: bool,
    pub url_redacted: Option<String>,
}

/// The page element an action touches, as the driver described it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserElementV1 {
    pub role: Option<String>,
    pub name_digest: Option<String>,
    /// At most [`BROWSER_ELEMENT_NAME_PREVIEW_MAX_CHARS`] characters. Display only.
    pub name_preview: Option<String>,
    pub is_password: bool,
    pub is_payment: bool,
    pub is_file_input: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BrowserInputKindV1 {
    Text,
    Key,
    File,
    Script,
}

/// How the card may preview input. Typed text is never stored; the card reads the live request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BrowserInputPreviewClassV1 {
    Plain,
    LooksLikeSecret,
    LooksLikePayment,
    Empty,
}

/// Shape of the input an action carries. Holds a digest and a length, never the content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserInputV1 {
    pub kind: BrowserInputKindV1,
    pub length: u64,
    pub digest: Option<String>,
    pub preview_class: BrowserInputPreviewClassV1,
}

/// DevTools protocol detail when the action is a protocol command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserCdpCommandV1 {
    pub domain: String,
    pub method: String,
    /// False when the method is not in the method table and was classified as `Other`.
    pub classified: bool,
}

/// One browser action, normalized from any route.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BrowserActionV2 {
    pub version: u32,
    pub driver: BrowserDriverV2,
    pub session: BrowserSessionV2,
    pub intent: BrowserIntentV1,
    /// The driver's own name for the operation, at most [`BROWSER_ACTION_OPERATION_MAX_BYTES`].
    pub operation: String,
    pub verb: BrowserVerbV1,
    pub target: BrowserTargetV2,
    pub element: Option<BrowserElementV1>,
    pub input: Option<BrowserInputV1>,
    pub sensitive_surface_flags: Vec<BrowserSensitiveSurfaceV1>,
    pub cdp: Option<BrowserCdpCommandV1>,
    pub volatile_fields_dropped: Vec<String>,
}

/// Contract-level shape errors. Classification rules live in the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserActionShapeErrorV1 {
    WrongVersion,
    OperationTooLong,
    ElementPreviewTooLong,
    CdpMissingForCdpDriver,
    UrlNotRedacted,
    DigestInvalid,
}

impl BrowserActionShapeErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::WrongVersion => "browser_action_wrong_version",
            Self::OperationTooLong => "browser_action_operation_too_long",
            Self::ElementPreviewTooLong => "browser_action_element_preview_too_long",
            Self::CdpMissingForCdpDriver => "browser_action_cdp_missing",
            Self::UrlNotRedacted => "browser_action_url_not_redacted",
            Self::DigestInvalid => "browser_action_digest_invalid",
        }
    }
}

impl BrowserActionV2 {
    /// Checks the bounds this contract promises. Does not classify.
    pub fn validate_shape(&self) -> Result<(), BrowserActionShapeErrorV1> {
        if self.version != BROWSER_ACTION_V2_VERSION {
            return Err(BrowserActionShapeErrorV1::WrongVersion);
        }
        if self.operation.len() > BROWSER_ACTION_OPERATION_MAX_BYTES {
            return Err(BrowserActionShapeErrorV1::OperationTooLong);
        }
        let preview_chars = self
            .element
            .as_ref()
            .and_then(|element| element.name_preview.as_ref())
            .map_or(0, |preview| preview.chars().count());
        if preview_chars > BROWSER_ELEMENT_NAME_PREVIEW_MAX_CHARS {
            return Err(BrowserActionShapeErrorV1::ElementPreviewTooLong);
        }
        if self.driver.kind == BrowserDriverKindV1::Cdp && self.cdp.is_none() {
            return Err(BrowserActionShapeErrorV1::CdpMissingForCdpDriver);
        }
        if self
            .target
            .url_redacted
            .as_deref()
            .is_some_and(|url| !browser_url_is_redacted(url))
        {
            return Err(BrowserActionShapeErrorV1::UrlNotRedacted);
        }
        let digests = [
            self.session.session_ref_digest.as_deref(),
            self.element
                .as_ref()
                .and_then(|element| element.name_digest.as_deref()),
            self.input
                .as_ref()
                .and_then(|input| input.digest.as_deref()),
        ];
        if digests
            .into_iter()
            .flatten()
            .any(|digest| !sha256_hex_is_valid(digest))
        {
            return Err(BrowserActionShapeErrorV1::DigestInvalid);
        }
        Ok(())
    }
}

/// Plain-language browser line on the card, derived from the profile mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserCardProfileLineV1 {
    /// "Your own browser profile". Guard does not know whether it is signed in, so the line
    /// says only whose profile it is.
    Shared,
    /// "A separate automation profile"
    Dedicated,
    /// "A throwaway browser"
    Isolated,
    /// "A browser attached over remote debugging"
    RemoteDebugging,
    /// "A browser Guard could not identify"
    Unknown,
}

impl From<BrowserProfileModeV1> for BrowserCardProfileLineV1 {
    fn from(mode: BrowserProfileModeV1) -> Self {
        match mode {
            BrowserProfileModeV1::Shared => Self::Shared,
            BrowserProfileModeV1::Dedicated => Self::Dedicated,
            BrowserProfileModeV1::Isolated => Self::Isolated,
            BrowserProfileModeV1::RemoteDebugging => Self::RemoteDebugging,
            BrowserProfileModeV1::Unknown => Self::Unknown,
        }
    }
}

/// Site line on the card.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserCardSiteV1 {
    pub origin: Option<String>,
    pub first_visit_in_task: bool,
    pub left_granted_site: bool,
}

/// "What exactly" block. Input preview comes from the live pending request only.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserCardDetailV1 {
    pub element_preview: Option<String>,
    pub input_kind: Option<BrowserInputKindV1>,
    pub input_length: Option<u64>,
    pub input_masked: bool,
}

/// A durable or scoped choice offered under "More choices".
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BrowserCardChoiceV1 {
    AllowOnce,
    AlwaysAllow,
    Deny,
    SiteGrant,
    SessionSiteGrant,
    AlwaysAllowVerbOnSite,
    BlockOnSite,
}

/// Native card projection every approval surface renders.
///
/// `choices` always contains `AllowOnce`, `AlwaysAllow` and `Deny` (approval invariant).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BrowserCardV1 {
    pub headline: String,
    pub verb: BrowserVerbV1,
    pub site: BrowserCardSiteV1,
    pub profile_line: BrowserCardProfileLineV1,
    pub detail: BrowserCardDetailV1,
    pub risk_chips: Vec<BrowserSensitiveSurfaceV1>,
    /// Provider finding ids, rendered through manifest-declared labels.
    pub provider_findings: Vec<String>,
    pub choices: Vec<BrowserCardChoiceV1>,
    /// Coalesced steps when the card covers a burst. Empty for a single action.
    pub steps: Vec<String>,
}

impl BrowserCardV1 {
    /// True when the card keeps both required approval choices and a visible deny.
    pub fn keeps_approval_invariant(&self) -> bool {
        [
            BrowserCardChoiceV1::AllowOnce,
            BrowserCardChoiceV1::AlwaysAllow,
            BrowserCardChoiceV1::Deny,
        ]
        .iter()
        .all(|required| self.choices.contains(required))
    }
}
