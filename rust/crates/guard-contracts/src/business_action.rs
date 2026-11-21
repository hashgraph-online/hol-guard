//! Bounded business facts for a private prepared-action snapshot.
//!
//! Decoding this contract authenticates nothing and grants no permission. An
//! adapter must establish these facts, bind them to the existing native review
//! origin, and retain the immutable input before a consumer can authorize work.
//! This document must not be attached to an older enforcing envelope whose
//! consumer does not advertise this schema explicitly.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const BUSINESS_ACTION_V1_SCHEMA: &str = "guard.business-action.v1";
pub const BUSINESS_ACTION_V1_VERSION: u16 = 1;
pub const MAX_BUSINESS_ACTION_BYTES: usize = 64 * 1024;
pub const MAX_BUSINESS_ACTION_ITEMS: usize = 256;
pub const MAX_BUSINESS_INLINE_BYTES: u64 = 256 * 1024;
/// Shared counters must remain exactly representable by wire JSON consumers.
pub const MAX_BUSINESS_WIRE_COUNT: u64 = (1 << 53) - 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BusinessServiceV1 {
    GoogleGmail,
    GoogleDrive,
    GoogleCalendar,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BusinessOperationV1 {
    MailRead,
    MailDraft,
    MailSend,
    MailLabel,
    MailPermanentDelete,
    MailSettings,
    DriveRead,
    DriveEdit,
    DriveShare,
    DriveExport,
    CalendarRead,
    CalendarInvite,
}

impl BusinessOperationV1 {
    pub fn service(self) -> BusinessServiceV1 {
        match self {
            Self::MailRead
            | Self::MailDraft
            | Self::MailSend
            | Self::MailLabel
            | Self::MailPermanentDelete
            | Self::MailSettings => BusinessServiceV1::GoogleGmail,
            Self::DriveRead | Self::DriveEdit | Self::DriveShare | Self::DriveExport => {
                BusinessServiceV1::GoogleDrive
            }
            Self::CalendarRead | Self::CalendarInvite => BusinessServiceV1::GoogleCalendar,
        }
    }

    /// Effect class of the operation. It is derived from the operation only,
    /// so a producer cannot assert a different class.
    pub fn action_class(self) -> BusinessActionClassV1 {
        use BusinessActionClassV1 as Class;
        match self {
            Self::MailRead | Self::DriveRead | Self::CalendarRead => Class::Read,
            Self::MailDraft => Class::Draft,
            Self::MailSend | Self::CalendarInvite => Class::Send,
            Self::DriveShare => Class::Share,
            Self::DriveExport => Class::Export,
            Self::MailLabel | Self::DriveEdit => Class::Update,
            Self::MailPermanentDelete => Class::Delete,
            Self::MailSettings => Class::Admin,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum BusinessActionClassV1 {
    Read,
    Draft,
    Send,
    Share,
    Export,
    Update,
    Delete,
    Admin,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BusinessFactStateV1 {
    Known,
    Unknown,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BusinessProviderV1 {
    pub service: BusinessServiceV1,
    /// Native-private identity commitment, not a browser/model account claim.
    /// Both binding keys are required even when their value is explicitly null.
    /// Do not add serde(default): an omitted identity must fail strict decoding.
    /// The business_provider_required_nullable tests pin this wire distinction.
    #[serde(deserialize_with = "required_nullable")]
    pub account_binding: Option<String>, // NOSONAR: rust:S9334; required key, nullable value.
    /// Explicit nullable tenant commitment. Missing is invalid.
    #[serde(deserialize_with = "required_nullable")]
    pub tenant_binding: Option<String>, // NOSONAR: rust:S9334; required key, nullable value.
    pub identity_state: BusinessFactStateV1,
    pub tool_identity_digest: String,
    pub tool_schema_digest: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum BusinessRecipientKindV1 {
    To,
    Cc,
    Bcc,
    CalendarAttendee,
    Collaborator,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BusinessRecipientV1 {
    /// Refers to the exact resolved address in the private snapshot. This is
    /// not suitable for Cloud export without tenant-keyed pseudonymization.
    pub identity_binding: String,
    /// Canonical ASCII domain from the trusted identity resolver.
    pub domain: String,
    pub kind: BusinessRecipientKindV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BusinessAudienceKindV1 {
    Private,
    Named,
    Public,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BusinessAudienceV1 {
    pub kind: BusinessAudienceKindV1,
    pub expansion_state: BusinessFactStateV1,
    pub recipients: Vec<BusinessRecipientV1>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum BusinessSensitivityV1 {
    Public,
    Personal,
    Confidential,
    Secret,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BusinessContentV1 {
    /// Digest of the complete frozen input, including bodies and attachments.
    /// A digest is an integrity commitment, not proof of inspection or custody.
    pub snapshot_digest: String,
    pub attachment_digests: Vec<String>,
    pub inspection_state: BusinessFactStateV1,
    pub inspected_bytes: u64,
    pub sensitivity_labels: Vec<BusinessSensitivityV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BusinessTargetV1 {
    pub resource_binding: String,
    pub revision_binding: String,
    pub field_diff_digest: String,
    pub batch_manifest_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BusinessVolumeV1 {
    /// Distinct resolved identities, including hidden recipients.
    pub recipient_count: u64,
    pub record_count: u64,
    pub byte_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BusinessActionV1 {
    pub schema: String,
    pub version: u16,
    pub provider: BusinessProviderV1,
    pub operation: BusinessOperationV1,
    pub audience: BusinessAudienceV1,
    pub content: BusinessContentV1,
    pub target: BusinessTargetV1,
    pub volume: BusinessVolumeV1,
    pub completeness: BusinessFactStateV1,
}

/// Finite error codes contain no provider content or private identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusinessActionErrorV1 {
    Invalid,
    UnsupportedVersion,
    LimitExceeded,
    Inconsistent,
    Incomplete,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn required_nullable<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(d)
}

/// Canonical DNS-name syntax shared by recipient facts and policy selectors.
/// This proves neither provider resolution nor organization membership.
pub fn is_canonical_business_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() || b == b'-')
        })
}

impl BusinessActionV1 {
    /// Size is checked before JSON allocation. Derived strict decoding rejects
    /// duplicate, missing and unknown fields at every object boundary. The
    /// finite type graph has no arbitrary nested values or extensible payload.
    pub fn from_bounded_json(bytes: &[u8]) -> Result<Self, BusinessActionErrorV1> {
        if bytes.len() > MAX_BUSINESS_ACTION_BYTES {
            return Err(BusinessActionErrorV1::LimitExceeded);
        }
        let action: Self =
            serde_json::from_slice(bytes).map_err(|_| BusinessActionErrorV1::Invalid)?;
        action.validate()?;
        Ok(action)
    }

    /// Checks representation and contradictions, never grants execution.
    pub fn validate(&self) -> Result<(), BusinessActionErrorV1> {
        use BusinessActionErrorV1 as Error;
        if self.schema != BUSINESS_ACTION_V1_SCHEMA || self.version != BUSINESS_ACTION_V1_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if self.provider.service != self.operation.service() {
            return Err(Error::Inconsistent);
        }
        if self.audience.recipients.len() > MAX_BUSINESS_ACTION_ITEMS
            || self.content.attachment_digests.len() > MAX_BUSINESS_ACTION_ITEMS
            || self.content.sensitivity_labels.len() > 5
            || [
                self.volume.recipient_count,
                self.volume.record_count,
                self.volume.byte_count,
                self.content.inspected_bytes,
            ]
            .iter()
            .any(|n| *n > MAX_BUSINESS_WIRE_COUNT)
        {
            return Err(Error::LimitExceeded);
        }
        let identity_bindings = [
            &self.provider.account_binding,
            &self.provider.tenant_binding,
        ];
        if ![
            &self.provider.tool_identity_digest,
            &self.provider.tool_schema_digest,
            &self.content.snapshot_digest,
            &self.target.resource_binding,
            &self.target.revision_binding,
            &self.target.field_diff_digest,
            &self.target.batch_manifest_digest,
        ]
        .iter()
        .all(|value| digest(value))
            || !identity_bindings
                .iter()
                .all(|value| value.as_deref().is_none_or(digest))
            || !self
                .content
                .attachment_digests
                .iter()
                .all(|value| digest(value))
            || !self
                .audience
                .recipients
                .iter()
                .all(|r| digest(&r.identity_binding) && is_canonical_business_domain(&r.domain))
        {
            return Err(Error::Invalid);
        }
        if self.provider.identity_state == BusinessFactStateV1::Known
            && (self.provider.account_binding.is_none() || self.provider.tenant_binding.is_none())
        {
            return Err(Error::Inconsistent);
        }
        if self
            .content
            .sensitivity_labels
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != self.content.sensitivity_labels.len()
            || self.content.sensitivity_labels.is_empty()
        {
            return Err(Error::Inconsistent);
        }
        let mut fields = BTreeSet::new();
        let mut identities = BTreeSet::new();
        let mut identity_domains = BTreeMap::new();
        for recipient in &self.audience.recipients {
            if !fields.insert((&recipient.identity_binding, recipient.kind)) {
                return Err(Error::Inconsistent);
            }
            let compatible_kind = match self.provider.service {
                BusinessServiceV1::GoogleGmail => matches!(
                    recipient.kind,
                    BusinessRecipientKindV1::To
                        | BusinessRecipientKindV1::Cc
                        | BusinessRecipientKindV1::Bcc
                ),
                BusinessServiceV1::GoogleDrive => {
                    recipient.kind == BusinessRecipientKindV1::Collaborator
                }
                BusinessServiceV1::GoogleCalendar => {
                    recipient.kind == BusinessRecipientKindV1::CalendarAttendee
                }
            };
            if !compatible_kind
                || identity_domains
                    .insert(&recipient.identity_binding, &recipient.domain)
                    .is_some_and(|previous| previous != &recipient.domain)
            {
                return Err(Error::Inconsistent);
            }
            identities.insert(&recipient.identity_binding);
        }
        if self.volume.recipient_count != identities.len() as u64
            || (self.audience.kind == BusinessAudienceKindV1::Private && !identities.is_empty())
            || (self.audience.kind == BusinessAudienceKindV1::Named && identities.is_empty())
            || self.content.inspected_bytes > self.volume.byte_count
        {
            return Err(Error::Inconsistent);
        }
        if (self.provider.service != BusinessServiceV1::GoogleDrive
            && self.audience.kind == BusinessAudienceKindV1::Public)
            || (matches!(
                self.operation,
                BusinessOperationV1::MailSend | BusinessOperationV1::CalendarInvite
            ) && self.audience.kind != BusinessAudienceKindV1::Unknown
                && self.audience.kind != BusinessAudienceKindV1::Named)
            // An export copies content to the caller; sharing is DriveShare.
            || (self.operation == BusinessOperationV1::DriveExport
                && self.audience.kind != BusinessAudienceKindV1::Unknown
                && self.audience.kind != BusinessAudienceKindV1::Private)
        {
            return Err(Error::Inconsistent);
        }
        // v1 has no reviewed streaming inspection path. A hash of a larger
        // request cannot turn it into a completely inspected inline request.
        if self.content.inspection_state == BusinessFactStateV1::Known
            && (self.content.inspected_bytes != self.volume.byte_count
                || self.content.inspected_bytes > MAX_BUSINESS_INLINE_BYTES)
        {
            return Err(Error::Inconsistent);
        }
        if serde_json::to_vec(self).map_err(|_| Error::Invalid)?.len() > MAX_BUSINESS_ACTION_BYTES {
            return Err(Error::LimitExceeded);
        }
        Ok(())
    }

    /// A consumer may require complete facts, but must still authenticate the
    /// producer, evaluate policy and establish immutable dispatch separately.
    pub fn require_complete_facts(&self) -> Result<(), BusinessActionErrorV1> {
        self.validate()?;
        if [
            self.completeness,
            self.provider.identity_state,
            self.audience.expansion_state,
            self.content.inspection_state,
        ]
        .iter()
        .any(|state| *state != BusinessFactStateV1::Known)
            || self.audience.kind == BusinessAudienceKindV1::Unknown
            || self
                .content
                .sensitivity_labels
                .contains(&BusinessSensitivityV1::Unknown)
        {
            return Err(BusinessActionErrorV1::Incomplete);
        }
        Ok(())
    }
}
