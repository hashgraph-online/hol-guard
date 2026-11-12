//! Provider-neutral action facts for hosted and local business actions.
//!
//! `guard.action-facts.v2` describes what an action does, not what it is
//! called: its class, the kind of object it touches, whether the effect can be
//! undone, how many records or recipients it reaches, who can see the result,
//! and what deterministic detectors found. Every fact other than the class has
//! an explicit state. Policy treats `unknown` and `unsupported` as "could be
//! the worse value", so a missing fact never lowers a decision.
//!
//! Facts come only from trusted producers: compiled pack extractors, gateway
//! read-backs and native detectors. Model-written text is never a fact.
//! Decoding grants nothing; the consumer still evaluates policy.

use serde::de::{DeserializeOwned, Deserializer, Error as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::business_action::{
    is_canonical_business_domain, BusinessActionClassV1, BusinessActionV1, BusinessAudienceKindV1,
    BusinessFactStateV1, BusinessOperationV1, BusinessSensitivityV1, MAX_BUSINESS_ACTION_ITEMS,
    MAX_BUSINESS_WIRE_COUNT,
};

pub const ACTION_FACTS_V2_SCHEMA: &str = "guard.action-facts.v2";
pub const ACTION_FACTS_V2_VERSION: u16 = 2;
pub const MAX_ACTION_FACTS_BYTES: usize = 32 * 1024;

/// A fact whose value may be unavailable. `unsupported` means the producer
/// cannot know it for this action; consumers treat it like `unknown`.
///
/// The wire form is `{"state": "known", "value": ...}`, `{"state": "unknown"}`
/// or `{"state": "unsupported"}`. Decoding is strict: no other key, a value
/// only with `known`, and no `"value": null` on an unknown fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
pub enum Fact<T> {
    Known(T),
    Unknown,
    Unsupported,
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Fact<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        const FIELDS: &[&str] = &["state", "value"];
        let mut map = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
        let state = map
            .remove("state")
            .ok_or_else(|| D::Error::missing_field("state"))?;
        let value = map.remove("value");
        if let Some(extra) = map.keys().next() {
            return Err(D::Error::unknown_field(extra, FIELDS));
        }
        match (state.as_str(), value) {
            (Some("known"), Some(value)) => serde_json::from_value(value)
                .map(Self::Known)
                .map_err(D::Error::custom),
            (Some("known"), None) => Err(D::Error::missing_field("value")),
            (Some("unknown"), None) => Ok(Self::Unknown),
            (Some("unsupported"), None) => Ok(Self::Unsupported),
            (Some("unknown" | "unsupported"), Some(_)) => {
                Err(D::Error::custom("only a known fact carries a value"))
            }
            _ => Err(D::Error::custom(
                "fact state must be known, unknown or unsupported",
            )),
        }
    }
}

impl<T> Fact<T> {
    pub fn known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            Self::Unknown | Self::Unsupported => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClassV2 {
    Read,
    Draft,
    Send,
    Share,
    Export,
    Update,
    Delete,
    Execute,
    Pay,
    Admin,
}

impl ActionClassV2 {
    /// Classes that can move data or value outside the account.
    pub const fn is_egress(self) -> bool {
        matches!(self, Self::Send | Self::Share | Self::Export | Self::Pay)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKindV2 {
    Message,
    Thread,
    File,
    Folder,
    Record,
    Table,
    Database,
    Repository,
    Branch,
    Channel,
    Event,
    Contact,
    User,
    Payment,
    Deployment,
    Secret,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReversibilityV2 {
    Reversible,
    Recoverable,
    Permanent,
}

impl ReversibilityV2 {
    /// Higher is harder to undo.
    pub const fn rank(self) -> u8 {
        match self {
            Self::Reversible => 0,
            Self::Recoverable => 1,
            Self::Permanent => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeV2 {
    Single,
    Enumerated,
    QuerySelected,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudienceKindV2 {
    Private,
    Named,
    Domain,
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentV2 {
    Production,
    NonProduction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityV2 {
    Public,
    Personal,
    Confidential,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneyDirectionV2 {
    Out,
    In,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingV2 {
    SecretInArguments,
    SecretInResult,
    InjectionSignalInResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiKindV2 {
    EmailAddress,
    PhoneNumber,
    PaymentCard,
    NationalId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudienceV2 {
    pub kind: Fact<AudienceKindV2>,
    /// Canonical ASCII domains of every resolved recipient, sorted, unique.
    pub recipient_domains: Fact<Vec<String>>,
    /// True when any recipient is outside the workspace's own domains.
    pub external: Fact<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoneyV2 {
    pub amount_minor: u64,
    /// ISO 4217 code, three uppercase ASCII letters.
    pub currency: String,
    pub direction: MoneyDirectionV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionFactsV2 {
    pub schema: String,
    pub version: u16,
    pub class: ActionClassV2,
    pub object: Fact<ObjectKindV2>,
    pub reversibility: Fact<ReversibilityV2>,
    pub scope: Fact<ScopeV2>,
    pub record_count: Fact<u64>,
    pub recipient_count: Fact<u64>,
    pub byte_count: Fact<u64>,
    pub audience: AudienceV2,
    pub environment: Fact<EnvironmentV2>,
    /// `known` with no value is not allowed; an action that moves no money
    /// says `unsupported`.
    pub money: Fact<MoneyV2>,
    /// Sorted, unique, nonempty when known.
    pub sensitivity: Fact<Vec<SensitivityV2>>,
    /// Findings deterministic detectors established. Absence is not proof
    /// that content is clean; it only means no detector fired.
    pub findings: Vec<FindingV2>,
    pub pii_kinds: Vec<PiiKindV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionFactsErrorV2 {
    Invalid,
    UnsupportedVersion,
    LimitExceeded,
    Inconsistent,
}

impl ActionFactsErrorV2 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Invalid => "facts_invalid",
            Self::UnsupportedVersion => "facts_unsupported_version",
            Self::LimitExceeded => "facts_limit",
            Self::Inconsistent => "facts_inconsistent",
        }
    }
}

fn sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

impl ActionFactsV2 {
    pub fn from_bounded_json(bytes: &[u8]) -> Result<Self, ActionFactsErrorV2> {
        if bytes.len() > MAX_ACTION_FACTS_BYTES {
            return Err(ActionFactsErrorV2::LimitExceeded);
        }
        let facts: Self = serde_json::from_slice(bytes).map_err(|_| ActionFactsErrorV2::Invalid)?;
        facts.validate()?;
        Ok(facts)
    }

    /// Checks representation and contradictions; never grants execution.
    pub fn validate(&self) -> Result<(), ActionFactsErrorV2> {
        use ActionFactsErrorV2 as Error;
        if self.schema != ACTION_FACTS_V2_SCHEMA || self.version != ACTION_FACTS_V2_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        let counts = [&self.record_count, &self.recipient_count, &self.byte_count];
        if counts
            .iter()
            .filter_map(|count| count.known())
            .any(|count| *count > MAX_BUSINESS_WIRE_COUNT)
            || self
                .money
                .known()
                .is_some_and(|money| money.amount_minor > MAX_BUSINESS_WIRE_COUNT)
        {
            return Err(Error::LimitExceeded);
        }
        if let Some(domains) = self.audience.recipient_domains.known() {
            if domains.len() > MAX_BUSINESS_ACTION_ITEMS {
                return Err(Error::LimitExceeded);
            }
            if !sorted_unique(domains) || !domains.iter().all(|d| is_canonical_business_domain(d)) {
                return Err(Error::Invalid);
            }
        }
        if let Some(money) = self.money.known() {
            if money.currency.len() != 3 || !money.currency.bytes().all(|b| b.is_ascii_uppercase())
            {
                return Err(Error::Invalid);
            }
        }
        if let Some(labels) = self.sensitivity.known() {
            if labels.is_empty() || !sorted_unique(labels) {
                return Err(Error::Invalid);
            }
        }
        if !sorted_unique(&self.findings) || !sorted_unique(&self.pii_kinds) {
            return Err(Error::Invalid);
        }
        self.check_consistency()
    }

    fn check_consistency(&self) -> Result<(), ActionFactsErrorV2> {
        let inconsistent = Err(ActionFactsErrorV2::Inconsistent);
        if let (Some(ScopeV2::Single), Some(count)) =
            (self.scope.known(), self.record_count.known())
        {
            if *count != 1 {
                return inconsistent;
            }
        }
        if let (Some(domains), Some(count)) = (
            self.audience.recipient_domains.known(),
            self.recipient_count.known(),
        ) {
            if (*count == 0) != domains.is_empty() || (domains.len() as u64) > *count {
                return inconsistent;
            }
        }
        if self.audience.kind.known() == Some(&AudienceKindV2::Private) {
            // A private result reaches nobody: no recipient, no recipient
            // domain and nobody outside the workspace.
            if self
                .recipient_count
                .known()
                .is_some_and(|count| *count != 0)
                || self
                    .audience
                    .recipient_domains
                    .known()
                    .is_some_and(|domains| !domains.is_empty())
                || self.audience.external.known() == Some(&true)
            {
                return inconsistent;
            }
        }
        if self.class == ActionClassV2::Pay && matches!(self.money, Fact::Unsupported) {
            return inconsistent;
        }
        if serde_json::to_vec(self)
            .map_err(|_| ActionFactsErrorV2::Invalid)?
            .len()
            > MAX_ACTION_FACTS_BYTES
        {
            return Err(ActionFactsErrorV2::LimitExceeded);
        }
        Ok(())
    }

    /// Lossless lift of a validated v1 business action. Facts v1 cannot carry
    /// (workspace-relative `external`, environment, money) are `unknown` or
    /// `unsupported`, never guessed.
    pub fn from_business_action_v1(action: &BusinessActionV1) -> Self {
        let operation = action.operation;
        let complete = action.completeness == BusinessFactStateV1::Known;
        let count = |value: u64| {
            if complete {
                Fact::Known(value)
            } else {
                Fact::Unknown
            }
        };
        let expanded = action.audience.expansion_state == BusinessFactStateV1::Known;
        let audience_kind = match action.audience.kind {
            BusinessAudienceKindV1::Private => Fact::Known(AudienceKindV2::Private),
            BusinessAudienceKindV1::Named => Fact::Known(AudienceKindV2::Named),
            BusinessAudienceKindV1::Public => Fact::Known(AudienceKindV2::Public),
            BusinessAudienceKindV1::Unknown => Fact::Unknown,
        };
        let domains: BTreeSet<String> = action
            .audience
            .recipients
            .iter()
            .map(|recipient| recipient.domain.clone())
            .collect();
        let labels = &action.content.sensitivity_labels;
        let inspected = action.content.inspection_state == BusinessFactStateV1::Known;
        let sensitivity = if !inspected
            || labels.contains(&BusinessSensitivityV1::Unknown)
            || labels.is_empty()
        {
            Fact::Unknown
        } else {
            let set: BTreeSet<SensitivityV2> = labels
                .iter()
                .filter_map(|label| match label {
                    BusinessSensitivityV1::Public => Some(SensitivityV2::Public),
                    BusinessSensitivityV1::Personal => Some(SensitivityV2::Personal),
                    BusinessSensitivityV1::Confidential => Some(SensitivityV2::Confidential),
                    BusinessSensitivityV1::Secret => Some(SensitivityV2::Secret),
                    BusinessSensitivityV1::Unknown => None,
                })
                .collect();
            Fact::Known(set.into_iter().collect())
        };
        let record_count = count(action.volume.record_count);
        let scope = match record_count.known() {
            Some(1) => Fact::Known(ScopeV2::Single),
            Some(_) => Fact::Known(ScopeV2::Enumerated),
            None => Fact::Unknown,
        };
        Self {
            schema: ACTION_FACTS_V2_SCHEMA.into(),
            version: ACTION_FACTS_V2_VERSION,
            class: class_from_v1(operation.action_class()),
            object: Fact::Known(object_from_v1(operation)),
            reversibility: reversibility_from_v1(operation),
            scope,
            record_count,
            recipient_count: if expanded {
                count(action.volume.recipient_count)
            } else {
                Fact::Unknown
            },
            byte_count: count(action.volume.byte_count),
            audience: AudienceV2 {
                kind: audience_kind,
                recipient_domains: if expanded && complete {
                    Fact::Known(domains.into_iter().collect())
                } else {
                    Fact::Unknown
                },
                external: Fact::Unknown,
            },
            environment: Fact::Unsupported,
            money: Fact::Unsupported,
            sensitivity,
            findings: Vec::new(),
            pii_kinds: Vec::new(),
        }
    }
}

pub fn class_from_v1(class: BusinessActionClassV1) -> ActionClassV2 {
    match class {
        BusinessActionClassV1::Read => ActionClassV2::Read,
        BusinessActionClassV1::Draft => ActionClassV2::Draft,
        BusinessActionClassV1::Send => ActionClassV2::Send,
        BusinessActionClassV1::Share => ActionClassV2::Share,
        BusinessActionClassV1::Export => ActionClassV2::Export,
        BusinessActionClassV1::Update => ActionClassV2::Update,
        BusinessActionClassV1::Delete => ActionClassV2::Delete,
        BusinessActionClassV1::Admin => ActionClassV2::Admin,
    }
}

pub fn object_from_v1(operation: BusinessOperationV1) -> ObjectKindV2 {
    use BusinessOperationV1 as Op;
    match operation {
        Op::MailRead | Op::MailDraft | Op::MailSend | Op::MailLabel | Op::MailPermanentDelete => {
            ObjectKindV2::Message
        }
        Op::MailSettings => ObjectKindV2::Other,
        Op::DriveRead | Op::DriveEdit | Op::DriveShare | Op::DriveExport => ObjectKindV2::File,
        Op::CalendarRead | Op::CalendarInvite => ObjectKindV2::Event,
    }
}

fn reversibility_from_v1(operation: BusinessOperationV1) -> Fact<ReversibilityV2> {
    use BusinessOperationV1 as Op;
    match operation {
        Op::MailRead | Op::DriveRead | Op::CalendarRead | Op::MailDraft => {
            Fact::Known(ReversibilityV2::Reversible)
        }
        Op::MailLabel | Op::DriveShare => Fact::Known(ReversibilityV2::Reversible),
        Op::MailSend | Op::CalendarInvite | Op::DriveExport | Op::MailPermanentDelete => {
            Fact::Known(ReversibilityV2::Permanent)
        }
        Op::DriveEdit | Op::MailSettings => Fact::Unknown,
    }
}
