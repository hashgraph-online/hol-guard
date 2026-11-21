//! Fact selectors for `guard.action-facts.v2`.
//!
//! Dimensions intersect; values within a dimension are alternatives; a
//! missing dimension is a wildcard; an explicit null is rejected so it can
//! never widen a rule silently. Matching is three-valued: a dimension that
//! tests an unknown fact answers `Unknown`, and the policy join resolves that
//! to whichever branch is stricter. A selector never grants anything by
//! itself.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::action_facts::{
    ActionClassV2, ActionFactsV2, AudienceKindV2, EnvironmentV2, Fact, FindingV2, MoneyDirectionV2,
    ObjectKindV2, PiiKindV2, ReversibilityV2, ScopeV2, SensitivityV2,
};
use crate::business_action::{
    is_canonical_business_domain, MAX_BUSINESS_ACTION_ITEMS, MAX_BUSINESS_WIRE_COUNT,
};

pub const MAX_USAGE_WINDOWS: usize = 32;

/// Three-valued match result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match3 {
    Yes,
    No,
    Unknown,
}

impl Match3 {
    fn from_bool(value: bool) -> Self {
        if value {
            Self::Yes
        } else {
            Self::No
        }
    }

    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::No, _) | (_, Self::No) => Self::No,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Yes,
        }
    }
}

/// What the gateway has seen earlier in the same host session. Kept by the
/// caller from its journal; never derived from request input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionFlowV2 {
    pub untrusted_content_seen: bool,
    pub sensitive_data_seen: bool,
    pub injection_signal_seen: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionFlagV2 {
    UntrustedContentSeen,
    SensitiveDataSeen,
    InjectionSignalSeen,
    /// The action itself can move data or value out: send, share, export,
    /// pay, or an update whose audience is external.
    Egress,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowBoundV2 {
    pub window: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub at_most: Option<u64>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub above: Option<u64>,
}

fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

macro_rules! optional_dimensions {
    ($(#[$meta:meta])* pub struct $name:ident { $($field:ident : $ty:ty,)* }) => {
        $(#[$meta])*
        pub struct $name {
            $(
                #[serde(default, deserialize_with = "present", skip_serializing_if = "Option::is_none")]
                pub $field: Option<$ty>,
            )*
        }

        impl $name {
            fn dimension_count(&self) -> usize {
                0 $(+ usize::from(self.$field.is_some()))*
            }
        }
    };
}

optional_dimensions! {
    #[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct FactSelectorV2 {
        providers: Vec<String>,
        classes: Vec<ActionClassV2>,
        objects: Vec<ObjectKindV2>,
        reversibility: Vec<ReversibilityV2>,
        scopes: Vec<ScopeV2>,
        audience_kinds: Vec<AudienceKindV2>,
        recipient_domains: Vec<String>,
        recipient_domains_outside: Vec<String>,
        external: bool,
        environments: Vec<EnvironmentV2>,
        sensitivity: Vec<SensitivityV2>,
        min_record_count: u64,
        max_record_count: u64,
        min_recipient_count: u64,
        max_recipient_count: u64,
        min_byte_count: u64,
        max_byte_count: u64,
        min_amount_minor: u64,
        currencies: Vec<String>,
        money_directions: Vec<MoneyDirectionV2>,
        findings: Vec<FindingV2>,
        pii_kinds: Vec<PiiKindV2>,
        session: Vec<SessionFlagV2>,
        windows: Vec<WindowBoundV2>,
    }
}

/// Everything a selector reads.
pub struct FactSubjectV2<'a> {
    pub provider: &'a str,
    pub facts: &'a ActionFactsV2,
    pub session: Option<&'a SessionFlowV2>,
    /// Authenticated usage so far in each named window, before this call.
    pub windows: &'a BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactSelectorErrorV2 {
    Invalid,
    BoundsExceeded,
}

fn valid_set<T: PartialEq>(values: &[T], maximum: usize) -> bool {
    !values.is_empty()
        && values.len() <= maximum
        && values
            .iter()
            .enumerate()
            .all(|(index, value)| !values[..index].contains(value))
}

/// Lowercase ASCII token used for provider ids and window names.
pub fn valid_fact_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
        })
}

impl FactSelectorV2 {
    pub fn validate(&self) -> Result<(), FactSelectorErrorV2> {
        use FactSelectorErrorV2 as Error;
        if self.dimension_count() == 0 {
            return Err(Error::Invalid);
        }
        let items = MAX_BUSINESS_ACTION_ITEMS;
        let sets_ok = self
            .providers
            .as_ref()
            .is_none_or(|v| valid_set(v, items) && v.iter().all(|p| valid_fact_token(p)))
            && self.classes.as_ref().is_none_or(|v| valid_set(v, 10))
            && self.objects.as_ref().is_none_or(|v| valid_set(v, 17))
            && self.reversibility.as_ref().is_none_or(|v| valid_set(v, 3))
            && self.scopes.as_ref().is_none_or(|v| valid_set(v, 4))
            && self.audience_kinds.as_ref().is_none_or(|v| valid_set(v, 4))
            && [&self.recipient_domains, &self.recipient_domains_outside]
                .iter()
                .all(|domains| {
                    domains.as_ref().is_none_or(|v| {
                        valid_set(v, items) && v.iter().all(|d| is_canonical_business_domain(d))
                    })
                })
            && self.environments.as_ref().is_none_or(|v| valid_set(v, 2))
            && self.sensitivity.as_ref().is_none_or(|v| valid_set(v, 4))
            && self.currencies.as_ref().is_none_or(|v| {
                valid_set(v, 32)
                    && v.iter()
                        .all(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_uppercase()))
            })
            && self
                .money_directions
                .as_ref()
                .is_none_or(|v| valid_set(v, 2))
            && self.findings.as_ref().is_none_or(|v| valid_set(v, 3))
            && self.pii_kinds.as_ref().is_none_or(|v| valid_set(v, 4))
            && self.session.as_ref().is_none_or(|v| valid_set(v, 4))
            && self.windows.as_ref().is_none_or(|v| {
                valid_set(v, MAX_USAGE_WINDOWS)
                    && v.iter().all(|w| {
                        valid_fact_token(&w.window) && (w.at_most.is_some() != w.above.is_some())
                    })
            });
        if !sets_ok {
            return Err(Error::Invalid);
        }
        let ranges = [
            (self.min_record_count, self.max_record_count),
            (self.min_recipient_count, self.max_recipient_count),
            (self.min_byte_count, self.max_byte_count),
        ];
        let numbers = ranges
            .iter()
            .flat_map(|(a, b)| [*a, *b])
            .chain([self.min_amount_minor])
            .chain(
                self.windows
                    .iter()
                    .flatten()
                    .flat_map(|w| [w.at_most, w.above]),
            )
            .flatten();
        if numbers.into_iter().any(|n| n > MAX_BUSINESS_WIRE_COUNT) {
            return Err(Error::BoundsExceeded);
        }
        if ranges
            .iter()
            .any(|(min, max)| matches!((min, max), (Some(a), Some(b)) if a > b))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// Three-valued match. The caller must have validated the selector and
    /// the facts.
    pub fn matches(&self, subject: &FactSubjectV2<'_>) -> Match3 {
        let facts = subject.facts;
        let mut result = Match3::Yes;
        let mut test = |value: Match3| result = result.and(value);

        if let Some(providers) = &self.providers {
            test(Match3::from_bool(
                providers.iter().any(|p| p == subject.provider),
            ));
        }
        if let Some(classes) = &self.classes {
            test(Match3::from_bool(classes.contains(&facts.class)));
        }
        test(one_of(&self.objects, &facts.object));
        test(one_of(&self.reversibility, &facts.reversibility));
        test(one_of(&self.scopes, &facts.scope));
        test(one_of(&self.audience_kinds, &facts.audience.kind));
        test(one_of(&self.environments, &facts.environment));
        if let Some(allowed) = &self.recipient_domains {
            test(known(&facts.audience.recipient_domains, |domains| {
                !domains.is_empty() && domains.iter().all(|d| allowed.contains(d))
            }));
        }
        if let Some(listed) = &self.recipient_domains_outside {
            test(known(&facts.audience.recipient_domains, |domains| {
                domains.iter().any(|d| !listed.contains(d))
            }));
        }
        if let Some(external) = self.external {
            test(known(&facts.audience.external, |value| *value == external));
        }
        if let Some(labels) = &self.sensitivity {
            test(known(&facts.sensitivity, |known| {
                known.iter().any(|label| labels.contains(label))
            }));
        }
        let ranges = [
            (
                &facts.record_count,
                self.min_record_count,
                self.max_record_count,
            ),
            (
                &facts.recipient_count,
                self.min_recipient_count,
                self.max_recipient_count,
            ),
            (&facts.byte_count, self.min_byte_count, self.max_byte_count),
        ];
        for (count, min, max) in ranges {
            if let Some(min) = min {
                test(known(count, |value| *value >= min));
            }
            if let Some(max) = max {
                test(known(count, |value| *value <= max));
            }
        }
        if let Some(min) = self.min_amount_minor {
            test(known(&facts.money, |money| money.amount_minor >= min));
        }
        if let Some(currencies) = &self.currencies {
            test(known(&facts.money, |money| {
                currencies.contains(&money.currency)
            }));
        }
        if let Some(directions) = &self.money_directions {
            test(known(&facts.money, |money| {
                directions.contains(&money.direction)
            }));
        }
        if let Some(findings) = &self.findings {
            test(Match3::from_bool(
                findings.iter().any(|f| facts.findings.contains(f)),
            ));
        }
        if let Some(kinds) = &self.pii_kinds {
            test(Match3::from_bool(
                kinds.iter().any(|k| facts.pii_kinds.contains(k)),
            ));
        }
        if let Some(flags) = &self.session {
            for flag in flags {
                test(session_flag(*flag, subject));
            }
        }
        if let Some(windows) = &self.windows {
            for bound in windows {
                test(window(bound, subject));
            }
        }
        result
    }
}

fn one_of<T: PartialEq>(selector: &Option<Vec<T>>, fact: &Fact<T>) -> Match3 {
    match selector {
        None => Match3::Yes,
        Some(values) => known(fact, |value| values.contains(value)),
    }
}

fn known<T>(fact: &Fact<T>, predicate: impl FnOnce(&T) -> bool) -> Match3 {
    fact.known()
        .map_or(Match3::Unknown, |value| Match3::from_bool(predicate(value)))
}

fn session_flag(flag: SessionFlagV2, subject: &FactSubjectV2<'_>) -> Match3 {
    let facts = subject.facts;
    let seen = |read: fn(&SessionFlowV2) -> bool| {
        subject
            .session
            .map_or(Match3::Unknown, |session| Match3::from_bool(read(session)))
    };
    match flag {
        SessionFlagV2::UntrustedContentSeen => seen(|s| s.untrusted_content_seen),
        SessionFlagV2::SensitiveDataSeen => seen(|s| s.sensitive_data_seen),
        SessionFlagV2::InjectionSignalSeen => seen(|s| s.injection_signal_seen),
        SessionFlagV2::Egress if facts.class.is_egress() => Match3::Yes,
        SessionFlagV2::Egress
            if matches!(facts.class, ActionClassV2::Update | ActionClassV2::Execute) =>
        {
            known(&facts.audience.external, |external| *external)
        }
        SessionFlagV2::Egress => Match3::No,
    }
}

/// A missing counter is treated as over every limit.
fn window(bound: &WindowBoundV2, subject: &FactSubjectV2<'_>) -> Match3 {
    let Some(used) = subject.windows.get(&bound.window) else {
        return Match3::from_bool(bound.above.is_some());
    };
    let increment = match subject.facts.record_count.known() {
        Some(count) => *count,
        None => return Match3::Unknown,
    };
    let total = used.saturating_add(increment);
    match (bound.at_most, bound.above) {
        (Some(limit), None) => Match3::from_bool(total <= limit),
        (None, Some(limit)) => Match3::from_bool(total > limit),
        _ => Match3::No,
    }
}
