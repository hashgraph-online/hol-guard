//! Fact extraction from checked arguments.
//!
//! Extraction is total: every fact comes back known, unknown or unsupported,
//! and anything an extractor cannot read with certainty (an absent flag with
//! no default, an out-of-range count, an address with no domain) is unknown.
//! Facts that depend on workspace settings, such as whether a recipient is
//! external or which environment a resource is in, stay unknown unless the
//! pack states them as constants; the host fills them from trusted settings.

use crate::cloud_pack::{Extractor, PackAction};
use guard_contracts::{
    ActionFactsV2, AudienceKindV2, AudienceV2, Fact, ACTION_FACTS_V2_SCHEMA,
    ACTION_FACTS_V2_VERSION,
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const MAX_DOMAINS: usize = 256;

/// Derive the facts of one call. `args` must already have passed `check_arguments`.
pub fn extract(action: &PackAction, args: &Map<String, Value>) -> ActionFactsV2 {
    let spec = &action.facts;
    let mut facts = ActionFactsV2 {
        schema: ACTION_FACTS_V2_SCHEMA.into(),
        version: ACTION_FACTS_V2_VERSION,
        class: spec.class,
        object: choice(spec.object.as_ref(), args),
        reversibility: choice(spec.reversibility.as_ref(), args),
        scope: choice(spec.scope.as_ref(), args),
        record_count: count(spec.record_count.as_ref(), args),
        recipient_count: count(spec.recipient_count.as_ref(), args),
        byte_count: count(spec.byte_count.as_ref(), args),
        audience: AudienceV2 {
            kind: choice(spec.audience_kind.as_ref(), args),
            recipient_domains: domains(spec.recipient_domains.as_ref(), args),
            external: Fact::Unknown,
        },
        environment: choice(spec.environment.as_ref(), args),
        money: Fact::Unknown,
        sensitivity: match &spec.sensitivity {
            Some(Extractor::Const(value)) => known(value),
            _ => Fact::Unknown,
        },
        findings: Vec::new(),
        pii_kinds: Vec::new(),
    };
    if facts.validate().is_err() {
        // An argument made the audience contradict itself; claim nothing about it.
        facts.audience = AudienceV2 {
            kind: Fact::Unknown,
            recipient_domains: Fact::Unknown,
            external: Fact::Unknown,
        };
        if facts.validate().is_err() {
            return unknown_facts(action);
        }
    }
    if facts.audience.kind.known() == Some(&AudienceKindV2::Private) {
        facts.audience.external = Fact::Known(false);
    }
    facts
}

/// Facts that claim nothing beyond the declared class.
pub fn unknown_facts(action: &PackAction) -> ActionFactsV2 {
    ActionFactsV2 {
        schema: ACTION_FACTS_V2_SCHEMA.into(),
        version: ACTION_FACTS_V2_VERSION,
        class: action.facts.class,
        object: Fact::Unknown,
        reversibility: Fact::Unknown,
        scope: Fact::Unknown,
        record_count: Fact::Unknown,
        recipient_count: Fact::Unknown,
        byte_count: Fact::Unknown,
        audience: AudienceV2 {
            kind: Fact::Unknown,
            recipient_domains: Fact::Unknown,
            external: Fact::Unknown,
        },
        environment: Fact::Unknown,
        money: Fact::Unknown,
        sensitivity: Fact::Unknown,
        findings: Vec::new(),
        pii_kinds: Vec::new(),
    }
}

fn known<T: DeserializeOwned>(value: &Value) -> Fact<T> {
    serde_json::from_value(value.clone()).map_or(Fact::Unknown, Fact::Known)
}

fn choice<T: DeserializeOwned>(
    extractor: Option<&Extractor>,
    args: &Map<String, Value>,
) -> Fact<T> {
    match extractor {
        Some(Extractor::Const(value)) => known(value),
        Some(Extractor::Flag {
            argument,
            when_true,
            when_false,
            when_absent,
        }) => match args.get(argument) {
            Some(Value::Bool(true)) => known(when_true),
            Some(Value::Bool(false)) => known(when_false),
            None => when_absent.as_ref().map_or(Fact::Unknown, known),
            Some(_) => Fact::Unknown,
        },
        _ => Fact::Unknown,
    }
}

fn count(extractor: Option<&Extractor>, args: &Map<String, Value>) -> Fact<u64> {
    match extractor {
        Some(Extractor::Const(value)) => known(value),
        Some(Extractor::Count { arguments }) => {
            let mut total = 0_u64;
            for name in arguments {
                match args.get(name) {
                    None => {}
                    Some(Value::Array(items)) => total = total.saturating_add(items.len() as u64),
                    Some(_) => return Fact::Unknown,
                }
            }
            Fact::Known(total)
        }
        Some(Extractor::Argument { name, max, default }) => match args.get(name) {
            Some(value) => value
                .as_u64()
                .filter(|n| n <= max)
                .map_or(Fact::Unknown, Fact::Known),
            None => default.map_or(Fact::Unknown, Fact::Known),
        },
        _ => Fact::Unknown,
    }
}

fn domains(extractor: Option<&Extractor>, args: &Map<String, Value>) -> Fact<Vec<String>> {
    match extractor {
        Some(Extractor::Const(value)) => known(value),
        Some(Extractor::Domains { arguments }) => {
            let mut found = BTreeSet::new();
            for name in arguments {
                let values: Vec<&Value> = match args.get(name) {
                    None => continue,
                    Some(Value::Array(items)) => items.iter().collect(),
                    Some(value) => vec![value],
                };
                for value in values {
                    let Some(domain) = value.as_str().and_then(address_domain) else {
                        return Fact::Unknown;
                    };
                    found.insert(domain);
                    if found.len() > MAX_DOMAINS {
                        return Fact::Unknown;
                    }
                }
            }
            Fact::Known(found.into_iter().collect())
        }
        _ => Fact::Unknown,
    }
}

/// The lowercased domain of `local@domain` or `Name <local@domain>`, when it is a plain DNS name.
pub(crate) fn address_domain(address: &str) -> Option<String> {
    let trimmed = address.trim();
    let inner = match (trimmed.rfind('<'), trimmed.strip_suffix('>')) {
        (Some(open), Some(rest)) => &rest[open + 1..],
        (None, None) => trimmed,
        _ => return None,
    };
    let (local, domain) = inner.rsplit_once('@')?;
    let domain = domain.to_ascii_lowercase();
    if local.is_empty()
        || local.contains(char::is_whitespace)
        || !crate::cloud_pack_validate::valid_host(&domain)
    {
        return None;
    }
    Some(domain)
}
