//! Validation of a pack action's fact extractors.
//!
//! Each extractor must produce a value of its fact's type, read an argument
//! of the right kind, and never claim a private audience while naming
//! recipient domains.

use crate::cloud_pack::*;
use guard_contracts::{
    AudienceKindV2, EnvironmentV2, ObjectKindV2, ReversibilityV2, ScopeV2, SensitivityV2,
};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub(crate) fn validate_facts(
    pack: &CloudActionPack,
    action: &PackAction,
) -> Result<(), &'static str> {
    let facts = &action.facts;
    let args = &action.arguments;
    enum_fact::<ObjectKindV2>(facts.object.as_ref(), args)?;
    enum_fact::<ReversibilityV2>(facts.reversibility.as_ref(), args)?;
    enum_fact::<ScopeV2>(facts.scope.as_ref(), args)?;
    enum_fact::<EnvironmentV2>(facts.environment.as_ref(), args)?;
    enum_fact::<AudienceKindV2>(facts.audience_kind.as_ref(), args)?;
    for count in [
        &facts.record_count,
        &facts.recipient_count,
        &facts.byte_count,
    ] {
        count_fact(count.as_ref(), args)?;
    }
    match &facts.recipient_domains {
        None => {}
        Some(Extractor::Const(value)) => typed::<Vec<String>>(value)?,
        Some(Extractor::Domains { arguments }) => {
            if !distinct(arguments)
                || !arguments.iter().all(|name| {
                    matches!(
                        args.get(name),
                        Some(ArgumentSpec::String { .. } | ArgumentSpec::Array { .. })
                    )
                })
            {
                return Err("cloud_pack_extractor_argument_invalid");
            }
        }
        Some(_) => return Err("cloud_pack_extractor_kind_invalid"),
    }
    match &facts.sensitivity {
        None => {}
        Some(Extractor::Const(value)) => typed::<Vec<SensitivityV2>>(value)?,
        Some(_) => return Err("cloud_pack_extractor_kind_invalid"),
    }
    if let (Some(Extractor::Const(kind)), Some(_)) =
        (&facts.audience_kind, &facts.recipient_domains)
    {
        if kind == "private" {
            return Err("cloud_pack_facts_inconsistent");
        }
    }
    mail_recipients_bound(action)?;
    if let Some(readback) = &facts.count_readback {
        let target = pack.action(readback).ok_or("cloud_pack_readback_invalid")?;
        if readback == &action.action_id
            || target.safety.effect != crate::cloud_action_binding::ActionEffect::Read
        {
            return Err("cloud_pack_readback_invalid");
        }
    }
    Ok(())
}

/// A message built by an `rfc822` body must report exactly its recipient arguments as
/// recipient domains and recipient count, so the facts name everyone the message reaches.
fn mail_recipients_bound(action: &PackAction) -> Result<(), &'static str> {
    let Executor::DeclarativeHttp { request } = &action.executor else {
        return Ok(());
    };
    let Some(body) = &request.body else {
        return Ok(());
    };
    for mail in crate::cloud_pack_mail::find(body) {
        let wanted: std::collections::BTreeSet<&str> =
            mail.recipient_arguments().into_iter().collect();
        let same = |arguments: &Vec<String>| {
            distinct(arguments)
                && arguments
                    .iter()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
                    == wanted
        };
        let domains = matches!(
            &action.facts.recipient_domains,
            Some(Extractor::Domains { arguments }) if same(arguments)
        );
        let count = matches!(
            &action.facts.recipient_count,
            Some(Extractor::Count { arguments }) if same(arguments)
        );
        if !(domains && count) {
            return Err("cloud_pack_mail_recipients_unbound");
        }
    }
    Ok(())
}

/// An extractor that lists an argument twice would count it twice and could stand in for
/// an argument it leaves out, so every list must name each argument once.
fn distinct(arguments: &[String]) -> bool {
    let unique: std::collections::BTreeSet<&str> = arguments.iter().map(String::as_str).collect();
    !arguments.is_empty() && unique.len() == arguments.len()
}

fn typed<T: DeserializeOwned>(value: &Value) -> Result<(), &'static str> {
    serde_json::from_value::<T>(value.clone())
        .map(|_| ())
        .map_err(|_| "cloud_pack_extractor_value_invalid")
}

fn enum_fact<T: DeserializeOwned>(
    extractor: Option<&Extractor>,
    args: &std::collections::BTreeMap<String, ArgumentSpec>,
) -> Result<(), &'static str> {
    match extractor {
        None => Ok(()),
        Some(Extractor::Const(value)) => typed::<T>(value),
        Some(Extractor::Flag {
            argument,
            when_true,
            when_false,
            when_absent,
        }) => {
            if !matches!(args.get(argument), Some(ArgumentSpec::Boolean { .. })) {
                return Err("cloud_pack_extractor_argument_invalid");
            }
            typed::<T>(when_true)?;
            typed::<T>(when_false)?;
            when_absent.as_ref().map_or(Ok(()), typed::<T>)
        }
        Some(_) => Err("cloud_pack_extractor_kind_invalid"),
    }
}

fn count_fact(
    extractor: Option<&Extractor>,
    args: &std::collections::BTreeMap<String, ArgumentSpec>,
) -> Result<(), &'static str> {
    match extractor {
        None => Ok(()),
        Some(Extractor::Const(value)) => typed::<u64>(value),
        Some(Extractor::Count { arguments }) => {
            if !distinct(arguments)
                || !arguments
                    .iter()
                    .all(|name| matches!(
                        args.get(name),
                        Some(ArgumentSpec::Array { .. } | ArgumentSpec::Json { max_items: Some(_), .. })
                    ))
            {
                return Err("cloud_pack_extractor_argument_invalid");
            }
            Ok(())
        }
        Some(Extractor::Argument { name, default, max }) => match args.get(name) {
            Some(ArgumentSpec::Integer { minimum, .. })
                if *minimum >= 0 && default.is_none_or(|value| value <= *max) =>
            {
                Ok(())
            }
            _ => Err("cloud_pack_extractor_argument_invalid"),
        },
        Some(_) => Err("cloud_pack_extractor_kind_invalid"),
    }
}
