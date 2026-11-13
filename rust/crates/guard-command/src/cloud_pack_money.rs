//! Money facts read from a pack action's arguments.
//!
//! A pack names the integer argument that holds the amount in the currency's
//! minor unit and either a string argument or a fixed code for the currency.
//! An absent or out-of-range amount, or a currency that is not a three-letter
//! code, leaves the money fact unknown, which policy treats as the stricter
//! branch.

use crate::cloud_pack::ArgumentSpec;
use guard_contracts::{Fact, MoneyDirectionV2, MoneyV2, MAX_BUSINESS_WIRE_COUNT};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// How a call's amount, currency and direction are read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MoneySpec {
    /// An integer argument holding the amount in the currency's minor unit.
    pub amount: String,
    /// A string argument holding an ISO 4217 code, in either case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency_argument: Option<String>,
    /// A fixed ISO 4217 code, for an action that always uses one currency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    pub direction: MoneyDirectionV2,
}

pub(crate) fn extract(spec: Option<&MoneySpec>, args: &Map<String, Value>) -> Fact<MoneyV2> {
    let Some(spec) = spec else {
        return Fact::Unknown;
    };
    let Some(amount_minor) = args
        .get(&spec.amount)
        .and_then(Value::as_u64)
        .filter(|amount| *amount <= MAX_BUSINESS_WIRE_COUNT)
    else {
        return Fact::Unknown;
    };
    let currency = match (&spec.currency_argument, &spec.currency) {
        (Some(name), None) => args
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_ascii_uppercase),
        (None, Some(code)) => Some(code.clone()),
        _ => None,
    };
    match currency.filter(|code| iso_code(code)) {
        Some(currency) => Fact::Known(MoneyV2 {
            amount_minor,
            currency,
            direction: spec.direction,
        }),
        None => Fact::Unknown,
    }
}

fn iso_code(code: &str) -> bool {
    code.len() == 3 && code.bytes().all(|b| b.is_ascii_uppercase())
}

/// The amount must be a non-negative integer argument and the currency either
/// a pattern-bound string argument of at most three characters or a fixed code.
pub(crate) fn validate(
    spec: Option<&MoneySpec>,
    args: &BTreeMap<String, ArgumentSpec>,
) -> Result<(), &'static str> {
    let Some(spec) = spec else {
        return Ok(());
    };
    if !matches!(
        args.get(&spec.amount),
        Some(ArgumentSpec::Integer { minimum, .. }) if *minimum >= 0
    ) {
        return Err("cloud_pack_money_invalid");
    }
    let currency_ok = match (&spec.currency_argument, &spec.currency) {
        (Some(name), None) => {
            name != &spec.amount
                && matches!(
                    args.get(name),
                    Some(ArgumentSpec::String { pattern: Some(_), max_length, .. })
                        if *max_length <= 3
                )
        }
        (None, Some(code)) => iso_code(code),
        _ => false,
    };
    if currency_ok {
        Ok(())
    } else {
        Err("cloud_pack_money_invalid")
    }
}
