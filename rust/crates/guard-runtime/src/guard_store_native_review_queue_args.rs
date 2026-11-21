//! Argument readers for `queue_native_review` calls.

use serde::Deserialize;
use serde_json::{Map, Value};

use super::{INVALID, WRITE_RESERVE_MS};
use crate::guard_store_db::StoreResult;

const DEFAULT_HINT_BUDGET_MS: u64 = 5_000;
const MAX_HINT_BUDGET_MS: u64 = 10_000;

/// The hook's remaining time, with null selecting the resident default.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HintAsk {
    #[serde(deserialize_with = "Option::deserialize")]
    deadline_left_ms: Option<u64>,
}

impl HintAsk {
    pub(super) fn budget_ms(self, call_budget_ms: u64, spent: u64) -> u64 {
        let hook_budget_ms = self
            .deadline_left_ms
            .map_or(DEFAULT_HINT_BUDGET_MS, |remaining_ms| {
                remaining_ms
                    .saturating_sub(WRITE_RESERVE_MS)
                    .min(MAX_HINT_BUDGET_MS)
            });
        hook_budget_ms
            .min(call_budget_ms.saturating_sub(WRITE_RESERVE_MS))
            .saturating_sub(spent)
    }
}

/// `text` unless it repeats an argument of `command` (`_without_operands`).
/// Arguments split as Python's `str.split()` does.
pub(super) fn without_operands<'a>(
    text: Option<&'a str>,
    command: Option<&str>,
) -> Option<&'a str> {
    let text = text.filter(|text| !text.trim().is_empty())?;
    let separator = |c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c);
    let mut operands = command.into_iter().flat_map(|command| {
        command
            .split(separator)
            .filter(|part| !part.is_empty())
            .skip(1)
    });
    (!operands.any(|operand| text.contains(operand))).then_some(text)
}

/// The ask a call names under `key`, or `None` when it names none.
pub(super) fn take_ask<T: serde::de::DeserializeOwned>(
    args: &mut Map<String, Value>,
    key: &str,
) -> StoreResult<Option<T>> {
    match args.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(ask) => serde_json::from_value(ask).map(Some).map_err(|_| INVALID),
    }
}

pub(super) fn take_flag(args: &mut Map<String, Value>, key: &str) -> StoreResult<bool> {
    match args.remove(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(flag)) => Ok(flag),
        Some(_) => Err(INVALID),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::HintAsk;

    #[test]
    fn the_hook_hint_budget_reserves_time_for_the_write() {
        for (deadline, call_budget, spent, expected) in [
            (None, 20_000, 0, 5_000),
            (Some(750), 20_000, 12, 388),
            (Some(350), 20_000, 0, 0),
            (Some(100), 20_000, 0, 0),
            (Some(20_000), 20_000, 0, 10_000),
            (Some(20_000), 2_000, 5, 1_645),
        ] {
            let ask: HintAsk =
                serde_json::from_value(json!({"deadline_left_ms": deadline})).unwrap();
            assert_eq!(ask.budget_ms(call_budget, spent), expected);
        }
        assert!(serde_json::from_value::<HintAsk>(json!({})).is_err());
    }
}
