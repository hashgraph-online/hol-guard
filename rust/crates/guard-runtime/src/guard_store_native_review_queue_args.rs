//! Argument readers for `queue_native_review` calls.

use serde_json::{Map, Value};

use super::INVALID;
use crate::guard_store_db::StoreResult;

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
