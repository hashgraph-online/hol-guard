//! What a Codex hook launcher makes of the child it ran, ported from
//! `TrustedCodexHookLaunch.run_start` and `run_fallback`.
//!
//! The launcher sends the child's result as facts; the runtime decides which
//! failure kind the child is told about and whether the child succeeded.

use serde_json::{json, Map, Value};

use crate::runner_authority_op::{KindResult, ERR_INVALID};

const DEFAULT_KIND: &str = "transport-failure";
const FAILURE_KINDS: [&str; 3] = [
    "authenticated-control-plane-failure",
    "overload",
    "transport-failure",
];

/// `launch_failure_kind`: `failure_kind` as the child is told it, which is
/// `transport-failure` unless it is one of the three the bridge knows.
pub(crate) fn failure_kind(args: &Map<String, Value>) -> KindResult {
    let kind = args
        .get("failure_kind")
        .and_then(Value::as_str)
        .filter(|kind| FAILURE_KINDS.contains(kind))
        .unwrap_or(DEFAULT_KIND);
    Ok(json!({ "failure_kind": kind }))
}

/// `launch_result`: the child succeeded only when it exited zero without
/// exceeding its output limit, timing out or failing containment.
pub(crate) fn succeeded(args: &Map<String, Value>) -> KindResult {
    let flag = |key: &str| match args.get(key) {
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(ERR_INVALID),
    };
    let exited_zero = args.get("returncode").and_then(Value::as_i64) == Some(0);
    let clean =
        !flag("output_limit_exceeded")? && !flag("timed_out")? && !flag("containment_failed")?;
    Ok(json!({ "succeeded": exited_zero && clean }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(value: Value) -> Map<String, Value> {
        value.as_object().cloned().expect("an object")
    }

    #[test]
    fn an_unknown_failure_kind_becomes_a_transport_failure() {
        for kind in FAILURE_KINDS {
            let answer = failure_kind(&map(json!({ "failure_kind": kind }))).unwrap();
            assert_eq!(answer["failure_kind"], json!(kind));
        }
        for given in [json!("other"), json!(7), Value::Null] {
            let answer = failure_kind(&map(json!({ "failure_kind": given }))).unwrap();
            assert_eq!(answer["failure_kind"], json!("transport-failure"));
        }
        let missing = failure_kind(&Map::new()).unwrap();
        assert_eq!(missing["failure_kind"], json!("transport-failure"));
    }

    #[test]
    fn only_a_clean_zero_exit_succeeds() {
        let result = |code: Value, limit: bool, timed_out: bool, contained: bool| {
            succeeded(&map(json!({
                "returncode": code,
                "output_limit_exceeded": limit,
                "timed_out": timed_out,
                "containment_failed": contained,
            })))
            .unwrap()["succeeded"]
                .clone()
        };
        assert_eq!(result(json!(0), false, false, false), json!(true));
        for answer in [
            result(json!(1), false, false, false),
            result(Value::Null, false, false, false),
            result(json!(0), true, false, false),
            result(json!(0), false, true, false),
            result(json!(0), false, false, true),
        ] {
            assert_eq!(answer, json!(false));
        }
        assert!(succeeded(&map(json!({ "returncode": 0 }))).is_err());
    }
}
