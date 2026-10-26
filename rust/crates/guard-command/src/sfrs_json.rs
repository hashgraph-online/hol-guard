//! `json.dumps(value, sort_keys=True)` with CPython's default separators and
//! `ensure_ascii=True`, used to reproduce request fingerprints byte for byte.

use guard_contracts::write_python_default_json;
use serde_json::Value;

/// Serialize `value` the way `json.dumps(value, sort_keys=True)` does.
pub(crate) fn dumps_sorted(value: &Value) -> String {
    let mut out = Vec::new();
    write_python_default_json(value, &mut out).expect("request fingerprints are always encodable");
    String::from_utf8(out).expect("ensure_ascii output is ASCII")
}

#[cfg(test)]
mod tests {
    use super::dumps_sorted;
    use serde_json::json;

    #[test]
    fn matches_cpython_spelling() {
        let value = json!({"b": ["x", 1], "a": "é\u{1f600}\n", "c": null});
        assert_eq!(
            dumps_sorted(&value),
            r#"{"a": "\u00e9\ud83d\ude00\n", "b": ["x", 1], "c": null}"#
        );
    }
}
