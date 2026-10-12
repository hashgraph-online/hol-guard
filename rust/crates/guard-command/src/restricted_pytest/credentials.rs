//! Credential denials shared by native contained-execution profiles.
use serde_json::{json, Value};

pub(super) fn seatbelt_string(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    )
}

fn literal(value: &str) -> String {
    let mut result = String::new();
    for c in value.chars() {
        if c.is_ascii_alphabetic() {
            result.push_str(&format!(
                "[{}{}]",
                c.to_ascii_lowercase(),
                c.to_ascii_uppercase()
            ));
        } else {
            if matches!(c, '.' | '-') {
                result.push('\\');
            }
            result.push(c);
        }
    }
    result
}

fn alternatives(names: &[&str]) -> String {
    names
        .iter()
        .map(|v| literal(v))
        .collect::<Vec<_>>()
        .join("|")
}

pub(super) fn patterns() -> Vec<String> {
    vec![
        format!("(^|/){}($|[./])", literal(".env")),
        format!("(^|/)[^/]*{}$", literal(".key")),
        format!("(^|/){}[^/]*$", literal("krb5cc_")),
        format!(
            "(^|/)({})$",
            alternatives(&[
                ".envrc",
                ".authrc",
                ".npmrc",
                ".pypirc",
                ".netrc",
                ".git-credentials",
                "terraform.tfvars",
                "private.key",
                "wallet.key"
            ])
        ),
        format!(
            "(^|/)[^/]*({})[^/]*$",
            alternatives(&["private-key", "private_key", "wallet-key", "wallet_key"])
        ),
        format!(
            "(^|/)({})(/|$)",
            alternatives(&[".ssh", ".aws", ".docker", ".kube", ".gnupg", ".hol-guard"])
        ),
    ]
}

pub(super) fn denials(hide_metadata: bool) -> Vec<String> {
    let operation = if hide_metadata {
        "file-read*"
    } else {
        "file-read-data"
    };
    patterns()
        .iter()
        .map(|v| format!("(deny {operation} (regex {}))", seatbelt_string(v)))
        .collect()
}

pub(super) fn evaluate(operation: &str, input: &Value) -> Option<Value> {
    let value = match operation {
        "seatbelt_string" => json!(seatbelt_string(input.get("value")?.as_str()?)),
        "credential_patterns" => json!(patterns()),
        "credential_denials" => json!(denials(
            input
                .get("hide_metadata")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        )),
        _ => return None,
    };
    Some(json!({"value":value}))
}
