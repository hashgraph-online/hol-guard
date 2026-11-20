//! Prompt risk-class reasons shown for a blocked prompt.

use super::Object;
use serde_json::Value;

const PROMPT_RISK_CLASSES: [(&str, &str); 7] = [
    ("local_env_read", "Prompt requests a local .env file."),
    (
        "sensitive_material",
        "Prompt requests potentially sensitive local material.",
    ),
    (
        "exfil_intent",
        "Prompt includes exfiltration-oriented transfer intent.",
    ),
    (
        "destructive_intent",
        "Prompt includes a destructive local action.",
    ),
    ("subprocess_intent", "Prompt requests subprocess execution."),
    (
        "guard_bypass_intent",
        "Prompt includes Guard bypass intent.",
    ),
    (
        "prompt_injection_intent",
        "Prompt asks to override or reveal trusted instructions.",
    ),
];

/// The reasons for the classes a prompt result carries, or none when the
/// classes are missing, unknown, unordered or repeated.
pub(super) fn prompt_risk_signals(response: &Object) -> Vec<&'static str> {
    let Some(Value::Array(classes)) = response.get("prompt_risk_classes") else {
        return Vec::new();
    };
    let order = |item: &Value| {
        PROMPT_RISK_CLASSES
            .iter()
            .position(|(code, _)| item.as_str() == Some(code))
    };
    let indexes: Option<Vec<usize>> = classes.iter().map(order).collect();
    match indexes {
        Some(indexes)
            if (1..=6).contains(&indexes.len()) && indexes.windows(2).all(|w| w[0] < w[1]) =>
        {
            indexes
                .into_iter()
                .map(|index| PROMPT_RISK_CLASSES[index].1)
                .collect()
        }
        _ => Vec::new(),
    }
}
