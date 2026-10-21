//! The wire artifact: launch definition plus the metadata keys the risk
//! derivation reads, with Python truthiness and `str()` for other values.

use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireArtifact {
    pub(super) name: String,
    pub(super) command: Option<String>,
    pub(super) url: Option<String>,
    pub(super) args: Vec<String>,
    pub(super) metadata: WireMetadata,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireMetadata {
    #[serde(default)]
    pub(super) env_keys: Option<Vec<Option<String>>>,
    #[serde(default)]
    pub(super) prompt_signals: Option<Vec<Option<String>>>,
    #[serde(default)]
    pub(super) runtime_request_signals: Option<Vec<Option<String>>>,
    #[serde(default)]
    pub(super) analysis_truncated: Option<WireScalar>,
    #[serde(default)]
    pub(super) config_parse_complete: Option<WireScalar>,
    #[serde(default)]
    pub(super) config_reason: Option<WireScalar>,
    #[serde(default)]
    pub(super) inspection_complete: Option<WireScalar>,
    #[serde(default)]
    pub(super) inspection_reason: Option<WireScalar>,
    #[serde(default)]
    pub(super) prompt_summary: Option<WireScalar>,
    #[serde(default)]
    pub(super) request_summary: Option<WireScalar>,
    #[serde(default)]
    pub(super) runtime_request_reason: Option<WireScalar>,
    #[serde(default)]
    pub(super) runtime_request_summary: Option<WireScalar>,
}

/// One metadata value: a `bool`, a `str`, or any other Python value as its
/// `str()` and truthiness. A missing key and `None` are both `Option::None`.
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum WireScalar {
    Flag(bool),
    Text(String),
    Other(PythonValue),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PythonValue {
    python_str: String,
    truthy: bool,
}

pub(super) fn truthy(value: Option<&WireScalar>) -> bool {
    match value {
        None => false,
        Some(WireScalar::Flag(flag)) => *flag,
        Some(WireScalar::Text(text)) => !text.is_empty(),
        Some(WireScalar::Other(other)) => other.truthy,
    }
}

pub(super) fn python_str(value: Option<&WireScalar>) -> String {
    match value {
        None => "None".to_owned(),
        Some(WireScalar::Flag(true)) => "True".to_owned(),
        Some(WireScalar::Flag(false)) => "False".to_owned(),
        Some(WireScalar::Text(text)) => text.clone(),
        Some(WireScalar::Other(other)) => other.python_str.clone(),
    }
}

/// A non-empty `str` metadata value.
pub(super) fn text(value: Option<&WireScalar>) -> Option<&str> {
    match value {
        Some(WireScalar::Text(text)) if !text.is_empty() => Some(text),
        _ => None,
    }
}

/// The non-empty `str` items of a metadata list.
pub(super) fn items(value: Option<&Vec<Option<String>>>) -> Vec<&str> {
    value
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_deref().filter(|item| !item.is_empty()))
        .collect()
}
