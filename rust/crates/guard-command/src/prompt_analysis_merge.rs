//! Folding the prompt artifacts a single prompt earned into the one review it
//! is held under.

use super::{python_strip, sha256_hex, GuardRunPromptArtifact};
use serde_json::{json, Map, Value};

impl GuardRunPromptArtifact {
    /// Rebuild an artifact the host already holds. The host copies the
    /// dataclass fields straight onto the wire rather than calling
    /// `GuardArtifact.to_dict()`, whose redaction would rewrite the matched
    /// text the merge reads.
    pub fn from_dict(value: &Value) -> Option<Self> {
        let text = |key: &str| value.get(key)?.as_str().map(str::to_owned);
        Some(Self {
            artifact_id: text("artifact_id")?,
            name: text("name")?,
            harness: text("harness")?,
            artifact_type: text("artifact_type")?,
            source_scope: text("source_scope")?,
            config_path: text("config_path")?,
            metadata: value.get("metadata")?.as_object()?.clone(),
        })
    }
}

/// The summary a merged prompt artifact carries when its parts disagree about
/// what the prompt asked for (`_merged_prompt_runtime_artifact` :127).
const MULTI_SIGNAL_SUMMARY: &str = "Prompt matches multiple guarded request classes.";

/// `_string_list` (`commands_support_runtime_artifacts.py` :66) — the string
/// items of a list whose stripped form is non-empty, kept unstripped.
fn string_list(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(items)) = value else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(Value::as_str)
        .filter(|item| !python_strip(item).is_empty())
        .map(str::to_owned)
        .collect()
}

/// A stripped metadata string, or `None` when the key is absent, not a string,
/// or blank.
fn stripped_metadata(metadata: &Map<String, Value>, key: &str) -> Option<String> {
    let stripped = python_strip(metadata.get(key)?.as_str()?);
    (!stripped.is_empty()).then_some(stripped)
}

/// `list(dict.fromkeys(values))` — first occurrence wins, order preserved.
fn deduped(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

/// `_merged_prompt_runtime_artifact` (:101) for two or more artifacts — the
/// one review a prompt that tripped several guarded classes is held under.
///
/// The id is the review's key, so it is derived here and nowhere else: the
/// sorted part ids make the same set of signals name the same review however
/// the parts were ordered. The host keeps the single-artifact case, which
/// returns its one part untouched and derives nothing.
pub fn merge_prompt_artifacts(
    harness: &str,
    artifacts: &[GuardRunPromptArtifact],
) -> Option<GuardRunPromptArtifact> {
    let first = artifacts.first()?;
    let mut part_ids: Vec<&str> = artifacts
        .iter()
        .map(|artifact| artifact.artifact_id.as_str())
        .collect();
    part_ids.sort_unstable();
    let request_identity = part_ids.join("|");

    let mut signals: Vec<String> = Vec::new();
    let mut matched_texts: Vec<String> = Vec::new();
    let mut display_texts: Vec<String> = Vec::new();
    let mut request_classes: Vec<String> = Vec::new();
    for artifact in artifacts {
        signals.extend(string_list(artifact.metadata.get("prompt_signals")));
        matched_texts.extend(stripped_metadata(&artifact.metadata, "prompt_matched_text"));
        display_texts.extend(stripped_metadata(&artifact.metadata, "prompt_display_text"));
        request_classes.extend(stripped_metadata(
            &artifact.metadata,
            "prompt_request_class",
        ));
    }
    let display_texts = deduped(display_texts);
    let request_summary = match display_texts.as_slice() {
        [only] => only.clone(),
        _ => MULTI_SIGNAL_SUMMARY.to_owned(),
    };

    let mut metadata = Map::new();
    metadata.insert("prompt_signals".to_owned(), json!(deduped(signals)));
    metadata.insert("prompt_summary".to_owned(), json!(MULTI_SIGNAL_SUMMARY));
    metadata.insert(
        "prompt_matched_texts".to_owned(),
        json!(deduped(matched_texts)),
    );
    metadata.insert("prompt_display_text".to_owned(), json!(request_summary));
    metadata.insert(
        "prompt_request_classes".to_owned(),
        json!(deduped(request_classes)),
    );
    metadata.insert("request_summary".to_owned(), json!(request_summary));
    metadata.insert("runtime_request_summary".to_owned(), json!(request_summary));

    Some(GuardRunPromptArtifact {
        artifact_id: format!(
            "{harness}:session:prompt:multi:{}",
            &sha256_hex(&request_identity)[..24]
        ),
        name: "prompt multi-signal request".to_owned(),
        harness: harness.to_owned(),
        artifact_type: "prompt_request".to_owned(),
        source_scope: first.source_scope.clone(),
        config_path: first.config_path.clone(),
        metadata,
    })
}
