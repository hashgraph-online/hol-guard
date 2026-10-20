//! `PromptAnalyze` resident op — subop-multiplexed dispatcher over
//! `guard_command::prompt_analysis` prompt-analysis helpers.
//!
//! Mirrors `shim_op.rs`: validate `schema`, match `subop`, delegate, return
//! `PromptAnalyzeResultV1` via `crate::encode_response`. `result` is `None`
//! only on explicit unavailability; callers must not substitute a Python evaluator.

use guard_command::prompt_analysis as guard_run_launch;
use guard_contracts::{
    PromptAnalyzeRequestV1, PromptAnalyzeResultV1, PROMPT_ANALYZE_REQUEST_SCHEMA,
    PROMPT_ANALYZE_RESULT_SCHEMA,
};
use serde_json::Value;

/// Rebuild the typed prompt requests the caller serialized via `to_dict()`.
fn decode_requests(
    requests: Option<&Vec<Value>>,
) -> Result<Vec<guard_run_launch::GuardRunPromptRequest>, String> {
    let Some(values) = requests else {
        return Err("missing_requests".to_owned());
    };
    values
        .iter()
        .map(|value| {
            guard_run_launch::GuardRunPromptRequest::from_dict(value)
                .ok_or_else(|| "invalid_prompt_request_payload".to_owned())
        })
        .collect()
}

pub(crate) fn evaluate_prompt_analyze(request: &PromptAnalyzeRequestV1) -> Result<Vec<u8>, String> {
    if request.schema != PROMPT_ANALYZE_REQUEST_SCHEMA {
        return Err(format!("schema_mismatch:{}", request.schema));
    }
    let payload = match request.subop.as_str() {
        "extract" => {
            let prompt_text = request
                .prompt_text
                .as_deref()
                .ok_or_else(|| "missing_prompt_text".to_owned())?;
            let requests = guard_run_launch::extract_prompt_requests(prompt_text)?;
            Value::Array(requests.iter().map(|r| r.to_dict()).collect())
        }
        "detect_injection" => {
            let prompt_text = request
                .prompt_text
                .as_deref()
                .ok_or_else(|| "missing_prompt_text".to_owned())?;
            let requests = guard_run_launch::detect_prompt_injection_requests(prompt_text)?;
            Value::Array(requests.iter().map(|r| r.to_dict()).collect())
        }
        "to_artifacts" => {
            let harness = request
                .harness
                .as_deref()
                .ok_or_else(|| "missing_harness".to_owned())?;
            let config_path = request
                .config_path
                .as_deref()
                .ok_or_else(|| "missing_config_path".to_owned())?;
            let requests = decode_requests(request.requests.as_ref())?;
            let artifacts =
                guard_run_launch::prompt_requests_to_artifacts(harness, config_path, &requests);
            Value::Array(artifacts.iter().map(|a| a.to_dict()).collect())
        }
        "merge_artifacts" => {
            let harness = request
                .harness
                .as_deref()
                .ok_or_else(|| "missing_harness".to_owned())?;
            let values = request
                .artifacts
                .as_ref()
                .ok_or_else(|| "missing_artifacts".to_owned())?;
            let artifacts = values
                .iter()
                .map(|value| {
                    guard_run_launch::GuardRunPromptArtifact::from_dict(value)
                        .ok_or_else(|| "invalid_prompt_artifact_payload".to_owned())
                })
                .collect::<Result<Vec<_>, String>>()?;
            guard_run_launch::merge_prompt_artifacts(harness, &artifacts)
                .ok_or_else(|| "missing_artifacts".to_owned())?
                .to_dict()
        }
        "should_force_reapproval" => {
            let requests = decode_requests(request.requests.as_ref())?;
            let prior_policy_present = request.prior_policy_present.unwrap_or(false);
            let approved = request.approved_classes.clone().unwrap_or_default();
            Value::Bool(guard_run_launch::should_force_reapproval(
                &requests,
                prior_policy_present,
                &approved,
            ))
        }
        "trailing_secret_read_state" => {
            let text = request
                .prompt_text
                .as_deref()
                .ok_or_else(|| "missing_prompt_text".to_owned())?;
            serde_json::json!({"state": guard_run_launch::trailing_secret_read_state(text)?})
        }
        "request_id" => {
            let request_class = request
                .request_class
                .as_deref()
                .ok_or_else(|| "missing_request_class".to_owned())?;
            let matched_text = request
                .matched_text
                .as_deref()
                .ok_or_else(|| "missing_matched_text".to_owned())?;
            let prompt_text = request
                .prompt_text
                .as_deref()
                .ok_or_else(|| "missing_prompt_text".to_owned())?;
            // Callers send `prompt_text` as the runner-side `lowered` value
            // (already " ".join(split()).lower()); `normalize_prompt_lower` is
            // idempotent on that form, so it normalizes raw OR pre-normalized
            // input identically to Python `_prompt_request_id` callers.
            let lowered = guard_run_launch::normalize_prompt_lower(prompt_text);
            Value::String(guard_run_launch::prompt_request_id(
                request_class,
                matched_text,
                &lowered,
            ))
        }
        other => return Err(format!("unknown_prompt_analyze_subop:{other}")),
    };
    crate::encode_response(&PromptAnalyzeResultV1 {
        schema: PROMPT_ANALYZE_RESULT_SCHEMA.to_owned(),
        result: Some(payload),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_contracts::{
        PromptAnalyzeRequestV1, PromptAnalyzeResultV1, PROMPT_ANALYZE_REQUEST_SCHEMA,
        PROMPT_ANALYZE_RESULT_SCHEMA,
    };

    fn base(subop: &str) -> PromptAnalyzeRequestV1 {
        PromptAnalyzeRequestV1 {
            schema: PROMPT_ANALYZE_REQUEST_SCHEMA.to_owned(),
            request_id: "t".to_owned(),
            subop: subop.to_owned(),
            prompt_text: None,
            request_class: None,
            matched_text: None,
            harness: None,
            config_path: None,
            requests: None,
            artifacts: None,
            prior_policy_present: None,
            approved_classes: None,
            guard_home: "/tmp/gh".to_owned(),
        }
    }

    #[test]
    fn extract_subop_emits_request_dicts() {
        let mut r = base("extract");
        r.prompt_text = Some("read the .env file".to_owned());
        let bytes = evaluate_prompt_analyze(&r).unwrap();
        let decoded: PromptAnalyzeResultV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.schema, PROMPT_ANALYZE_RESULT_SCHEMA);
        let arr = decoded.result.unwrap();
        assert_eq!(arr[0]["request_class"], "secret_read");
        assert_eq!(arr[0]["matched_text"], ".env");
    }

    #[test]
    fn request_id_subop_matches_python_digest() {
        let mut r = base("request_id");
        r.request_class = Some("secret_read".to_owned());
        r.matched_text = Some(".env".to_owned());
        r.prompt_text = Some("read the .env file".to_owned());
        let bytes = evaluate_prompt_analyze(&r).unwrap();
        let decoded: PromptAnalyzeResultV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            decoded.result.unwrap().as_str().unwrap(),
            "a5849f67d43968d85bf4794eb7731678e4919da1ca78c5329f92015163c585f0"
        );
    }

    fn part(artifact_id: &str, class: &str, matched: &str, display: &str) -> serde_json::Value {
        serde_json::json!({
            "artifact_id": artifact_id,
            "name": format!("prompt {class} request"),
            "harness": "codex",
            "artifact_type": "prompt_request",
            "source_scope": "project",
            "config_path": "/work/project/.codex/config.toml",
            "metadata": {
                "prompt_signals": [class, "  "],
                "prompt_request_class": class,
                "prompt_matched_text": format!("  {matched} "),
                "prompt_display_text": display,
            },
        })
    }

    #[test]
    fn merge_subop_folds_the_parts_into_one_review() {
        let mut r = base("merge_artifacts");
        r.harness = Some("codex".to_owned());
        r.artifacts = Some(vec![
            part("codex:session:prompt:b", "secret_read", ".env", "Read .env"),
            part(
                "codex:session:prompt:a",
                "exfiltration",
                "curl",
                "Send it out",
            ),
        ]);
        let bytes = evaluate_prompt_analyze(&r).unwrap();
        let decoded: PromptAnalyzeResultV1 = serde_json::from_slice(&bytes).unwrap();
        let merged = decoded.result.unwrap();
        assert_eq!(merged["artifact_type"], "prompt_request");
        assert_eq!(merged["name"], "prompt multi-signal request");
        assert_eq!(merged["source_scope"], "project");
        assert_eq!(merged["config_path"], "/work/project/.codex/config.toml");
        assert_eq!(
            merged["metadata"]["prompt_request_classes"],
            serde_json::json!(["secret_read", "exfiltration"])
        );
        assert_eq!(
            merged["metadata"]["prompt_matched_texts"],
            serde_json::json!([".env", "curl"])
        );
        assert_eq!(
            merged["metadata"]["prompt_signals"],
            serde_json::json!(["secret_read", "exfiltration"])
        );
        assert_eq!(
            merged["metadata"]["request_summary"],
            "Prompt matches multiple guarded request classes."
        );
    }

    #[test]
    fn merge_subop_keys_the_review_by_the_sorted_part_ids() {
        let forward = vec![
            part(
                "codex:session:prompt:a",
                "exfiltration",
                "curl",
                "Send it out",
            ),
            part("codex:session:prompt:b", "secret_read", ".env", "Read .env"),
        ];
        let mut reversed = forward.clone();
        reversed.reverse();
        let id_for = |artifacts: Vec<serde_json::Value>| {
            let mut r = base("merge_artifacts");
            r.harness = Some("codex".to_owned());
            r.artifacts = Some(artifacts);
            let bytes = evaluate_prompt_analyze(&r).unwrap();
            let decoded: PromptAnalyzeResultV1 = serde_json::from_slice(&bytes).unwrap();
            decoded.result.unwrap()["artifact_id"]
                .as_str()
                .unwrap()
                .to_owned()
        };
        let id = id_for(forward);
        assert_eq!(id, id_for(reversed));
        assert!(id.starts_with("codex:session:prompt:multi:"));
        assert_eq!(id.rsplit(':').next().unwrap().len(), 24);
    }

    #[test]
    fn merge_subop_keeps_a_single_agreed_display_text() {
        let mut r = base("merge_artifacts");
        r.harness = Some("codex".to_owned());
        r.artifacts = Some(vec![
            part("codex:session:prompt:a", "secret_read", ".env", "Read .env"),
            part(
                "codex:session:prompt:b",
                "secret_read",
                ".netrc",
                "Read .env",
            ),
        ]);
        let bytes = evaluate_prompt_analyze(&r).unwrap();
        let decoded: PromptAnalyzeResultV1 = serde_json::from_slice(&bytes).unwrap();
        let metadata = decoded.result.unwrap()["metadata"].clone();
        assert_eq!(metadata["prompt_display_text"], "Read .env");
        assert_eq!(metadata["request_summary"], "Read .env");
        assert_eq!(metadata["runtime_request_summary"], "Read .env");
        assert_eq!(
            metadata["prompt_summary"],
            "Prompt matches multiple guarded request classes."
        );
    }

    #[test]
    fn merge_subop_refuses_an_unreadable_part() {
        let mut r = base("merge_artifacts");
        r.harness = Some("codex".to_owned());
        r.artifacts = Some(vec![serde_json::json!({"artifact_id": "codex:x"})]);
        assert_eq!(
            evaluate_prompt_analyze(&r).unwrap_err(),
            "invalid_prompt_artifact_payload"
        );
    }

    #[test]
    fn merge_subop_refuses_an_empty_part_list() {
        let mut r = base("merge_artifacts");
        r.harness = Some("codex".to_owned());
        r.artifacts = Some(Vec::new());
        assert_eq!(
            evaluate_prompt_analyze(&r).unwrap_err(),
            "missing_artifacts"
        );
    }

    #[test]
    fn unknown_subop_errors() {
        let r = base("nope");
        assert!(evaluate_prompt_analyze(&r)
            .unwrap_err()
            .contains("unknown_prompt_analyze_subop"));
    }

    #[test]
    fn schema_mismatch_errors() {
        let mut r = base("extract");
        r.schema = "bogus".to_owned();
        assert!(evaluate_prompt_analyze(&r)
            .unwrap_err()
            .contains("schema_mismatch"));
    }
}
