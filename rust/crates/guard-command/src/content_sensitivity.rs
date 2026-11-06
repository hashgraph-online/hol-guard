//! Bounded sensitivity requests; Python receives DTOs rather than verdict logic.

use std::borrow::Cow;
use std::path::Path;
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use crate::safe_decode::read_gzip;

#[path = "content_sensitivity_json.rs"]
mod json_tree;
#[path = "content_sensitivity_mediation.rs"]
mod mediation;
#[path = "content_sensitivity_patterns.rs"]
mod patterns;
#[path = "content_sensitivity_policy.rs"]
mod policy;
#[path = "content_sensitivity_structured.rs"]
mod structured;
#[cfg(test)]
#[path = "content_sensitivity_tests.rs"]
mod tests;
/// Lossless wire encoding for large output; native code bounds and decodes it.
pub fn decode_input(body: &Value) -> Result<Cow<'_, Value>, &'static str> {
    if body.get("packed_json_gzip_v1").is_none() {
        return Ok(Cow::Borrowed(body));
    }
    keys(body, &["packed_json_gzip_v1", "decoded_bytes"])?;
    let length = body["decoded_bytes"]
        .as_u64()
        .ok_or("content_input_invalid")?;
    if length > 12 * 1024 * 1024 {
        return Err("content_input_invalid");
    }
    let packed = body["packed_json_gzip_v1"]
        .as_str()
        .ok_or("content_input_invalid")?;
    if packed.len() > 6 * 1024 * 1024 {
        return Err("content_input_invalid");
    }
    let compressed = STANDARD
        .decode(packed)
        .map_err(|_| "content_input_invalid")?;
    let decoded = read_gzip(&compressed, length as usize + 1)?;
    if decoded.len() != length as usize {
        return Err("content_input_invalid");
    }
    let text = std::str::from_utf8(&decoded).map_err(|_| "content_input_invalid")?;
    json_tree::parse(text).map_err(|_| "content_input_invalid")?;
    let input = serde_json::from_str(text).map_err(|_| "content_input_invalid")?;
    Ok(Cow::Owned(input))
}

pub fn evaluate(query: &str, body: &Value, deadline: Instant) -> Result<Value, &'static str> {
    if Instant::now() >= deadline {
        return Err("content_scan_deadline_exceeded");
    }
    let result = match query {
        "path_batch" => {
            keys(body, &["paths", "cwd", "home_dir"])?;
            let paths = body["paths"].as_array().ok_or("content_input_invalid")?;
            if paths.len() > 128 {
                return Err("content_input_invalid");
            }
            let mut results = Vec::with_capacity(paths.len());
            for path in paths {
                if !path.is_string() || Instant::now() >= deadline {
                    return Err("content_input_invalid");
                }
                let item = evaluate(
                    "path",
                    &json!({"path":path,"cwd":body["cwd"],"home_dir":body["home_dir"]}),
                    deadline,
                )?;
                results.push(item["ok"].clone());
            }
            Value::Array(results)
        }
        "path" => {
            keys(body, &["path", "cwd", "home_dir"])?;
            let path = body["path"].as_str();
            let cwd = body["cwd"].as_str().map(Path::new);
            let home = body["home_dir"].as_str().map(Path::new);
            path.and_then(|path| {
                crate::shell_secret_read_support::classify_request_secret_path(path, cwd, home)
            })
            .map(|found| {
                json!({"family":found.family,"path":found.path,"sensitivity":found.sensitivity,
                    "reason":found.reason,"requested_path":found.requested_path})
            })
            .unwrap_or(Value::Null)
        }
        "legacy" => {
            keys(body, &["text"])?;
            patterns::legacy(body["text"].as_str().ok_or("content_input_invalid")?)?
        }
        "content" => {
            keys(
                body,
                &["text", "suppress_samples", "documentation_sample_context"],
            )?;
            patterns::content(
                body["text"].as_str(),
                body["suppress_samples"]
                    .as_bool()
                    .ok_or("content_input_invalid")?,
                body["documentation_sample_context"]
                    .as_bool()
                    .ok_or("content_input_invalid")?,
                deadline,
            )?
        }
        "content_version" => {
            keys(body, &[])?;
            json!(patterns::version()?)
        }
        "classifier_version" | "declared" => {
            keys(
                body,
                if query == "declared" {
                    &["schema", "content"]
                } else {
                    &["schema"]
                },
            )?;
            let fields = if body["schema"].is_null() {
                None
            } else {
                match structured::fields(&body["schema"]) {
                    Ok(fields) => Some(fields),
                    Err(message) => return Ok(json!({"error":message,"type":"ValueError"})),
                }
            };
            if query == "classifier_version" {
                json!(structured::version(fields.as_deref())?)
            } else {
                structured::scan(
                    body["content"].as_str().ok_or("content_input_invalid")?,
                    fields.as_deref(),
                    deadline,
                )?
            }
        }
        "canonical" => {
            keys(body, &["value"])?;
            json!(structured::canonical(&body["value"]))
        }
        "harness" => {
            keys(body, &["value"])?;
            json!(policy::harness(
                body["value"].as_str().ok_or("content_input_invalid")?
            ))
        }
        "policy" => {
            keys(body, &["value"])?;
            match policy::parse(&body["value"]) {
                Ok(value) => value,
                Err(message) => return Ok(json!({"error":message,"type":"ValueError"})),
            }
        }
        "resolution" => {
            keys(body, &["config", "harness"])?;
            policy::resolve(
                &body["config"],
                body["harness"].as_str().ok_or("content_input_invalid")?,
            )?
        }
        "fields" => {
            keys(body, &["schema"])?;
            match structured::fields(&body["schema"]) {
                Ok(fields) => json!(fields),
                Err(message) => return Ok(json!({"error":message,"type":"ValueError"})),
            }
        }
        "declared_bytes" => {
            keys(
                body,
                &["schema", "content_type", "content_bytes", "content_length"],
            )?;
            let fields = if body["schema"].is_null() {
                None
            } else {
                Some(structured::fields(&body["schema"]).map_err(|_| "content_input_invalid")?)
            };
            let deadline = deadline.min(Instant::now() + std::time::Duration::from_millis(200));
            let encoded = body["content_bytes"]
                .as_str()
                .ok_or("content_input_invalid")?;
            let bytes = STANDARD
                .decode(encoded)
                .map_err(|_| "content_input_invalid")?;
            let length = body["content_length"]
                .as_u64()
                .ok_or("content_input_invalid")?;
            let kind = body["content_type"]
                .as_str()
                .ok_or("content_input_invalid")?;
            if length < bytes.len() as u64 || length > bytes.len() as u64 && bytes.len() != 65_537 {
                return Err("content_input_invalid");
            }
            if kind == "other" {
                structured::unsupported(fields.as_deref(), "input_type_unsupported")?
            } else if !matches!(kind, "bytes" | "str") {
                return Err("content_input_invalid");
            } else if length > 65_536 {
                structured::unsupported(fields.as_deref(), "input_too_large")?
            } else if let Ok(text) = std::str::from_utf8(&bytes) {
                structured::scan(text, fields.as_deref(), deadline)?
            } else {
                structured::unsupported(
                    fields.as_deref(),
                    if kind == "str" {
                        "invalid_unicode"
                    } else {
                        "invalid_utf8"
                    },
                )?
            }
        }
        "mediate_prepare" | "mediate_finish" => {
            let mut expected = vec![
                "harness",
                "event_name",
                "native_result",
                "validated_receipt",
                "structured_output_json",
                "binding",
                "required_reason_code",
                "cancelled",
                "allow_observe_mode",
                "recheck_available",
            ];
            if query == "mediate_finish" {
                expected.extend(["refreshed_binding", "recheck_error"]);
            }
            keys(body, &expected)?;
            if query == "mediate_prepare" {
                mediation::prepare(body, deadline)?
            } else {
                mediation::finish(body, deadline)?
            }
        }
        #[cfg(test)]
        "mediate" => mediation::replay(body, deadline)?,
        _ => return Err("content_query_invalid"),
    };
    if Instant::now() >= deadline {
        return Err("content_scan_deadline_exceeded");
    }
    Ok(json!({"ok":result}))
}

fn keys(body: &Value, expected: &[&str]) -> Result<(), &'static str> {
    let object = body.as_object().ok_or("content_input_invalid")?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err("content_input_invalid");
    }
    Ok(())
}
