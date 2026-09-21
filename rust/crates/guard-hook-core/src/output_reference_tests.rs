// Independent copy of the extraction contract at 2e672d2. Keep the reference
// unchanged when optimizing the production traversal; it is a parity oracle.
use super::{
    ExtractedOutput, MAX_CONTENT_ITEMS, MAX_DEPTH, MAX_OBJECT_KEYS, MAX_OUTPUT_CHARS,
    OUTPUT_TEXT_KEYS, PAYLOAD_OUTPUT_KEYS,
};
use serde_json::{json, Value};
use std::collections::HashSet;

fn collect_output_text(value: &Value) -> ExtractedOutput {
    fn append(parts: &mut Vec<String>, chars: &mut usize, truncated: &mut bool, text: &str) {
        if *truncated || text.is_empty() {
            return;
        }
        let remaining = MAX_OUTPUT_CHARS.saturating_sub(*chars);
        if text.chars().count() > remaining {
            parts.push(text.chars().take(remaining).collect());
            *chars = MAX_OUTPUT_CHARS;
            *truncated = true;
            return;
        }
        parts.push(text.to_owned());
        *chars += text.chars().count();
    }

    fn traverse(
        value: &Value,
        depth: usize,
        parts: &mut Vec<String>,
        chars: &mut usize,
        truncated: &mut bool,
        seen: &mut HashSet<usize>,
    ) {
        if *truncated {
            return;
        }
        if depth > MAX_DEPTH {
            *truncated = true;
            return;
        }
        match value {
            Value::String(text) => append(parts, chars, truncated, text),
            Value::Array(items) => {
                let id = value as *const Value as usize;
                if !seen.insert(id) {
                    *truncated = true;
                    return;
                }
                for item in items.iter().take(MAX_CONTENT_ITEMS) {
                    traverse(item, depth + 1, parts, chars, truncated, seen);
                    if *truncated {
                        break;
                    }
                }
                if items.len() > MAX_CONTENT_ITEMS {
                    *truncated = true;
                }
                seen.remove(&id);
            }
            Value::Object(record) => {
                if record.get("type").and_then(Value::as_str) == Some("text") {
                    if let Some(text) = record.get("text").and_then(Value::as_str) {
                        append(parts, chars, truncated, text);
                        return;
                    }
                }
                let id = value as *const Value as usize;
                if !seen.insert(id) {
                    *truncated = true;
                    return;
                }
                let mut keys_seen = 0usize;
                for key in OUTPUT_TEXT_KEYS {
                    let Some(child) = record.get(*key) else {
                        continue;
                    };
                    if keys_seen >= MAX_OBJECT_KEYS {
                        *truncated = true;
                        break;
                    }
                    keys_seen += 1;
                    traverse(child, depth + 1, parts, chars, truncated, seen);
                    if *truncated {
                        break;
                    }
                }
                seen.remove(&id);
            }
            _ => {}
        }
    }

    let mut parts = Vec::new();
    let mut chars = 0usize;
    let mut truncated = false;
    let mut seen = HashSet::new();
    traverse(value, 0, &mut parts, &mut chars, &mut truncated, &mut seen);
    ExtractedOutput {
        text: parts.concat(),
        chars,
        truncated,
    }
}

fn reference_extract_payload_output(payload: &Value) -> ExtractedOutput {
    let Some(record) = payload.as_object() else {
        return ExtractedOutput {
            text: String::new(),
            chars: 0,
            truncated: false,
        };
    };
    let mut parts = Vec::new();
    let mut truncated = false;
    for key in PAYLOAD_OUTPUT_KEYS {
        if let Some(value) = record.get(*key) {
            let result = collect_output_text(value);
            truncated |= result.truncated;
            if !result.text.is_empty() {
                parts.push(result.text);
            }
        }
    }
    let joined = parts.join("\n");
    let chars = joined.chars().count();
    if chars > MAX_OUTPUT_CHARS {
        truncated = true;
    }
    ExtractedOutput {
        text: joined.chars().take(MAX_OUTPUT_CHARS).collect(),
        chars: chars.min(MAX_OUTPUT_CHARS),
        truncated,
    }
}

#[test]
fn extraction_preserves_unicode_limits_order_and_structural_truncation() {
    let mut fixtures = vec![
        Value::Null,
        json!({"tool_response": [{"type": "text", "text": "α"}, "β", {"stdout": "out", "stderr": "err"}], "stdout": "", "stderr": "終"}),
        json!({"tool_response": [], "tool_output": "é", "stdout": "", "stderr": "🙂"}),
        json!({"tool_response": vec!["x"; MAX_CONTENT_ITEMS + 1], "stderr": "tail"}),
    ];
    for size in [MAX_OUTPUT_CHARS - 1, MAX_OUTPUT_CHARS, MAX_OUTPUT_CHARS + 1] {
        fixtures.push(json!({"tool_response": "é".repeat(size)}));
        fixtures.push(json!({"tool_response": "a".repeat(size), "stderr": "🙂"}));
    }
    let mut deep = json!("nested");
    for _ in 0..MAX_DEPTH + 2 {
        deep = json!([deep]);
    }
    fixtures.push(json!({"tool_response": deep, "stdout": "visible"}));
    for (index, payload) in fixtures.iter().enumerate() {
        assert_eq!(
            super::extract_payload_output(payload),
            reference_extract_payload_output(payload),
            "fixture {index}"
        );
    }
}

#[test]
#[ignore = "diagnostic release microbenchmark; not an installed latency gate"]
fn benchmark_output_extraction() {
    use std::hint::black_box;
    use std::time::Instant;
    let fixtures = [
        ("ascii_16k", json!({"tool_response": "x".repeat(16 * 1024)})),
        ("unicode_16k", json!({"tool_response": "🙂é".repeat(2048)})),
        (
            "many_parts",
            json!({"tool_response": vec![json!({"type": "text", "text": "content".repeat(32)}); MAX_CONTENT_ITEMS]}),
        ),
        (
            "maximum",
            json!({"tool_response": "x".repeat(MAX_OUTPUT_CHARS)}),
        ),
    ];
    for (name, payload) in fixtures {
        assert_eq!(
            super::extract_payload_output(&payload),
            reference_extract_payload_output(&payload)
        );
        let mut baseline = Vec::new();
        let mut candidate = Vec::new();
        for round in 0..5 {
            for _ in 0..20 {
                for optimized in [round % 2 == 0, round % 2 != 0] {
                    let started = Instant::now();
                    let output = if optimized {
                        super::extract_payload_output(black_box(&payload))
                    } else {
                        reference_extract_payload_output(black_box(&payload))
                    };
                    black_box(output);
                    let micros = started.elapsed().as_secs_f64() * 1_000_000.0;
                    if optimized {
                        candidate.push(micros);
                    } else {
                        baseline.push(micros);
                    }
                }
            }
        }
        baseline.sort_by(f64::total_cmp);
        candidate.sort_by(f64::total_cmp);
        println!("{{\"benchmark\":\"output_extraction\",\"fixture\":\"{name}\",\"samples\":100,\"baseline_p95_us\":{},\"candidate_p95_us\":{}}}", baseline[94], candidate[94]);
    }
}
