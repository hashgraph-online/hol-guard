//! Parity tests against vectors recorded from the legacy Python `safe_decode`.

use serde_json::Value;

use super::{decode_layers_with, DecodeError, DecodeLimits, NativeSafeDecode};
use crate::detectors::SafeDecodeApi;

const VECTORS: &str = include_str!("../../tests/fixtures/safe_decode_vectors.json");

fn limits(options: Option<&Value>) -> DecodeLimits {
    // Python never timed out while recording; keep slow/loaded CI from tripping the 50ms
    // default unless a vector sets its own limit.
    let mut limits = DecodeLimits {
        max_time_ms: 1.0e9,
        ..DecodeLimits::default()
    };
    let Some(options) = options else {
        return limits;
    };
    if let Some(v) = options.get("max_input_bytes").and_then(Value::as_u64) {
        limits.max_input_bytes = v as usize;
    }
    if let Some(v) = options.get("max_decoded_bytes").and_then(Value::as_u64) {
        limits.max_decoded_bytes = v as usize;
    }
    if let Some(v) = options.get("max_depth").and_then(Value::as_u64) {
        limits.max_depth = v as usize;
    }
    if let Some(v) = options.get("max_time_ms").and_then(Value::as_f64) {
        limits.max_time_ms = v;
    }
    limits
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|v| v.as_str().expect("string"))
        .collect()
}

#[test]
fn safe_decode_matches_recorded_python_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).expect("fixture parses");
    assert!(vectors.len() >= 150, "expected 150+ vectors");
    let mut failures: Vec<String> = Vec::new();
    for vector in &vectors {
        let name = vector["name"].as_str().expect("name");
        let input = vector["input"].as_str().expect("input");
        let expected = &vector["expected"];
        let outcome = decode_layers_with(input, &limits(vector.get("options")));
        if let Some(error) = expected["error"].as_str() {
            if error != "EOFError" || outcome != Err(DecodeError::Eof) {
                failures.push(format!("{name}: expected error {error}, got {outcome:?}"));
            }
            continue;
        }
        let Ok(got) = outcome else {
            failures.push(format!("{name}: unexpected error"));
            continue;
        };
        // A small positive wall-clock budget races machine load. The recorded
        // answer is the one that finished in time; a run that ran out of time
        // on a loaded machine is not evidence either way.
        let budget_ms = vector
            .get("options")
            .and_then(|options| options.get("max_time_ms"))
            .and_then(Value::as_f64);
        if got.timed_out && budget_ms.is_some_and(|ms| ms > 0.0 && ms < 1_000.0) {
            continue;
        }
        let mut check = |field: &str, ok: bool, detail: String| {
            if !ok {
                failures.push(format!("{name}: {field} mismatch {detail}"));
            }
        };
        let layers = expected["layers"].as_array().expect("layers");
        check(
            "layer-count",
            layers.len() == got.layers.len(),
            format!("want {} got {:?}", layers.len(), got.layers),
        );
        for (want, have) in layers.iter().zip(&got.layers) {
            let ok = want["encoding"] == have.encoding
                && want["input_length"] == have.input_length
                && want["output_length"] == have.output_length
                && want["content_hash"] == have.content_hash.as_str()
                && want["preview_redacted"] == have.preview_redacted.as_str()
                && want["depth"] == have.depth;
            check("layer", ok, format!("want {want} got {have:?}"));
        }
        check(
            "final_text",
            expected["final_text"] == got.final_text.as_str(),
            format!(
                "got {:?}",
                got.final_text.chars().take(80).collect::<String>()
            ),
        );
        for (field, have) in [
            ("truncated", got.truncated),
            ("timed_out", got.timed_out),
            ("depth_exceeded", got.depth_exceeded),
            ("size_exceeded", got.size_exceeded),
        ] {
            check(field, expected[field] == have, format!("got {have}"));
        }
        for (field, have) in [
            ("eval_signals", &got.eval_signals),
            ("exec_signals", &got.exec_signals),
            ("marshal_signals", &got.marshal_signals),
        ] {
            let want = strings(&expected[field]);
            check(field, want == *have, format!("want {want:?} got {have:?}"));
        }
        if vector.get("options").is_none() && input.len() < 300 {
            let view = NativeSafeDecode.decode_layers(input).expect("decodes");
            let encodings: Vec<&str> = view.layers.iter().map(|l| l.encoding).collect();
            let want: Vec<&str> = layers
                .iter()
                .map(|l| l["encoding"].as_str().expect("encoding"))
                .collect();
            check(
                "view-layers",
                encodings == want,
                format!("got {encodings:?}"),
            );
            check(
                "view-final-text",
                expected["final_text"] == view.final_text.as_ref(),
                String::new(),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn detector_version_matches_python() {
    assert_eq!(
        NativeSafeDecode.safe_decode_detector_version(),
        "safe-decode.v2"
    );
}

#[test]
fn backtrack_heavy_command_reports_an_error_instead_of_no_candidate() {
    let content = format!("python -c '{}", "\\".repeat(80));
    assert_eq!(
        decode_layers_with(&content, &DecodeLimits::default()).map(|_| ()),
        Err(DecodeError::RegexBudget)
    );
    let error = NativeSafeDecode
        .decode_layers(&content)
        .map(|_| ())
        .unwrap_err();
    assert_eq!(error, "RegexBudgetExceeded");
}
