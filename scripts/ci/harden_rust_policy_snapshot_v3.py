#!/usr/bin/env python3
"""Make native policy snapshot validation canonical even over prior migration variants."""

from __future__ import annotations

from pathlib import Path


def function_span(source: str, name: str) -> tuple[int, int] | None:
    marker = f"fn {name}("
    start = source.find(marker)
    if start == -1:
        return None
    brace = source.find("{", start)
    if brace == -1:
        raise RuntimeError(f"function {name} has no body")
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return start, index + 1
    raise RuntimeError(f"function {name} has an unterminated body")


def replace_function(source: str, name: str, replacement: str) -> str:
    span = function_span(source, name)
    if span is None:
        return source
    start, end = span
    return source[:start] + replacement.strip() + source[end:]


def _patch_resident_evaluation(source: str) -> str:
    resident_span = function_span(source, "evaluate_resident_bytes")
    if resident_span is None:
        raise RuntimeError("evaluate_resident_bytes missing")
    start, end = resident_span
    resident = source[start:end]
    resident = resident.replace(
        "    let value = strict_json_value(bytes)?;",
        "    let mut value = strict_json_value(bytes)?;",
    )
    if 'if value.get("operation").is_none()' not in resident:
        resident = resident.replace(
            "    let mut value = strict_json_value(bytes)?;",
            '    let mut value = strict_json_value(bytes)?;\n    if value.get("operation").is_none() {\n        validate_request_policy_snapshot(&value)?;\n        remove_policy_snapshot(&mut value);\n    }',
            1,
        )
    elif "remove_policy_snapshot(&mut value);" not in resident:
        resident = resident.replace(
            "        validate_request_policy_snapshot(&value)?;\n    }",
            "        validate_request_policy_snapshot(&value)?;\n        remove_policy_snapshot(&mut value);\n    }",
            1,
        )
    return source[:start] + resident + source[end:]


def main() -> int:
    path = Path("rust/crates/guard-runtime/src/main.rs")
    source = path.read_text(encoding="utf-8")
    source = source.replace(
        "use guard_policy_snapshot::{validate as validate_policy_snapshot, PolicySnapshotV1};",
        "use guard_policy_snapshot::{digest_bytes, validate as validate_policy_snapshot, PolicySnapshotV1};",
    )
    if "use guard_policy_snapshot" not in source:
        anchor = "use guard_hook_core::review_post_tool;\n"
        if anchor not in source:
            raise RuntimeError("guard hook-core import anchor missing")
        source = source.replace(
            anchor,
            anchor
            + "use guard_policy_snapshot::{digest_bytes, validate as validate_policy_snapshot, PolicySnapshotV1};\n",
            1,
        )

    for name in (
        "canonical_config_digest",
        "canonical_policy_digest",
        "validate_request_policy_snapshot",
        "remove_policy_snapshot",
    ):
        span = function_span(source, name)
        if span is not None:
            start, end = span
            source = source[:start] + source[end:]

    helpers = r'''
fn canonical_config_digest(mode: &str) -> String {
    digest_bytes(format!("{{\"mode\":\"{mode}\"}}").as_bytes())
}

fn canonical_policy_digest(config_digest: &str, rule_digest: &str) -> String {
    digest_bytes(
        format!(
            "{{\"config_digest\":\"{config_digest}\",\"rule_digest\":\"{rule_digest}\"}}"
        )
        .as_bytes(),
    )
}

fn validate_request_policy_snapshot(value: &Value) -> Result<(), String> {
    let Some(snapshot_value) = value.get("policy_snapshot") else {
        return Ok(());
    };
    if snapshot_value.is_null() {
        return Err("native_policy_snapshot_missing".to_owned());
    }
    let snapshot: PolicySnapshotV1 = serde_json::from_value(snapshot_value.clone())
        .map_err(|_| "native_policy_snapshot_invalid".to_owned())?;
    let minimum = MIN_POLICY_GENERATION.load(Ordering::Acquire);
    validate_policy_snapshot(&snapshot, minimum).map_err(|error| error.to_string())?;
    if snapshot.mode != "enforce" && snapshot.mode != "observe" {
        return Err("native_policy_snapshot_mode_invalid".to_owned());
    }
    if snapshot.rule_digest != guard_rule_contract::rule_digest() {
        return Err("native_policy_snapshot_rule_mismatch".to_owned());
    }
    let expected_config = canonical_config_digest(&snapshot.mode);
    if snapshot.config_digest != expected_config {
        return Err("native_policy_snapshot_config_mismatch".to_owned());
    }
    let expected_policy = canonical_policy_digest(&snapshot.config_digest, &snapshot.rule_digest);
    if snapshot.policy_digest != expected_policy {
        return Err("native_policy_snapshot_policy_mismatch".to_owned());
    }
    let mut current = minimum;
    while snapshot.generation > current {
        match MIN_POLICY_GENERATION.compare_exchange_weak(
            current,
            snapshot.generation,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
    Ok(())
}

fn remove_policy_snapshot(value: &mut Value) {
    if let Value::Object(record) = value {
        record.remove("policy_snapshot");
    }
}

'''
    anchor = "fn evaluate_hook_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {"
    if anchor not in source:
        raise RuntimeError("native hook evaluation anchor missing")
    source = source.replace(anchor, helpers + anchor, 1)

    hook_span = function_span(source, "evaluate_hook_bytes")
    if hook_span is None:
        raise RuntimeError("evaluate_hook_bytes missing")
    start, end = hook_span
    hook = source[start:end]
    hook = hook.replace("    let value = strict_json_value(bytes)?;", "    let mut value = strict_json_value(bytes)?;")
    if "validate_request_policy_snapshot(&value)?;" not in hook:
        hook = hook.replace(
            "    let mut value = strict_json_value(bytes)?;",
            "    let mut value = strict_json_value(bytes)?;\n    validate_request_policy_snapshot(&value)?;\n    remove_policy_snapshot(&mut value);",
            1,
        )
    elif "remove_policy_snapshot(&mut value);" not in hook:
        hook = hook.replace(
            "    validate_request_policy_snapshot(&value)?;",
            "    validate_request_policy_snapshot(&value)?;\n    remove_policy_snapshot(&mut value);",
            1,
        )
    source = source[:start] + hook + source[end:]
    source = _patch_resident_evaluation(source)

    path.write_text(source, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
