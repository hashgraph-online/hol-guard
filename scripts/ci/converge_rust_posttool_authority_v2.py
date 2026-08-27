#!/usr/bin/env python3
"""Converge main onto fail-closed Rust PostToolUse authority."""

from __future__ import annotations

import re
from pathlib import Path


def patch_hook_worker() -> None:
    path = Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py")
    source = path.read_text(encoding="utf-8")
    source = source.replace(
        "- Native authority is limited to PostToolUse and falls back to Python on\n  any unavailable, incompatible, timeout, transport, or invalid-response case.\n",
        "- Native authority owns supported PostToolUse and fails closed on\n  unavailable, incompatible, timeout, transport, or invalid-response cases.\n",
    )
    exact = '''        mode = native_mode()
        if mode in {"auto", "force"}:
            config = self._load_config(guard_home, workspace)
            response = review_post_tool_native(
                request,
                observe_mode=config.mode == "observe",
            )
            if response is None:
                response = self.engine.review(request)
        else:
            response = self.engine.review(request)
            if mode == "shadow":
                # Shadow evidence is explicitly non-authoritative. No native
                # failure may replace or discard the completed Python result.
                with suppress(Exception):
                    _ = review_post_tool_native(
                        request,
                        observe_mode=response.observe_mode,
                    )

'''
    replacement = '''        config = self._load_config(guard_home, workspace)
        response = review_post_tool_native(
            request,
            observe_mode=config.mode == "observe",
        )
        if response is None:
            return post_tool_fail_safe_response(
                harness,
                reason="HOL Guard could not complete the native local output review safely.",
                reason_code="native_post_tool_unavailable",
            )

'''
    if exact in source:
        source = source.replace(exact, replacement, 1)
    elif "response = self.engine.review(request)" in source:
        pattern = re.compile(
            r"        mode = native_mode\(\)\n[\s\S]*?(?=        succeeded = hook_post_succeeded)",
        )
        source, count = pattern.subn(replacement, source, count=1)
        if count != 1 and "response = self.engine.review(request)" in source:
            raise RuntimeError("could not remove Python PostToolUse fallback")
    if "native_mode(" not in source:
        source = source.replace("from ..native_runtime import native_mode, review_post_tool_native\n", "from ..native_runtime import review_post_tool_native\n")
    if "suppress(" not in source:
        source = source.replace("from contextlib import suppress\n", "")
    path.write_text(source, encoding="utf-8")


def patch_native_runtime() -> None:
    path = Path("src/codex_plugin_scanner/guard/native_runtime.py")
    source = path.read_text(encoding="utf-8")
    marker = '_UNAVAILABLE_IDENTITY = "0" * 64\n'
    if "_POLICY_GENERATION" not in source:
        if marker not in source:
            raise RuntimeError("native runtime identity marker not found")
        source = source.replace(marker, marker + "_POLICY_GENERATION = max(1, time.time_ns())\n", 1)
    helper_marker = "\ndef native_runtime_health(guard_home: Path) -> NativeRuntimeHealthSnapshot:\n"
    if "def _native_policy_snapshot(" not in source:
        helper = '''
def _native_policy_snapshot(
    status: NativeRuntimeStatus,
    *,
    observe_mode: bool,
) -> dict[str, object] | None:
    capabilities = status.capabilities
    if capabilities is None:
        return None
    mode = "observe" if observe_mode else "enforce"
    config_bytes = json.dumps({"mode": mode}, separators=(",", ":"), sort_keys=True).encode("utf-8")
    config_digest = hashlib.sha256(config_bytes).hexdigest()
    policy_bytes = json.dumps(
        {"config_digest": config_digest, "rule_digest": capabilities.rule_digest},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "schema": "hol-guard-native-policy.v1",
        "generation": _POLICY_GENERATION,
        "policy_digest": hashlib.sha256(policy_bytes).hexdigest(),
        "config_digest": config_digest,
        "rule_digest": capabilities.rule_digest,
        "mode": mode,
    }

'''
        if helper_marker not in source:
            raise RuntimeError("native runtime health marker not found")
        source = source.replace(helper_marker, "\n" + helper + helper_marker, 1)
    envelope_old = '''        "observe_mode": observe_mode,
        "deadline_budget_ms": _deadline_budget_ms(request),
    }
'''
    envelope_new = '''        "observe_mode": observe_mode,
        "deadline_budget_ms": _deadline_budget_ms(request),
        "policy_snapshot": _native_policy_snapshot(status, observe_mode=observe_mode),
    }
'''
    if envelope_old in source:
        source = source.replace(envelope_old, envelope_new, 1)
    elif '"policy_snapshot": _native_policy_snapshot' not in source:
        raise RuntimeError("native policy snapshot envelope marker not found")
    source = source.replace(
        "Native failure is reported as ``None`` so the currently supported Python\n    reference backend remains authoritative until the dedicated cutover gate.\n",
        "Native transport failure is reported as ``None`` so the caller can return\n    a deterministic fail-closed harness response without Python re-evaluation.\n",
    )
    path.write_text(source, encoding="utf-8")


def patch_runtime_cargo() -> None:
    path = Path("rust/crates/guard-runtime/Cargo.toml")
    source = path.read_text(encoding="utf-8")
    dependency = 'guard-policy-snapshot = { path = "../guard-policy-snapshot" }\n'
    if dependency not in source:
        anchor = 'guard-hook-core = { path = "../guard-hook-core" }\n'
        if anchor not in source:
            raise RuntimeError("guard-runtime dependency anchor not found")
        source = source.replace(anchor, anchor + dependency, 1)
    path.write_text(source, encoding="utf-8")


def _ensure_atomic_import(source: str) -> str:
    marker = "use std::sync::atomic::{AtomicU64, Ordering};\n"
    if marker in source:
        return source
    return source.replace(
        "use std::sync::{Arc, Mutex};\n",
        marker + "use std::sync::{Arc, Mutex};\n",
        1,
    )


def patch_runtime_rust() -> None:
    path = Path("rust/crates/guard-runtime/src/main.rs")
    source = path.read_text(encoding="utf-8")
    import_anchor = "use guard_hook_core::review_post_tool;\n"
    policy_import = "use guard_policy_snapshot::{digest_bytes, validate as validate_policy_snapshot, PolicySnapshotV1};\n"
    if "guard_policy_snapshot" not in source:
        if import_anchor not in source:
            raise RuntimeError("runtime hook-core import anchor not found")
        source = source.replace(import_anchor, import_anchor + policy_import, 1)
    source = _ensure_atomic_import(source)
    const_anchor = 'const CLIENT_PROOF_LABEL: &[u8] = b"hol-guard-resident-client-v1\\0";\n'
    if "MIN_POLICY_GENERATION" not in source:
        if const_anchor not in source:
            raise RuntimeError("runtime proof-label anchor not found")
        source = source.replace(const_anchor, const_anchor + "static MIN_POLICY_GENERATION: AtomicU64 = AtomicU64::new(0);\n", 1)
    feature_anchor = '        "resident-command-model-shadow-v1".into(),\n'
    if '"policy-snapshot-v1".into()' not in source:
        if feature_anchor not in source:
            raise RuntimeError("runtime feature anchor not found")
        source = source.replace(feature_anchor, feature_anchor + '        "policy-snapshot-v1".into(),\n', 1)
    helper_anchor = "\nfn evaluate_hook_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {\n"
    if "fn validate_request_policy_snapshot(" not in source:
        helper = r'''

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
        if helper_anchor not in source:
            raise RuntimeError("runtime hook evaluation anchor not found")
        source = source.replace(helper_anchor, helper + helper_anchor, 1)
    hook_old = '''fn evaluate_hook_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    let request: NativeHookRequestV1 =
        serde_json::from_value(value).map_err(|_| "native_request_invalid_json".to_owned())?;
'''
    hook_new = '''fn evaluate_hook_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut value = strict_json_value(bytes)?;
    validate_request_policy_snapshot(&value)?;
    remove_policy_snapshot(&mut value);
    let request: NativeHookRequestV1 =
        serde_json::from_value(value).map_err(|_| "native_request_invalid_json".to_owned())?;
'''
    if hook_old in source:
        source = source.replace(hook_old, hook_new, 1)
    elif "validate_request_policy_snapshot(&value)?;" not in source:
        raise RuntimeError("runtime one-shot policy validation marker not found")
    resident_old = '''fn evaluate_resident_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    let request: ResidentRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_resident_request_invalid_json".to_owned())?;
'''
    resident_new = '''fn evaluate_resident_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut value = strict_json_value(bytes)?;
    if value.get("operation").is_none() {
        validate_request_policy_snapshot(&value)?;
        remove_policy_snapshot(&mut value);
    }
    let request: ResidentRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_resident_request_invalid_json".to_owned())?;
'''
    if resident_old in source:
        source = source.replace(resident_old, resident_new, 1)
    elif 'if value.get("operation").is_none()' not in source:
        raise RuntimeError("runtime resident policy validation marker not found")
    path.write_text(source, encoding="utf-8")


def main() -> int:
    patch_hook_worker()
    patch_native_runtime()
    patch_runtime_cargo()
    patch_runtime_rust()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
