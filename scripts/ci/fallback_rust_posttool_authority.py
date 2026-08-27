#!/usr/bin/env python3
"""Apply the main-branch PostToolUse authority hardening when no historical candidate passes.

The migration is intentionally narrow: Rust remains the semantic authority,
Python becomes transport/configuration only, native failure is rendered as a
fail-closed harness result, and the native runtime validates generation-bound
policy snapshots.
"""

from __future__ import annotations

from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    source = path.read_text(encoding="utf-8")
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"expected exactly one match in {path}: found {count}")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def patch_hook_worker() -> None:
    path = Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py")
    source = path.read_text(encoding="utf-8")
    source = source.replace("from contextlib import suppress\n", "")
    source = source.replace("from ..native_runtime import native_mode, review_post_tool_native\n", "from ..native_runtime import review_post_tool_native\n")
    old = '''        mode = native_mode()
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
    new = '''        config = self._load_config(guard_home, workspace)
        response = review_post_tool_native(
            request,
            observe_mode=config.mode == "observe",
        )
        if response is None:
            # Rust is the sole semantic authority for supported PostToolUse.
            # Transport, integrity, overload, timeout, and containment failures
            # fail closed instead of spilling into the Python review engine.
            return post_tool_fail_safe_response(
                harness,
                reason="HOL Guard could not complete the native local hook review safely.",
                reason_code="native_post_tool_unavailable",
            )
'''
    if old not in source:
        if "response = self.engine.review(request)" in source:
            raise RuntimeError("unexpected HookWorker fallback shape")
    else:
        source = source.replace(old, new, 1)
    source = source.replace(
        "- Native authority is limited to PostToolUse and falls back to Python on\n  any unavailable, incompatible, timeout, transport, or invalid-response case.\n",
        "- Native authority owns supported PostToolUse decisions and fails closed on\n  unavailable, incompatible, timeout, transport, or invalid-response cases.\n",
    )
    path.write_text(source, encoding="utf-8")


def patch_native_runtime_python() -> None:
    path = Path("src/codex_plugin_scanner/guard/native_runtime.py")
    source = path.read_text(encoding="utf-8")
    if "import itertools\n" not in source:
        source = source.replace("import functools\n", "import functools\nimport itertools\n")
    marker = '_UNAVAILABLE_IDENTITY = "0" * 64\n'
    if "_POLICY_GENERATIONS" not in source:
        source = source.replace(
            marker,
            marker
            + "_POLICY_GENERATIONS = itertools.count(max(1, time.time_ns()))\n",
            1,
        )
    helper_marker = "\ndef native_runtime_health(guard_home: Path) -> NativeRuntimeHealthSnapshot:\n"
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
    policy_digest = hashlib.sha256(policy_bytes).hexdigest()
    generation = int(policy_digest[:16], 16) or 1
    return {
        "schema": "hol-guard-native-policy.v1",
        "generation": generation,
        "policy_digest": policy_digest,
        "config_digest": config_digest,
        "rule_digest": capabilities.rule_digest,
        "mode": mode,
    }

'''
    if "def _native_policy_snapshot(" not in source:
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
        raise RuntimeError("native hook envelope marker not found")
    source = source.replace(
        "Native failure is reported as ``None`` so the currently supported Python\n    reference backend remains authoritative until the dedicated cutover gate.\n",
        "Native transport failure is reported as ``None`` so the caller can return\n    a deterministic fail-closed harness result without Python re-evaluation.\n",
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


def patch_runtime_rust() -> None:
    path = Path("rust/crates/guard-runtime/src/main.rs")
    source = path.read_text(encoding="utf-8")
    if "guard_policy_snapshot" not in source:
        anchor = "use guard_hook_core::review_post_tool;\n"
        addition = "use guard_policy_snapshot::{validate as validate_policy_snapshot, PolicySnapshotV1};\n"
        if anchor not in source:
            raise RuntimeError("runtime import anchor not found")
        source = source.replace(anchor, anchor + addition, 1)
    if "use std::sync::atomic::{AtomicU64, Ordering};\n" not in source:
        source = source.replace(
            "use std::sync::{Arc, Mutex};\n",
            "use std::sync::atomic::{AtomicU64, Ordering};\nuse std::sync::{Arc, Mutex};\n",
            1,
        )
    const_anchor = 'const CLIENT_PROOF_LABEL: &[u8] = b"hol-guard-resident-client-v1\\0";\n'
    if "MIN_POLICY_GENERATION" not in source:
        if const_anchor not in source:
            raise RuntimeError("runtime constant anchor not found")
        source = source.replace(
            const_anchor,
            const_anchor + "static MIN_POLICY_GENERATION: AtomicU64 = AtomicU64::new(0);\n",
            1,
        )
    feature_anchor = '        "resident-command-model-shadow-v1".into(),\n'
    if '"policy-snapshot-v1".into()' not in source:
        if feature_anchor not in source:
            raise RuntimeError("runtime feature anchor not found")
        source = source.replace(feature_anchor, feature_anchor + '        "policy-snapshot-v1".into(),\n', 1)
    helper_anchor = "\nfn evaluate_hook_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {\n"
    helper = '''
fn validate_request_policy_snapshot(value: &Value) -> Result<(), String> {
    let Some(snapshot_value) = value.get("policy_snapshot") else {
        // Protocol-v1 compatibility is retained for already-installed clients.
        // Current package clients always send a generation-bound snapshot.
        return Ok(());
    };
    if snapshot_value.is_null() {
        return Err("native_policy_snapshot_missing".to_owned());
    }
    let snapshot: PolicySnapshotV1 = serde_json::from_value(snapshot_value.clone())
        .map_err(|_| "native_policy_snapshot_invalid".to_owned())?;
    let minimum = MIN_POLICY_GENERATION.load(Ordering::Acquire);
    validate_policy_snapshot(&snapshot, minimum)
        .map_err(|error| error.to_string())?;
    if snapshot.rule_digest != guard_rule_contract::rule_digest() {
        return Err("native_policy_snapshot_rule_mismatch".to_owned());
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

'''
    if "fn validate_request_policy_snapshot(" not in source:
        if helper_anchor not in source:
            raise RuntimeError("runtime evaluate hook anchor not found")
        source = source.replace(helper_anchor, "\n" + helper + helper_anchor, 1)
    hook_old = '''fn evaluate_hook_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    let request: NativeHookRequestV1 =
'''
    hook_new = '''fn evaluate_hook_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    validate_request_policy_snapshot(&value)?;
    let request: NativeHookRequestV1 =
'''
    if hook_old in source:
        source = source.replace(hook_old, hook_new, 1)
    elif "validate_request_policy_snapshot(&value)?;" not in source:
        raise RuntimeError("runtime hook validation insertion point not found")
    resident_old = '''fn evaluate_resident_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    let request: ResidentRequestV1 = serde_json::from_value(value)
'''
    resident_new = '''fn evaluate_resident_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = strict_json_value(bytes)?;
    if value.get("operation").is_none() {
        validate_request_policy_snapshot(&value)?;
    }
    let request: ResidentRequestV1 = serde_json::from_value(value)
'''
    if resident_old in source:
        source = source.replace(resident_old, resident_new, 1)
    elif 'if value.get("operation").is_none()' not in source:
        raise RuntimeError("runtime resident validation insertion point not found")
    path.write_text(source, encoding="utf-8")


def main() -> int:
    patch_hook_worker()
    patch_native_runtime_python()
    patch_runtime_cargo()
    patch_runtime_rust()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
