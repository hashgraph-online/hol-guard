#!/usr/bin/env python3
"""Enforce HOL Guard's permanent Rust hook/data-plane ownership boundary."""

from __future__ import annotations

import argparse
import ast
import json
import os
from pathlib import Path
from typing import Final

SCHEMA: Final = "hol-guard-rust-authority-ownership.v1"
MANIFEST: Final = Path("ci/rust-authority-ownership.v1.json")

TEMPORARY_PATHS: Final = (
    Path(".github/workflows/rust-local-toolchain-export.yml"),
    Path(".github/workflows/rust-pretool-authority-bootstrap.yml"),
    Path(".github/workflows/rust-pretool-authority-orchestrator.yml"),
    Path(".github/workflows/rust-authority-batch1-finalize.yml"),
    Path(".github/workflows/rust-authority-batch1-merge-gate.yml"),
    Path(".github/workflows/rust-posttool-authority-bootstrap.yml"),
    Path(".github/workflows/rust-posttool-authority-orchestrator.yml"),
    Path(".github/workflows/rust-posttool-authority-lint-fix.yml"),
    Path(".github/workflows/rust-authority-batch2-merge-gate.yml"),
    Path(".github/workflows/rust-authority-batch2-retry-merge-v2.yml"),
    Path(".github/workflows/rust-authority-batch2-converge-v3.yml"),
    Path(".github/workflows/rust-authority-batch2-converge-v4.yml"),
    Path(".github/workflows/rust-authority-final-orchestrator.yml"),
    Path(".github/workflows/rust-authority-final-lint-fix.yml"),
    Path(".github/workflows/rust-authority-final-merge-gate.yml"),
    Path(".github/workflows/rust-authority-final-retry-merge-v2.yml"),
    Path(".github/workflows/rust-authority-batch3-converge-v3.yml"),
    Path("scripts/ci/bootstrap_rust_pretool_authority.sh"),
    Path("scripts/ci/bootstrap_rust_posttool_authority.sh"),
    Path("scripts/ci/fallback_rust_posttool_authority.py"),
    Path("scripts/ci/converge_rust_posttool_authority_v2.py"),
    Path("scripts/ci/harden_rust_policy_snapshot_v3.py"),
    Path("scripts/ci/select_rust_posttool_authority_candidate_v2.sh"),
    Path("scripts/ci/rust_authority_ownership_gate_v2.py"),
    Path("scripts/ci/rust_authority_ownership_gate_v3.py"),
    Path("scripts/ci/finalize_rust_authority_migration.py"),
    Path("scripts/ci/finalize_rust_authority_migration_v2.py"),
    Path("docs/guard/.batch1-merge-probe"),
    Path("docs/guard/rust-authority-batch-2-bootstrap.md"),
    Path("rust/AUTHORITY_BATCH_1"),
    Path("rust/AUTHORITY_BATCH_1_FINAL"),
    Path("rust/AUTHORITY_BATCH_2"),
    Path("rust/AUTHORITY_BATCH_2_FINAL"),
    Path("rust/AUTHORITY_FINAL"),
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not inspect required authority source: {path}") from exc


def _function_source(path: Path, function_name: str) -> str:
    source = _read(path)
    tree = ast.parse(source, filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
            segment = ast.get_source_segment(source, node)
            if segment is None:
                break
            return segment
    raise RuntimeError(f"required function is missing: {path}:{function_name}")


def _manifest_gate() -> dict[str, object]:
    value = json.loads(_read(MANIFEST))
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise RuntimeError("Rust authority ownership manifest has an invalid schema")

    default = value.get("default_runtime_contract")
    if not isinstance(default, dict):
        raise RuntimeError("default runtime contract is missing")
    expected_default = {
        "native_mode_without_environment": "auto",
        "hook_fast_path_without_environment": True,
        "path_runtime_search": False,
        "decision_time_runtime_download": False,
        "automatic_python_semantic_fallback": False,
    }
    for key, expected in expected_default.items():
        if default.get(key) != expected:
            raise RuntimeError(f"invalid default runtime contract: {key}")

    compatibility = value.get("explicit_compatibility")
    if not isinstance(compatibility, dict):
        raise RuntimeError("explicit compatibility contract is missing")
    if compatibility.get("modes") != ["off", "shadow"]:
        raise RuntimeError("only off/shadow may select Python compatibility")
    if compatibility.get("python_reference_evaluator") is not True:
        raise RuntimeError("explicit compatibility reference evaluator contract is missing")
    if compatibility.get("automatic_entry_from_native_failure") is not False:
        raise RuntimeError("native failure may enter Python compatibility")
    if compatibility.get("default_selected") is not False:
        raise RuntimeError("Python compatibility may be selected by default")

    surfaces = value.get("surfaces")
    if not isinstance(surfaces, dict):
        raise RuntimeError("Rust authority surfaces are missing")
    for key in ("pre_tool_use", "post_tool_use"):
        surface = surfaces.get(key)
        if not isinstance(surface, dict):
            raise RuntimeError(f"Rust authority surface is missing: {key}")
        if surface.get("semantic_authority") != "rust":
            raise RuntimeError(f"default semantic authority is not Rust: {key}")
        if surface.get("python_semantic_fallback") is not False:
            raise RuntimeError(f"automatic Python semantic fallback is enabled: {key}")
        if surface.get("native_failure") != "fail_closed":
            raise RuntimeError(f"native failure is not fail closed: {key}")

    edge = surfaces.get("hook_edge")
    if not isinstance(edge, dict) or edge.get("event_and_action_extraction") != "rust":
        raise RuntimeError("raw hook edge is not Rust-owned")
    if edge.get("python_semantic_envelope_parsing") is not False:
        raise RuntimeError("default hook edge permits Python semantic envelope parsing")

    client = surfaces.get("resident_client")
    if not isinstance(client, dict):
        raise RuntimeError("resident client ownership surface is missing")
    for field in ("authentication", "framing", "request_response_digest_validation", "socket_io"):
        if client.get(field) != "rust":
            raise RuntimeError(f"resident client {field} is not Rust-owned")

    io_surface = surfaces.get("decision_critical_io")
    if not isinstance(io_surface, dict) or any(item != "rust" for item in io_surface.values()):
        raise RuntimeError("default decision-critical PostToolUse I/O is not Rust-owned")
    return value


def _hook_worker_gate() -> None:
    path = Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py")
    source = _read(path)
    for required in (
        "review_hook_edge_native",
        'mode in {"off", "shadow"}',
        "_review_explicit_python_compatibility",
        "native_hook_edge_unavailable",
        "_harness_json_from_native_edge",
    ):
        if required not in source:
            raise RuntimeError(f"HookWorker ownership contract is missing: {required}")

    production = _function_source(path, "review_http_payload")
    if "self.engine.review(" in production or "_request_from_payload(" in production:
        raise RuntimeError("default HookWorker path directly invokes Python semantic evaluation")
    if "review_hook_edge_native(" not in production:
        raise RuntimeError("default HookWorker path does not invoke the Rust hook edge")
    if "HookWorkerUnsupported" in production:
        raise RuntimeError("auto/force HookWorker path can escape Rust authority")

    compatibility = _function_source(path, "_review_explicit_python_compatibility")
    if "self.engine.review(" not in compatibility:
        raise RuntimeError("explicit compatibility no longer has its bounded reference evaluator")
    if 'event_name != "PostToolUse"' not in compatibility:
        raise RuntimeError("explicit compatibility is not bounded away from PreTool semantic authority")

    if "review_pre_tool_native" in source or "review_post_tool_native" in source:
        raise RuntimeError("HookWorker retains the superseded split native bridge")
    for forbidden in ("_pre_tool_command(",):
        if forbidden in source:
            raise RuntimeError(f"HookWorker retains default Python PreTool parsing: {forbidden}")


def _cli_gate() -> None:
    path = Path("src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py")
    source = _read(path)
    native = _function_source(path, "try_native_hook_authority")
    route = _function_source(path, "try_native_or_source_ref_hook")

    if 'native_mode() not in {"auto", "force"}' not in native:
        raise RuntimeError("CLI does not isolate explicit off/shadow compatibility")
    if "HookWorker(store=store).review_http_payload(" not in native:
        raise RuntimeError("CLI auto/force route does not terminate at HookWorker Rust authority")
    if "try" in native and "except" in native:
        raise RuntimeError("CLI auto/force route catches native authority failures for fallback")
    if "_try_source_ref_fast_path" not in route:
        raise RuntimeError("explicit compatibility source-ref reference path is missing")
    if "native_result is not None" not in route or '_emit("hook"' not in route:
        raise RuntimeError("CLI native result is not terminal before compatibility")


def _rust_runtime_gate() -> None:
    runtime = _read(Path("rust/crates/guard-runtime/src/main.rs"))
    oneshot = _read(Path("rust/crates/guard-runtime/src/oneshot.rs"))
    client = _read(Path("rust/crates/guard-runtime/src/resident_client.rs"))
    core = _read(Path("rust/crates/guard-hook-core/src/lib.rs"))

    for required in (
        '"hook-edge-v2"',
        '"resident-client-v1"',
        "HookEdge(Value)",
        'command == "hook-edge"',
        'command == "resident-client"',
    ):
        if required not in runtime:
            raise RuntimeError(f"Rust runtime feature is missing: {required}")
    for required in (
        "evaluate_hook_edge_value",
        "hook_event_name",
        "extract_pre_tool_command",
        "native_pre_tool_unsupported_review",
        "review_post_tool",
    ):
        if required not in oneshot:
            raise RuntimeError(f"Rust hook edge implementation is missing: {required}")
    for required in ("read_bounded", "scan_text", "extract_payload_output", "review_post_tool"):
        if required not in core:
            raise RuntimeError(f"Rust decision-critical PostToolUse I/O is missing: {required}")
    for required in (
        "authenticate(",
        "hmac_sha256",
        "REQUEST_MAGIC",
        "RESPONSE_MAGIC",
        "Sha256::digest(payload)",
        "response_id_mismatch",
        "response_digest_mismatch",
    ):
        if required not in client:
            raise RuntimeError(f"Rust resident-client implementation is missing: {required}")


def _resident_bridge_gate() -> None:
    path = Path("src/codex_plugin_scanner/guard/native_runtime_resident.py")
    source = _read(path)
    class_start = source.find("class _ResidentService:")
    send_start = source.find("    def _send(", class_start)
    send_end = source.find("\n    def _ensure_started(", send_start)
    if send_start < 0 or send_end <= send_start:
        raise RuntimeError("resident lifecycle has no bounded _send bridge")
    send = source[send_start:send_end]
    for required in ("resident-client", "run_isolated_hook_process"):
        if required not in send:
            raise RuntimeError(f"production resident bridge does not delegate {required} to Rust")
    for forbidden in (
        "_send_authenticated_unix_request",
        "_send_authenticated_loopback_request",
        "_authenticate_client(",
        "socket.create_connection",
    ):
        if forbidden in send:
            raise RuntimeError(f"production resident client I/O still executes in Python: {forbidden}")


def _default_gate() -> None:
    native = _read(Path("src/codex_plugin_scanner/guard/native_runtime.py"))
    config = _read(Path("src/codex_plugin_scanner/guard/config.py"))
    if '_DEFAULT_NATIVE_MODE: NativeMode = "auto"' not in native:
        raise RuntimeError("unset native mode is not auto")
    if 'os.environ.get(HOOK_FAST_PATH_ENV, "1") == "1"' not in config:
        raise RuntimeError("unset hook fast path is not enabled")
    start = native.find("def _runtime_candidates()")
    end = native.find("\ndef _validate_binary", start)
    candidates = native[start:end]
    if "shutil.which" in candidates or "PATH" in candidates:
        raise RuntimeError("automatic native runtime selection searches PATH")


def _workflow_gate() -> None:
    source = _read(Path(".github/workflows/rust-authority-ownership.yml"))
    for required in (
        '"rust/**"',
        '"src/codex_plugin_scanner/guard/**"',
        "rust_pretool_authority_integration.py",
        "rust_posttool_failclosed_integration.py",
        "test_guard_native_runtime_differential.py",
        "test_guard_native_runtime_mutation_differential.py",
        "bench_guard_native_release_gate.py",
        "test_native_hol_guard_wheel.py",
    ):
        if required not in source:
            raise RuntimeError(f"authority workflow coverage is missing: {required}")


def _hygiene_gate() -> None:
    residue = [str(path) for path in TEMPORARY_PATHS if path.exists()]
    if residue:
        raise RuntimeError(f"temporary Rust migration delivery residue remains: {residue}")


def run(root: Path) -> dict[str, object]:
    original = Path.cwd()
    try:
        os.chdir(root)
        manifest = _manifest_gate()
        _hook_worker_gate()
        _cli_gate()
        _rust_runtime_gate()
        _resident_bridge_gate()
        _default_gate()
        _workflow_gate()
        _hygiene_gate()
        return {"schema": SCHEMA, "status": "passed", "manifest": manifest}
    finally:
        os.chdir(original)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    payload = run(args.root.resolve())
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
