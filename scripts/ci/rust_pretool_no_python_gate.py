#!/usr/bin/env python3
"""Prove supported generic PreToolUse authority is native, with Python as transport only."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Final

SCHEMA: Final = "hol-guard-rust-pretool-no-python.v3"


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not inspect {path}") from exc


def required_tokens(path: Path, tokens: tuple[str, ...]) -> list[str]:
    source = read(path)
    return [f"{path.as_posix()} missing {token}" for token in tokens if token not in source]


def function_node(path: Path, name: str, *, class_name: str | None = None) -> ast.FunctionDef:
    tree = ast.parse(read(path), filename=path.as_posix())
    candidates: list[ast.FunctionDef] = []
    for node in tree.body:
        if class_name is None and isinstance(node, ast.FunctionDef) and node.name == name:
            candidates.append(node)
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            candidates.extend(child for child in node.body if isinstance(child, ast.FunctionDef) and child.name == name)
    if len(candidates) != 1:
        raise RuntimeError(f"expected exactly one {class_name or 'module'}.{name} in {path}")
    return candidates[0]


def function_calls(node: ast.AST) -> set[str]:
    calls: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if isinstance(child.func, ast.Name):
            calls.add(child.func.id)
        elif isinstance(child.func, ast.Attribute):
            calls.add(child.func.attr)
    return calls


_TYPED_FAIL_SAFE = frozenset(
    {
        "post_tool_fail_safe_response",
        "availability_harness_response",
        "_native_worker_fail_safe_result",
        "_runtime_hook_fail_safe_response",
    }
)


def _has_typed_fail_safe(node: ast.AST) -> bool:
    return bool(_TYPED_FAIL_SAFE.intersection(function_calls(node)))


def function_strings(node: ast.AST) -> set[str]:
    return {child.value for child in ast.walk(node) if isinstance(child, ast.Constant) and isinstance(child.value, str)}


def _function_node_or_none(path: Path, name: str, *, class_name: str | None = None) -> ast.FunctionDef | None:
    try:
        return function_node(path, name, class_name=class_name)
    except RuntimeError:
        return None


def _called_node(node: ast.AST, name: str) -> ast.Call | None:
    return next(
        (
            child
            for child in ast.walk(node)
            if isinstance(child, ast.Call)
            and (
                (isinstance(child.func, ast.Name) and child.func.id == name)
                or (isinstance(child.func, ast.Attribute) and child.func.attr == name)
            )
        ),
        None,
    )


def _guard_if_before(node: ast.FunctionDef, helper: str, line: int) -> ast.If | None:
    return next(
        (
            child
            for child in ast.walk(node)
            if isinstance(child, ast.If)
            and child.lineno < line
            and isinstance(child.test, ast.Call)
            and isinstance(child.test.func, ast.Name)
            and child.test.func.id == helper
            and any(isinstance(item, ast.Return) for item in ast.walk(child))
        ),
        None,
    )


def _exception_handler(node: ast.FunctionDef, exception_name: str) -> ast.ExceptHandler | None:
    return next(
        (
            child
            for child in ast.walk(node)
            if isinstance(child, ast.ExceptHandler)
            and isinstance(child.type, ast.Name)
            and child.type.id == exception_name
        ),
        None,
    )


def _keyword_value(call: ast.Call, name: str) -> ast.AST | None:
    return next((keyword.value for keyword in call.keywords if keyword.arg == name), None)


def _server_graph_failures(root: Path) -> list[str]:
    failures: list[str] = []
    server = root / "src/codex_plugin_scanner/guard/daemon/server.py"
    server_ingress = _function_node_or_none(server, "_handle_runtime_hook", class_name="_GuardDaemonHandler")
    server_execute = _function_node_or_none(server, "_execute_runtime_hook", class_name="_GuardDaemonHandler")
    server_fast = _function_node_or_none(server, "_handle_runtime_hook_fast", class_name="_GuardDaemonHandler")
    if server_ingress is None or server_execute is None or server_fast is None:
        failures.append("server native hook fallback graph is incomplete")
        return failures
    if _called_node(server_ingress, "hydrate_hook_payload_reference") is not None:
        failures.append("daemon hook ingress hydrates a payload before native dispatch")
    if _called_node(server_execute, "hydrate_hook_payload_reference") is not None:
        failures.append("daemon hook execution hydrates a payload before native dispatch")
    compatibility_call = _called_node(server_execute, "_handle_runtime_hook_compatibility_cli")
    if compatibility_call is None:
        failures.append("server execute path has no explicit compatibility boundary")
    elif _guard_if_before(server_execute, "_native_mode_requires_rust", compatibility_call.lineno) is None:
        failures.append("server execute path can reach compatibility CLI without a native-mode return guard")
    if "_native_mode_requires_rust" not in function_calls(server_execute):
        failures.append("server execute path does not branch on native mode before compatibility dispatch")
    generic = _exception_handler(server_fast, "Exception")
    if generic is None or "_runtime_hook_fail_safe_response" not in function_calls(generic):
        failures.append("server fast path worker exception has no fail-safe response")
    return failures


def _resident_graph_failures(root: Path) -> list[str]:
    failures: list[str] = []
    entrypoint = root / "src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py"
    resident = _function_node_or_none(entrypoint, "_run_resident_hook_request")
    if resident is None:
        failures.append("resident hook entrypoint is missing")
        return failures
    if _called_node(resident, "_run_guard_hook_command") is not None:
        failures.append("resident entrypoint can still reach the Python CLI")
    if _called_node(resident, "review_http_payload") is None:
        failures.append("resident entrypoint does not route hooks through the native worker")
    generic = _exception_handler(resident, "Exception")
    if generic is None or "_native_worker_fail_safe_result" not in function_calls(generic):
        failures.append("resident worker exception has no fail-safe response")
    return failures


def _native_cli_graph_failures(root: Path) -> list[str]:
    failures: list[str] = []
    native_cli = root / "src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py"
    native_route = _function_node_or_none(native_cli, "route_native_hook")
    if native_route is None:
        failures.append("CLI native route is missing")
        return failures
    pipeline_call = _called_node(native_route, "run_native_hook_pipeline")
    if pipeline_call is None and _called_node(native_route, "try_native_hook_authority") is None:
        failures.append("CLI native route does not call native authority")
    if pipeline_call is not None:
        pipeline_module = root / "src/codex_plugin_scanner/guard/cli/commands_hook_native_pipeline.py"
        pipeline = _function_node_or_none(pipeline_module, "run_native_hook_pipeline")
        if pipeline is None:
            failures.append("CLI native pipeline dispatcher is missing")
        elif _called_node(pipeline, "review_native_edge_decision") is None:
            failures.append("CLI native pipeline does not reach the native edge authority")
    for retired in ("_try_source_ref_fast_path", "record_python_semantic_hook_route", "evaluate_source_file_ref"):
        if _called_node(native_route, retired) is not None:
            failures.append(f"CLI native route still calls retired Python route {retired}")
    if "_native_mode_requires_rust" not in function_calls(native_route):
        failures.append("CLI native route has no native-mode guard")
    if not _has_typed_fail_safe(native_route):
        failures.append("CLI native route has no fail-safe native terminal")
    return failures


def _hook_cli_graph_failures(root: Path) -> list[str]:
    failures: list[str] = []
    hook_cli = root / "src/codex_plugin_scanner/guard/cli/commands_hook.py"
    hook_command = _function_node_or_none(hook_cli, "_run_guard_hook_command")
    if hook_command is None:
        failures.append("CLI hook command entrypoint is missing")
        return failures
    load_call = _called_node(hook_command, "_load_hook_payload")
    native_call = _called_node(hook_command, "route_native_hook")
    normalize_value = _keyword_value(load_call, "normalize") if load_call is not None else None
    if load_call is None or normalize_value is None:
        failures.append("CLI hook command does not load an explicit raw payload")
    elif not isinstance(normalize_value, ast.Constant) or normalize_value.value is not False:
        failures.append("CLI hook command normalizes payload before native authority")
    if native_call is None:
        failures.append("CLI hook command does not route through native authority")
    for retired in ("hydrate_hook_payload_reference", "_normalize_hook_payload"):
        if _called_node(hook_command, retired) is not None:
            failures.append(f"CLI hook command still calls retired Python helper {retired}")
    return failures


def _payload_graph_failures(root: Path) -> list[str]:
    failures: list[str] = []
    payload_support = root / "src/codex_plugin_scanner/guard/cli/commands_support_hook_payload.py"
    payload_loader = _function_node_or_none(payload_support, "_load_hook_payload")
    if payload_loader is None:
        failures.append("CLI hook payload loader is missing")
    elif _called_node(payload_loader, "hydrate_hook_payload_reference") is not None:
        failures.append("CLI hook payload loader still hydrates payload references in Python")
    return failures


def _graph_failures(root: Path) -> list[str]:
    """Reject any path that can spill auto/force hooks into Python semantics."""
    failures: list[str] = []
    for check in (
        _server_graph_failures,
        _resident_graph_failures,
        _native_cli_graph_failures,
        _hook_cli_graph_failures,
        _payload_graph_failures,
    ):
        failures.extend(check(root))
    return failures


def _contract_failures(root: Path) -> list[str]:
    failures: list[str] = []
    checks = (
        (
            root / "rust/crates/guard-command/src/pretool.rs",
            ("pub fn evaluate_pre_tool", "PreToolDecisionV1", "pub mod generic", "~/.npmrc"),
        ),
        (
            root / "rust/crates/guard-command/src/pretool/generic.rs",
            ("pub fn evaluate_pre_tool_envelope", "PreToolResultV1"),
        ),
        (
            root / "rust/crates/guard-command/src/pretool/generic_result.rs",
            ("native_pre_tool_unknown_review", "PreToolResultV1"),
        ),
        (
            root / "rust/crates/guard-runtime/src/main.rs",
            ('command == "pre-tool"',),
        ),
        (
            root / "rust/crates/guard-runtime/src/resident_protocol.rs",
            (
                "pre-tool-command-authority-v1",
                "pre-tool-generic-authority-v1",
                "PreToolUse(CommandModelRequestV1)",
            ),
        ),
        (
            root / "rust/crates/guard-runtime/src/edge.rs",
            ("evaluate_pre_tool_envelope", "guard-pre-tool-result.v1"),
        ),
        (
            root / "rust/crates/guard-runtime/src/oneshot.rs",
            ("fn evaluate_pre_tool_bytes", "pre_tool_response", "evaluate_pre_tool_request"),
        ),
    )
    for path, tokens in checks:
        failures.extend(required_tokens(path, tokens))
    return failures


def _bridge_failures(root: Path) -> list[str]:
    failures: list[str] = []
    command_bridge = root / "src/codex_plugin_scanner/guard/native_pretool.py"
    failures.extend(
        required_tokens(
            command_bridge,
            (
                "def review_pre_tool_native(",
                "native_resident_client_request",
                '"operation": "pre_tool_use"',
                "def native_pre_tool_policy_floor(",
            ),
        )
    )
    bridge_source = read(command_bridge)
    failures.extend(
        required_tokens(
            root / "src/codex_plugin_scanner/guard/native_hook_edge.py",
            ("guard-pre-tool-result.v1", "pre-tool-generic-authority-v1", "_decode_pre_tool_result"),
        )
    )
    command_review = function_node(command_bridge, "review_pre_tool_native")
    if "native_resident_client_request" not in function_calls(command_review):
        failures.append("review_pre_tool_native does not invoke native_resident_client_request")
    if "pre_tool_use" not in function_strings(command_review):
        failures.append("review_pre_tool_native does not construct the native pre_tool_use operation")
    if "Python remains authoritative" in read(root / "src/codex_plugin_scanner/guard/native_command_model.py"):
        failures.append("native_command_model.py still describes Python as authoritative")
    if "Python remains authoritative" in bridge_source:
        failures.append(f"{command_bridge.as_posix()} still describes Python as authoritative")
    review_start = bridge_source.find("def review_pre_tool_native(")
    review_end = bridge_source.find("\ndef native_pre_tool_policy_floor(", review_start)
    review_body = bridge_source[review_start:review_end] if review_start >= 0 and review_end > review_start else ""
    if "evaluate_command(" in review_body:
        failures.append("review_pre_tool_native invokes the Python command evaluator")
    for retired_transport in ("run_isolated_hook_process", "resident_native_request"):
        if retired_transport in review_body:
            failures.append(f"review_pre_tool_native still invokes {retired_transport}")
    return failures


def _worker_failures(root: Path) -> list[str]:
    failures: list[str] = []
    hook_worker = root / "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    native_hook = root / "src/codex_plugin_scanner/guard/daemon/hook_worker_native.py"
    failures.extend(
        required_tokens(
            hook_worker,
            (
                "from ..native_hook_edge import review_raw_hook_native",
                'if event_name == "PreToolUse":',
            ),
        )
    )
    failures.extend(required_tokens(native_hook, ("native_pre_tool_unavailable",)))
    native_review = root / "src/codex_plugin_scanner/guard/daemon/hook_worker_native_review.py"
    review_chain = (
        (native_hook, "_review_native_edge", "HookWorkerNativeMixin", "review_native_edge"),
        (native_review, "review_native_edge", None, "_review_native_edge_once"),
        (native_review, "_review_native_edge_once", None, "_review_native_edge_with_snapshot"),
    )
    # Follow the extracted bounded-review helper instead of requiring the old
    # direct call. Every link must still reach the snapshot-bound native edge.
    for path, name, class_name, callee in review_chain:
        node = function_node(path, name, class_name=class_name)
        if callee not in function_calls(node):
            failures.append(f"{class_name or 'module'}.{name} does not invoke {callee}")
    native_edge_snapshot = function_node(
        native_hook, "_review_native_edge_with_snapshot", class_name="HookWorkerNativeMixin"
    )
    if "_review_raw_hook_native" not in function_calls(native_edge_snapshot):
        failures.append("HookWorkerNativeMixin._review_native_edge_with_snapshot does not invoke the native hook edge")
    raw_edge_review = function_node(hook_worker, "_review_raw_hook_native", class_name="HookWorker")
    if "review_raw_hook_native" not in function_calls(raw_edge_review):
        failures.append("HookWorker._review_raw_hook_native does not invoke review_raw_hook_native")
    return failures


def run(root: Path) -> dict[str, object]:
    failures = _contract_failures(root)
    failures.extend(_bridge_failures(root))
    failures.extend(_worker_failures(root))
    failures.extend(_graph_failures(root))
    result: dict[str, object] = {
        "schema": SCHEMA,
        "status": "passed" if not failures else "failed",
        "failures": failures,
    }
    if failures:
        raise RuntimeError(json.dumps(result, indent=2, sort_keys=True))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    result = run(args.root.resolve())
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
