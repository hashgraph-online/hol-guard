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


def _contains_name(node: ast.AST, name: str) -> bool:
    return any(isinstance(child, ast.Name) and child.id == name for child in ast.walk(node))


def _calls_guarded_by(node: ast.FunctionDef, call_name: str, guard_name: str) -> tuple[ast.Call, ...]:
    """Return calls whose enclosing branch mentions the required guard."""
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(node):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    guarded: list[ast.Call] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        called_name = (
            child.func.id
            if isinstance(child.func, ast.Name)
            else (child.func.attr if isinstance(child.func, ast.Attribute) else None)
        )
        if called_name != call_name:
            continue
        ancestor = parents.get(child)
        while ancestor is not None and ancestor is not node:
            if isinstance(ancestor, ast.If) and _contains_name(ancestor.test, guard_name):
                guarded.append(child)
                break
            ancestor = parents.get(ancestor)
    return tuple(guarded)


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
    unsupported = _exception_handler(server_fast, "HookWorkerUnsupported")
    if unsupported is None or "_native_mode_requires_rust" not in function_calls(unsupported):
        failures.append("server fast path can spill HookWorkerUnsupported into compatibility CLI in auto/force")
    elif "_runtime_hook_fail_safe_response" not in function_calls(unsupported):
        failures.append("server HookWorkerUnsupported native branch has no fail-safe response")
    return failures


def _resident_graph_failures(root: Path) -> list[str]:
    failures: list[str] = []
    entrypoint = root / "src/codex_plugin_scanner/guard/daemon/hook_process_entrypoint.py"
    resident = _function_node_or_none(entrypoint, "_run_resident_hook_request")
    if resident is None:
        failures.append("resident hook entrypoint is missing")
        return failures
    fallback = _called_node(resident, "_run_guard_hook_command")
    unsupported = _exception_handler(resident, "HookWorkerUnsupported")
    if fallback is None or unsupported is None:
        failures.append("resident entrypoint native/compatibility graph is incomplete")
        return failures
    has_unknown_event_native_route = any(
        isinstance(child, ast.If)
        and "_native_mode_requires_rust" in function_calls(child.test)
        and _contains_name(child.test, "event_name")
        and "review_http_payload" in function_calls(child)
        for child in ast.walk(resident)
    )
    if not has_unknown_event_native_route:
        failures.append("resident entrypoint does not send unknown events to native authority")
    elif not any(
        isinstance(child, ast.If)
        and child.lineno < fallback.lineno
        and "_native_mode_requires_rust" in function_calls(child.test)
        and any(isinstance(item, ast.Return) for item in ast.walk(child))
        for child in resident.body
    ):
        failures.append("resident entrypoint can reach Python CLI without a native-mode return guard")
    elif not _has_typed_fail_safe(unsupported):
        failures.append("resident HookWorkerUnsupported native branch has no fail-safe response")
    return failures


def _native_cli_graph_failures(root: Path) -> list[str]:
    failures: list[str] = []
    native_cli = root / "src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py"
    native_route = _function_node_or_none(native_cli, "try_native_or_source_ref_hook")
    if native_route is None:
        failures.append("CLI native/source-ref route is missing")
        return failures
    native_call = _called_node(native_route, "try_native_hook_authority")
    source_call = _called_node(native_route, "_try_source_ref_fast_path")
    if native_call is None or source_call is None or native_call.lineno >= source_call.lineno:
        failures.append("CLI source-ref path is reachable before native authority")
    if "_native_mode_requires_rust" not in function_calls(native_route):
        failures.append("CLI native/source-ref route has no native-mode guard")
    if not _has_typed_fail_safe(native_route):
        failures.append("CLI native/source-ref route has no fail-safe native terminal")
    return failures


def _hook_cli_graph_failures(root: Path) -> list[str]:
    failures: list[str] = []
    hook_cli = root / "src/codex_plugin_scanner/guard/cli/commands_hook.py"
    hook_command = _function_node_or_none(hook_cli, "_run_guard_hook_command")
    if hook_command is None:
        failures.append("CLI hook command entrypoint is missing")
        return failures
    load_call = _called_node(hook_command, "_load_hook_payload")
    native_call = _called_node(hook_command, "try_native_or_source_ref_hook")
    hydrate_call = _called_node(hook_command, "hydrate_hook_payload_reference")
    normalize_call = _called_node(hook_command, "_normalize_hook_payload")
    normalize_value = _keyword_value(load_call, "normalize") if load_call is not None else None
    if load_call is None or normalize_value is None:
        failures.append("CLI hook command does not load an explicit raw payload")
    elif not isinstance(normalize_value, ast.Constant) or normalize_value.value is not False:
        failures.append("CLI hook command normalizes payload before native authority")
    if native_call is None or normalize_call is None or native_call.lineno >= normalize_call.lineno:
        failures.append("CLI hook command reaches adapter normalization before native authority")
        return failures
    compatibility_value = _keyword_value(native_call, "allow_compatibility")
    if not isinstance(compatibility_value, ast.Constant) or compatibility_value.value is not False:
        failures.append("CLI raw native route does not disable compatibility fallback")
    if (
        hydrate_call is None
        or native_call.lineno >= hydrate_call.lineno
        or hydrate_call.lineno >= normalize_call.lineno
    ):
        failures.append("CLI hook command hydrates references before native routing or after normalization")
    return failures


def _payload_graph_failures(root: Path) -> list[str]:
    failures: list[str] = []
    payload_support = root / "src/codex_plugin_scanner/guard/cli/commands_support_hook_payload.py"
    payload_loader = _function_node_or_none(payload_support, "_load_hook_payload")
    if payload_loader is None:
        failures.append("CLI hook payload loader is missing")
    elif not _calls_guarded_by(payload_loader, "hydrate_hook_payload_reference", "normalize"):
        failures.append("CLI hook payload loader hydrates references outside explicit normalization")
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
    native_edge_review = function_node(native_hook, "_review_native_edge", class_name="HookWorkerNativeMixin")
    if "_review_raw_hook_native" not in function_calls(native_edge_review):
        failures.append("HookWorkerNativeMixin._review_native_edge does not invoke the native hook edge")
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
