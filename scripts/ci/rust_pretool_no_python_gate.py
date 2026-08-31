#!/usr/bin/env python3
"""Prove supported command PreToolUse authority is native, with Python as transport only."""

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


def function_calls(node: ast.FunctionDef) -> set[str]:
    calls: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if isinstance(child.func, ast.Name):
            calls.add(child.func.id)
        elif isinstance(child.func, ast.Attribute):
            calls.add(child.func.attr)
    return calls


def function_strings(node: ast.FunctionDef) -> set[str]:
    return {child.value for child in ast.walk(node) if isinstance(child, ast.Constant) and isinstance(child.value, str)}


def run(root: Path) -> dict[str, object]:
    failures: list[str] = []
    failures.extend(
        required_tokens(
            root / "rust/crates/guard-command/src/pretool.rs",
            ("pub fn evaluate_pre_tool", "PreToolDecisionV1", "~/.npmrc"),
        )
    )
    failures.extend(
        required_tokens(
            root / "rust/crates/guard-runtime/src/main.rs",
            (
                "pre-tool-command-authority-v1",
                'command == "pre-tool"',
                "PreToolUse(CommandModelRequestV1)",
            ),
        )
    )
    failures.extend(
        required_tokens(
            root / "rust/crates/guard-runtime/src/oneshot.rs",
            ("fn evaluate_pre_tool_bytes", "pre_tool_response", "evaluate_pre_tool_request"),
        )
    )
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
    hook_worker = root / "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    failures.extend(
        required_tokens(
            hook_worker,
            (
                "from ..native_hook_edge import review_raw_hook_native",
                'if event_name == "PreToolUse":',
                "native_pre_tool_unavailable",
            ),
        )
    )
    native_edge_review = function_node(hook_worker, "_review_native_edge", class_name="HookWorker")
    if "review_raw_hook_native" not in function_calls(native_edge_review):
        failures.append("HookWorker._review_native_edge does not invoke review_raw_hook_native")
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
