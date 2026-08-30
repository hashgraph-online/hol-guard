#!/usr/bin/env python3
"""Prove default PreToolUse authority is Rust with no automatic Python fallback."""

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


def function_source(path: Path, name: str) -> str:
    source = read(path)
    tree = ast.parse(source, filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            segment = ast.get_source_segment(source, node)
            if segment is not None:
                return segment
    raise RuntimeError(f"missing function {path}:{name}")


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
                '"hook-edge-v2"',
                "HookEdge(Value)",
            ),
        )
    )
    failures.extend(
        required_tokens(
            root / "rust/crates/guard-runtime/src/oneshot.rs",
            (
                "fn evaluate_pre_tool_bytes",
                "pre_tool_response",
                "evaluate_pre_tool_request",
                "evaluate_hook_edge_value",
                "extract_pre_tool_command",
                "native_pre_tool_unsupported_review",
            ),
        )
    )

    worker_path = root / "src/codex_plugin_scanner/guard/daemon/hook_worker.py"
    worker = read(worker_path)
    production = function_source(worker_path, "review_http_payload")
    compatibility = function_source(worker_path, "_review_explicit_python_compatibility")
    for required in ("review_hook_edge_native", 'mode in {"off", "shadow"}', "native_hook_edge_unavailable"):
        if required not in production:
            failures.append(f"default HookWorker PreTool contract missing {required}")
    if "self.engine.review(" in production or "_request_from_payload(" in production:
        failures.append("default HookWorker path invokes Python semantic evaluation")
    if "HookWorkerUnsupported" in production:
        failures.append("default HookWorker path can escape Rust authority")
    if 'event_name != "PostToolUse"' not in compatibility:
        failures.append("explicit Python compatibility is not bounded away from PreToolUse")
    if "review_pre_tool_native" in worker or "_pre_tool_command(" in worker:
        failures.append("HookWorker retains superseded Python-side PreTool parsing")

    edge = root / "src/codex_plugin_scanner/guard/native_hook_edge.py"
    edge_source = read(edge)
    for required in ('"operation": "hook_edge"', '"hook-edge", "--stdin"', "review_hook_edge_native"):
        if required not in edge_source:
            failures.append(f"{edge.as_posix()} missing {required}")
    for forbidden in ("evaluate_command(", "HookReviewEngine", "review_pre_tool_native("):
        if forbidden in edge_source:
            failures.append(f"native hook edge bridge invokes Python PreTool semantics: {forbidden}")

    cli_path = root / "src/codex_plugin_scanner/guard/cli/commands_hook_native_authority.py"
    native_route = function_source(cli_path, "try_native_hook_authority")
    compatibility_route = function_source(cli_path, "try_native_or_source_ref_hook")
    if 'native_mode() not in {"auto", "force"}' not in native_route:
        failures.append("CLI does not restrict Python compatibility to explicit off/shadow")
    if "HookWorker(store=store).review_http_payload(" not in native_route:
        failures.append("CLI auto/force PreTool route does not terminate at Rust HookWorker")
    if "except" in native_route:
        failures.append("CLI auto/force PreTool route catches native failures for fallback")
    if "_try_source_ref_fast_path" not in compatibility_route:
        failures.append("explicit source-ref compatibility route is missing")
    if "native_result is not None" not in compatibility_route:
        failures.append("native PreTool result is not terminal before compatibility")

    result = {
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
