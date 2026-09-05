#!/usr/bin/env python3
"""Prove that hook route and evidence artifacts are privacy-safe.

Decision transport may carry the raw envelope to Rust, but route receipts,
metrics, journals, and enrichment tasks must contain only bounded dimensions,
counts, hashes, and booleans.  This gate checks the serializer AST and runs a
small adversarial validator against the emitted artifact shapes.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

if not __package__:
    _PROJECT_ROOT = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(_PROJECT_ROOT / "src"))
    sys.path.insert(0, str(_PROJECT_ROOT))


SCHEMA: Final = "hol-guard.native-hook-io-privacy.v1"
_SAFE_STRING: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_METRIC_KEY: Final = re.compile(
    r"^(?:decision|latency|size|scanner_size|model_output_action|policy_action|failure|metrics):"
    r"[A-Za-z0-9<>=][A-Za-z0-9_.:<> =-]{0,95}$",
)
_PRIVATE_PATH: Final = re.compile(
    r"(?:^|[/\\])(?:Users|home|private|var[/\\]folders|tmp)(?:[/\\]|$)|(?:^[A-Za-z]:[/\\])",
    re.IGNORECASE,
)
_SECRET_VALUE: Final = re.compile(
    r"(?:-----BEGIN[^\n]*PRIVATE KEY-----|(?:ghp|github_pat|xox[baprs])_[A-Za-z0-9_-]+|"
    r"AKIA[0-9A-Z]{16}|Bearer\s+\S+|sk-[A-Za-z0-9_-]{16,})",
    re.IGNORECASE,
)
_FORBIDDEN_KEY_WORDS: Final = (
    "raw",
    "command",
    "cmd",
    "prompt",
    "secret",
    "token",
    "path",
    "source",
    "content",
    "stdout",
    "stderr",
    "output",
    "excerpt",
    "reason",
    "workspace",
    "url",
    "body",
    "input",
)
_SAFE_KEY_EXCEPTIONS: Final = frozenset(
    {
        "workspace_bound",
        "has_command",
        "payload_bytes",
        "model_output_action",
        "reason_code",
    }
)
_SERIALIZERS: Final = (
    (
        "src/codex_plugin_scanner/guard/daemon/runtime_hook_evidence_journal.py",
        "serialized",
        "_CommandActivityRecord",
    ),
    (
        "src/codex_plugin_scanner/guard/runtime/hook_enrichment_queue.py",
        "make_receipt_task",
        "HookEnrichmentQueue",
    ),
    (
        "src/codex_plugin_scanner/guard/daemon/hook_metrics.py",
        "snapshot",
        "HookMetricsRecorder",
    ),
    (
        "src/codex_plugin_scanner/guard/daemon/hook_metrics.py",
        "maybe_flush_to_store",
        "HookMetricsRecorder",
    ),
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"could not inspect {path}") from exc


def _function_node(path: Path, name: str, class_name: str | None) -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse(_read(path), filename=path.as_posix())
    candidates: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name != name:
            continue
        if class_name is None:
            parent_class = next(
                (parent.name for parent in ast.walk(tree) if isinstance(parent, ast.ClassDef) and node in parent.body),
                None,
            )
            if parent_class is None:
                candidates.append(node)
        else:
            in_class = any(
                isinstance(parent, ast.ClassDef) and parent.name == class_name and node in parent.body
                for parent in ast.walk(tree)
            )
            if in_class:
                candidates.append(node)
    if len(candidates) != 1:
        raise RuntimeError(f"expected one serializer {class_name or 'module'}.{name} in {path}")
    return candidates[0]


def _constant_key(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _key_failure(key: str, location: str) -> str | None:
    normalized = key.strip().lower()
    if normalized in _SAFE_KEY_EXCEPTIONS:
        return None
    if _SAFE_METRIC_KEY.fullmatch(normalized):
        return None
    if not re.fullmatch(r"[a-z][a-z0-9_:-]{0,95}", normalized):
        return f"invalid artifact field {key!r} at {location}"
    if any(word in normalized for word in _FORBIDDEN_KEY_WORDS):
        return f"forbidden raw-content artifact field {key!r} at {location}"
    return None


def validate_artifact(value: object, *, location: str = "artifact") -> list[str]:
    """Return privacy violations without exposing the offending value."""
    failures: list[str] = []

    def visit(item: object, path: str) -> None:
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    failures.append(f"non-string artifact field at {path}")
                    continue
                failure = _key_failure(key, path)
                if failure is not None:
                    failures.append(failure)
                visit(child, f"{path}.{key}")
            return
        if isinstance(item, (list, tuple)):
            for index, child in enumerate(item):
                visit(child, f"{path}[{index}]")
            return
        if isinstance(item, str):
            if not _SAFE_STRING.fullmatch(item):
                failures.append(f"unbounded artifact string at {path}")
            if _PRIVATE_PATH.search(item):
                failures.append(f"private path in artifact at {path}")
            if _SECRET_VALUE.search(item):
                failures.append(f"secret-like value in artifact at {path}")
            return
        if isinstance(item, (bytes, bytearray, memoryview)):
            failures.append(f"raw bytes in artifact at {path}")

    visit(value, location)
    return failures


def _static_failures(root: Path) -> list[str]:
    failures: list[str] = []
    for relative, name, class_name in _SERIALIZERS:
        path = root / relative
        if not path.is_file():
            failures.append(f"privacy serializer is missing: {relative}")
            continue
        node = _function_node(path, name, class_name)
        for child in ast.walk(node):
            if not isinstance(child, ast.Dict):
                continue
            for key_node in child.keys:
                key = _constant_key(key_node) if key_node is not None else None
                if key is None:
                    continue
                failure = _key_failure(key, f"{relative}:{child.lineno}")
                if failure is not None:
                    failures.append(failure)
    route = root / "src/codex_plugin_scanner/guard/native_route_receipt.py"
    if not route.is_file():
        failures.append("native route receipt module is missing")
    elif "ContextVar" not in _read(route):
        failures.append("native route receipt is not request-local")
    return failures


def _dynamic_failures() -> list[str]:
    safe_receipt = {
        "schema": "hol-guard-native-hook-evidence.v1",
        "harness": "pi",
        "event_name": "PostToolUse",
        "decision": "allow",
        "reason_code": "source_full_scan_allow",
        "workspace_bound": False,
    }
    safe_evidence = {
        "record_id": "a" * 32,
        "harness": "pi",
        "event": "PostToolUse",
        "correlation": {"kind": "installation", "harness": "pi", "key_id": "k1", "digest": "b" * 64},
        "has_command": True,
        "succeeded": True,
        "payload_bytes": 128,
    }
    safe_metrics = {
        "counters": {"decision:pi:posttooluse:allow:policy:miss:none": 1},
        "latency_p50_ms": 5.0,
        "latency_p95_ms": 10.0,
        "total_decisions": 1,
        "routes": {"native_resident": 1},
    }
    failures: list[str] = []
    for name, artifact in (("receipt", safe_receipt), ("evidence", safe_evidence), ("metrics", safe_metrics)):
        failures.extend(f"{name}: {failure}" for failure in validate_artifact(artifact, location=name))
    adversarial = (
        {"command": "cat /private/source"},
        {"safe": "/Users/alice/project"},
        {"safe": "-----BEGIN PRIVATE KEY-----"},
        {"safe": "source bytes\nfn main() {}"},
    )
    for artifact in adversarial:
        if not validate_artifact(artifact):
            failures.append("dynamic privacy probe accepted a raw-content adversarial artifact")
    try:
        from codex_plugin_scanner.guard.daemon.hook_metrics import HookMetricsRecorder
        from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import _CommandActivityRecord
        from codex_plugin_scanner.guard.runtime.command_activity_contract import (
            CorrelationHandle,
            CorrelationKind,
        )
        from codex_plugin_scanner.guard.runtime.hook_enrichment_queue import HookEnrichmentQueue

        queue_task = HookEnrichmentQueue().make_receipt_task(
            task_id="privacy-probe",
            harness="pi",
            event_name="PostToolUse",
            decision="allow",
            reason_code="source_full_scan_allow",
            reason="cat /private/source",
            workspace="/Users/alice/private/project",
        )
        correlation = CorrelationHandle(
            kind=CorrelationKind.REQUEST,
            harness="pi",
            key_id="probe-key",
            digest="a" * 64,
        )
        evidence = _CommandActivityRecord(
            record_id="privacy-probe",
            harness="pi",
            event="PostToolUse",
            correlation=correlation,
            has_command=True,
            succeeded=True,
            payload_bytes=32,
        )
        metrics = HookMetricsRecorder()
        metrics.record(
            harness="pi",
            event_name="PostToolUse",
            route="native_resident",
            payload_kind="inline",
            output_size=32,
            latency_ms=5.0,
            decision="allow",
            policy_action=None,
            model_output_action="allow",
            reason_code="source_full_scan_allow",
            cache_status="miss",
            fallback_kind="none",
            scanner_bytes=32,
        )
        runtime_artifacts = (
            queue_task.payload,
            json.loads(evidence.serialized()),
            metrics.snapshot(),
        )
        for name, artifact in zip(("queue", "evidence", "metrics"), runtime_artifacts, strict=True):
            failures.extend(f"runtime {name}: {failure}" for failure in validate_artifact(artifact, location=name))
    except (ImportError, TypeError, ValueError, AttributeError) as exc:
        failures.append(f"runtime serializer probe failed: {type(exc).__name__}")
    return failures


def validate(root: Path) -> dict[str, object]:
    root = root.resolve()
    failures = _static_failures(root)
    failures.extend(_dynamic_failures())
    if failures:
        raise RuntimeError("; ".join(failures))
    return {
        "schema": SCHEMA,
        "status": "passed",
        "static_serializers": [relative for relative, _name, _class_name in _SERIALIZERS],
        "dynamic_probes": [
            "safe_receipt",
            "safe_evidence",
            "safe_metrics",
            "raw_command",
            "private_path",
            "secret",
            "raw_source",
        ],
        "excluded_fields": [
            "raw_payload",
            "command",
            "prompt",
            "path",
            "source",
            "content",
            "secret",
            "token",
            "private_path",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--json", type=Path)
    args = parser.parse_args(argv)
    payload = validate(args.root)
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
