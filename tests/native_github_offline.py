"""Offline GitHub CLI classification for evaluator harnesses that run without a resident.

The corpus worker evaluates commands through the offline native compiler and
never starts a resident, so the production transport has no guard home to talk
to. This stub answers with the same Rust classifier through the compiler's
``github-classify-serve`` subcommand (one long-lived process); it never
recomputes a classification in Python.
"""

from __future__ import annotations

import atexit
import json
import subprocess
import sys
import types
from dataclasses import dataclass
from pathlib import Path

_MODULE = "codex_plugin_scanner.guard.native_github_cli"


@dataclass(frozen=True, slots=True)
class _Classification:
    capability: str
    reason_code: str
    detail: str
    capabilities: tuple[str, ...]
    pr_body_file_operand: str | None


def install_offline_github_classifier(compiler: Path) -> None:
    cache: dict[tuple[str, ...], _Classification] = {}
    server: subprocess.Popen[bytes] | None = None

    def start() -> subprocess.Popen[bytes]:
        process = subprocess.Popen(
            [str(compiler), "github-classify-serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        atexit.register(process.kill)
        return process

    def classify(args, **_kwargs):  # type: ignore[no-untyped-def]
        nonlocal server
        key = tuple(str(item) for item in args)
        if key not in cache:
            if server is None or server.poll() is not None:
                server = start()
            assert server.stdin is not None and server.stdout is not None
            server.stdin.write(json.dumps({"args": list(key)}).encode() + b"\n")
            server.stdin.flush()
            value = json.loads(server.stdout.readline())
            if value.get("ok") is False:
                raise RuntimeError("offline github classification failed")
            cache[key] = _Classification(
                capability=value["capability"],
                reason_code=value["reason_code"],
                detail=value["detail"],
                capabilities=tuple(value["capabilities"]),
                pr_body_file_operand=value.get("pr_body_file_operand"),
            )
        return cache[key]

    module = types.ModuleType(_MODULE)
    module.__dict__["github_cli_classify_native"] = classify
    sys.modules[_MODULE] = module
