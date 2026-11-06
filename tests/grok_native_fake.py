"""A stand-in for the native `grok-executable` command.

It trusts any existing launcher without the ownership checks, so adapter
tests can run from a shared temporary directory. The checks themselves are
covered by the runtime's own tests and the real-runtime tests in
`test_guard_grok_executable_security.py`.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import grok_executable as grok_executable_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext


def install_grok_native_fake(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(grok_executable_module, "_answer", _answer)


def _answer(op: str, context: HarnessContext, fields: Mapping[str, object]) -> dict[str, object]:
    registration = context.guard_home / "managed" / "grok" / "trusted-executable.json"
    if op == "launch-env":
        path_value = fields.get("path_value")
        return {"path": path_value if isinstance(path_value, str) and path_value else os.defpath, "drop": []}
    if op == "register":
        executable = _trusted(str(fields["path"]), "registration")
        registration.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = {"path": executable["path"], "schemaVersion": 1, "sha256": executable["content_sha256"]}
        registration.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        registration.chmod(0o600)
        return {"executable": executable, "error": None, "trusted": True}
    explicit = fields.get("explicit")
    if isinstance(explicit, str) and explicit.strip():
        return {"executable": _trusted(explicit.strip(), "explicit"), "error": None}
    if registration.is_file():
        payload = json.loads(registration.read_text(encoding="utf-8"))
        executable = _trusted(payload["path"], "registration")
        if executable["content_sha256"] != payload["sha256"]:
            return {"executable": None, "error": "The registered Grok executable changed."}
        return {"executable": executable, "error": None}
    candidate = fields.get("candidate")
    if isinstance(candidate, str):
        return {"executable": _trusted(candidate, "automatic"), "error": None}
    return {"executable": None, "error": "Grok executable was not found in a trusted installation location."}


def _trusted(value: str, source: str) -> dict[str, object]:
    resolved = Path(value).resolve(strict=True)
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    return {"path": str(resolved), "content_sha256": digest, "source": source}
