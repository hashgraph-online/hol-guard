"""Judge distribution roots with the CI-built runtime when no runtime is packaged."""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any

from codex_plugin_scanner.guard.catalog_delivery import lifecycle
from codex_plugin_scanner.guard.extension_builder import native_source_compiler as transport


def route_distribution(monkeypatch: Any) -> None:
    """Send only `distribution` and `release-transport` requests to the pinned binary in a source checkout.

    A checkout carries no packaged runtime for the production session to verify.
    A test that installs one, or replaces `lifecycle.invoke`, keeps its own path.
    """
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    if not binary:
        return
    original = lifecycle.invoke

    def invoke(kind: str, **fields: Any) -> dict[str, Any]:
        if (
            kind not in {"distribution", "release-transport"}
            or (transport._NATIVE_PACKAGE / transport._MANIFEST_NAME).is_file()
        ):
            return original(kind, **fields)
        result = subprocess.run(
            [binary, "pack-lifecycle", "--stdin"],
            input=json.dumps({"kind": kind, **fields}).encode(),
            capture_output=True,
            timeout=60,
            check=False,
        )
        if result.returncode:
            raise ValueError(f"native_pack_lifecycle_unavailable: {result.stderr.decode().strip()}")
        return json.loads(result.stdout)

    monkeypatch.setattr(lifecycle, "invoke", invoke)
