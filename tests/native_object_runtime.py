"""Route delivery object and container checks to the pinned compiled runtime.

CI pins the candidate binary with HOL_GUARD_NATIVE_BINARY. Without it the
checks keep their production route through the installed runtime.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.catalog_delivery import object_native


@pytest.fixture(autouse=True)
def compiled_delivery_objects(monkeypatch):
    binary = Path(os.environ.get("HOL_GUARD_NATIVE_BINARY") or "")
    if not binary.is_file():
        return

    def native(**fields):
        result = subprocess.run(
            [str(binary), "pack-lifecycle", "--stdin"],
            input=json.dumps({"kind": "object", **fields}).encode(),
            capture_output=True,
            timeout=60,
        )
        if result.returncode:
            raise ValueError(result.stderr.decode().strip())
        return json.loads(result.stdout)

    monkeypatch.setattr(object_native, "_native", native)
