from __future__ import annotations

import json
from pathlib import Path
from typing import cast


def json_object(text: str) -> dict[str, object]:
    payload = cast(object, json.loads(text))
    assert isinstance(payload, dict)
    return {str(key): value for key, value in cast(dict[object, object], payload).items()}


def config(tmp_path: Path, *, harness: str) -> dict[str, object]:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    return {
        "python_executable": "python",
        "package_root": str(tmp_path),
        "guard_home": str(guard_home),
        "cli_args": [
            "guard",
            "hook",
            "--guard-home",
            str(guard_home),
            "--harness",
            harness,
        ],
        "harness": harness,
        "timeout_seconds": 3,
    }
