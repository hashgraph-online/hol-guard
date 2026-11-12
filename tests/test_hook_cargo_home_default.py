"""Every hook sender marks a default-spelled CARGO_HOME the same way."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import pi_extension_source
from codex_plugin_scanner.guard.hook_execution_environment import (
    HOOK_EXECUTION_ENVIRONMENT_KEY,
    cargo_home_default,
    stamp_hook_input_text,
)

# Mirrors the cases in guard-contracts' execution_environment_tests.rs, which
# the native receiver applies to the pair it inherits.
CARGO_HOME_CASES = [
    ("/Users/dev", "/Users/dev/.cargo", True),
    ("/Users/dev/", "/Users/dev/.cargo", True),
    ("/Users/dev", "/Users/dev/.cargo/", True),
    ("/Users/dev", "/opt/cargo", False),
    ("/Users/dev", "/Users/dev/.cargo/vendor", False),
    ("/Users/dev", ".cargo", False),
    ("/Users/dev", "", False),
    ("/Users/dev", None, False),
    (None, "/Users/dev/.cargo", False),
    ("/", "/.cargo", False),
]


def _pi_execution_environment(tmp_path: Path, home: str | None, cargo_home: str | None) -> dict[str, object]:
    source = pi_extension_source.managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )
    start = source.index("  const activeEnvironment = Object.create(null);")
    end = source.index("  let serializedPayload = '';", start)
    prelude = "".join(
        f"process.env.{name} = {json.dumps(value)};\n" if value is not None else f"delete process.env.{name};\n"
        for name, value in (("HOME", home), ("CARGO_HOME", cargo_home))
    )
    script = tmp_path / "pi-environment.mjs"
    script.write_text(
        'import { createHash } from "node:crypto";\n'
        "const payload = {};\n"
        f"{prelude}{source[start:end]}"
        "console.log(JSON.stringify(payloadToSend.guard_execution_environment));\n",
        encoding="utf-8",
    )
    env = {name: value for name, value in os.environ.items() if name not in {"HOME", "CARGO_HOME"}}
    result = subprocess.run(["node", str(script)], env=env, capture_output=True, text=True, timeout=30, check=True)
    return json.loads(result.stdout)


@pytest.mark.parametrize(("home", "cargo_home", "expected"), CARGO_HOME_CASES)
def test_python_senders_mark_only_a_default_cargo_home(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    home: str | None,
    cargo_home: str | None,
    expected: bool,
) -> None:
    for name, value in (("HOME", home), ("CARGO_HOME", cargo_home)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)

    contexts = [
        json.loads(stamp_hook_input_text("{}"))[HOOK_EXECUTION_ENVIRONMENT_KEY],
    ]

    assert cargo_home_default(home, cargo_home) is expected
    for context in contexts:
        # The key is present only when true, and the value itself is never sent.
        assert context.get("cargo_home_default", False) is expected
        assert ("cargo_home_default" in context) is expected
        if cargo_home:
            assert cargo_home not in json.dumps(context.get("environment_names", []))


@pytest.mark.skipif(shutil.which("node") is None, reason="the Pi extension runs under node")
def test_pi_sender_marks_only_a_default_cargo_home(tmp_path: Path) -> None:
    for index, (home, cargo_home, expected) in enumerate(CARGO_HOME_CASES):
        case_root = tmp_path / str(index)
        case_root.mkdir()
        context = _pi_execution_environment(case_root, home, cargo_home)
        assert ("cargo_home_default" in context) is expected, (home, cargo_home)
        if expected:
            assert context["cargo_home_default"] is True
