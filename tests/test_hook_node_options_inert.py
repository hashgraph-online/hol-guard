"""Every hook sender marks a heap-size or diagnostics-only NODE_OPTIONS the same way."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from codex_plugin_scanner.guard.adapters import pi_extension_source
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import _render_bounded_hook_script
from codex_plugin_scanner.guard.hook_execution_environment import (
    HOOK_EXECUTION_ENVIRONMENT_KEY,
    node_options_inert,
    stamp_hook_input_text,
)

# Mirrors the cases in guard-contracts' execution_environment_tests.rs, which
# the native receiver applies to the value it inherits.
NODE_OPTIONS_CASES = [
    (None, False),
    ("--max-old-space-size=8192", True),
    (" --max_old_space_size=4096  --no-warnings ", True),
    ("--enable-source-maps --stack-trace-limit=50", True),
    ("--max-semi-space-size=64 --trace-deprecation", True),
    ("", False),
    ("   ", False),
    ("--require ./hook.js", False),
    ("--require=./hook.js", False),
    ("-r ./hook.js", False),
    ("--import=data:text/javascript,0", False),
    ("--loader ./loader.mjs", False),
    ("--experimental-loader=./loader.mjs", False),
    ("--inspect=0.0.0.0:9229", False),
    ("--max-old-space-size=8192 --require=./hook.js", False),
    ("--max-old-space-size=", False),
    ("--max-old-space-size=8g", False),
    ("--max-old-space-size 8192", False),
    ("--env-file=.env", False),
    ("--max-old-space-size=8192\t--require=x", False),
    ('"--max-old-space-size=8192"', False),
    ("--no-warnings=1", False),
]


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _zcode_hook(tmp_path: Path) -> ModuleType:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    script = guard_home / "zcode.py"
    script.write_text(
        _render_bounded_hook_script(guard_home=guard_home, harness="zcode", timeout_seconds=8),
        encoding="utf-8",
    )
    return _load(script, f"generated_zcode_node_options_hook_{tmp_path.name}")


def _pi_execution_environment(tmp_path: Path, node_options: str | None) -> dict[str, object]:
    source = pi_extension_source.managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )
    start = source.index("  const activeEnvironment = Object.create(null);")
    end = source.index("  let serializedPayload = '';", start)
    # Node would refuse to start with most of these values, so the script sets
    # the variable after startup instead.
    prelude = "" if node_options is None else f"process.env.NODE_OPTIONS = {json.dumps(node_options)};\n"
    script = tmp_path / "pi-environment.mjs"
    script.write_text(
        'import { createHash } from "node:crypto";\n'
        "const payload = {};\n"
        f"{prelude}{source[start:end]}"
        "console.log(JSON.stringify(payloadToSend.guard_execution_environment));\n",
        encoding="utf-8",
    )
    env = {name: value for name, value in os.environ.items() if name != "NODE_OPTIONS"}
    result = subprocess.run(["node", str(script)], env=env, capture_output=True, text=True, timeout=30, check=True)
    return json.loads(result.stdout)


@pytest.mark.parametrize(("value", "expected"), NODE_OPTIONS_CASES)
def test_python_senders_mark_only_inert_node_options(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    value: str | None,
    expected: bool,
) -> None:
    generated = _zcode_hook(tmp_path)
    if value is None:
        monkeypatch.delenv("NODE_OPTIONS", raising=False)
    else:
        monkeypatch.setenv("NODE_OPTIONS", value)

    contexts = [
        json.loads(stamp_hook_input_text("{}"))[HOOK_EXECUTION_ENVIRONMENT_KEY],
        json.loads(generated._stamp_hook_input("{}"))[HOOK_EXECUTION_ENVIRONMENT_KEY],
    ]

    assert node_options_inert(value) is expected
    for context in contexts:
        # The key is present only when true, and the value itself is never sent.
        assert context.get("node_options_inert", False) is expected
        assert ("node_options_inert" in context) is expected
        if value and value.strip():
            assert value.strip() not in json.dumps(context)


@pytest.mark.skipif(shutil.which("node") is None, reason="the Pi extension runs under node")
def test_pi_sender_marks_only_inert_node_options(tmp_path: Path) -> None:
    for index, (value, expected) in enumerate(NODE_OPTIONS_CASES):
        case_root = tmp_path / str(index)
        case_root.mkdir()
        context = _pi_execution_environment(case_root, value)
        assert ("node_options_inert" in context) is expected, value
        if expected:
            assert context["node_options_inert"] is True
