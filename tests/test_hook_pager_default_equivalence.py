"""Pager values every hook sender reports as no wider than Git's default pager."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.hook_execution_environment import (
    HOOK_EXECUTION_ENVIRONMENT_KEY,
    LIBRARY_SEARCH_PATH_NAMES,
    pager_default_equivalent,
    stamp_hook_input_text,
)
from tests import pi_extension_support as pi_extension_source

PAGER_CASES = [
    (None, False),
    ("", True),
    ("cat", True),
    ("less", True),
    ("less -R", True),
    ("less -FRX -S", True),
    ("more", False),
    ("delta", False),
    ("less; touch x", False),
    ("less --lesskey-src=x", False),
    # These options read the rest of the word as a file name or pattern.
    ("less -Ovictim", False),
    ("less -R -ovictim", False),
    ("less -klesskey", False),
    ("less -Ttags", False),
    ("less -Pprompt", False),
    ("less -+R", False),
    # Cursor's agent terminal pager, exactly as Cursor exports it.
    ('sh -c "head -n 10000 | cat"', True),
    ('sh -c "head -n 10000 | cat; touch x"', False),
    ('sh -c "head -n 10000 | tee x"', False),
    ("sh -c 'head -n 10000 | cat'", False),
    ('sh -c "head -n 10000 | cat" x', False),
    ('bash -c "head -n 10000 | cat"', False),
]


def _set_pagers(monkeypatch: pytest.MonkeyPatch, pager: str | None) -> None:
    for name in ("PAGER", "GIT_PAGER"):
        if pager is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, pager)


@pytest.mark.parametrize(("pager", "expected"), PAGER_CASES)
def test_python_sender_agrees_on_default_equivalent_pagers(
    monkeypatch: pytest.MonkeyPatch,
    pager: str | None,
    expected: bool,
) -> None:
    _set_pagers(monkeypatch, pager)

    stamped = json.loads(stamp_hook_input_text(json.dumps({"hook_event_name": "PreToolUse"})))
    context = stamped[HOOK_EXECUTION_ENVIRONMENT_KEY]

    assert pager_default_equivalent(pager) is expected
    assert context["pager_disabled"] is context["git_pager_disabled"] is expected


def test_stamp_keeps_near_limit_input_forwardable() -> None:
    text = json.dumps({"hook_event_name": "PreToolUse", "tool_input": {"command": "x" * 999_800}})

    assert stamp_hook_input_text(text) == text


def test_python_sender_keeps_present_but_empty_pager_names(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_PAGER", "")
    monkeypatch.setenv("PAGER", "delta")

    contexts = [
        json.loads(stamp_hook_input_text("{}"))[HOOK_EXECUTION_ENVIRONMENT_KEY],
    ]
    for context in contexts:
        assert "GIT_PAGER" in context["environment_names"]
        assert "PAGER" in context["environment_names"]
        assert context["git_pager_disabled"] is True
        assert context["pager_disabled"] is False
    assert len({tuple(c["environment_names"]) for c in contexts}) == 1
    assert len({c["environment_digest"] for c in contexts}) == 1

    monkeypatch.delenv("GIT_PAGER")
    unset = json.loads(stamp_hook_input_text("{}"))[HOOK_EXECUTION_ENVIRONMENT_KEY]
    assert "GIT_PAGER" not in unset["environment_names"]


def _pi_execution_environment(tmp_path: Path, env: dict[str, str]) -> dict[str, object]:
    source = pi_extension_source.managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )
    start = source.index("  const activeEnvironment = Object.create(null);")
    end = source.index("  let serializedPayload = '';", start)
    script = tmp_path / "pi-environment.mjs"
    script.write_text(
        'import { createHash } from "node:crypto";\n'
        "const payload = {};\n"
        f"{source[start:end]}"
        "console.log(JSON.stringify(payloadToSend.guard_execution_environment));\n",
        encoding="utf-8",
    )
    result = subprocess.run(["node", str(script)], env=env, capture_output=True, text=True, timeout=30, check=True)
    return json.loads(result.stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="the Pi extension runs under node")
def test_pi_sender_keeps_present_but_empty_pager_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GIT_PAGER", "")
    monkeypatch.setenv("PAGER", "delta")
    env = dict(os.environ)

    pi = _pi_execution_environment(tmp_path, env)
    python = json.loads(stamp_hook_input_text("{}"))[HOOK_EXECUTION_ENVIRONMENT_KEY]

    assert "GIT_PAGER" in pi["environment_names"]
    assert pi["git_pager_disabled"] is True
    assert pi["pager_disabled"] is False
    assert pi["environment_names"] == python["environment_names"]
    assert pi["environment_digest"] == python["environment_digest"]

    del env["GIT_PAGER"]
    unset = _pi_execution_environment(tmp_path, env)
    assert "GIT_PAGER" not in unset["environment_names"]
    assert unset["git_pager_disabled"] is False


def test_all_senders_stamp_the_same_loader_search_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in LIBRARY_SEARCH_PATH_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LD_LIBRARY_PATH", "/usr/local/cuda/lib64:/usr/lib")
    monkeypatch.setenv("DYLD_FALLBACK_LIBRARY_PATH", "")
    monkeypatch.setenv("LD_PRELOAD", "/synthetic/preload.so")
    expected = {"LD_LIBRARY_PATH": "/usr/local/cuda/lib64:/usr/lib"}

    contexts = [
        json.loads(stamp_hook_input_text("{}"))[HOOK_EXECUTION_ENVIRONMENT_KEY],
    ]
    if shutil.which("node") is not None:
        contexts.append(_pi_execution_environment(tmp_path, dict(os.environ)))
    for context in contexts:
        assert context["library_search_paths"] == expected
        assert "LD_PRELOAD" in context["environment_names"]
