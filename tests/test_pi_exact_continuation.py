"""Generated Pi-family tool-call approval continuation coverage."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from tests.pi_continuation_support import (
    _PI_SDK_ROOT_ENV,
    _decode_json_object,
    _node_executable,
    _pi_runner_module,
    _run_child,
    _write_pi_package,
)


def test_pi_runner_module_accepts_published_old_cli_layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package_root = tmp_path / "old-layout"
    cli_path = _write_pi_package(package_root, "dist/cli.js")
    monkeypatch.delenv(_PI_SDK_ROOT_ENV, raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: str(cli_path) if name == "pi" else None)

    assert _pi_runner_module() == (package_root / "dist" / "index.js").resolve()


def test_pi_runner_module_accepts_published_nested_cli_layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package_root = tmp_path / "nested-layout"
    cli_path = _write_pi_package(package_root, "dist/bundle/cli.js")
    monkeypatch.delenv(_PI_SDK_ROOT_ENV, raising=False)
    monkeypatch.setattr(shutil, "which", lambda name: str(cli_path) if name == "pi" else None)

    assert _pi_runner_module() == (package_root / "dist" / "index.js").resolve()


def test_pi_runner_module_rejects_undeclared_package_wrapper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package_root = tmp_path / "package"
    _write_pi_package(package_root, "dist/bundle/cli.js")
    monkeypatch.delenv(_PI_SDK_ROOT_ENV, raising=False)
    wrapper_path = package_root / "shim" / "pi"
    wrapper_path.parent.mkdir()
    wrapper_path.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    monkeypatch.setattr(shutil, "which", lambda name: str(wrapper_path) if name == "pi" else None)

    assert _pi_runner_module() is None


def test_generated_input_resume_guard_condition_is_closed(tmp_path: Path) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="pi",
        display_name="fixture",
    )
    assert re.search(
        r"if \(\n"
        r"      !requestId \|\|\n"
        r"      binding === null \|\|\n"
        r"      !inputApprovalResumeBindingIsActive\(ctx, binding\)\n"
        r"    \) return;",
        source,
    )


@pytest.mark.parametrize("harness", ("pi", "omp"))
def test_generated_extension_is_typescript_parseable(tmp_path: Path, harness: str) -> None:
    node = _node_executable()
    if node is None:
        pytest.skip("Node is required to parse the generated extension")
    extension_path = tmp_path / f"hol-guard-{harness}.ts"
    extension_path.write_text(
        managed_extension_source(
            guard_home=tmp_path / "guard-home",
            home_dir=tmp_path,
            settings_path=tmp_path / "settings.json",
            harness=harness,
            display_name="fixture",
        ),
        encoding="utf-8",
    )
    _run_child(
        [node, "--experimental-strip-types", "--check", str(extension_path)],
        timeout=10,
    )


def test_generated_snapshot_preserves_proto_data_and_rejects_empty_session(tmp_path: Path) -> None:
    node = _node_executable()
    if node is None:
        pytest.skip("Node is required to execute generated helpers")
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="fixture",
    )
    start = source.index("function canonicalJson")
    end = source.index("function approvalContinuationFailureReason", start)
    helper_source = source[start:end]
    harness_path = tmp_path / "snapshot-helpers.ts"
    script = f"""
{helper_source}
const protoInput = JSON.parse('{{"__proto__":{{"marker":"kept"}},"path":"original.txt"}}');
const protoCanonical = canonicalJson(protoInput);
const protoParsed = JSON.parse(protoCanonical);
const event = {{ toolCallId: 'call-fixture', toolName: 'read', input: {{ path: 'original.txt' }} }};
const emptySession = snapshotToolCall(event, {{
  sessionManager: {{ getCwd: () => '/fixture/workspace', getSessionId: () => '' }},
}}, '/fixture/settings.json');
const validSession = snapshotToolCall(event, {{
  sessionManager: {{ getCwd: () => '/fixture/workspace', getSessionId: () => 'session-fixture' }},
}}, '/fixture/settings.json');
console.log(JSON.stringify({{
  protoOwn: Object.prototype.hasOwnProperty.call(protoParsed, '__proto__'),
  protoCanonical: protoCanonical.includes('"__proto__"'),
  protoMarker: protoParsed.__proto__.marker,
  emptySessionRejected: emptySession === null,
  validSessionAccepted: validSession !== null,
}}));
"""
    harness_path.write_text(script, encoding="utf-8")
    completed = _run_child(
        [node, "--experimental-strip-types", str(harness_path)],
        timeout=10,
    )
    assert _decode_json_object(completed.stdout) == {
        "protoOwn": True,
        "protoCanonical": True,
        "protoMarker": "kept",
        "emptySessionRejected": True,
        "validSessionAccepted": True,
    }
