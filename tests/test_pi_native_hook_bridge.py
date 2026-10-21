"""The generated Pi extension's native hook bridge selection and reply reader."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import native_hook_bridge
from codex_plugin_scanner.guard.adapters._modules.pi.pi_extension_native_hook import (
    PI_HOOK_BRIDGE_FEATURE,
    PI_HOOK_BRIDGE_SWITCH,
    native_hook_reply_source,
    native_hook_runtime_source,
    pi_native_hook_runtime,
)
from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from tests.test_pi_hook_latency import _bun_executable, _decode_json_object

pytestmark = pytest.mark.native_pi_hook_bridge

RUNTIME = Path("/opt/hol-guard/hol-guard-runtime")


@pytest.fixture
def advertised_runtime(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Path | None]]:
    """A native runtime that advertises only the Pi hook bridge."""

    calls: list[tuple[str, Path | None]] = []

    def executable(feature: str, *, guard_home: Path | None = None) -> Path | None:
        calls.append((feature, guard_home))
        return RUNTIME if feature == PI_HOOK_BRIDGE_FEATURE else None

    monkeypatch.delenv(PI_HOOK_BRIDGE_SWITCH, raising=False)
    monkeypatch.setattr(native_hook_bridge, "native_hook_bridge_executable", executable)
    return calls


def test_extension_spawns_the_runtime_that_advertises_the_pi_bridge(
    tmp_path: Path,
    advertised_runtime: list[tuple[str, Path | None]],
) -> None:
    assert pi_native_hook_runtime(guard_home=tmp_path, platform_name="posix") == RUNTIME
    assert advertised_runtime == [(PI_HOOK_BRIDGE_FEATURE, tmp_path)]
    assert native_hook_runtime_source(json.dumps(str(tmp_path))) == (
        f"const GUARD_NATIVE_HOOK_RUNTIME: string | null = {json.dumps(str(RUNTIME))};\n"
    )


def test_windows_and_the_fetch_switch_keep_the_daemon_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    advertised_runtime: list[tuple[str, Path | None]],
) -> None:
    assert pi_native_hook_runtime(guard_home=tmp_path, platform_name="nt") is None
    monkeypatch.setenv(PI_HOOK_BRIDGE_SWITCH, "fetch")
    assert pi_native_hook_runtime(guard_home=tmp_path, platform_name="posix") is None
    assert native_hook_runtime_source(json.dumps(str(tmp_path))) == (
        "const GUARD_NATIVE_HOOK_RUNTIME: string | null = null;\n"
    )
    assert advertised_runtime == []


def test_a_runtime_without_the_pi_bridge_is_not_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PI_HOOK_BRIDGE_SWITCH, raising=False)
    monkeypatch.setattr(native_hook_bridge, "native_hook_bridge_executable", lambda *_args, **_kwargs: None)

    assert pi_native_hook_runtime(guard_home=tmp_path, platform_name="posix") is None


@pytest.mark.skipif(os.name == "nt", reason="Generated Pi sources only name the native runtime on POSIX")
@pytest.mark.usefixtures("advertised_runtime")
@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_generated_extension_asks_the_bridge_for_its_own_harness(tmp_path: Path, harness: str) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness=harness,
        display_name="Oh My Pi" if harness == "omp" else "Pi",
    )

    assert f"const GUARD_NATIVE_HOOK_RUNTIME: string | null = {json.dumps(str(RUNTIME))};" in source
    assert f"const GUARD_NATIVE_HOOK_HARNESS = {json.dumps(harness)};" in source
    assert "spawn(runtime, ['pi-hook-bridge', config]" in source
    decision_path = source.split("async function runGuard(", 1)[1]
    assert "runGuardCliCommand(" not in decision_path


def _bridge_harness(tmp_path: Path, runtime: Path | None) -> Path:
    """A Bun module exposing the generated reply reader with `runtime`."""

    harness = tmp_path / "bridge.ts"
    _ = harness.write_text(
        "import { spawn } from 'node:child_process';\n"
        "const GUARD_MAX_SERIALIZED_RESPONSE_CHARS = 1024;\n"
        f"const GUARD_HOME = {json.dumps(str(tmp_path))};\n"
        "const GUARD_NATIVE_HOOK_RUNTIME: string | null = "
        f"{json.dumps(None if runtime is None else str(runtime))};\n"
        "function guardCliProcessErrorCode(error: unknown): string | null {\n"
        "  return typeof error === 'object' && error !== null && 'code' in error &&\n"
        "    typeof error.code === 'string' ? error.code : null;\n"
        "}\n"
        + native_hook_reply_source("omp")
        + "const reply = await nativeGuardReply('guard-home=%2Fh&workspace=%2Fw', '{\"a\":1}', 400);\n"
        "const body = reply ? await reply.readBody(1024) : undefined;\n"
        "console.log(JSON.stringify({\n"
        "  kind: reply === undefined ? 'unused' : reply === null ? 'failed' : 'reply',\n"
        "  status: reply ? reply.status : null,\n"
        "  body: body ?? null,\n"
        "}));\n",
        encoding="utf-8",
    )
    return harness


def _fake_runtime(tmp_path: Path, script: str) -> Path:
    runtime = tmp_path / "hol-guard-runtime"
    _ = runtime.write_text(f"#!/bin/sh\n{script}\n", encoding="utf-8")
    runtime.chmod(0o755)
    return runtime


def _run_bridge(tmp_path: Path, runtime: Path | None) -> dict[str, object]:
    bun = _bun_executable()
    assert bun is not None
    completed = subprocess.run(
        [bun, str(_bridge_harness(tmp_path, runtime))],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "BRIDGE_CAPTURE": str(tmp_path / "capture")},
    )
    return _decode_json_object(completed.stdout)


@pytest.mark.skipif(
    _bun_executable() is None or os.name != "posix",
    reason="Bun and a POSIX shell are required to run the generated bridge reader",
)
class TestNativeReplyReader:
    def test_reply_line_becomes_the_daemon_response(self, tmp_path: Path) -> None:
        runtime = _fake_runtime(
            tmp_path,
            'printf "%s\\n" "$1" > "$BRIDGE_CAPTURE.argv"\n'
            'printf "%s\\n" "$2" >> "$BRIDGE_CAPTURE.argv"\n'
            'cat > "$BRIDGE_CAPTURE.stdin"\n'
            'printf \'{"status":403,"body":"{\\\\"error\\\\":\\\\"forbidden\\\\"}"}\\n\'',
        )

        result = _run_bridge(tmp_path, runtime)

        assert result == {"kind": "reply", "status": 403, "body": '{"error":"forbidden"}'}
        command, config = (tmp_path / "capture.argv").read_text(encoding="utf-8").splitlines()
        assert command == "pi-hook-bridge"
        assert json.loads(config) == {
            "harness": "omp",
            "guard_home": str(tmp_path),
            "query": "guard-home=%2Fh&workspace=%2Fw",
            "timeout_ms": 400,
        }
        assert (tmp_path / "capture.stdin").read_text(encoding="utf-8") == '{"a":1}\n'

    @pytest.mark.parametrize(
        "script",
        [
            "cat >/dev/null; printf '{\"status\":0}\\n'",
            'cat >/dev/null; printf \'{"status":200,"body":"ok"}\\n\'; exit 3',
            "cat >/dev/null; printf 'not json\\n'",
            "cat >/dev/null; sleep 5",
        ],
        ids=["no-reply", "nonzero-exit", "garbled", "past-deadline"],
    )
    def test_anything_but_a_reply_is_a_transport_failure(self, tmp_path: Path, script: str) -> None:
        result = _run_bridge(tmp_path, _fake_runtime(tmp_path, script))

        assert result == {"kind": "failed", "status": None, "body": None}

    def test_a_runtime_that_cannot_start_falls_back_to_the_daemon_request(self, tmp_path: Path) -> None:
        assert _run_bridge(tmp_path, tmp_path / "missing-runtime")["kind"] == "unused"
        assert _run_bridge(tmp_path, None)["kind"] == "unused"


def _budget_harness(tmp_path: Path, runtime: Path | None) -> Path:
    harness = tmp_path / "budget.ts"
    _ = harness.write_text(
        "import { spawn } from 'node:child_process';\n"
        "const GUARD_MAX_SERIALIZED_RESPONSE_CHARS = 1024;\n"
        f"const GUARD_HOME = {json.dumps(str(tmp_path))};\n"
        "const GUARD_NATIVE_HOOK_RUNTIME: string | null = "
        f"{json.dumps(None if runtime is None else str(runtime))};\n"
        + native_hook_reply_source("omp")
        + "console.log(JSON.stringify([[3100, 4000], [3100, 1000], [150, 4000], [5, 1]].map(\n"
        "  ([budget, remaining]) => nativeGuardBudgetMs(budget, remaining))));\n",
        encoding="utf-8",
    )
    return harness


@pytest.mark.skipif(
    _bun_executable() is None or os.name == "nt",
    reason="Bun is required, and Windows keeps the daemon request instead of the bridge",
)
@pytest.mark.parametrize(
    ("runtime", "expected"),
    [(RUNTIME, [2800, 700, 150, 1]), (None, [3100, 3100, 150, 5])],
    ids=["bridge", "fetch"],
)
def test_bridge_uses_at_most_seventy_percent_of_the_remaining_hook_time(
    tmp_path: Path, runtime: Path | None, expected: list[int]
) -> None:
    bun = _bun_executable()
    assert bun is not None
    completed = subprocess.run(
        [bun, str(_budget_harness(tmp_path, runtime))],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert json.loads(completed.stdout) == expected


@pytest.mark.usefixtures("advertised_runtime")
def test_generated_extension_caps_the_bridge_daemon_budget(tmp_path: Path) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="Oh My Pi",
    )

    request = source.split("async function daemonGuardResponse(", 1)[1].split("\n}\n", 1)[0]
    assert "const bridgeBudgetMs = nativeGuardBudgetMs(budgetMs, remainingMs);" in request
    assert "payloadWithBudget(bridgeBudgetMs),\n    bridgeBudgetMs," in request
    # A direct daemon post after the bridge is unavailable keeps the full budget.
    assert "const daemonPayload = payloadWithBudget(budgetMs);" in request
    assert "body: daemonPayload," in request
