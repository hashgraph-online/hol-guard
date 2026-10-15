"""The packaged runtime answers every source-compiler operation byte-for-byte.

``guard-command-source`` stays a standalone build-time binary, while the wheel
ships only ``hol-guard-runtime``. These tests run both executables from one
build over the same inputs and require identical stdout bytes and exit codes.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_EXAMPLE_SOURCE = ROOT / "rust/crates/guard-command/tests/fixtures/command-source-example.v1.json"
_BEHAVIOR_FIXTURES = ROOT / "rust/crates/guard-command/tests/fixtures/command-source-behavior.v1.json"


def _binary(environment_name: str, filename: str) -> Path:
    configured = os.environ.get(environment_name)
    if configured and Path(configured).is_file():
        return Path(configured)
    for profile in ("release", "debug"):
        candidate = ROOT / "rust" / "target" / profile / filename
        if candidate.is_file():
            return candidate
        windows_candidate = candidate.with_name(candidate.name + ".exe")
        if windows_candidate.is_file():
            return windows_candidate
    pytest.skip(f"native {filename} is not available (set {environment_name})")


@pytest.fixture(scope="module")
def runtime() -> Path:
    return _binary("HOL_GUARD_NATIVE_BINARY", "hol-guard-runtime")


@pytest.fixture(scope="module")
def compiler() -> Path:
    return _binary("HOL_GUARD_NATIVE_SOURCE_COMPILER", "guard-command-source")


def _invoke(binary: Path, arguments: list[str], payload: bytes) -> tuple[int, bytes, bytes]:
    completed = subprocess.run(
        [str(binary), *arguments],
        input=payload,
        capture_output=True,
        timeout=120,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def _assert_same(
    runtime: Path,
    compiler: Path,
    arguments: list[str],
    payload: bytes,
) -> tuple[int, bytes, bytes]:
    expected = _invoke(compiler, arguments, payload)
    actual = _invoke(runtime, arguments, payload)
    assert actual == expected, (
        f"{arguments}: runtime {actual[0]}/{actual[1][:200]!r} vs compiler {expected[0]}/{expected[1][:200]!r}"
    )
    assert actual[2] == expected[2]
    return actual


@pytest.fixture(scope="module")
def build_request(compiler: Path) -> dict[str, object]:
    # The trust map is a generated artifact; ask the compiler to export the
    # exact bytes it embeds instead of reading the checkout.
    code, stdout, stderr = _invoke(compiler, ["export-trust"], b"")
    assert code == 0, stderr
    return {
        "schema": "guard.command-extension-build.v1",
        "sources": [json.loads(_EXAMPLE_SOURCE.read_text(encoding="utf-8"))],
        "mcp_sources": [],
        "trust": json.loads(stdout),
        "base": "packaged",
    }


@pytest.mark.parametrize(
    "arguments",
    [
        ["export-trust"],
        ["export-built"],
        ["schema"],
        ["descriptor-schema"],
        ["validate"],
        ["compile"],
        ["check", "0" * 64],
        ["check", "not-a-digest"],
        ["check", "Z" * 64],
    ],
)
def test_runtime_hosts_argument_only_operations(
    runtime: Path, compiler: Path, build_request: dict[str, object], arguments: list[str]
) -> None:
    payload = json.dumps(build_request).encode() if arguments[0] in {"validate", "compile", "check"} else b""
    _assert_same(runtime, compiler, arguments, payload)


def test_runtime_check_accepts_the_compiled_program_digest(
    runtime: Path, compiler: Path, build_request: dict[str, object]
) -> None:
    payload = json.dumps(build_request).encode()
    code, stdout, _ = _assert_same(runtime, compiler, ["compile"], payload)
    assert code == 0
    digest = json.loads(stdout)["program"]["program_digest"]
    _assert_same(runtime, compiler, ["check", digest], payload)


def test_runtime_hosts_fixture_simulation(runtime: Path, compiler: Path, build_request: dict[str, object]) -> None:
    fixtures = json.loads(_BEHAVIOR_FIXTURES.read_text(encoding="utf-8"))
    fixtures["build"] = build_request
    _assert_same(runtime, compiler, ["test"], json.dumps(fixtures).encode())
    fixtures["cases"][0]["expected_action"] = "allow"
    _assert_same(runtime, compiler, ["test"], json.dumps(fixtures).encode())


def test_runtime_hosts_program_parity(runtime: Path, compiler: Path, build_request: dict[str, object]) -> None:
    build = build_request
    code, stdout, _ = _assert_same(runtime, compiler, ["compile"], json.dumps(build).encode())
    assert code == 0
    request = {
        "schema": "guard.command-extension-parity.v1",
        "baseline_program": json.loads(stdout)["program"],
        "build": build,
        "cases": [{"id": "one", "payload": {"tool_input": {"command": "git status"}}, "controls": []}],
    }
    _assert_same(runtime, compiler, ["compare"], json.dumps(request).encode())


def test_runtime_hosts_evaluation_batch(runtime: Path, compiler: Path) -> None:
    request = {
        "schema": "guard.command-extension-evaluation-batch.v1",
        "cases": [{"id": "embedded-identity", "command": "pwd"}],
    }
    _assert_same(runtime, compiler, ["evaluate-batch"], json.dumps(request).encode())


@pytest.mark.parametrize(
    "payload",
    [
        b'{"args": ["gh", "pr", "view", "7"]}',
        b'{"args": "not-a-list"}',
        b"garbage{{{",
        b"",
    ],
)
def test_runtime_hosts_github_classify(runtime: Path, compiler: Path, payload: bytes) -> None:
    _assert_same(runtime, compiler, ["github-classify"], payload)


def test_runtime_hosts_github_classify_serve(runtime: Path, compiler: Path) -> None:
    lines = [
        b'{"args": ["gh", "pr", "view", "7"]}',
        b'{"args": "not-a-list"}',
        b"garbage",
    ]
    expected = subprocess.run(
        [str(compiler), "github-classify-serve"],
        input=b"\n".join(lines) + b"\n",
        capture_output=True,
        timeout=60,
        check=False,
    )
    actual = subprocess.run(
        [str(runtime), "github-classify-serve"],
        input=b"\n".join(lines) + b"\n",
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert (actual.returncode, actual.stdout, actual.stderr) == (
        expected.returncode,
        expected.stdout,
        expected.stderr,
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"{}",
        b'{"schema":1,"schema":2}',
        b"{} {}",
        b"not json",
    ],
)
def test_runtime_preserves_compile_error_envelopes(runtime: Path, compiler: Path, payload: bytes) -> None:
    _assert_same(runtime, compiler, ["compile"], payload)
