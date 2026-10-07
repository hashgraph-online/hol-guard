from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.package_intent import (
    extract_package_intent_request,
    parse_package_intent,
)
from tests.package_intent_fixtures import (
    _native_package_intent,  # noqa: F401 -- registers the module autouse fixture
    _write_text,
)


def test_parse_package_intent_reviews_declared_local_test_runner_execution(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo","devDependencies":{"vitest":"^4.1.8"}}\n')
    _write_text(tmp_path / "bun.lock", '"vitest": "4.1.8"\n')
    runner = tmp_path / "node_modules" / ".bin" / "vitest"
    _write_text(runner, "#!/bin/sh\n")
    runner.chmod(0o755)

    assert parse_package_intent("bunx --no-install vitest run tests/example.test.ts", workspace=tmp_path) is not None
    assert parse_package_intent("npx --no-install vitest --run tests/example.test.ts", workspace=tmp_path) is not None
    assert parse_package_intent("bunx vitest --run tests/example.test.ts", workspace=tmp_path) is not None
    assert parse_package_intent("bunx vitest --help", workspace=tmp_path) is not None
    assert parse_package_intent("bunx vitest --no-install", workspace=tmp_path) is not None
    assert (
        extract_package_intent_request(
            "Bash",
            {"command": "bunx --no-install vitest run tests/example.test.ts"},
            action_envelope_command="bunx --no-install vitest run tests/example.test.ts",
            workspace=tmp_path,
        )
        is not None
    )


def test_parse_package_intent_records_guard_shimmed_bunx_test_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `bunx` resolved to the guard's package-shim is flagged as a shim.

    The resident detects the shim by canonicalizing
    ``$HOME/.hol-guard/package-shims/bin/<command>`` against the resolved
    manager path. ``HOME`` must point at the shim home *before* the resident
    is spawned, and the parse must carry the shim directory on its effective
    PATH. A fresh guard home is provisioned so a new resident is spawned
    under the patched ``HOME`` rather than reusing the session pool.
    """
    from codex_plugin_scanner.guard.native_policy_snapshot import (
        provision_native_policy_verifier_key,
    )
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents

    _write_text(tmp_path / "package.json", '{"name":"demo","devDependencies":{"vitest":"^4.1.8"}}\n')
    _write_text(tmp_path / "bun.lock", '"vitest": "4.1.8"\n')
    runner = tmp_path / "node_modules" / ".bin" / "vitest"
    _write_text(runner, "#!/bin/sh\n")
    runner.chmod(0o755)
    home_dir = tmp_path / "home"
    shim_dir = home_dir / ".hol-guard" / "package-shims" / "bin"
    shim_path = shim_dir / "bunx"
    _write_text(shim_path, "#!/bin/sh\n")
    shim_path.chmod(0o755)
    monkeypatch.setenv("HOME", str(home_dir))

    guard_home = tmp_path / "shim-guard-home"
    (guard_home / "native-runtime").mkdir(mode=0o700, parents=True)
    provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
    try:
        environment = {"PATH": str(shim_dir)}
        intent = parse_package_intent(
            "bunx vitest run tests/example.test.ts",
            workspace=tmp_path,
            guard_home=guard_home,
            environment=environment,
        )
        bun_intent = parse_package_intent(
            "bunx --bun vitest run tests/example.test.ts",
            workspace=tmp_path,
            guard_home=guard_home,
            environment=environment,
        )
    finally:
        close_native_residents(guard_home)

    assert intent is not None
    assert bun_intent is not None
    assert intent.local_executions[0].manager_is_guard_shim is True
    assert bun_intent.local_executions[0].manager_is_guard_shim is True


def test_extract_package_intent_records_guard_shimmed_npx_test_runner_in_pipeline(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo","devDependencies":{"vitest":"^4.1.8"}}\n')
    _write_text(tmp_path / "bun.lock", '"vitest": "4.1.8"\n')
    runner = tmp_path / "node_modules" / ".bin" / "vitest"
    _write_text(runner, "#!/bin/sh\n")
    runner.chmod(0o755)
    command = "cd project && npx vitest run tests/unit.test.tsx 2>&1 | tail -15"

    assert (
        extract_package_intent_request(
            "Bash", {"command": command}, action_envelope_command=command, workspace=tmp_path
        )
        is not None
    )


def test_parse_package_intent_keeps_unverified_or_remote_test_runner_execution_guarded(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo","devDependencies":{"vitest":"^4.1.8"}}\n')
    _write_text(tmp_path / "bun.lock", '"vitest": "4.1.8"\n')
    runner = tmp_path / "node_modules" / ".bin" / "vitest"
    _write_text(runner, "#!/bin/sh\n")
    runner.chmod(0o755)

    assert parse_package_intent("bunx vitest@latest run tests/example.test.ts", workspace=tmp_path) is not None
    assert (
        parse_package_intent("bunx --package vitest vitest run tests/example.test.ts", workspace=tmp_path) is not None
    )
    (tmp_path / "bun.lock").unlink()

    assert parse_package_intent("bunx vitest run tests/example.test.ts", workspace=tmp_path) is not None


def test_parse_package_intent_keeps_local_runner_guarded_without_lockfile_record(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo","devDependencies":{"vitest":"^4.1.8"}}\n')
    _write_text(tmp_path / "bun.lock", "{}\n")
    runner = tmp_path / "node_modules" / ".bin" / "vitest"
    _write_text(runner, "#!/bin/sh\n")
    runner.chmod(0o755)

    assert parse_package_intent("bunx vitest run tests/example.test.ts", workspace=tmp_path) is not None


@pytest.mark.parametrize(
    ("lockfile_name", "lockfile_content"),
    (
        ("bun.lock", '"vitest-helpers": "1.0.0"\n'),
        ("bun.lockb", b"vitest"),
    ),
)
def test_parse_package_intent_keeps_runner_guarded_without_exact_text_lockfile_record(
    tmp_path: Path, lockfile_name: str, lockfile_content: str | bytes
) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo","devDependencies":{"vitest":"^4.1.8"}}\n')
    lockfile_path = tmp_path / lockfile_name
    if isinstance(lockfile_content, bytes):
        lockfile_path.write_bytes(lockfile_content)
    else:
        _write_text(lockfile_path, lockfile_content)
    runner = tmp_path / "node_modules" / ".bin" / "vitest"
    _write_text(runner, "#!/bin/sh\n")
    runner.chmod(0o755)

    assert parse_package_intent("bunx vitest run tests/example.test.ts", workspace=tmp_path) is not None


@pytest.mark.skipif(os.name == "nt", reason="Windows supports .cmd local launchers")
def test_parse_package_intent_keeps_non_windows_script_wrapper_guarded(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo","devDependencies":{"vitest":"^4.1.8"}}\n')
    _write_text(tmp_path / "bun.lock", '"vitest": "4.1.8"\n')
    _write_text(tmp_path / "node_modules" / ".bin" / "vitest.cmd", "@echo off\n")

    assert parse_package_intent("bunx vitest run tests/example.test.ts", workspace=tmp_path) is not None


def test_parse_package_intent_reviews_declared_local_jest_and_mocha_runs(tmp_path: Path) -> None:
    _write_text(
        tmp_path / "package.json",
        '{"name":"demo","peerDependencies":{"jest":"^30.0.0"},"devDependencies":{"mocha":"^11.0.0"}}\n',
    )
    _write_text(
        tmp_path / "package-lock.json",
        '{"packages":{"node_modules/jest":{"version":"30.0.0"},"node_modules/mocha":{"version":"11.0.0"}}}\n',
    )
    for runner_name in ("jest", "mocha"):
        runner = tmp_path / "node_modules" / ".bin" / runner_name
        _write_text(runner, "#!/bin/sh\n")
        runner.chmod(0o755)

    assert parse_package_intent("npx --no-install jest tests/unit.test.js", workspace=tmp_path) is not None
    assert parse_package_intent("bunx --no-install mocha test/unit.test.js", workspace=tmp_path) is not None


def test_parse_package_intent_reviews_declared_local_executable(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo","devDependencies":{"eslint":"^9.0.0"}}\n')
    _write_text(tmp_path / "bun.lock", '"eslint": "9.0.0"\n')
    executable = tmp_path / "node_modules" / ".bin" / "eslint"
    _write_text(executable, "#!/bin/sh\n")
    executable.chmod(0o755)

    assert parse_package_intent("bunx --no-install eslint .", workspace=tmp_path) is not None
