"""The verifier key is provisioned by the native runtime, never by Python.

The resident refuses to serve until the key exists, so provisioning is a
one-shot runtime arm rather than a resident call. These tests hold the Python
side to being transport: it supplies the master on stdin, reports the code the
runtime printed, and never derives, writes or compares a key itself.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_windows_key as route
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.codex_hook_launch_runtime import BoundedHookProcessResult
from codex_plugin_scanner.guard.native_policy_snapshot_constants import (
    NATIVE_POLICY_VERIFIER_KEY_NAME,
    NATIVE_RUNTIME_STATE_DIRECTORY,
    NativePolicySnapshotError,
)
from codex_plugin_scanner.guard.native_runtime_values import (
    NativeRuntimeCapabilities,
    NativeRuntimeIdentity,
    NativeRuntimeStatus,
)

MASTER = b"m" * 32


@pytest.fixture(autouse=True)
def _forget_memo() -> None:
    route._forget_provisioned()
    yield
    route._forget_provisioned()


def _status(*, features: tuple[str, ...] = (route._PROVISION_FEATURE,), available: bool = True) -> NativeRuntimeStatus:
    return NativeRuntimeStatus(
        mode="force",
        available=available,
        compatible=True,
        reason="",
        identity=NativeRuntimeIdentity(path=Path("/opt/hol-guard-runtime"), size=1, mtime_ns=1, sha256="a" * 64),
        capabilities=NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="0.0.0",
            rule_digest="b" * 64,
            build_sha="c" * 40,
            target="test",
            features=features,
        ),
    )


def _reply(status: str = "created") -> str:
    return json.dumps({"schema": route._PROVISION_SCHEMA, "status": status})


def _ok(stdout: str) -> BoundedHookProcessResult:
    return BoundedHookProcessResult(returncode=0, stdout=stdout, output_limit_exceeded=False, timed_out=False)


def _failure(stderr: str) -> BoundedHookProcessResult:
    return BoundedHookProcessResult(
        returncode=2,
        stdout="",
        output_limit_exceeded=False,
        timed_out=False,
        stderr=stderr,
    )


def _install(
    monkeypatch: pytest.MonkeyPatch,
    calls: list[tuple[Path, tuple[str, ...], str]],
    results: list[BoundedHookProcessResult],
    *,
    status: NativeRuntimeStatus | None = None,
) -> None:
    def run(path: Path, args: tuple[str, ...], *, input_text: str, **_kwargs: object) -> BoundedHookProcessResult:
        calls.append((path, args, input_text))
        result = results.pop(0)
        if result.returncode == 0:
            # The real runtime leaves the key behind, and the memo stands for
            # the file it wrote, so a fake that writes nothing would make every
            # repeat look like a first provisioning.
            state_dir = Path(args[-1])
            state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            (state_dir / NATIVE_POLICY_VERIFIER_KEY_NAME).write_bytes(b"k" * 32)
        return result

    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: status or _status())
    monkeypatch.setattr(native_runtime, "_run_native_process_result", run)


def test_the_master_reaches_the_runtime_on_stdin_and_never_on_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    calls: list[tuple[Path, tuple[str, ...], str]] = []
    _install(monkeypatch, calls, [_ok(_reply())])

    key_path = route.provision_native_policy_verifier_key(guard_home, MASTER)

    state_dir = guard_home / NATIVE_RUNTIME_STATE_DIRECTORY
    assert key_path == state_dir / NATIVE_POLICY_VERIFIER_KEY_NAME
    assert len(calls) == 1
    path, args, input_text = calls[0]
    assert path == Path("/opt/hol-guard-runtime")
    assert args == ("provision-verifier-key", "--stdin", str(state_dir))
    assert json.loads(input_text) == {"policy_integrity_key": MASTER.hex()}
    assert MASTER.hex() not in " ".join(args)


def test_a_repeat_for_the_same_master_does_not_launch_the_runtime_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    calls: list[tuple[Path, tuple[str, ...], str]] = []
    _install(monkeypatch, calls, [_ok(_reply())])

    first = route.provision_native_policy_verifier_key(guard_home, MASTER)
    second = route.provision_native_policy_verifier_key(guard_home, MASTER)

    assert first == second
    assert len(calls) == 1


def test_a_key_replaced_behind_the_memo_is_sent_back_to_the_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A remembered success must not answer for a file nothing has checked.

    Python never reads the key, so the only honest way to notice a replacement
    is to stop standing for the old file and let the native provisioner look at
    the new one.
    """

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    calls: list[tuple[Path, tuple[str, ...], str]] = []
    _install(monkeypatch, calls, [_ok(_reply()), _failure("native_policy_verifier_key_mismatch\n")])

    key_path = route.provision_native_policy_verifier_key(guard_home, MASTER)
    key_path.write_bytes(b"x" * 48)

    with pytest.raises(NativePolicySnapshotError, match="native_policy_verifier_key_mismatch"):
        route.provision_native_policy_verifier_key(guard_home, MASTER)

    assert len(calls) == 2


def test_a_key_removed_behind_the_memo_is_sent_back_to_the_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    calls: list[tuple[Path, tuple[str, ...], str]] = []
    _install(monkeypatch, calls, [_ok(_reply()), _ok(_reply())])

    key_path = route.provision_native_policy_verifier_key(guard_home, MASTER)
    key_path.unlink()

    route.provision_native_policy_verifier_key(guard_home, MASTER)

    assert len(calls) == 2


def test_a_changed_master_is_always_sent_back_to_the_runtime(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    calls: list[tuple[Path, tuple[str, ...], str]] = []
    _install(monkeypatch, calls, [_ok(_reply()), _failure("native_policy_verifier_key_mismatch\n")])

    route.provision_native_policy_verifier_key(guard_home, MASTER)
    with pytest.raises(NativePolicySnapshotError, match="native_policy_verifier_key_mismatch"):
        route.provision_native_policy_verifier_key(guard_home, b"n" * 32)

    assert len(calls) == 2


def test_the_runtime_error_code_is_reported_verbatim(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    calls: list[tuple[Path, tuple[str, ...], str]] = []
    _install(monkeypatch, calls, [_failure("native_policy_verifier_key_not_private\n")])

    with pytest.raises(NativePolicySnapshotError) as error:
        route.provision_native_policy_verifier_key(guard_home, MASTER)

    assert str(error.value) == "native_policy_verifier_key_not_private"


def test_a_failure_that_prints_no_usable_code_still_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    calls: list[tuple[Path, tuple[str, ...], str]] = []
    _install(monkeypatch, calls, [_failure("Segmentation fault: 11\n")])

    with pytest.raises(NativePolicySnapshotError) as error:
        route.provision_native_policy_verifier_key(guard_home, MASTER)

    assert str(error.value) == "native_policy_verifier_provision_failed"


@pytest.mark.parametrize(
    "stdout",
    ["", "not json", json.dumps({"schema": "other", "status": "created"}), _reply("replaced")],
)
def test_an_unrecognized_reply_is_not_treated_as_provisioned(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stdout: str
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    calls: list[tuple[Path, tuple[str, ...], str]] = []
    _install(monkeypatch, calls, [_ok(stdout), _ok(stdout)])

    with pytest.raises(NativePolicySnapshotError, match="native_policy_verifier_provision_failed"):
        route.provision_native_policy_verifier_key(guard_home, MASTER)
    # A rejected reply must not be remembered, or one bad launch would hide
    # every later attempt behind a key that was never written.
    with pytest.raises(NativePolicySnapshotError):
        route.provision_native_policy_verifier_key(guard_home, MASTER)
    assert len(calls) == 2


@pytest.mark.parametrize(
    "status",
    [
        _status(available=False),
        _status(features=()),
        _status(features=("native-workspace-review-enrollment-resident-v1",)),
    ],
)
def test_a_runtime_that_cannot_provision_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: NativeRuntimeStatus
) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(mode=0o700)
    calls: list[tuple[Path, tuple[str, ...], str]] = []
    _install(monkeypatch, calls, [], status=status)

    with pytest.raises(NativePolicySnapshotError, match="native_policy_verifier_runtime_unavailable"):
        route.provision_native_policy_verifier_key(guard_home, MASTER)

    assert calls == []
