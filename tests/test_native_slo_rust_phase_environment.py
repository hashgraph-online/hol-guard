"""Controls for explicit fixture forwarding without production allowlist changes."""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime, native_resident_stream, native_runtime
from scripts import native_slo_rust_phase_environment as forwarding
from scripts.native_slo_rust_phase_receiver import NativePhaseReceiver, supported

pytestmark = pytest.mark.skipif(not supported(), reason="Linux private native phase receiver")


def _providers() -> list[ModuleType]:
    return [importlib.import_module("codex_plugin_scanner.guard." + name) for name in forwarding._PROVIDER_MODULES]


def test_production_environment_providers_drop_all_native_phase_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    fields = dict.fromkeys(forwarding.PHASE_ENVIRONMENT_KEYS, "untrusted")
    for name, value in fields.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("PRIVATE_DIAGNOSTIC_SECRET", "untrusted")
    assert not forwarding.PHASE_ENVIRONMENT_KEYS & native_runtime._isolated_environment().keys()
    for provider in (
        codex_hook_launch_runtime.isolated_hook_environment,
        native_resident_stream.isolated_hook_environment,
    ):
        result = provider({**fields, "HOME": "/tmp", "PRIVATE_DIAGNOSTIC_SECRET": "untrusted"})
        assert result == {"HOME": "/tmp"}


@pytest.mark.parametrize("raise_in_fixture", [False, True])
def test_forwarding_preserves_real_filters_adds_attested_fields_and_restores_every_alias(
    monkeypatch: pytest.MonkeyPatch, raise_in_fixture: bool
) -> None:
    runtime = Path(sys.executable).resolve()
    receiver = NativePhaseReceiver(runtime)
    modules = _providers()
    before = [module._isolated_environment for module in modules]
    stream_before = native_resident_stream.isolated_hook_environment
    launch_before = codex_hook_launch_runtime.isolated_hook_environment
    identities: list[Path] = []
    monkeypatch.setattr(forwarding, "_installed_identity", lambda path, _executable: identities.append(path))
    monkeypatch.setenv("PRIVATE_DIAGNOSTIC_SECRET", "private")
    original_environment = native_runtime._isolated_environment()
    fields = receiver.environment()
    try:
        with forwarding.forward_native_phase_environment(runtime, fields):
            assert identities == [runtime]
            for module in modules:
                assert module._isolated_environment() == {**original_environment, **fields}
            source = {"HOME": "/tmp", "PRIVATE_DIAGNOSTIC_SECRET": "private", **dict.fromkeys(fields, "untrusted")}
            assert native_resident_stream.isolated_hook_environment(source) == {"HOME": "/tmp", **fields}
            assert codex_hook_launch_runtime.isolated_hook_environment is launch_before
            assert codex_hook_launch_runtime.isolated_hook_environment(source) == {"HOME": "/tmp"}
            if raise_in_fixture:
                raise RuntimeError("controlled fixture body failure")
    except RuntimeError as error:
        assert raise_in_fixture and str(error) == "controlled fixture body failure"
    finally:
        receiver.close()
    assert [module._isolated_environment for module in modules] == before
    assert native_resident_stream.isolated_hook_environment is stream_before


@pytest.mark.parametrize("failure", ["extra_key", "missing_key", "wrong_inode", "wrong_mode"])
def test_forwarding_rejects_unattested_environment_before_modifying_providers(failure: str) -> None:
    runtime = Path(sys.executable).resolve()
    receiver = NativePhaseReceiver(runtime)
    original = native_runtime._isolated_environment
    fields = receiver.environment()
    try:
        if failure == "extra_key":
            fields["HOL_GUARD_NATIVE_BINARY"] = "/untrusted"
        elif failure == "missing_key":
            fields.pop("HOL_GUARD_NATIVE_PHASE_DEVICE")
        elif failure == "wrong_inode":
            fields["HOL_GUARD_NATIVE_PHASE_INODE"] = str(int(fields["HOL_GUARD_NATIVE_PHASE_INODE"]) + 1)
        else:
            receiver.path.chmod(0o666)
        with (
            pytest.raises(ValueError, match="native_phase_"),
            forwarding.forward_native_phase_environment(runtime, fields),
        ):
            pytest.fail("unattested diagnostic fields were forwarded")
        assert native_runtime._isolated_environment is original
    finally:
        receiver.close()


def test_setup_failure_closes_executable_and_keeps_original_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = Path(sys.executable).resolve()
    receiver = NativePhaseReceiver(runtime)
    original = native_runtime._isolated_environment
    descriptors: list[int] = []

    def fail_identity(_runtime: Path, executable: forwarding.Executable) -> None:
        descriptors.append(executable.descriptor)
        raise ValueError("controlled installed identity failure")

    monkeypatch.setattr(forwarding, "_installed_identity", fail_identity)
    try:
        with (
            pytest.raises(ValueError, match="controlled installed identity failure"),
            forwarding.forward_native_phase_environment(runtime, receiver.environment()),
        ):
            pytest.fail("unadmitted runtime activated diagnostic forwarding")
        assert native_runtime._isolated_environment is original
        assert len(descriptors) == 1
        with pytest.raises(OSError):
            os.fstat(descriptors[0])
    finally:
        receiver.close()


def test_changed_endpoint_drops_diagnostics_preserves_original_environment_and_restores(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = Path(sys.executable).resolve()
    receiver = NativePhaseReceiver(runtime)
    original = native_runtime._isolated_environment
    monkeypatch.setattr(forwarding, "_installed_identity", lambda *_args: None)
    try:
        with forwarding.forward_native_phase_environment(runtime, receiver.environment()):
            receiver.path.chmod(0o666)
            assert native_runtime._isolated_environment() == original()
            assert native_resident_stream.isolated_hook_environment({"HOME": "/tmp"}) == {"HOME": "/tmp"}
        assert native_runtime._isolated_environment is original
    finally:
        receiver.close()


def test_ordinary_fixture_clears_ambient_overrides_and_requires_explicit_forwarding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receiver = NativePhaseReceiver(Path(sys.executable).resolve())
    try:
        fields = receiver.environment()
        for key, value in {**fields, "HOL_GUARD_NATIVE_BINARY": "/untrusted", "HOL_GUARD_TEST_MODE": "1"}.items():
            monkeypatch.setenv(key, value)
        ordinary = forwarding.fixture_environment(None)
        assert not forwarding.PHASE_ENVIRONMENT_KEYS & ordinary.keys()
        diagnostic = forwarding.fixture_environment(fields)
        assert diagnostic == {**ordinary, **fields}
        for environment in (ordinary, diagnostic):
            assert "HOL_GUARD_NATIVE_BINARY" not in environment and "HOL_GUARD_TEST_MODE" not in environment
        original = native_runtime._isolated_environment
        with forwarding.native_phase_fixture(Path("unused"), enabled=False):
            assert native_runtime._isolated_environment is original
            assert not forwarding.PHASE_ENVIRONMENT_KEYS & original().keys()
    finally:
        receiver.close()
