"""Select Windows source evidence using the installed runtime's public contract."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_runtime
from scripts import native_slo_source_witness
from scripts.native_slo_workloads import source_reference_supported

_SOURCE_FEATURE = "post-tool-source-read-windows-handles-v1"


def _ready_status(runtime: Path, *, windows_source: bool = True) -> native_runtime.NativeRuntimeStatus:
    # Runtime capabilities use ARCH-OS, as emitted by resident_protocol.rs and
    # the installed Windows native-wheel job; wheel manifests use Rust triples.
    payload = {
        "protocol_version": 1,
        "runtime_version": "3.0.1",
        "rule_digest": "a" * 64,
        "build_sha": "b" * 40,
        "target": "x86_64-windows",
        "features": ["post-tool-source-read-v1", *([_SOURCE_FEATURE] if windows_source else [])],
    }
    capabilities = native_runtime._decode_capabilities(payload)
    assert capabilities is not None
    return native_runtime.NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="native_ready",
        identity=native_runtime.NativeRuntimeIdentity(runtime, 1, 1, "c" * 64),
        capabilities=capabilities,
    )


@pytest.mark.parametrize("windows_source", [False, True])
def test_actual_windows_capabilities_select_exact_artifact_contract(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, windows_source: bool
) -> None:
    runtime = tmp_path / "hol-guard-runtime.exe"
    status = _ready_status(runtime, windows_source=windows_source)
    monkeypatch.setattr(native_slo_source_witness, "native_runtime_status", lambda: status)

    # Generic source support alone retains the frozen Windows refusal contract.
    assert source_reference_supported(system="Windows", runtime=runtime) is windows_source


@pytest.mark.parametrize("target", ["x86_64-linux", "aarch64-windows", "x86_64-pc-windows-msvc"])
def test_source_selection_requires_public_windows_runtime_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, target: str
) -> None:
    runtime = tmp_path / "hol-guard-runtime.exe"
    status = _ready_status(runtime)
    assert status.capabilities is not None
    status = replace(status, capabilities=replace(status.capabilities, target=target))
    monkeypatch.setattr(native_slo_source_witness, "native_runtime_status", lambda: status)

    with pytest.raises(RuntimeError, match="runtime identity is not bound"):
        _ = source_reference_supported(system="Windows", runtime=runtime)
