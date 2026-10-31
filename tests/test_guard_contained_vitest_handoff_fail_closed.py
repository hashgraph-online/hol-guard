from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import contained_node_execution, native_execution

_REFUSAL = "HOL Guard refused uncontained Vitest execution: sandbox startup or enforcement proof failed"


def _resident_replies(monkeypatch: pytest.MonkeyPatch, refusal: str | None) -> None:
    """Resident that ran no contained Vitest launch (sandbox or proof unavailable)."""

    def resident(**_kwargs: object) -> dict[str, object]:
        return {"schema": "guard-contained-node-execute-result.v2", "result": None, "refusal": refusal}

    monkeypatch.setattr(native_execution, "_resident_request", resident)


def _launch(tmp_path: Path, shim_directory: Path) -> object:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return contained_node_execution.try_execute_contained_node_command(
        "bunx",
        ("vitest", "run", "tests/unit.test.ts"),
        workspace=workspace,
        guard_home=tmp_path / "guard-home",
        shim_directory=shim_directory,
        environment={"PATH": "/usr/bin"},
    )


def test_installed_package_shim_stops_vitest_when_the_resident_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shim_directory = tmp_path / "guard-home" / "package-shims" / "bin"
    shim_directory.mkdir(parents=True)
    _resident_replies(monkeypatch, _REFUSAL)

    with pytest.raises(SystemExit) as stopped:
        _launch(tmp_path, shim_directory)
    assert stopped.value.code == _REFUSAL


def test_vitest_returns_to_review_when_the_resident_returns_no_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shim_directory = tmp_path / "bin"
    shim_directory.mkdir()
    _resident_replies(monkeypatch, None)

    assert _launch(tmp_path, shim_directory) is None


def _resident_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resident that never answers: a transport failure, an older schema or a missing feature."""

    def resident(**_kwargs: object) -> None:
        return None

    monkeypatch.setattr(native_execution, "_resident_request", resident)


def test_installed_package_shim_stops_vitest_when_the_resident_gives_no_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shim_directory = tmp_path / "guard-home" / "package-shims" / "bin"
    shim_directory.mkdir(parents=True)
    _resident_unavailable(monkeypatch)

    with pytest.raises(SystemExit) as stopped:
        _launch(tmp_path, shim_directory)
    assert "refused uncontained Vitest execution" in str(stopped.value.code)


def test_installed_package_shim_stops_vitest_when_the_result_is_undecodable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shim_directory = tmp_path / "guard-home" / "package-shims" / "bin"
    shim_directory.mkdir(parents=True)

    def resident(**_kwargs: object) -> dict[str, object]:
        return {"schema": "guard-contained-node-execute-result.v2", "result": "not-a-result", "refusal": None}

    monkeypatch.setattr(native_execution, "_resident_request", resident)

    with pytest.raises(SystemExit):
        _launch(tmp_path, shim_directory)


def test_other_shim_returns_to_review_when_the_resident_gives_no_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shim_directory = tmp_path / "bin"
    shim_directory.mkdir()
    _resident_unavailable(monkeypatch)

    assert _launch(tmp_path, shim_directory) is None
