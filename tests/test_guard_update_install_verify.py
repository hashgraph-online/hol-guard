"""Post-install distribution verification contracts for HOL Guard updates."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli import update_commands
from codex_plugin_scanner.guard.cli.update_install_verify import (
    verify_installed_distribution,
)
from codex_plugin_scanner.guard.cli.update_subprocess import (
    TrustedProcessResult,
    TrustedUpdateContext,
    UpdateSubprocessError,
)


def _context_with_distribution_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result: TrustedProcessResult,
) -> TrustedUpdateContext:
    install_prefix = tmp_path / "installed-environment"
    install_prefix.mkdir(exist_ok=True)
    context = cast(
        TrustedUpdateContext,
        SimpleNamespace(
            install_prefix=install_prefix,
            run=lambda command, **_kwargs: result,
            python_command=lambda script: (str(Path.cwd() / "python"), "-c", script),
        ),
    )
    _ = monkeypatch
    return context


def test_distribution_query_parses_code_version_from_version_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "installed-environment" / "site-packages"
    root.mkdir(parents=True)
    result = TrustedProcessResult(
        args=(str(Path.cwd() / "python"),),
        returncode=0,
        stdout=json.dumps(
            {
                "code_source": '"""Single source of truth."""\n\n__version__ = "2.0.0"\n',
                "direct_url": None,
                "name": "hol-guard",
                "root": str(root),
                "version": "2.0.0",
            }
        ),
        stderr="",
    )
    context = _context_with_distribution_result(tmp_path, monkeypatch, result)

    distribution = TrustedUpdateContext.query_distribution(context)

    assert distribution.version == "2.0.0"
    assert distribution.code_version == "2.0.0"


def test_distribution_query_reports_missing_version_source_as_empty(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "installed-environment" / "site-packages"
    root.mkdir(parents=True)
    result = TrustedProcessResult(
        args=(str(Path.cwd() / "python"),),
        returncode=0,
        stdout=json.dumps(
            {
                "code_source": "",
                "direct_url": None,
                "name": "hol-guard",
                "root": str(root),
                "version": "2.0.0",
            }
        ),
        stderr="",
    )
    context = _context_with_distribution_result(tmp_path, monkeypatch, result)

    distribution = TrustedUpdateContext.query_distribution(context)

    assert distribution.code_version == ""


@pytest.mark.parametrize(
    "code_source",
    [
        '__version__ = "not-a-version"',
        7,
    ],
)
def test_distribution_query_rejects_invalid_code_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code_source: object,
) -> None:
    root = tmp_path / "installed-environment" / "site-packages"
    root.mkdir(parents=True)
    result = TrustedProcessResult(
        args=(str(Path.cwd() / "python"),),
        returncode=0,
        stdout=json.dumps(
            {
                "code_source": code_source,
                "direct_url": None,
                "name": "hol-guard",
                "root": str(root),
                "version": "2.0.0",
            }
        ),
        stderr="",
    )
    context = _context_with_distribution_result(tmp_path, monkeypatch, result)

    with pytest.raises(UpdateSubprocessError) as error:
        TrustedUpdateContext.query_distribution(context)

    assert error.value.reason_code == "update_version_output_invalid"


@pytest.mark.parametrize(
    ("code_version", "expected_version"),
    (
        ("2.2.3", "2.2.3"),
        (None, "2.2.3"),
    ),
)
def test_verify_accepts_consistent_or_legacy_probe(
    code_version: str | None,
    expected_version: str,
) -> None:
    distribution = SimpleNamespace(version="2.2.3", code_version=code_version)

    assert (
        verify_installed_distribution(
            cast(TrustedUpdateContext, SimpleNamespace(query_distribution=lambda: distribution)),
        )
        == expected_version
    )


@pytest.mark.parametrize("code_version", ["", "2.2.1"])
def test_verify_rejects_missing_or_mismatched_code_version(code_version: str) -> None:
    distribution = SimpleNamespace(version="2.2.3", code_version=code_version)

    with pytest.raises(UpdateSubprocessError) as error:
        verify_installed_distribution(
            cast(TrustedUpdateContext, SimpleNamespace(query_distribution=lambda: distribution)),
        )

    assert error.value.reason_code == "update_install_inconsistent"


def test_verify_skips_probe_without_code_version_field() -> None:
    distribution = SimpleNamespace(version="2.2.3")

    assert (
        verify_installed_distribution(
            cast(TrustedUpdateContext, SimpleNamespace(query_distribution=lambda: distribution)),
        )
        == "2.2.3"
    )


def test_update_fails_when_installed_code_disagrees_with_version_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.update_context_test_support import (
        build_legacy_status_distribution,
        build_legacy_update_context,
        stage_legacy_wheel,
    )

    monkeypatch.setattr(update_commands, "build_trusted_update_context", build_legacy_update_context)
    monkeypatch.setattr(update_commands, "_status_installed_distribution", build_legacy_status_distribution)
    monkeypatch.setattr(update_commands, "stage_trusted_wheel", stage_legacy_wheel)
    monkeypatch.setattr(update_commands, "_current_version", lambda: "2.2.1")
    monkeypatch.setattr(
        update_commands,
        "_current_version_from_subprocess",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            UpdateSubprocessError(
                "update_install_inconsistent",
                detail="installed code files report 2.2.1 while installed metadata reports 2.2.3",
            )
        ),
    )
    monkeypatch.setattr(update_commands, "_latest_version_from_pypi", lambda: "2.2.3")
    monkeypatch.setattr(update_commands, "_direct_url_payload", lambda: None)
    monkeypatch.setattr(update_commands, "_installer_kind", lambda: "pipx")
    monkeypatch.setattr(
        update_commands.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "installed", ""),
    )
    monkeypatch.setattr(update_commands, "_refresh_package_shims_after_update", lambda **_: (None, None))
    monkeypatch.setattr(update_commands, "_repair_supported_harnesses", lambda **_: ([], []))

    payload, exit_code = update_commands.run_guard_update(dry_run=False)

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert payload["changed"] is False
    assert payload["reason_code"] == "update_install_inconsistent"
    assert "not all of its installed files" in str(payload["message"])
    assert payload["retry_command"] == "hol-guard update"
