"""Caller-side archive fulfilment keeps the aggregate time budget the resident set."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_supply_chain_archive
from codex_plugin_scanner.guard.native_supply_chain_archive import ArchiveFulfilment
from tests.native_archive_fakes import forbid_download, install_download, install_inspection


def _need(aggregate: float) -> dict[str, object]:
    return {
        "url": "https://packages.example.com/demo.tgz",
        "timeout_seconds": 5.0,
        "max_response_bytes": 1024,
        "max_redirects": 2,
        "inspect": {
            "timeout_seconds": 5.0,
            "aggregate_timeout_seconds": aggregate,
            "max_files": 10,
            "max_package_json_bytes": 1024,
        },
    }


@pytest.fixture(autouse=True)
def _permissive_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_supply_chain_archive, "resolved_network_policy", lambda _value: (None, False))
    monkeypatch.setattr(native_supply_chain_archive, "validate_destination", lambda _url, _policy: None)


def test_non_numeric_aggregate_timeout_does_not_download(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    forbid_download(monkeypatch, "download started for a non-numeric timeout")
    fulfilment = ArchiveFulfilment(guard_home=tmp_path, scratch_dir=tmp_path, retain=False)
    need = _need(aggregate=10.0)
    inspect = need["inspect"]
    assert isinstance(inspect, dict)
    inspect["aggregate_timeout_seconds"] = "10"

    with pytest.raises(TypeError, match="archive timeout must be a number"):
        fulfilment.fulfil(need)


def test_current_download_reduces_the_inspection_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = {"now": 1_000.0}
    monkeypatch.setattr(native_supply_chain_archive.time, "monotonic", lambda: clock["now"])
    install_download(monkeypatch, tmp_path)
    download = native_supply_chain_archive.download_restricted_archive

    def slow_download(*args: object, **kwargs: object) -> object:
        clock["now"] += 1.0
        return download(*args, **kwargs)

    monkeypatch.setattr(native_supply_chain_archive, "download_restricted_archive", slow_download)
    timeouts: list[float] = []

    def inspect(_path: Path, **kwargs: object) -> SimpleNamespace:
        timeouts.append(float(kwargs["timeout_seconds"]))
        return SimpleNamespace(
            status="clean",
            code="archive_clean",
            message="Archive inspection found no blocking behavior.",
            severity="info",
        )

    monkeypatch.setattr(native_supply_chain_archive, "inspect_archive_native", inspect)
    fulfilment = ArchiveFulfilment(guard_home=tmp_path, scratch_dir=tmp_path, retain=False)
    fulfilment._elapsed = 5.5

    outcome = fulfilment.fulfil(_need(aggregate=8.0))

    assert outcome["kind"] == "archive"
    assert timeouts == [1.0]


def test_review_evidence_tail_has_one_implementation() -> None:
    from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import (
        _strip_review_evidence_tail as cli_strip,
    )
    from codex_plugin_scanner.guard.runtime.package_request_evaluation import strip_review_evidence_tail

    assert cli_strip is strip_review_evidence_tail
    assert strip_review_evidence_tail("Hold. Review evidence: .") == "Hold."
    assert strip_review_evidence_tail("Hold. Review evidence:") == "Hold."


def test_exhausted_aggregate_budget_fails_before_the_next_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forbid_download(monkeypatch, "download started after the aggregate budget was spent")
    fulfilment = ArchiveFulfilment(guard_home=tmp_path, scratch_dir=tmp_path, retain=False)
    fulfilment._elapsed = 10.0

    outcome = fulfilment.fulfil(_need(aggregate=10.0))

    assert outcome["kind"] == "archive_failure"
    assert outcome["code"] == "external_archive_request_timeout"


def test_remaining_budget_still_downloads_and_reports_the_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blobs = install_download(monkeypatch, tmp_path)
    install_inspection(monkeypatch)
    fulfilment = ArchiveFulfilment(guard_home=tmp_path, scratch_dir=tmp_path, retain=False)

    outcome = fulfilment.fulfil(_need(aggregate=60.0))

    assert outcome["kind"] == "archive"
    assert outcome["inspection"]["status"] == "clean"  # type: ignore[index]
    assert blobs and all(path.exists() is False for path in blobs)
