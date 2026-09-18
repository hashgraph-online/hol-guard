from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

from scripts.verify_release_registry import Registry, RegistryVerificationError, list_registry_versions, main
from tests.test_verify_release_registry import (
    PLUGIN_PROJECT,
    FakeFetcher,
    SequencedFetcher,
    _http_error,
    _project_url,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_lists_sorted_canonical_registry_versions() -> None:
    fetcher = FakeFetcher(
        {_project_url(Registry.PYPI): json.dumps({"releases": {"2.2.0a2": [], "2.1.0": [], "2.2.0a1": []}}).encode()}
    )

    assert list_registry_versions(Registry.PYPI, fetcher=fetcher) == (
        "2.1.0",
        "2.2.0a1",
        "2.2.0a2",
    )


def test_lists_plugin_scanner_registry_versions() -> None:
    fetcher = FakeFetcher(
        {_project_url(Registry.PYPI, PLUGIN_PROJECT): json.dumps({"releases": {"3.0.0a2": [], "3.0.0a1": []}}).encode()}
    )

    assert list_registry_versions(Registry.PYPI, project_name=PLUGIN_PROJECT, fetcher=fetcher) == (
        "3.0.0a1",
        "3.0.0a2",
    )


@pytest.mark.parametrize(
    "response",
    [
        b"not-json",
        json.dumps([]).encode(),
        json.dumps({}).encode(),
        json.dumps({"releases": {"v2.2.0a1": []}}).encode(),
    ],
)
def test_listing_registry_versions_fails_closed_on_invalid_data(response: bytes) -> None:
    fetcher = FakeFetcher({_project_url(Registry.PYPI): response})

    with pytest.raises(RegistryVerificationError):
        list_registry_versions(Registry.PYPI, fetcher=fetcher)
    assert fetcher.calls == [_project_url(Registry.PYPI)]


def test_listing_registry_versions_fails_closed_on_network_error() -> None:
    fetcher = FakeFetcher({_project_url(Registry.PYPI): urllib.error.URLError("offline")})

    with pytest.raises(RegistryVerificationError, match="Registry request failed"):
        list_registry_versions(Registry.PYPI, fetcher=fetcher, retry_attempts=1)


@pytest.mark.parametrize("registry", [Registry.PYPI, Registry.TESTPYPI])
def test_listing_registry_versions_treats_missing_project_as_empty(registry: Registry) -> None:
    url = _project_url(registry)
    fetcher = FakeFetcher({url: _http_error(url, 404)})
    delays: list[float] = []

    assert (
        list_registry_versions(
            registry,
            fetcher=fetcher,
            retry_attempts=2,
            retry_initial_delay_seconds=0,
            retry_max_delay_seconds=0,
            sleep=delays.append,
        )
        == ()
    )
    assert fetcher.calls == [url]
    assert delays == []


def test_list_versions_cli_reports_empty_for_unregistered_project(capsys: pytest.CaptureFixture[str]) -> None:
    url = _project_url(Registry.TESTPYPI)
    fetcher = FakeFetcher({url: _http_error(url, 404)})

    assert main(["list-versions", "--registry", "testpypi"], fetcher=fetcher) == 0
    assert json.loads(capsys.readouterr().out) == []
    assert fetcher.calls == [url]


@pytest.mark.parametrize(
    "transient_error",
    [
        urllib.error.URLError("offline"),
        _http_error(_project_url(Registry.PYPI), 503),
    ],
)
def test_listing_registry_versions_retries_transient_errors(transient_error: Exception) -> None:
    url = _project_url(Registry.PYPI)
    payload = json.dumps({"releases": {"2.2.0": []}}).encode()
    fetcher = SequencedFetcher(url, [transient_error, payload])
    delays: list[float] = []

    assert list_registry_versions(
        Registry.PYPI,
        fetcher=fetcher,
        retry_attempts=2,
        retry_initial_delay_seconds=0,
        retry_max_delay_seconds=0,
        sleep=delays.append,
    ) == ("2.2.0",)
    assert fetcher.calls == [url, url]
    assert delays == [0]


def test_listing_registry_versions_exhausts_transient_retries() -> None:
    url = _project_url(Registry.PYPI)
    fetcher = SequencedFetcher(url, [urllib.error.URLError("offline"), urllib.error.URLError("offline")])
    delays: list[float] = []

    with pytest.raises(RegistryVerificationError, match="Registry request failed"):
        list_registry_versions(
            Registry.PYPI,
            fetcher=fetcher,
            retry_attempts=2,
            retry_initial_delay_seconds=0,
            retry_max_delay_seconds=0,
            sleep=delays.append,
        )
    assert fetcher.calls == [url, url]
    assert delays == [0]


def test_listing_registry_versions_fails_fast_on_permanent_http_error() -> None:
    url = _project_url(Registry.PYPI)
    fetcher = FakeFetcher({url: _http_error(url, 401)})
    delays: list[float] = []

    with pytest.raises(RegistryVerificationError, match="HTTP 401"):
        list_registry_versions(
            Registry.PYPI,
            fetcher=fetcher,
            retry_attempts=2,
            retry_initial_delay_seconds=0,
            retry_max_delay_seconds=0,
            sleep=delays.append,
        )
    assert fetcher.calls == [url]
    assert delays == []


def test_verify_release_registry_script_help_avoids_circular_import() -> None:
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "verify_release_registry.py"), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "list-versions" in result.stdout
