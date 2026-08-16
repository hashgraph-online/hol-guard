from __future__ import annotations

import io
import json
import sys

import pytest

import scripts.compute_main_release_version as version_module
from scripts.compute_main_release_version import (
    compute_main_release_version,
    latest_main_release_version,
    latest_unyanked_main_release_version,
    main,
)


class _FakePyPIResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self.headers: dict[str, str] = {}

    def __enter__(self) -> _FakePyPIResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self._payload


@pytest.mark.parametrize(
    ("base", "existing", "expected"),
    [
        ("2.0.1117", ["2.0.1116"], "2.0.1117"),
        ("2.0.1117", ["2.0.1117"], "2.0.1118"),
        ("2.0.1117", ["2.0.1120"], "2.0.1121"),
        ("2.0.1117", ["2.0.1117.dev4", "2.2.0a1", "3.0.0a5"], "2.0.1117"),
        ("2.1.0", ["2.1.0a30", "2.1.0a31", "3.0.0a5"], "2.1.0"),
        ("3.0.0", ["2.0.2000", "3.0.0a5"], "3.0.0"),
    ],
)
def test_computes_monotonic_version_for_repository_release_line(
    base: str,
    existing: list[str],
    expected: str,
) -> None:
    assert compute_main_release_version(base, existing) == expected


@pytest.mark.parametrize("base", ["2.0", "2.0.1a1", "2.0.1.dev1", "v2.0.1", "not-a-version"])
def test_rejects_noncanonical_repository_versions(base: str) -> None:
    with pytest.raises(ValueError, match="Repository version"):
        compute_main_release_version(base, [])


def test_ignores_invalid_or_noncanonical_registry_versions() -> None:
    assert compute_main_release_version("2.0.1", ["2.0.01", "invalid", "2.0.0+local"]) == "2.0.1"


def test_reports_latest_stable_version_for_source_monotonicity() -> None:
    assert latest_main_release_version("2.0.1117", ["2.0.1116", "2.0.1117.dev4", "3.0.0a5"]) == "2.0.1116"
    assert latest_main_release_version("2.0.1117", ["2.2.0a1", "3.0.0a5"]) is None


def test_publication_anchor_skips_fully_yanked_pypi_releases() -> None:
    states: dict[str, version_module.PyPIReleaseState] = {
        "2.2.8": "active",
        "2.2.9": "yanked",
        "2.2.10": "yanked",
    }

    assert (
        latest_unyanked_main_release_version(
            "2.2.0",
            ["2.2.8", "2.2.9", "2.2.10", "3.1.0a5"],
            release_state_loader=states.__getitem__,
        )
        == "2.2.8"
    )


def test_publication_anchor_keeps_absent_current_candidate() -> None:
    states: dict[str, version_module.PyPIReleaseState] = {
        "2.2.13": "active",
        "2.2.14": "absent",
    }

    assert (
        latest_unyanked_main_release_version(
            "2.2.0",
            ["2.2.13", "2.2.14"],
            release_state_loader=states.__getitem__,
        )
        == "2.2.14"
    )


def test_publication_anchor_keeps_active_release_even_if_git_tag_is_missing() -> None:
    states: dict[str, version_module.PyPIReleaseState] = {
        "2.2.9": "active",
        "2.2.10": "active",
    }

    assert (
        latest_unyanked_main_release_version(
            "2.2.0",
            ["2.2.9", "2.2.10"],
            release_state_loader=states.__getitem__,
        )
        == "2.2.10"
    )


@pytest.mark.parametrize(
    ("yanked_flags", "expected"),
    [
        ([True, True], "yanked"),
        ([False, False], "active"),
        ([True, False], "active"),
    ],
)
def test_pypi_release_state_parses_file_yank_status(
    monkeypatch: pytest.MonkeyPatch,
    yanked_flags: list[bool],
    expected: version_module.PyPIReleaseState,
) -> None:
    payload = json.dumps(
        {
            "info": {"version": "2.2.10"},
            "urls": [{"yanked": yanked} for yanked in yanked_flags],
        }
    ).encode()
    monkeypatch.setattr(
        version_module.urllib.request,
        "urlopen",
        lambda _request, timeout: _FakePyPIResponse(payload),
    )

    assert version_module._pypi_release_state("2.2.10") == expected


def test_pypi_release_state_maps_not_found_to_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    def _not_found(request: object, timeout: int) -> _FakePyPIResponse:
        del timeout
        raise version_module.urllib.error.HTTPError(str(request), 404, "not found", None, None)

    monkeypatch.setattr(version_module.urllib.request, "urlopen", _not_found)

    assert version_module._pypi_release_state("2.2.14") == "absent"


def test_default_publication_anchor_uses_pypi_yank_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def _urlopen(request: object, timeout: int) -> _FakePyPIResponse:
        del timeout
        url = str(getattr(request, "full_url"))
        version = url.rsplit("/", 2)[-2]
        seen.append(version)
        payload = json.dumps(
            {
                "info": {"version": version},
                "urls": [{"yanked": version == "2.2.10"}],
            }
        ).encode()
        return _FakePyPIResponse(payload)

    monkeypatch.setattr(version_module.urllib.request, "urlopen", _urlopen)

    assert latest_unyanked_main_release_version("2.2.0", ["2.2.9", "2.2.10"]) == "2.2.9"
    assert seen == ["2.2.10", "2.2.9"]


def test_default_publication_anchor_returns_none_when_all_stables_are_yanked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _urlopen(request: object, timeout: int) -> _FakePyPIResponse:
        del timeout
        url = str(getattr(request, "full_url"))
        version = url.rsplit("/", 2)[-2]
        payload = json.dumps({"info": {"version": version}, "urls": [{"yanked": True}]}).encode()
        return _FakePyPIResponse(payload)

    monkeypatch.setattr(version_module.urllib.request, "urlopen", _urlopen)

    assert latest_unyanked_main_release_version("2.2.0", ["2.2.9", "2.2.10"]) is None


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        (b"not-json", "invalid JSON"),
        (b'{"info":{"version":"2.2.10"},"urls":[]}', "missing the release files"),
        (json.dumps({"info": {"version": "2.2.9"}, "urls": [{"yanked": False}]}).encode(), "wrong version"),
    ],
)
def test_pypi_release_state_fails_closed_for_bad_metadata(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    match: str,
) -> None:
    monkeypatch.setattr(
        version_module.urllib.request,
        "urlopen",
        lambda _request, timeout: _FakePyPIResponse(payload),
    )

    with pytest.raises(ValueError, match=match):
        version_module._pypi_release_state("2.2.10")


def test_pypi_release_state_fails_closed_for_http_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _server_error(request: object, timeout: int) -> _FakePyPIResponse:
        del timeout
        raise version_module.urllib.error.HTTPError(str(request), 500, "server error", None, None)

    monkeypatch.setattr(version_module.urllib.request, "urlopen", _server_error)

    with pytest.raises(ValueError, match="HTTP 500"):
        version_module._pypi_release_state("2.2.10")


def test_cli_reports_latest_existing_stable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["compute_main_release_version.py", "--base-version", "2.0.1117", "--latest-existing"],
    )
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(["2.0.1116", "3.1.0a5"])))
    monkeypatch.setattr(
        version_module,
        "latest_unyanked_main_release_version",
        lambda _base, _versions: "2.0.1116",
    )

    assert main() == 0
    assert capsys.readouterr().out == "2.0.1116\n"


def test_cli_reads_registry_versions_from_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["compute_main_release_version.py", "--base-version", "2.0.1117"])
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(["2.0.1116"])))

    assert main() == 0
    assert capsys.readouterr().out == "2.0.1117\n"


def test_cli_fails_closed_for_invalid_registry_payload(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["compute_main_release_version.py", "--base-version", "2.0.1117"])
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"version":"2.0.1116"}'))

    assert main() == 1
    assert "JSON array of strings" in capsys.readouterr().err
