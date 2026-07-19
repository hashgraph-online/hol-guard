from __future__ import annotations

import hashlib
import io
import json
import urllib.error
from email.message import Message
from pathlib import Path

import pytest

import scripts.verify_release_registry as registry_module
from scripts.verify_release_registry import (
    Registry,
    RegistryVerificationError,
    assert_pypi_release_absent,
    compute_local_distribution_hashes,
    inspect_release,
    list_registry_versions,
    main,
    verify_registry_release,
    verify_testpypi_release,
)


class ChunkedResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = iter(chunks)
        self.headers = Message()

    def __enter__(self) -> ChunkedResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _size: int) -> bytes:
        return next(self._chunks, b"")


VERSION = "2.2.0a1"
WHEEL = f"hol_guard-{VERSION}-py3-none-any.whl"
SDIST = f"hol_guard-{VERSION}.tar.gz"
WHEEL_BYTES = b"wheel-content"
SDIST_BYTES = b"sdist-content"


class FakeFetcher:
    def __init__(self, responses: dict[str, bytes | Exception]) -> None:
        self.responses = responses
        self.calls: list[str] = []

    def __call__(self, url: str) -> bytes:
        self.calls.append(url)
        response = self.responses.get(url)
        if response is None:
            raise AssertionError(f"Unexpected fetch: {url}")
        if isinstance(response, Exception):
            raise response
        return response


def _project_url(registry: Registry) -> str:
    return f"https://{registry.api_host}/pypi/hol-guard/json"


def _release_url(registry: Registry, version: str = VERSION) -> str:
    return f"https://{registry.api_host}/pypi/hol-guard/{version}/json"


def _file_url(registry: Registry, filename: str) -> str:
    return f"https://{registry.file_host}/packages/{filename}"


def _http_error(url: str, code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, "failure", Message(), io.BytesIO())


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _release_payload(
    registry: Registry,
    files: dict[str, tuple[bytes, str | None]],
    *,
    version: str = VERSION,
) -> bytes:
    urls = []
    for filename, (payload, override_digest) in files.items():
        urls.append(
            {
                "filename": filename,
                "digests": {"sha256": override_digest or _sha(payload)},
                "url": _file_url(registry, filename),
            }
        )
    return json.dumps({"info": {"version": version}, "urls": urls}).encode()


def _local_dist(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / WHEEL).write_bytes(WHEEL_BYTES)
    (dist / SDIST).write_bytes(SDIST_BYTES)
    return dist


def test_lists_sorted_canonical_registry_versions() -> None:
    fetcher = FakeFetcher(
        {_project_url(Registry.PYPI): json.dumps({"releases": {"2.2.0a2": [], "2.1.0": [], "2.2.0a1": []}}).encode()}
    )

    assert list_registry_versions(Registry.PYPI, fetcher=fetcher) == (
        "2.1.0",
        "2.2.0a1",
        "2.2.0a2",
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


def test_listing_registry_versions_fails_closed_on_network_error() -> None:
    fetcher = FakeFetcher({_project_url(Registry.PYPI): urllib.error.URLError("offline")})

    with pytest.raises(RegistryVerificationError, match="Registry request failed"):
        list_registry_versions(Registry.PYPI, fetcher=fetcher)


def test_stdlib_fetch_rejects_oversized_chunked_responses(monkeypatch: pytest.MonkeyPatch) -> None:
    response = ChunkedResponse([b"1234", b"5678", b"9"])
    monkeypatch.setattr(registry_module, "MAX_RESPONSE_BYTES", 8)
    monkeypatch.setattr(registry_module.urllib.request, "urlopen", lambda *_args, **_kwargs: response)

    with pytest.raises(RegistryVerificationError, match="maximum allowed size"):
        registry_module.stdlib_fetch("https://pypi.org/pypi/hol-guard/json")


def test_inspect_release_reports_absent_only_for_404() -> None:
    url = _release_url(Registry.TESTPYPI)
    fetcher = FakeFetcher({url: _http_error(url, 404)})

    inspection = inspect_release(Registry.TESTPYPI, VERSION, fetcher=fetcher)

    assert inspection.exists is False
    assert inspection.files == ()


def test_inspect_release_fails_closed_for_non_404_http_error() -> None:
    url = _release_url(Registry.TESTPYPI)
    fetcher = FakeFetcher({url: _http_error(url, 503)})

    with pytest.raises(RegistryVerificationError, match="HTTP 503"):
        inspect_release(Registry.TESTPYPI, VERSION, fetcher=fetcher)


def test_inspects_exact_release_without_exposing_urls_in_cli(capsys: pytest.CaptureFixture[str]) -> None:
    payload = _release_payload(
        Registry.TESTPYPI,
        {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
    )
    fetcher = FakeFetcher({_release_url(Registry.TESTPYPI): payload})

    assert (
        main(
            ["inspect-release", "--registry", "testpypi", "--version", VERSION],
            fetcher=fetcher,
        )
        == 0
    )
    output = capsys.readouterr().out
    decoded = json.loads(output)
    assert decoded["status"] == "present"
    assert {item["filename"] for item in decoded["files"]} == {WHEEL, SDIST}
    assert "pythonhosted.org" not in output


def test_inspect_release_ignores_valid_publish_attestation_sidecars() -> None:
    attestation = f"{WHEEL}.publish.attestation"
    payload = _release_payload(
        Registry.TESTPYPI,
        {
            WHEEL: (WHEEL_BYTES, None),
            SDIST: (SDIST_BYTES, None),
            attestation: (b"signed-attestation", None),
        },
    )
    fetcher = FakeFetcher({_release_url(Registry.TESTPYPI): payload})

    inspection = inspect_release(Registry.TESTPYPI, VERSION, fetcher=fetcher)

    assert {item.filename for item in inspection.files} == {WHEEL, SDIST}


def test_inspect_release_rejects_publish_attestation_for_invalid_distribution() -> None:
    attestation = "not-a-distribution.publish.attestation"
    payload = _release_payload(
        Registry.TESTPYPI,
        {attestation: (b"signed-attestation", None)},
    )
    fetcher = FakeFetcher({_release_url(Registry.TESTPYPI): payload})

    with pytest.raises(RegistryVerificationError, match="Invalid distribution filename"):
        inspect_release(Registry.TESTPYPI, VERSION, fetcher=fetcher)


def test_inspect_release_rejects_an_invalid_distribution_port() -> None:
    document = json.loads(
        _release_payload(
            Registry.TESTPYPI,
            {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
        )
    )
    document["urls"][0]["url"] = f"https://test-files.pythonhosted.org:invalid/{WHEEL}"
    fetcher = FakeFetcher({_release_url(Registry.TESTPYPI): json.dumps(document).encode()})

    with pytest.raises(RegistryVerificationError, match="invalid port"):
        inspect_release(Registry.TESTPYPI, VERSION, fetcher=fetcher)


def test_computes_local_guard_wheel_and_sdist_hashes(tmp_path: Path) -> None:
    dist = _local_dist(tmp_path)
    (dist / f"plugin_scanner-{VERSION}-py3-none-any.whl").write_bytes(b"scanner")

    assert compute_local_distribution_hashes(dist, VERSION) == {
        SDIST: _sha(SDIST_BYTES),
        WHEEL: _sha(WHEEL_BYTES),
    }


def test_verify_testpypi_accepts_absent_release(tmp_path: Path) -> None:
    dist = _local_dist(tmp_path)
    url = _release_url(Registry.TESTPYPI)
    fetcher = FakeFetcher({url: _http_error(url, 404)})

    result = verify_testpypi_release(VERSION, dist, fetcher=fetcher)

    assert result.status == "absent"
    assert set(result.files) == {WHEEL, SDIST}


@pytest.mark.parametrize("registry", [Registry.PYPI, Registry.TESTPYPI])
def test_generic_registry_reconciliation_reports_absent(tmp_path: Path, registry: Registry) -> None:
    dist = _local_dist(tmp_path)
    url = _release_url(registry)
    fetcher = FakeFetcher({url: _http_error(url, 404)})

    result = verify_registry_release(registry, VERSION, dist, fetcher=fetcher)

    assert result.registry is registry
    assert result.status == "absent"
    assert set(result.files) == {WHEEL, SDIST}


def test_verify_testpypi_accepts_exact_release_and_downloads_installable_paths(
    tmp_path: Path,
) -> None:
    dist = _local_dist(tmp_path)
    payload = _release_payload(
        Registry.TESTPYPI,
        {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
    )
    fetcher = FakeFetcher(
        {
            _release_url(Registry.TESTPYPI): payload,
            _file_url(Registry.TESTPYPI, WHEEL): WHEEL_BYTES,
            _file_url(Registry.TESTPYPI, SDIST): SDIST_BYTES,
        }
    )

    result = verify_testpypi_release(
        VERSION,
        dist,
        download_dir=tmp_path / "verified",
        fetcher=fetcher,
    )

    assert result.status == "exact"
    assert {path.name for path in result.downloaded_paths} == {WHEEL, SDIST}
    assert all(path.is_file() for path in result.downloaded_paths)
    assert {path.name: path.read_bytes() for path in result.downloaded_paths} == {
        WHEEL: WHEEL_BYTES,
        SDIST: SDIST_BYTES,
    }


@pytest.mark.parametrize("registry", [Registry.PYPI, Registry.TESTPYPI])
def test_generic_registry_reconciliation_accepts_exact_and_downloads(tmp_path: Path, registry: Registry) -> None:
    dist = _local_dist(tmp_path)
    payload = _release_payload(
        registry,
        {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
    )
    fetcher = FakeFetcher(
        {
            _release_url(registry): payload,
            _file_url(registry, WHEEL): WHEEL_BYTES,
            _file_url(registry, SDIST): SDIST_BYTES,
        }
    )

    result = verify_registry_release(
        registry,
        VERSION,
        dist,
        download_dir=tmp_path / f"verified-{registry.value}",
        fetcher=fetcher,
    )

    assert result.registry is registry
    assert result.status == "exact"
    assert {path.name for path in result.downloaded_paths} == {WHEEL, SDIST}
    assert all(path.is_file() for path in result.downloaded_paths)


def test_verify_release_cli_reconciles_pypi_without_exposing_urls(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    dist = _local_dist(tmp_path)
    payload = _release_payload(
        Registry.PYPI,
        {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
    )
    fetcher = FakeFetcher({_release_url(Registry.PYPI): payload})

    assert (
        main(
            [
                "verify-release",
                "--registry",
                "pypi",
                "--version",
                VERSION,
                "--dist-dir",
                str(dist),
            ],
            fetcher=fetcher,
        )
        == 0
    )
    output = capsys.readouterr().out
    decoded = json.loads(output)
    assert decoded["registry"] == "pypi"
    assert decoded["status"] == "exact"
    assert "pythonhosted.org" not in output


@pytest.mark.parametrize(
    "files",
    [
        {WHEEL: (b"different", None), SDIST: (SDIST_BYTES, None)},
        {WHEEL: (WHEEL_BYTES, None)},
        {
            WHEEL: (WHEEL_BYTES, None),
            SDIST: (SDIST_BYTES, None),
            f"hol_guard-{VERSION}-py2-none-any.whl": (b"extra", None),
        },
    ],
)
def test_verify_testpypi_rejects_mismatch_partial_and_extra(
    tmp_path: Path,
    files: dict[str, tuple[bytes, str | None]],
) -> None:
    dist = _local_dist(tmp_path)
    fetcher = FakeFetcher({_release_url(Registry.TESTPYPI): _release_payload(Registry.TESTPYPI, files)})

    with pytest.raises(RegistryVerificationError):
        verify_testpypi_release(VERSION, dist, fetcher=fetcher)


def test_generic_pypi_reconciliation_rejects_digest_mismatch(tmp_path: Path) -> None:
    dist = _local_dist(tmp_path)
    payload = _release_payload(
        Registry.PYPI,
        {WHEEL: (b"different", None), SDIST: (SDIST_BYTES, None)},
    )
    fetcher = FakeFetcher({_release_url(Registry.PYPI): payload})

    with pytest.raises(RegistryVerificationError, match="pypi distribution digest mismatch"):
        verify_registry_release(Registry.PYPI, VERSION, dist, fetcher=fetcher)


def test_download_rejects_tampered_bytes_without_writing_target(tmp_path: Path) -> None:
    dist = _local_dist(tmp_path)
    payload = _release_payload(
        Registry.TESTPYPI,
        {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
    )
    download_dir = tmp_path / "verified"
    fetcher = FakeFetcher(
        {
            _release_url(Registry.TESTPYPI): payload,
            _file_url(Registry.TESTPYPI, WHEEL): b"tampered",
            _file_url(Registry.TESTPYPI, SDIST): SDIST_BYTES,
        }
    )

    with pytest.raises(RegistryVerificationError, match="Downloaded distribution digest mismatch"):
        verify_testpypi_release(
            VERSION,
            dist,
            download_dir=download_dir,
            fetcher=fetcher,
        )
    assert not (download_dir / WHEEL).exists()


def test_download_is_all_or_nothing_when_later_file_is_tampered(tmp_path: Path) -> None:
    dist = _local_dist(tmp_path)
    payload = _release_payload(
        Registry.TESTPYPI,
        {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
    )
    download_dir = tmp_path / "verified"
    fetcher = FakeFetcher(
        {
            _release_url(Registry.TESTPYPI): payload,
            _file_url(Registry.TESTPYPI, WHEEL): WHEEL_BYTES,
            _file_url(Registry.TESTPYPI, SDIST): b"tampered",
        }
    )

    with pytest.raises(RegistryVerificationError, match="Downloaded distribution digest mismatch"):
        verify_testpypi_release(
            VERSION,
            dist,
            download_dir=download_dir,
            fetcher=fetcher,
        )
    assert not (download_dir / WHEEL).exists()
    assert not (download_dir / SDIST).exists()


def test_pypi_duplicate_is_detectable_and_fatal() -> None:
    payload = _release_payload(
        Registry.PYPI,
        {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
    )
    fetcher = FakeFetcher({_release_url(Registry.PYPI): payload})

    with pytest.raises(RegistryVerificationError, match="already exists"):
        assert_pypi_release_absent(VERSION, fetcher=fetcher)


def test_pypi_absence_passes() -> None:
    url = _release_url(Registry.PYPI)
    fetcher = FakeFetcher({url: _http_error(url, 404)})

    assert_pypi_release_absent(VERSION, fetcher=fetcher)
