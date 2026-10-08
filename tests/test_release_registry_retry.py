from __future__ import annotations

import hashlib
import io
import json
import urllib.error
from email.message import Message
from pathlib import Path

import pytest
import yaml

import scripts.release_registry_retry as retry_module
from scripts.verify_release_registry import (
    Registry,
    RegistryVerificationError,
    main,
    verify_registry_release,
    verify_testpypi_release,
)

VERSION = "2.2.0a1"
WHEEL = f"hol_guard-{VERSION}-py3-none-any.whl"
SDIST = f"hol_guard-{VERSION}.tar.gz"
WHEEL_BYTES = b"wheel-content"
SDIST_BYTES = b"sdist-content"


class SequencedFetcher:
    def __init__(self, url: str, responses: list[bytes | Exception]) -> None:
        self.url = url
        self.responses = responses
        self.calls: list[str] = []

    def __call__(self, url: str) -> bytes:
        self.calls.append(url)
        if url != self.url:
            raise AssertionError(f"Unexpected fetch: {url}")
        if not self.responses:
            raise AssertionError("Fetcher response sequence was exhausted")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class DownloadFetcher:
    def __init__(
        self,
        release_url: str,
        release_payload: bytes,
        files: dict[str, bytes],
        failing_url: str,
        failure_count: int,
    ) -> None:
        self.release_url = release_url
        self.release_payload = release_payload
        self.files = files
        self.failing_url = failing_url
        self.remaining_failures = failure_count
        self.calls: list[str] = []

    def __call__(self, url: str) -> bytes:
        self.calls.append(url)
        if url == self.release_url:
            return self.release_payload
        if url not in self.files:
            raise AssertionError(f"Unexpected fetch: {url}")
        if url == self.failing_url and self.remaining_failures:
            self.remaining_failures -= 1
            raise _http_error(url, 404)
        return self.files[url]


def _release_url(registry: Registry, version: str = VERSION, project_name: str = "hol-guard") -> str:
    return f"https://{registry.api_host}/pypi/{project_name}/{version}/json"


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


def test_inspect_release_cli_reports_pending_then_present_for_empty_metadata(
    capsys: pytest.CaptureFixture[str],
) -> None:
    url = _release_url(Registry.TESTPYPI)
    incomplete_payload = json.dumps({"info": {"version": VERSION}, "urls": []}).encode()
    complete_payload = _release_payload(
        Registry.TESTPYPI,
        {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
    )
    fetcher = SequencedFetcher(url, [incomplete_payload, complete_payload])
    delays: list[float] = []

    inspect_args = ["inspect-release", "--registry", "testpypi", "--version", VERSION]
    assert main(inspect_args, fetcher=fetcher, sleep=delays.append) == 0

    pending_output = json.loads(capsys.readouterr().out)
    assert pending_output["status"] == "pending"
    assert pending_output["files"] == []
    assert fetcher.calls == [url]
    assert delays == []

    assert main(inspect_args, fetcher=fetcher, sleep=delays.append) == 0

    present_output = json.loads(capsys.readouterr().out)
    assert present_output["status"] == "present"
    assert fetcher.calls == [url, url]
    assert delays == []


def test_verify_registry_release_reports_absent_without_internal_retry(tmp_path: Path) -> None:
    dist = _local_dist(tmp_path)
    url = _release_url(Registry.PYPI)
    fetcher = SequencedFetcher(url, [_http_error(url, 404)])
    delays: list[float] = []

    result = verify_registry_release(
        Registry.PYPI,
        VERSION,
        dist,
        fetcher=fetcher,
        retry_attempts=2,
        sleep=delays.append,
    )

    assert result.status == "absent"
    assert fetcher.calls == [url]
    assert delays == []


def test_verify_registry_release_retries_transient_metadata_error(tmp_path: Path) -> None:
    dist = _local_dist(tmp_path)
    url = _release_url(Registry.PYPI)
    payload = _release_payload(
        Registry.PYPI,
        {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
    )
    fetcher = SequencedFetcher(url, [_http_error(url, 503), payload])
    delays: list[float] = []

    result = verify_registry_release(
        Registry.PYPI,
        VERSION,
        dist,
        fetcher=fetcher,
        retry_attempts=2,
        sleep=delays.append,
    )

    assert result.status == "exact"
    assert fetcher.calls == [url, url]
    assert delays == [retry_module.REGISTRY_RETRY_INITIAL_DELAY_SECONDS]


def test_verify_registry_release_retries_partial_pypi_metadata(tmp_path: Path) -> None:
    dist = _local_dist(tmp_path)
    url = _release_url(Registry.PYPI)
    partial_payload = _release_payload(Registry.PYPI, {WHEEL: (WHEEL_BYTES, None)})
    complete_payload = _release_payload(
        Registry.PYPI,
        {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
    )
    fetcher = SequencedFetcher(url, [partial_payload, complete_payload])
    delays: list[float] = []

    result = verify_registry_release(
        Registry.PYPI,
        VERSION,
        dist,
        fetcher=fetcher,
        retry_attempts=2,
        sleep=delays.append,
    )

    assert result.status == "exact"
    assert fetcher.calls == [url, url]
    assert delays == [retry_module.REGISTRY_RETRY_INITIAL_DELAY_SECONDS]


def test_verify_registry_release_fails_after_persistent_partial_metadata(tmp_path: Path) -> None:
    dist = _local_dist(tmp_path)
    url = _release_url(Registry.PYPI)
    partial_payload = _release_payload(Registry.PYPI, {WHEEL: (WHEEL_BYTES, None)})
    fetcher = SequencedFetcher(url, [partial_payload, partial_payload, partial_payload])
    delays: list[float] = []

    with pytest.raises(RegistryVerificationError, match=r"missing=hol_guard-2\.2\.0a1\.tar\.gz"):
        verify_registry_release(
            Registry.PYPI,
            VERSION,
            dist,
            fetcher=fetcher,
            retry_attempts=3,
            retry_initial_delay_seconds=0,
            retry_max_delay_seconds=0,
            sleep=delays.append,
        )

    assert fetcher.calls == [url, url, url]
    assert delays == [0, 0]


def test_verify_registry_release_retries_transient_download_404(tmp_path: Path) -> None:
    dist = _local_dist(tmp_path)
    release_url = _release_url(Registry.PYPI)
    payload = _release_payload(
        Registry.PYPI,
        {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
    )
    wheel_url = _file_url(Registry.PYPI, WHEEL)
    fetcher = DownloadFetcher(
        release_url,
        payload,
        {
            wheel_url: WHEEL_BYTES,
            _file_url(Registry.PYPI, SDIST): SDIST_BYTES,
        },
        wheel_url,
        failure_count=1,
    )
    delays: list[float] = []

    result = verify_registry_release(
        Registry.PYPI,
        VERSION,
        dist,
        download_dir=tmp_path / "verified",
        fetcher=fetcher,
        retry_attempts=2,
        sleep=delays.append,
    )

    assert result.status == "exact"
    assert {path.name: path.read_bytes() for path in result.downloaded_paths} == {
        WHEEL: WHEEL_BYTES,
        SDIST: SDIST_BYTES,
    }
    assert fetcher.calls.count(release_url) == 2
    assert fetcher.calls.count(wheel_url) == 2
    assert delays == [retry_module.REGISTRY_RETRY_INITIAL_DELAY_SECONDS]


def test_verify_registry_release_fails_after_persistent_download_404(tmp_path: Path) -> None:
    dist = _local_dist(tmp_path)
    release_url = _release_url(Registry.PYPI)
    payload = _release_payload(
        Registry.PYPI,
        {WHEEL: (WHEEL_BYTES, None), SDIST: (SDIST_BYTES, None)},
    )
    wheel_url = _file_url(Registry.PYPI, WHEEL)
    download_dir = tmp_path / "verified"
    fetcher = DownloadFetcher(
        release_url,
        payload,
        {
            wheel_url: WHEEL_BYTES,
            _file_url(Registry.PYPI, SDIST): SDIST_BYTES,
        },
        wheel_url,
        failure_count=3,
    )
    delays: list[float] = []

    with pytest.raises(RegistryVerificationError, match="HTTP 404"):
        verify_registry_release(
            Registry.PYPI,
            VERSION,
            dist,
            download_dir=download_dir,
            fetcher=fetcher,
            retry_attempts=3,
            retry_initial_delay_seconds=0,
            retry_max_delay_seconds=0,
            sleep=delays.append,
        )

    assert fetcher.calls.count(release_url) == 3
    assert fetcher.calls.count(wheel_url) == 3
    assert not (download_dir / WHEEL).exists()
    assert not (download_dir / SDIST).exists()
    assert delays == [0, 0]


@pytest.mark.parametrize(
    "retry_settings",
    [
        {"retry_attempts": 10**100},
        {"retry_max_delay_seconds": 10**1000},
        {"retry_initial_delay_seconds": 61, "retry_max_delay_seconds": 61},
        {"retry_attempts": 6, "retry_initial_delay_seconds": 3, "retry_max_delay_seconds": 30},
        {"retry_initial_delay_seconds": float("nan"), "retry_max_delay_seconds": 1},
    ],
)
def test_verify_registry_release_rejects_unbounded_retry_settings(
    tmp_path: Path,
    retry_settings: dict[str, int | float],
) -> None:
    dist = _local_dist(tmp_path)
    fetcher = SequencedFetcher("unused", [])

    with pytest.raises(RegistryVerificationError, match="Registry retry"):
        verify_registry_release(Registry.PYPI, VERSION, dist, fetcher=fetcher, **retry_settings)

    assert fetcher.calls == []


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
    url = _release_url(Registry.TESTPYPI)
    fetcher = SequencedFetcher(url, [_release_payload(Registry.TESTPYPI, files)])

    with pytest.raises(RegistryVerificationError):
        verify_testpypi_release(VERSION, dist, fetcher=fetcher, retry_attempts=1)


def test_alpha_post_publish_probe_allows_pending_guard_metadata() -> None:
    workflow_path = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    verify_step = next(
        step
        for step in workflow["jobs"]["publish-alpha-pypi"]["steps"]
        if step.get("name") == "Download and verify exact PyPI artifacts"
    )

    assert 'guard_status" != "pending"' in verify_step["run"]
