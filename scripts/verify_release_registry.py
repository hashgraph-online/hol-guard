from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final

from packaging.utils import InvalidSdistFilename, InvalidWheelFilename, parse_sdist_filename, parse_wheel_filename
from packaging.version import InvalidVersion, Version

if __package__:
    from .release_registry_types import (
        Registry,
        RegistryResult,
        RegistryVerificationError,
        ReleaseFile,
        ReleaseInspection,
        TestPyPIResult,
    )
else:
    from release_registry_types import (  # pyright: ignore[reportImplicitRelativeImport]
        Registry,
        RegistryResult,
        RegistryVerificationError,
        ReleaseFile,
        ReleaseInspection,
        TestPyPIResult,
    )

DEFAULT_PROJECT_NAME: Final = "hol-guard"
SUPPORTED_PROJECT_NAMES: Final = ("hol-guard", "plugin-scanner")
MAX_RESPONSE_BYTES: Final = 256 * 1024 * 1024
REGISTRY_RETRY_ATTEMPTS: Final = 6
REGISTRY_RETRY_INITIAL_DELAY_SECONDS: Final = 2.0
REGISTRY_RETRY_MAX_DELAY_SECONDS: Final = 30.0
REGISTRY_RETRY_MAX_ATTEMPTS: Final = REGISTRY_RETRY_ATTEMPTS
REGISTRY_RETRY_MAX_TOTAL_DELAY_SECONDS: Final = 60.0
_SHA256: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{64}")

Fetcher = Callable[[str], bytes]
Sleeper = Callable[[float], None]


class _RetryableRegistryError(RegistryVerificationError):
    """A registry response may become valid during the bounded retry window."""


def stdlib_fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "hol-guard-release-registry-verifier"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        declared_length = response.headers.get("Content-Length")
        if declared_length is not None:
            try:
                parsed_length = int(declared_length)
            except ValueError as exc:
                raise RegistryVerificationError("Registry response has an invalid content length") from exc
            if parsed_length < 0 or parsed_length > MAX_RESPONSE_BYTES:
                raise RegistryVerificationError("Registry response exceeds the maximum allowed size")
        chunks: list[bytes] = []
        total_bytes = 0
        while True:
            chunk = response.read(min(1024 * 1024, MAX_RESPONSE_BYTES - total_bytes + 1))
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > MAX_RESPONSE_BYTES:
                raise RegistryVerificationError("Registry response exceeds the maximum allowed size")
            chunks.append(chunk)
    return b"".join(chunks)


def _validated_project_name(project_name: str) -> str:
    if project_name not in SUPPORTED_PROJECT_NAMES:
        raise RegistryVerificationError(f"Unsupported release project: {project_name}")
    return project_name


def _project_url(registry: Registry, project_name: str) -> str:
    return f"https://{registry.api_host}/pypi/{_validated_project_name(project_name)}/json"


def _release_url(registry: Registry, project_name: str, version: str) -> str:
    quoted_version = urllib.parse.quote(version, safe="")
    return f"https://{registry.api_host}/pypi/{_validated_project_name(project_name)}/{quoted_version}/json"


def _fetch_payload(
    url: str,
    *,
    fetcher: Fetcher,
    allow_not_found: bool = False,
) -> bytes | None:
    try:
        return fetcher(url)
    except urllib.error.HTTPError as exc:
        if allow_not_found and exc.code == 404:
            return None
        if exc.code == 404 or exc.code in {408, 425, 429} or 500 <= exc.code < 600:
            raise _RetryableRegistryError(f"Registry request failed with HTTP {exc.code}") from exc
        raise RegistryVerificationError(f"Registry request failed with HTTP {exc.code}") from exc
    except RegistryVerificationError:
        raise
    except (OSError, TimeoutError, urllib.error.URLError) as exc:
        raise _RetryableRegistryError("Registry request failed") from exc


def _decode_object(payload: bytes, *, label: str) -> dict[str, object]:
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryVerificationError(f"{label} returned invalid JSON") from exc
    if not isinstance(decoded, dict) or not all(isinstance(key, str) for key in decoded):
        raise RegistryVerificationError(f"{label} must be a JSON object")
    return {str(key): value for key, value in decoded.items()}


def _canonical_public_version(version_text: object, *, label: str) -> Version:
    if not isinstance(version_text, str):
        raise RegistryVerificationError(f"{label} must be a string")
    try:
        version = Version(version_text)
    except InvalidVersion as exc:
        raise RegistryVerificationError(f"{label} is not a valid PEP 440 version") from exc
    if version_text != str(version) or version.local is not None:
        raise RegistryVerificationError(f"{label} is not a canonical public PEP 440 version")
    return version


def list_registry_versions(
    registry: Registry,
    *,
    project_name: str = DEFAULT_PROJECT_NAME,
    fetcher: Fetcher = stdlib_fetch,
) -> tuple[str, ...]:
    payload = _fetch_payload(_project_url(registry, project_name), fetcher=fetcher)
    if payload is None:
        raise RegistryVerificationError("Registry project response was unexpectedly absent")
    document = _decode_object(payload, label="Registry project response")
    releases = document.get("releases")
    if not isinstance(releases, dict):
        raise RegistryVerificationError("Registry project response is missing the releases object")

    versions: list[Version] = []
    for version_text in releases:
        versions.append(_canonical_public_version(version_text, label="Registry version"))
    return tuple(str(version) for version in sorted(versions))


def _distribution_identity(filename: str) -> tuple[str, Version]:
    try:
        if filename.endswith(".whl"):
            name, version, _build, _tags = parse_wheel_filename(filename)
            return name, version
        name, version = parse_sdist_filename(filename)
        return name, version
    except (InvalidWheelFilename, InvalidSdistFilename) as exc:
        raise RegistryVerificationError(f"Invalid distribution filename: {filename}") from exc


def _validate_distribution_filename(filename: object, version: Version, project_name: str) -> str:
    if not isinstance(filename, str) or not filename or Path(filename).name != filename:
        raise RegistryVerificationError("Registry distribution filename is invalid")
    name, file_version = _distribution_identity(filename)
    if name != _validated_project_name(project_name) or file_version != version:
        raise RegistryVerificationError("Registry returned a distribution for the wrong project or version")
    return filename


def _is_publish_attestation(filename: object, version: Version, project_name: str) -> bool:
    if not isinstance(filename, str) or not filename.endswith(".publish.attestation"):
        return False
    distribution_filename = filename
    while distribution_filename.endswith(".publish.attestation"):
        distribution_filename = distribution_filename.removesuffix(".publish.attestation")
    _validate_distribution_filename(distribution_filename, version, project_name)
    return True


def _validated_download_url(url: object, filename: str, registry: Registry) -> str:
    if not isinstance(url, str):
        raise RegistryVerificationError("Registry distribution URL must be a string")
    parsed = urllib.parse.urlsplit(url)
    remote_filename = urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1])
    try:
        port = parsed.port
    except ValueError as exc:
        raise RegistryVerificationError("Registry distribution URL has an invalid port") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != registry.file_host
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or remote_filename != filename
    ):
        raise RegistryVerificationError("Registry distribution URL is not an approved file URL")
    return url


def inspect_release(
    registry: Registry,
    version_text: str,
    *,
    project_name: str = DEFAULT_PROJECT_NAME,
    fetcher: Fetcher = stdlib_fetch,
) -> ReleaseInspection:
    version = _canonical_public_version(version_text, label="Requested version")
    payload = _fetch_payload(
        _release_url(registry, project_name, str(version)),
        fetcher=fetcher,
        allow_not_found=True,
    )
    if payload is None:
        return ReleaseInspection(registry=registry, version=str(version), exists=False)

    document = _decode_object(payload, label="Registry release response")
    info = document.get("info")
    if not isinstance(info, dict):
        raise RegistryVerificationError("Registry release response is missing package information")
    info_version = _canonical_public_version(info.get("version"), label="Registry release version")
    if info_version != version:
        raise RegistryVerificationError("Registry release response returned the wrong version")
    urls = document.get("urls")
    if not isinstance(urls, list):
        raise RegistryVerificationError("Existing registry release has no distribution files")
    if not urls:
        raise _RetryableRegistryError("Existing registry release has no distribution files yet")

    files: list[ReleaseFile] = []
    seen: set[str] = set()
    for item in urls:
        if not isinstance(item, dict):
            raise RegistryVerificationError("Registry release file entry must be an object")
        if _is_publish_attestation(item.get("filename"), version, project_name):
            continue
        filename = _validate_distribution_filename(item.get("filename"), version, project_name)
        if filename in seen:
            raise RegistryVerificationError(f"Registry release repeats distribution filename: {filename}")
        seen.add(filename)
        digests = item.get("digests")
        if not isinstance(digests, dict):
            raise RegistryVerificationError(f"Registry release is missing a digest for {filename}")
        sha256 = digests.get("sha256")
        if not isinstance(sha256, str) or _SHA256.fullmatch(sha256) is None:
            raise RegistryVerificationError(f"Registry release has an invalid SHA-256 for {filename}")
        download_url = _validated_download_url(item.get("url"), filename, registry)
        files.append(ReleaseFile(filename=filename, sha256=sha256, download_url=download_url))
    if not files:
        raise _RetryableRegistryError("Existing registry release has no distribution files yet")
    return ReleaseInspection(
        registry=registry,
        version=str(version),
        exists=True,
        files=tuple(sorted(files, key=lambda item: item.filename)),
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compute_local_distribution_hashes(
    dist_dir: Path,
    version_text: str,
    project_name: str = DEFAULT_PROJECT_NAME,
) -> dict[str, str]:
    version = _canonical_public_version(version_text, label="Requested version")
    normalized_project_name = _validated_project_name(project_name)
    project_prefixes = (normalized_project_name, normalized_project_name.replace("-", "_"))
    if not dist_dir.is_dir():
        raise RegistryVerificationError("Distribution directory does not exist")

    hashes: dict[str, str] = {}
    found_wheel = False
    found_sdist = False
    for path in sorted(dist_dir.iterdir()):
        if path.is_symlink():
            if path.name.startswith(tuple(f"{prefix}-" for prefix in project_prefixes)):
                raise RegistryVerificationError("Local project distributions cannot be symbolic links")
            continue
        if not path.is_file() or _is_publish_attestation(path.name, version, project_name):
            continue
        try:
            name, file_version = _distribution_identity(path.name)
        except RegistryVerificationError:
            if path.name.startswith(tuple(f"{prefix}-" for prefix in project_prefixes)):
                raise
            continue
        if name != normalized_project_name:
            continue
        if file_version != version:
            raise RegistryVerificationError("Local project distribution has the wrong version")
        if path.name in hashes:
            raise RegistryVerificationError("Local project distribution filename is duplicated")
        hashes[path.name] = _sha256_file(path)
        found_wheel = found_wheel or path.name.endswith(".whl")
        found_sdist = found_sdist or not path.name.endswith(".whl")

    if not hashes or not found_wheel or not found_sdist:
        raise RegistryVerificationError("Local release requires both a project wheel and sdist")
    return hashes


def _compare_digest_sets(
    local_hashes: Mapping[str, str],
    remote_hashes: Mapping[str, str],
    *,
    registry: Registry,
) -> None:
    local_names = set(local_hashes)
    remote_names = set(remote_hashes)
    if local_names != remote_names:
        missing = sorted(local_names - remote_names)
        extra = sorted(remote_names - local_names)
        details: list[str] = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if extra:
            details.append(f"extra={','.join(extra)}")
        mismatch = RegistryVerificationError(
            f"{registry.value} distribution set does not match the local build ({'; '.join(details)})"
        )
        if _is_eventually_complete_distribution_set(local_hashes, remote_hashes):
            raise _RetryableRegistryError(str(mismatch))
        raise mismatch
    mismatched = sorted(filename for filename, digest in local_hashes.items() if remote_hashes[filename] != digest)
    if mismatched:
        raise RegistryVerificationError(f"{registry.value} distribution digest mismatch: {','.join(mismatched)}")


def _is_eventually_complete_distribution_set(
    local_hashes: Mapping[str, str],
    remote_hashes: Mapping[str, str],
) -> bool:
    """Return true only for a matching remote subset missing local artifacts."""

    local_names = set(local_hashes)
    remote_names = set(remote_hashes)
    return remote_names < local_names and all(
        local_hashes[filename] == remote_hashes[filename] for filename in remote_names
    )


def _retry_delay(attempt: int, *, initial: float, maximum: float) -> float:
    capped_attempt = min(attempt, REGISTRY_RETRY_MAX_ATTEMPTS - 1)
    return min(maximum, initial * (2**capped_attempt))


def _is_valid_retry_delay_value(delay: object) -> bool:
    if isinstance(delay, bool) or not isinstance(delay, (int, float)):
        return False
    return isinstance(delay, int) or math.isfinite(delay)


def _validate_retry_settings(
    attempts: int,
    initial_delay: float,
    maximum_delay: float,
) -> None:
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= REGISTRY_RETRY_MAX_ATTEMPTS:
        raise RegistryVerificationError(
            f"Registry retry attempts must be between one and {REGISTRY_RETRY_MAX_ATTEMPTS}"
        )
    if not all(_is_valid_retry_delay_value(delay) for delay in (initial_delay, maximum_delay)):
        raise RegistryVerificationError("Registry retry delays must be finite numbers")
    if initial_delay < 0 or maximum_delay < initial_delay:
        raise RegistryVerificationError("Registry retry delays must be non-negative and ordered")
    if maximum_delay > REGISTRY_RETRY_MAX_TOTAL_DELAY_SECONDS:
        raise RegistryVerificationError(
            f"Registry retry delay must not exceed {REGISTRY_RETRY_MAX_TOTAL_DELAY_SECONDS:g} seconds"
        )
    total_delay = sum(
        _retry_delay(attempt, initial=initial_delay, maximum=maximum_delay) for attempt in range(attempts - 1)
    )
    if total_delay > REGISTRY_RETRY_MAX_TOTAL_DELAY_SECONDS:
        raise RegistryVerificationError(
            f"Registry retry delay budget must not exceed {REGISTRY_RETRY_MAX_TOTAL_DELAY_SECONDS:g} seconds"
        )


def _wait_for_retry(
    attempt: int,
    *,
    attempts: int,
    initial_delay: float,
    maximum_delay: float,
    sleep: Sleeper,
) -> bool:
    if attempt == attempts - 1:
        return False
    sleep(_retry_delay(attempt, initial=initial_delay, maximum=maximum_delay))
    return True


def download_verified_release(
    inspection: ReleaseInspection,
    destination: Path,
    *,
    fetcher: Fetcher = stdlib_fetch,
) -> tuple[Path, ...]:
    if not inspection.exists or not inspection.files:
        raise RegistryVerificationError("Cannot download an absent registry release")
    destination.mkdir(parents=True, exist_ok=True)
    downloaded: list[Path] = []
    with tempfile.TemporaryDirectory(dir=destination) as temporary_dir_text:
        temporary_dir = Path(temporary_dir_text)
        staged: list[tuple[Path, Path]] = []
        for item in inspection.files:
            payload = _fetch_payload(item.download_url, fetcher=fetcher)
            if payload is None:
                raise RegistryVerificationError(f"Registry distribution was absent: {item.filename}")
            actual_digest = hashlib.sha256(payload).hexdigest()
            if actual_digest != item.sha256:
                raise RegistryVerificationError(f"Downloaded distribution digest mismatch: {item.filename}")
            staged_path = temporary_dir / item.filename
            _ = staged_path.write_bytes(payload)
            staged.append((staged_path, destination / item.filename))
        for staged_path, target in staged:
            os.replace(staged_path, target)
            downloaded.append(target)
    return tuple(downloaded)


def verify_registry_release(
    registry: Registry,
    version_text: str,
    dist_dir: Path,
    *,
    project_name: str = DEFAULT_PROJECT_NAME,
    download_dir: Path | None = None,
    fetcher: Fetcher = stdlib_fetch,
    retry_attempts: int = REGISTRY_RETRY_ATTEMPTS,
    retry_initial_delay_seconds: float = REGISTRY_RETRY_INITIAL_DELAY_SECONDS,
    retry_max_delay_seconds: float = REGISTRY_RETRY_MAX_DELAY_SECONDS,
    sleep: Sleeper | None = None,
) -> RegistryResult:
    local_hashes = compute_local_distribution_hashes(dist_dir, version_text, project_name)
    _validate_retry_settings(
        retry_attempts,
        retry_initial_delay_seconds,
        retry_max_delay_seconds,
    )
    sleep_fn = time.sleep if sleep is None else sleep

    for attempt in range(retry_attempts):
        try:
            inspection = inspect_release(registry, version_text, project_name=project_name, fetcher=fetcher)
            if not inspection.exists:
                return RegistryResult(
                    registry=registry,
                    status="absent",
                    version=inspection.version,
                    files=tuple(sorted(local_hashes)),
                )

            _compare_digest_sets(local_hashes, inspection.digests, registry=registry)
            downloaded = (
                download_verified_release(inspection, download_dir, fetcher=fetcher) if download_dir is not None else ()
            )
            return RegistryResult(
                registry=registry,
                status="exact",
                version=inspection.version,
                files=tuple(sorted(local_hashes)),
                downloaded_paths=downloaded,
            )
        except _RetryableRegistryError:
            if not _wait_for_retry(
                attempt,
                attempts=retry_attempts,
                initial_delay=retry_initial_delay_seconds,
                maximum_delay=retry_max_delay_seconds,
                sleep=sleep_fn,
            ):
                raise

    raise AssertionError("Registry verification exhausted without a result")


def verify_testpypi_release(
    version_text: str,
    dist_dir: Path,
    *,
    project_name: str = DEFAULT_PROJECT_NAME,
    download_dir: Path | None = None,
    fetcher: Fetcher = stdlib_fetch,
    retry_attempts: int = REGISTRY_RETRY_ATTEMPTS,
    retry_initial_delay_seconds: float = REGISTRY_RETRY_INITIAL_DELAY_SECONDS,
    retry_max_delay_seconds: float = REGISTRY_RETRY_MAX_DELAY_SECONDS,
    sleep: Sleeper | None = None,
) -> TestPyPIResult:
    """Compatibility wrapper for existing TestPyPI workflow callers."""

    return verify_registry_release(
        Registry.TESTPYPI,
        version_text,
        dist_dir,
        project_name=project_name,
        download_dir=download_dir,
        fetcher=fetcher,
        retry_attempts=retry_attempts,
        retry_initial_delay_seconds=retry_initial_delay_seconds,
        retry_max_delay_seconds=retry_max_delay_seconds,
        sleep=sleep,
    )


def assert_pypi_release_absent(
    version_text: str,
    *,
    project_name: str = DEFAULT_PROJECT_NAME,
    fetcher: Fetcher = stdlib_fetch,
) -> None:
    inspection = inspect_release(Registry.PYPI, version_text, project_name=project_name, fetcher=fetcher)
    if inspection.exists:
        raise RegistryVerificationError(f"PyPI release {inspection.version} already exists")


def _inspection_output(inspection: ReleaseInspection) -> dict[str, object]:
    return {
        "registry": inspection.registry.value,
        "version": inspection.version,
        "status": "present" if inspection.exists else "absent",
        "files": [{"filename": item.filename, "sha256": item.sha256} for item in inspection.files],
    }


def _result_output(result: RegistryResult) -> dict[str, object]:
    return {
        "registry": result.registry.value,
        "version": result.version,
        "status": result.status,
        "files": list(result.files),
        "install_paths": [str(path) for path in result.downloaded_paths],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify Guard release registry state")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list-versions")
    _ = list_parser.add_argument("--registry", choices=[item.value for item in Registry], required=True)
    _ = list_parser.add_argument("--project", choices=SUPPORTED_PROJECT_NAMES, default=DEFAULT_PROJECT_NAME)

    inspect_parser = subparsers.add_parser("inspect-release")
    _ = inspect_parser.add_argument("--registry", choices=[item.value for item in Registry], required=True)
    _ = inspect_parser.add_argument("--project", choices=SUPPORTED_PROJECT_NAMES, default=DEFAULT_PROJECT_NAME)
    _ = inspect_parser.add_argument("--version", required=True)

    verify_parser = subparsers.add_parser("verify-testpypi")
    _ = verify_parser.add_argument("--project", choices=SUPPORTED_PROJECT_NAMES, default=DEFAULT_PROJECT_NAME)
    _ = verify_parser.add_argument("--version", required=True)
    _ = verify_parser.add_argument("--dist-dir", type=Path, required=True)
    _ = verify_parser.add_argument("--download-dir", type=Path)

    generic_verify_parser = subparsers.add_parser("verify-release")
    _ = generic_verify_parser.add_argument("--registry", choices=[item.value for item in Registry], required=True)
    _ = generic_verify_parser.add_argument("--project", choices=SUPPORTED_PROJECT_NAMES, default=DEFAULT_PROJECT_NAME)
    _ = generic_verify_parser.add_argument("--version", required=True)
    _ = generic_verify_parser.add_argument("--dist-dir", type=Path, required=True)
    _ = generic_verify_parser.add_argument("--download-dir", type=Path)

    absent_parser = subparsers.add_parser("assert-pypi-absent")
    _ = absent_parser.add_argument("--project", choices=SUPPORTED_PROJECT_NAMES, default=DEFAULT_PROJECT_NAME)
    _ = absent_parser.add_argument("--version", required=True)
    return parser


def main(argv: Sequence[str] | None = None, *, fetcher: Fetcher = stdlib_fetch) -> int:
    args = _parser().parse_args(argv)
    command = getattr(args, "command", None)
    try:
        if command == "list-versions":
            registry = Registry(args.registry)
            output: object = list_registry_versions(registry, project_name=args.project, fetcher=fetcher)
        elif command == "inspect-release":
            registry = Registry(args.registry)
            inspection = inspect_release(
                registry,
                args.version,
                project_name=args.project,
                fetcher=fetcher,
            )
            output = _inspection_output(inspection)
        elif command == "verify-testpypi":
            result = verify_testpypi_release(
                args.version,
                args.dist_dir,
                project_name=args.project,
                download_dir=args.download_dir,
                fetcher=fetcher,
            )
            output = _result_output(result)
        elif command == "verify-release":
            result = verify_registry_release(
                Registry(args.registry),
                args.version,
                args.dist_dir,
                project_name=args.project,
                download_dir=args.download_dir,
                fetcher=fetcher,
            )
            output = _result_output(result)
        elif command == "assert-pypi-absent":
            version = args.version
            assert_pypi_release_absent(version, project_name=args.project, fetcher=fetcher)
            output = {"registry": Registry.PYPI.value, "version": version, "status": "absent"}
        else:
            raise RegistryVerificationError("Unsupported registry verification command")
    except RegistryVerificationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
