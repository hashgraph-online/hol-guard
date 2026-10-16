"""Where native wheel digests come from, and the bounded downloads that fetch them.

Stable digests come from ``native-wheels.json`` in the pure wheel on PyPI; alpha
digests come from the provenance bundle on the GitHub prerelease. Every request
is limited to the GitHub release download and PyPI hosts.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import shutil
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Protocol

from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from ..mdm.contracts import ManagedNetworkPolicy
from ..mdm.network import ManagedNetworkError, managed_urlopen
from ..native_runtime import _installed_package_root

RELEASE_DOWNLOAD_PREFIX = "https://github.com/hashgraph-online/hol-guard/releases/download/"


PYPI_JSON_PREFIX = "https://pypi.org/pypi/hol-guard/"


PYPI_FILES_PREFIX = "https://files.pythonhosted.org/"


NATIVE_WHEEL_MANIFEST_NAME = "native-wheels.json"


NATIVE_WHEEL_MANIFEST_MEMBER = f"codex_plugin_scanner/{NATIVE_WHEEL_MANIFEST_NAME}"


NATIVE_WHEEL_MANIFEST_SCHEMA = "hol-guard-native-wheels.v1"


_PROVENANCE_REPOSITORY = "https://github.com/hashgraph-online/hol-guard"


_PROVENANCE_WORKFLOW_PATH = ".github/workflows/publish.yml"


_MAX_PROVENANCE_BYTES = 512 * 1024


_MAX_PYPI_JSON_BYTES = 4 * 1024 * 1024


_MAX_MANIFEST_BYTES = 64 * 1024


_MAX_WHEEL_BYTES = 256 * 1024 * 1024


_READ_CHUNK_BYTES = 1024 * 1024


_REQUEST_TIMEOUT_SECONDS = 60.0


_DOWNLOAD_DEADLINE_SECONDS = 600.0


_USER_AGENT = "HOL-Guard-Native-Update"


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


class _Readable(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


Opener = Callable[[urllib.request.Request], AbstractContextManager[_Readable]]


_FAILURE_MESSAGES = {
    "native_wheel_platform_unsupported": (
        "This release has no native wheel for this platform. The current installation remains active."
    ),
    "native_wheel_release_unavailable": (
        "The GitHub release for this version is not published (an alpha may have been retracted). "
        "The current installation remains active."
    ),
    "native_wheel_provenance_invalid": (
        "The release provenance could not be verified, so no native wheel was installed. "
        "The current installation remains active."
    ),
    "native_wheel_manifest_invalid": (
        "The native wheel digests published on PyPI for this release could not be read, "
        "so no native wheel was installed. The current installation remains active."
    ),
    "native_wheel_asset_missing": (
        "The release has no native wheel for this platform. The current installation remains active."
    ),
    "native_wheel_download_failed": (
        "The native wheel could not be downloaded. The current installation remains active."
    ),
    "native_wheel_digest_mismatch": (
        "The downloaded wheel did not match its published digest and was discarded. "
        "The current installation remains active."
    ),
}


class NativeWheelError(RuntimeError):
    """The native wheel could not be fetched and verified; callers fail closed."""

    reason_code: str

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)

    @property
    def message(self) -> str:
        return _FAILURE_MESSAGES.get(self.reason_code, "The native wheel could not be installed.")


def is_alpha_version(version: object) -> bool:
    if not isinstance(version, str):
        return False
    try:
        parsed = Version(version.strip())
    except InvalidVersion:
        return False
    return parsed.pre is not None and parsed.pre[0] == "a"


def release_url(version: str, name: str) -> str:
    tag = f"alpha%2Fv{version}" if is_alpha_version(version) else f"v{version}"
    return f"{RELEASE_DOWNLOAD_PREFIX}{tag}/{name}"


def provenance_name(version: str) -> str:
    return f"hol-guard-v{version}.intoto.jsonl"


def parse_provenance_subjects(raw: bytes) -> dict[str, str]:
    """Return ``{artifact name: sha256}`` from a release provenance bundle, or raise."""

    try:
        line = next(item for item in raw.decode("utf-8").splitlines() if item.strip())
        document = json.loads(line)
        envelope = document["dsseEnvelope"]
        if envelope["payloadType"] != "application/vnd.in-toto+json":
            raise NativeWheelError("native_wheel_provenance_invalid")
        statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
        if statement.get("_type") != "https://in-toto.io/Statement/v1":
            raise NativeWheelError("native_wheel_provenance_invalid")
        if not str(statement.get("predicateType", "")).startswith("https://slsa.dev/provenance/"):
            raise NativeWheelError("native_wheel_provenance_invalid")
        workflow = statement["predicate"]["buildDefinition"]["externalParameters"]["workflow"]
        if workflow.get("repository") != _PROVENANCE_REPOSITORY or workflow.get("path") != _PROVENANCE_WORKFLOW_PATH:
            raise NativeWheelError("native_wheel_provenance_invalid")
        subjects: dict[str, str] = {}
        for subject in statement["subject"]:
            name = subject["name"]
            digest = subject["digest"]["sha256"]
            if not isinstance(name, str) or not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
                raise NativeWheelError("native_wheel_provenance_invalid")
            subjects[name] = digest
    except NativeWheelError:
        raise
    except (
        StopIteration,
        KeyError,
        TypeError,
        AttributeError,
        ValueError,
        UnicodeDecodeError,
        binascii.Error,
    ) as error:
        raise NativeWheelError("native_wheel_provenance_invalid") from error
    return subjects


def parse_native_wheel_manifest(raw: bytes, version: str) -> dict[str, str]:
    """Return ``{native wheel name: sha256}`` from the manifest embedded in the pure wheel, or raise."""

    try:
        document = json.loads(raw.decode("utf-8"))
        if (
            not isinstance(document, dict)
            or document.get("schema") != NATIVE_WHEEL_MANIFEST_SCHEMA
            or document.get("version") != version
        ):
            raise NativeWheelError("native_wheel_manifest_invalid")
        wheels = document["wheels"]
        if not isinstance(wheels, dict) or not wheels:
            raise NativeWheelError("native_wheel_manifest_invalid")
        digests: dict[str, str] = {}
        for name, digest in wheels.items():
            if (
                not isinstance(name, str)
                or not isinstance(digest, str)
                or _SHA256_RE.fullmatch(digest) is None
                or native_wheel_platform_tag(name, version) is None
            ):
                raise NativeWheelError("native_wheel_manifest_invalid")
            digests[name] = digest
    except NativeWheelError:
        raise
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
        raise NativeWheelError("native_wheel_manifest_invalid") from error
    return digests


def installed_native_wheel_manifest(version: str, *, package_root: Path | None = None) -> dict[str, str] | None:
    """Read the manifest of the installed pure wheel when it describes ``version``."""

    try:
        with ((package_root or _installed_package_root()) / NATIVE_WHEEL_MANIFEST_NAME).open("rb") as handle:
            raw = handle.read(_MAX_MANIFEST_BYTES + 1)
    except OSError:
        return None
    if len(raw) > _MAX_MANIFEST_BYTES:
        return None
    try:
        return parse_native_wheel_manifest(raw, version)
    except NativeWheelError:
        return None


def published_native_digests(open_url: Opener, version: str, *, package_root: Path | None) -> dict[str, str]:
    if is_alpha_version(version):
        provenance = _read_bounded(open_url, release_url(version, provenance_name(version)), _MAX_PROVENANCE_BYTES)
        return parse_provenance_subjects(provenance)
    installed = installed_native_wheel_manifest(version, package_root=package_root)
    if installed is not None:
        return installed
    return _pypi_native_wheel_manifest(open_url, version)


def _pypi_native_wheel_manifest(open_url: Opener, version: str) -> dict[str, str]:
    """Download the pure wheel PyPI publishes for ``version`` and read its embedded manifest."""

    raw = _read_bounded(open_url, f"{PYPI_JSON_PREFIX}{version}/json", _MAX_PYPI_JSON_BYTES)
    pure_name = f"hol_guard-{version}-py3-none-any.whl"
    try:
        files = json.loads(raw.decode("utf-8"))["urls"]
        entry = next(item for item in files if isinstance(item, dict) and item.get("filename") == pure_name)
        url = entry["url"]
        digest = entry["digests"]["sha256"]
    except StopIteration as error:
        raise NativeWheelError("native_wheel_manifest_invalid") from error
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
        raise NativeWheelError("native_wheel_manifest_invalid") from error
    if (
        not isinstance(url, str)
        or not url.startswith(PYPI_FILES_PREFIX)
        or not isinstance(digest, str)
        or _SHA256_RE.fullmatch(digest) is None
    ):
        raise NativeWheelError("native_wheel_manifest_invalid")
    directory = Path(tempfile.mkdtemp(prefix="hol-guard-pure-"))
    try:
        target = directory / pure_name
        if download_to_file(open_url, url, target) != digest:
            raise NativeWheelError("native_wheel_digest_mismatch")
        try:
            with zipfile.ZipFile(target) as archive:
                info = archive.getinfo(NATIVE_WHEEL_MANIFEST_MEMBER)
                if info.file_size > _MAX_MANIFEST_BYTES:
                    raise NativeWheelError("native_wheel_manifest_invalid")
                manifest = archive.read(info)
        except (KeyError, OSError, zipfile.BadZipFile) as error:
            raise NativeWheelError("native_wheel_manifest_invalid") from error
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    return parse_native_wheel_manifest(manifest, version)


def native_wheel_platform_tag(name: str, version: str) -> str | None:
    try:
        distribution, wheel_version, _build, tags = parse_wheel_filename(name)
    except (InvalidWheelFilename, InvalidVersion):
        return None
    if canonicalize_name(distribution) != "hol-guard" or wheel_version != Version(version):
        return None
    if "/" in name or "\\" in name or len(tags) != 1:
        return None
    tag = next(iter(tags))
    if tag.interpreter != "py3" or tag.abi != "none" or tag.platform == "any":
        return None
    return tag.platform


def default_opener(policy: ManagedNetworkPolicy | None) -> Opener:
    def open_url(request: urllib.request.Request) -> AbstractContextManager[_Readable]:
        return managed_urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS, policy=policy)

    return open_url


def _request(url: str) -> urllib.request.Request:
    if not url.startswith((RELEASE_DOWNLOAD_PREFIX, PYPI_JSON_PREFIX, PYPI_FILES_PREFIX)):
        raise NativeWheelError("native_wheel_download_failed")
    accept = "application/json" if url.startswith(PYPI_JSON_PREFIX) else "application/octet-stream"
    return urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, "Accept": accept})


def _http_failure(error: urllib.error.HTTPError) -> NativeWheelError:
    error.close()
    return NativeWheelError("native_wheel_release_unavailable" if error.code == 404 else "native_wheel_download_failed")


def _read_bounded(open_url: Opener, url: str, limit: int) -> bytes:
    deadline = time.monotonic() + _REQUEST_TIMEOUT_SECONDS
    try:
        with open_url(_request(url)) as response:
            payload = bytearray()
            while len(payload) <= limit:
                if time.monotonic() >= deadline:
                    raise NativeWheelError("native_wheel_download_failed")
                chunk = response.read(min(_READ_CHUNK_BYTES, limit + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
    except urllib.error.HTTPError as error:
        raise _http_failure(error) from error
    except (ManagedNetworkError, OSError, TimeoutError, urllib.error.URLError) as error:
        raise NativeWheelError("native_wheel_download_failed") from error
    if not payload or len(payload) > limit:
        raise NativeWheelError("native_wheel_download_failed")
    return bytes(payload)


def download_to_file(open_url: Opener, url: str, target: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    deadline = time.monotonic() + _DOWNLOAD_DEADLINE_SECONDS
    try:
        with open_url(_request(url)) as response, target.open("xb") as handle:
            while True:
                if time.monotonic() >= deadline:
                    raise NativeWheelError("native_wheel_download_failed")
                chunk = response.read(_READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_WHEEL_BYTES:
                    raise NativeWheelError("native_wheel_download_failed")
                digest.update(chunk)
                handle.write(chunk)
    except urllib.error.HTTPError as error:
        raise _http_failure(error) from error
    except (ManagedNetworkError, OSError, TimeoutError, urllib.error.URLError) as error:
        raise NativeWheelError("native_wheel_download_failed") from error
    if total == 0:
        raise NativeWheelError("native_wheel_download_failed")
    return digest.hexdigest()


def pypi_native_wheel_tags(open_url: Opener, version: str) -> set[str]:
    """Return the platform tags of the native wheels PyPI lists for ``version``."""

    raw = _read_bounded(open_url, f"{PYPI_JSON_PREFIX}{version}/json", _MAX_PYPI_JSON_BYTES)
    try:
        files = json.loads(raw.decode("utf-8"))["urls"]
        names = [item.get("filename") for item in files if isinstance(item, dict)]
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
        raise NativeWheelError("native_wheel_manifest_invalid") from error
    return {tag for name in names if isinstance(name, str) and (tag := native_wheel_platform_tag(name, version))}
