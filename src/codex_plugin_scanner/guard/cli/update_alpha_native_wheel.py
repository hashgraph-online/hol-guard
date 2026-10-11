"""Install the platform-native alpha wheel from the live GitHub prerelease.

Alpha publication uploads only the pure ``py3-none-any`` wheel to PyPI, so an
alpha installed from PyPI has no bundled ``_native/hol-guard-runtime``. The
platform wheels are attached to the ``alpha/v<version>`` GitHub prerelease
together with a build-provenance bundle whose in-toto subjects list the
sha256 of every attached artifact. This module picks the wheel that matches
the running interpreter, downloads it from the release, and verifies its
digest against the provenance subjects before the existing wheel installer
runs.

Trust model: the digest source is the provenance bundle published by the
release workflow on the same prerelease. The statement is checked for the
expected repository and workflow, but the Sigstore signature chain is not
verified here, so this guards against corrupted or mismatched downloads and
binds the wheel to the release's own attestation; it is not an offline proof
of publisher identity beyond the HTTPS release host.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from packaging.tags import sys_tags
from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from ..mdm.contracts import ManagedNetworkPolicy
from ..mdm.network import ManagedNetworkError, managed_urlopen
from ..native_runtime import _bundled_runtime_candidate

RELEASE_DOWNLOAD_PREFIX = "https://github.com/hashgraph-online/hol-guard/releases/download/"
ALPHA_UPDATE_COMMAND = "hol-guard update --alpha"
PUBLISHED_PLATFORM_TAGS = frozenset(
    {
        "macosx_11_0_arm64",
        "macosx_13_0_x86_64",
        "manylinux_2_17_x86_64",
        "win_amd64",
    }
)
_PROVENANCE_REPOSITORY = "https://github.com/hashgraph-online/hol-guard"
_PROVENANCE_WORKFLOW_PATH = ".github/workflows/publish.yml"
_MAX_PROVENANCE_BYTES = 512 * 1024
_MAX_WHEEL_BYTES = 256 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024
_REQUEST_TIMEOUT_SECONDS = 60.0
_DOWNLOAD_DEADLINE_SECONDS = 600.0
_USER_AGENT = "HOL-Guard-Alpha-Update"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_MARKER_NAME = "alpha-native-wheel.json"
_MARKER_SCHEMA_VERSION = 1


class _Readable(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


Opener = Callable[[urllib.request.Request], AbstractContextManager[_Readable]]

_FAILURE_MESSAGES = {
    "alpha_native_platform_unsupported": (
        "This alpha release has no native wheel for this platform. "
        "The current installation remains active; PyPI only carries the pure wheel without the native runtime."
    ),
    "alpha_native_release_unavailable": (
        "The alpha prerelease is no longer published on GitHub (it may have been retracted). "
        "The current installation remains active."
    ),
    "alpha_native_provenance_invalid": (
        "The alpha release provenance could not be verified, so no native wheel was installed. "
        "The current installation remains active."
    ),
    "alpha_native_asset_missing": (
        "The alpha prerelease has no native wheel for this platform. The current installation remains active."
    ),
    "alpha_native_download_failed": (
        "The native alpha wheel could not be downloaded from GitHub. The current installation remains active."
    ),
    "alpha_native_digest_mismatch": (
        "The downloaded native alpha wheel did not match its published digest and was discarded. "
        "The current installation remains active."
    ),
}


class AlphaNativeWheelError(RuntimeError):
    """The native alpha wheel could not be fetched and verified; callers fail closed."""

    reason_code: str

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)

    @property
    def message(self) -> str:
        return _FAILURE_MESSAGES.get(self.reason_code, "The native alpha wheel could not be installed.")


@dataclass(frozen=True, slots=True)
class AlphaNativePlan:
    """Why an alpha update must install the native wheel from the prerelease."""

    version: str
    reason: Literal["upgrade", "repair"]


@dataclass(frozen=True, slots=True)
class AlphaNativeDownload:
    path: Path
    directory: Path
    sha256: str
    version: str

    def cleanup(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)


def is_alpha_version(version: object) -> bool:
    if not isinstance(version, str):
        return False
    try:
        parsed = Version(version.strip())
    except InvalidVersion:
        return False
    return parsed.pre is not None and parsed.pre[0] == "a"


def bundled_native_runtime_missing(candidate: Path | None = None) -> bool:
    return not (candidate or _bundled_runtime_candidate()).is_file()


def native_platform_supported(tags: Iterable[str] | None = None) -> bool:
    """True when this interpreter can install a platform wheel the release publishes."""

    return any(tag in PUBLISHED_PLATFORM_TAGS for tag in (tags if tags is not None else _platform_tags()))


def plan_alpha_native_update(
    *,
    include_alpha: bool,
    current_version: str,
    target_version: str | None,
    runtime_missing: bool,
    platform_supported: bool,
) -> AlphaNativePlan | None:
    """Decide whether the update must install the native wheel from the prerelease."""

    if not include_alpha or not platform_supported:
        # Hosts without a published native wheel keep the ordinary alpha path.
        return None
    if target_version is not None:
        if is_alpha_version(target_version):
            return AlphaNativePlan(version=target_version, reason="upgrade")
        return None
    if is_alpha_version(current_version) and runtime_missing:
        return AlphaNativePlan(version=current_version.strip(), reason="repair")
    return None


def native_runtime_payload(runtime_missing: bool, *, platform_supported: bool = True) -> dict[str, object]:
    if not runtime_missing:
        return {"status": "present", "bundled": True}
    payload: dict[str, object] = {"status": "missing", "bundled": False}
    if platform_supported:
        payload["fix"] = ALPHA_UPDATE_COMMAND
        payload["message"] = (
            "This alpha was installed without the bundled native runtime (the PyPI upload is the pure wheel only). "
            f"Run `{ALPHA_UPDATE_COMMAND}` to install the native wheel from the GitHub prerelease."
        )
    return payload


def failure_payload(payload: dict[str, object], error: AlphaNativeWheelError) -> None:
    payload.update(
        {
            "status": "failed",
            "changed": False,
            "reason_code": error.reason_code,
            "error": error.reason_code,
            "message": error.message,
        }
    )


def prepare_alpha_native_wheel(
    plan: AlphaNativePlan,
    *,
    network_policy: ManagedNetworkPolicy | None,
) -> tuple[AlphaNativeDownload | None, str | None]:
    """Download the native wheel for ``plan``; a retracted repair target is a note, not a failure."""

    try:
        return download_alpha_native_wheel(plan.version, network_policy=network_policy), None
    except AlphaNativeWheelError as error:
        if plan.reason == "repair" and error.reason_code in {
            "alpha_native_release_unavailable",
            "alpha_native_platform_unsupported",
            "alpha_native_asset_missing",
        }:
            return None, f"Could not repair the native runtime: {error.message}"
        raise


def release_url(version: str, name: str) -> str:
    return f"{RELEASE_DOWNLOAD_PREFIX}alpha%2Fv{version}/{name}"


def provenance_name(version: str) -> str:
    return f"hol-guard-v{version}.intoto.jsonl"


def parse_provenance_subjects(raw: bytes) -> dict[str, str]:
    """Return ``{artifact name: sha256}`` from a release provenance bundle, or raise."""

    try:
        line = next(item for item in raw.decode("utf-8").splitlines() if item.strip())
        document = json.loads(line)
        envelope = document["dsseEnvelope"]
        if envelope["payloadType"] != "application/vnd.in-toto+json":
            raise AlphaNativeWheelError("alpha_native_provenance_invalid")
        statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
        if statement.get("_type") != "https://in-toto.io/Statement/v1":
            raise AlphaNativeWheelError("alpha_native_provenance_invalid")
        if not str(statement.get("predicateType", "")).startswith("https://slsa.dev/provenance/"):
            raise AlphaNativeWheelError("alpha_native_provenance_invalid")
        workflow = statement["predicate"]["buildDefinition"]["externalParameters"]["workflow"]
        if workflow.get("repository") != _PROVENANCE_REPOSITORY or workflow.get("path") != _PROVENANCE_WORKFLOW_PATH:
            raise AlphaNativeWheelError("alpha_native_provenance_invalid")
        subjects: dict[str, str] = {}
        for subject in statement["subject"]:
            name = subject["name"]
            digest = subject["digest"]["sha256"]
            if not isinstance(name, str) or not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
                raise AlphaNativeWheelError("alpha_native_provenance_invalid")
            subjects[name] = digest
    except AlphaNativeWheelError:
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
        raise AlphaNativeWheelError("alpha_native_provenance_invalid") from error
    return subjects


def select_native_wheel(
    subjects: dict[str, str],
    version: str,
    *,
    tags: Iterable[str] | None = None,
) -> tuple[str, str]:
    """Pick the best-matching platform wheel for ``version`` from the attested subjects."""

    ranked_tags = list(tags if tags is not None else _platform_tags())
    best: tuple[int, str] | None = None
    for name in sorted(subjects):
        platform_tag = _native_wheel_platform_tag(name, version)
        if platform_tag is None or platform_tag not in ranked_tags:
            continue
        rank = ranked_tags.index(platform_tag)
        if best is None or rank < best[0]:
            best = (rank, name)
    if best is None:
        has_wheel = any(_native_wheel_platform_tag(name, version) is not None for name in subjects)
        raise AlphaNativeWheelError("alpha_native_platform_unsupported" if has_wheel else "alpha_native_asset_missing")
    return best[1], subjects[best[1]]


def download_alpha_native_wheel(
    version: str,
    *,
    network_policy: ManagedNetworkPolicy | None = None,
    opener: Opener | None = None,
    tags: Iterable[str] | None = None,
) -> AlphaNativeDownload:
    """Fetch, verify, and place the native wheel in a private temporary directory."""

    if _SAFE_VERSION_RE.fullmatch(version) is None or not is_alpha_version(version):
        raise AlphaNativeWheelError("alpha_native_release_unavailable")
    open_url = opener or _default_opener(network_policy)
    provenance = _read_bounded(open_url, release_url(version, provenance_name(version)), _MAX_PROVENANCE_BYTES)
    name, expected_sha256 = select_native_wheel(parse_provenance_subjects(provenance), version, tags=tags)
    # mkdtemp creates the directory owner-only (0700).
    directory = Path(tempfile.mkdtemp(prefix="hol-guard-alpha-native-"))
    try:
        target = directory / name
        actual = _download_to_file(open_url, release_url(version, name), target)
        if actual != expected_sha256:
            raise AlphaNativeWheelError("alpha_native_digest_mismatch")
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    return AlphaNativeDownload(path=target, directory=directory, sha256=expected_sha256, version=version)


def record_alpha_native_install(guard_home: Path, *, version: str, sha256: str) -> None:
    """Remember the verified native wheel so later alpha updates keep managing this install."""

    payload = json.dumps(
        {"schema_version": _MARKER_SCHEMA_VERSION, "version": version, "wheel_sha256": sha256},
        sort_keys=True,
    )
    temporary = guard_home / f".{_MARKER_NAME}.{os.getpid()}.tmp"
    try:
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, guard_home / _MARKER_NAME)
    except OSError:
        temporary.unlink(missing_ok=True)


def alpha_native_install_recorded(guard_home: Path, *, archive_sha256: str | None) -> bool:
    """True when the installed wheel's digest matches a native alpha wheel this updater installed."""

    if not archive_sha256:
        return False
    try:
        payload = json.loads((guard_home / _MARKER_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("schema_version") == _MARKER_SCHEMA_VERSION
        and payload.get("wheel_sha256") == archive_sha256
    )


def _platform_tags() -> list[str]:
    tags: list[str] = []
    for tag in sys_tags():
        if (
            tag.interpreter.startswith("py3")
            and tag.abi == "none"
            and tag.platform != "any"
            and tag.platform not in tags
        ):
            tags.append(tag.platform)
    return tags


def _native_wheel_platform_tag(name: str, version: str) -> str | None:
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


def _default_opener(policy: ManagedNetworkPolicy | None) -> Opener:
    def open_url(request: urllib.request.Request) -> AbstractContextManager[_Readable]:
        return managed_urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS, policy=policy)

    return open_url


def _request(url: str) -> urllib.request.Request:
    if not url.startswith(RELEASE_DOWNLOAD_PREFIX):
        raise AlphaNativeWheelError("alpha_native_download_failed")
    return urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "application/octet-stream"})


def _http_failure(error: urllib.error.HTTPError) -> AlphaNativeWheelError:
    error.close()
    return AlphaNativeWheelError(
        "alpha_native_release_unavailable" if error.code == 404 else "alpha_native_download_failed"
    )


def _read_bounded(open_url: Opener, url: str, limit: int) -> bytes:
    deadline = time.monotonic() + _REQUEST_TIMEOUT_SECONDS
    try:
        with open_url(_request(url)) as response:
            payload = bytearray()
            while len(payload) <= limit:
                if time.monotonic() >= deadline:
                    raise AlphaNativeWheelError("alpha_native_download_failed")
                chunk = response.read(min(_READ_CHUNK_BYTES, limit + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
    except urllib.error.HTTPError as error:
        raise _http_failure(error) from error
    except (ManagedNetworkError, OSError, TimeoutError, urllib.error.URLError) as error:
        raise AlphaNativeWheelError("alpha_native_download_failed") from error
    if not payload or len(payload) > limit:
        raise AlphaNativeWheelError("alpha_native_download_failed")
    return bytes(payload)


def _download_to_file(open_url: Opener, url: str, target: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    deadline = time.monotonic() + _DOWNLOAD_DEADLINE_SECONDS
    try:
        with open_url(_request(url)) as response, target.open("xb") as handle:
            while True:
                if time.monotonic() >= deadline:
                    raise AlphaNativeWheelError("alpha_native_download_failed")
                chunk = response.read(_READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_WHEEL_BYTES:
                    raise AlphaNativeWheelError("alpha_native_download_failed")
                digest.update(chunk)
                handle.write(chunk)
    except urllib.error.HTTPError as error:
        raise _http_failure(error) from error
    except (ManagedNetworkError, OSError, TimeoutError, urllib.error.URLError) as error:
        raise AlphaNativeWheelError("alpha_native_download_failed") from error
    if total == 0:
        raise AlphaNativeWheelError("alpha_native_download_failed")
    return digest.hexdigest()
