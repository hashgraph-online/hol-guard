"""Read policy packs authenticated by the normal installed release channel.

This profile supplies no remote update authority or freshness claim. Its Root
must be bound by both installed native manifests to the same executable bytes.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import threading
import zipfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

from ..extension_builder.io import read_bytes
from ..extension_builder.native_source_compiler import NativeSourceCompilerError, run_source_compiler
from .authority import decode
from .containers import location, maximum, member

MANIFEST = "command-pack-bundle.v1.json"
PREFIX = "codex_plugin_scanner/guard/contracts/data/extensions/command-pack-bundle/"
ROOT = PREFIX + MANIFEST
MAX_BYTES = 512 * 1024 * 1024
MAX_FILES = 8192


def validate(data, *, source_sha, engine, compiler=None):
    return _native_metadata("root", data=data.decode("utf-8"), source_sha=source_sha, engine=engine, compiler=compiler)


def descriptor(data, *, source_sha, engine):
    return _native_metadata("descriptor", data=data.decode("utf-8"), source_sha=source_sha, engine=engine)


def validate_compatibility(value, extensions, *, compiler=None):
    _native_metadata("compatibility", value=value, extensions=extensions, compiler=compiler)


def target(value, *, source_sha):
    # These checks constrain local IO paths; Root and policy admission are native.
    if not isinstance(value, dict):
        raise ValueError("installed bundle location invalid")
    name = value.get("member", value.get("asset", ""))
    match = re.fullmatch(r"(object|pack)-([0-9a-f]{64})\.(json|zip)", name) if isinstance(name, str) else None
    if match is None or match[3] != ("json" if match[1] == "object" else "zip"):
        raise ValueError("installed bundle asset invalid")
    location(value, match[2], match[1])
    if not value["tag"].startswith("extension-data-" + source_sha + "-0.0-"):
        raise ValueError("installed bundle asset source differs")
    return name, match[2], match[1]


def asset_path(relative, *, source_sha):
    if (
        re.fullmatch(
            r"assets/extension-data-"
            + re.escape(source_sha)
            + r"-0\.0-[0-9]{6}/(?:(?:objects|packs)-[0-9]{6}\.zip|object-[0-9a-f]{64}\.json|pack-[0-9a-f]{64}\.zip)",
            relative,
        )
        is None
    ):
        raise ValueError("installed bundle asset path invalid")


def _package() -> Path:
    meipass = getattr(sys, "_MEIPASS", None)
    if bool(getattr(sys, "frozen", False)) and isinstance(meipass, str):
        return Path(meipass) / "codex_plugin_scanner"
    return Path(__file__).absolute().parents[2]


def compatibility_payloads(family: str) -> tuple[dict[str, Any], ...] | None:
    """Explicit offline legacy API; never load the library on decision paths.

    Only genuine legacy absence permits fallback. An advertised installed bundle
    must authenticate through both release manifests before any metadata reads.
    """
    if family not in {"commands", "mcp"}:
        raise ValueError("unknown compatibility metadata family")
    if not advertised():
        return None
    bundle = load_installed_bundle()

    @lru_cache(maxsize=2)
    def read_asset(path: Path, *, limit: int) -> bytes:
        # Offline traversals commonly read thousands of members in one bounded
        # container. Keep at most two containers, scoped to this explicit read.
        return read_bytes(path, limit=limit)

    try:
        result = run_source_compiler(
            "bundle-compatibility",
            {
                "family": family,
                "source_sha": bundle.source_sha,
                "engine": bundle.engine,
                "data": bundle.data.decode("utf-8"),
                "max_bytes": MAX_BYTES,
            },
            fetch=lambda reference: bundle._fetch(
                cast(dict[str, Any], reference["location"]), cast(int, reference["length"]), read_asset
            ),
        )
    except NativeSourceCompilerError as error:
        raise ValueError(f"installed compatibility metadata unavailable: {error}") from error
    return tuple(cast(list[dict[str, Any]], result["payloads"])) if result["available"] else None


_ANSWERS: dict[str, tuple[tuple[object, ...], object]] = {}
_ANSWERS_LOCK = threading.Lock()


def _installed_files(package: Path) -> tuple[object, ...]:
    """Identify every installed file the presence and identity answers read.

    Replacing or modifying any of them, or adding or removing one, changes this
    value, so the next call asks native again. Native still verifies the
    executable bytes before every run.
    """
    from ..extension_builder import native_source_compiler

    def identity(path: Path) -> tuple[int, ...] | None:
        try:
            st = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            return None
        return (st.st_mode, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

    bundle = package / "guard/contracts/data/extensions/command-pack-bundle"
    paths = [bundle, bundle / MANIFEST]
    for directory in dict.fromkeys((package / "_native", native_source_compiler._NATIVE_PACKAGE)):
        paths.append(directory)
        if directory.is_dir():
            paths.extend(sorted(directory.iterdir()))
    return tuple((str(path), identity(path)) for path in paths)


def _reused(name: str, answer):  # type: ignore[no-untyped-def]
    """Reuse a successful answer while the installed files stay the same."""
    try:
        files = _installed_files(_package())
    except OSError:
        return answer()
    with _ANSWERS_LOCK:
        cached = _ANSWERS.get(name)
    if cached is not None and cached[0] == files:
        return cached[1]
    value = answer()
    with _ANSWERS_LOCK:
        _ANSWERS[name] = (files, value)
    return value


def advertised() -> bool:
    """Ask the native reader whether this installation carries a bundle.

    Only genuine legacy absence skips loading; any other state loads and
    fails closed in the factory.
    """
    return cast(bool, _reused("advertised", _advertised))


def _advertised() -> bool:
    package = _package()
    directory = package / "guard/contracts/data/extensions/command-pack-bundle"
    manifests = []
    for name in ("runtime-manifest.json", "source-compiler-manifest.json"):
        path = package / "_native" / name
        present = path.exists() or path.is_symlink()
        manifests.append(decode(read_bytes(path, limit=65536)) if present else None)
    answer = _native_metadata(
        "installed-presence", bundle=directory.exists() or directory.is_symlink(), manifests=manifests
    )
    return answer["advertised"] is True


@dataclass(frozen=True, slots=True, init=False)
class VerifiedInstalledBundle:
    data: bytes
    source_sha: str
    digest: str
    engine: str
    kind = "installed-release-bundle"

    def __new__(cls) -> VerifiedInstalledBundle:
        raise TypeError("installed bundles must be loaded from the installed release")

    def manifest(self) -> dict[str, Any]:
        return cast(dict[str, Any], decode(self.data))

    def fetch(self, target_location: dict[str, Any], max_bytes: int) -> bytes:
        return self._fetch(target_location, max_bytes, read_bytes)

    def preparation_fetch(self):
        """Keep one bounded container for the current native preparation."""
        reader = lru_cache(maxsize=1)(read_bytes)
        return lambda location, maximum: self._fetch(location, maximum, reader)

    def _fetch(self, target_location: dict[str, Any], max_bytes: int, read_asset) -> bytes:
        name, _, kind = target(target_location, source_sha=self.source_sha)
        limit = 65536 if kind == "object" else 32 * 1024 * 1024
        if type(max_bytes) is not int or not 0 < max_bytes <= limit:
            raise ValueError("installed bundle fetch bounds invalid")
        path = (
            _package()
            / "guard/contracts/data/extensions/command-pack-bundle/assets"
            / target_location["tag"]
            / target_location["asset"]
        )
        if not path.exists() and not path.is_symlink() and kind == "pack" and "member" not in target_location:
            # The fixed native factory checks the installed release/executable
            # binding and constructs the public URL. No selector, caller URL,
            # remote Root or new publisher authority enters this path.
            from . import lifecycle
            from .transport import download

            request = lifecycle.invoke(
                "installed-asset", **lifecycle.release_evidence(self), location=target_location, length=max_bytes
            )
            try:
                data = download(request["url"], max_bytes)
            except OSError as error:
                raise ValueError("Optional protection data is unavailable; existing controls were retained.") from error
        elif "member" in target_location:
            try:
                data = member(
                    read_asset(path, limit=maximum(target_location["asset"])), target_location["asset"], name, max_bytes
                )
            except zipfile.BadZipFile as error:
                raise ValueError("installed bundle container invalid") from error
        else:
            data = read_asset(path, limit=max_bytes)
        # Integrity belongs to whoever consumes these bytes: the native blob
        # reader for the authoring transport, the object store for a located
        # reference. Both reject a member that misses its length or digest.
        return data


def load_installed_bundle() -> VerifiedInstalledBundle:
    # Each answer hashes, copies and starts the 120 MB runtime; preview, apply
    # and refresh ask several times per change.
    return cast(VerifiedInstalledBundle, _reused("installed", _load_installed_bundle))


def _load_installed_bundle() -> VerifiedInstalledBundle:
    package = _package()
    native = package / "_native"
    runtime = decode(read_bytes(native / "runtime-manifest.json", limit=65536))
    compiler = decode(read_bytes(native / "source-compiler-manifest.json", limit=65536))
    evidence = {"runtime_manifest": runtime, "compiler_manifest": compiler}
    plan = _native_metadata("installed-plan", **evidence)
    binary = read_bytes(native / cast(str, plan["executable"]), limit=cast(int, plan["size"]))
    data = read_bytes(package / "guard/contracts/data/extensions/command-pack-bundle" / MANIFEST, limit=65536)
    identity = _native_metadata(
        "installed",
        **evidence,
        binary_length=len(binary),
        binary_digest=hashlib.sha256(binary).hexdigest(),
        data=data.decode("utf-8"),
    )
    result = object.__new__(VerifiedInstalledBundle)
    for name, value in (
        ("data", bytes(data)),
        ("source_sha", identity["source_sha"]),
        ("digest", identity["digest"]),
        ("engine", identity["engine"]),
    ):
        object.__setattr__(result, name, value)
    return result


def _native_metadata(operation: str, *, compiler=None, **fields: object) -> dict[str, object]:
    try:
        configured = compiler or (
            os.environ.get("HOL_GUARD_BUILD_SOURCE_COMPILER")
            if operation in {"root", "descriptor", "compatibility"}
            else None
        )
        request = {"operation": operation, **fields}
        if configured:
            return run_source_compiler("bundle-metadata", request, compiler=Path(configured))
        return run_source_compiler("bundle-metadata", request)
    except NativeSourceCompilerError as error:
        raise ValueError(f"installed bundle metadata unavailable: {error}") from error
