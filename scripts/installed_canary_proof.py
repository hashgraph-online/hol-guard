"""Create and verify immutable evidence for an installed Guard PR canary."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.metadata
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, cast

from packaging.utils import parse_wheel_filename
from packaging.version import InvalidVersion, Version

PROJECT: Final = "hol-guard"
SCHEMA: Final = "hol-guard.installed-canary-subject.v1"
_SHA256: Final = re.compile(r"[0-9a-f]{64}")


class InstalledCanaryError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_version(value: object) -> str:
    if not isinstance(value, str):
        raise InstalledCanaryError("Canary version must be a string")
    version = Version(value)
    if str(version) != value or version.local is not None:
        raise InstalledCanaryError("Canary version must be canonical and public")
    return value


def _source_sha(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise InstalledCanaryError("Canary source SHA must be a full lowercase commit SHA")
    return value


def _guard_wheel(directory: Path, version: str) -> Path:
    wheels = sorted(directory.glob("hol_guard-*.whl"))
    matching: list[Path] = []
    for wheel in wheels:
        name, parsed_version, _build, _tags = parse_wheel_filename(wheel.name)
        if name == PROJECT and str(parsed_version) == version:
            matching.append(wheel)
    if len(matching) != 1 or matching[0].is_symlink():
        raise InstalledCanaryError("Expected exactly one regular Guard wheel for the canary version")
    return matching[0]


def write_subject(dist_dir: Path, version: str, source_sha: str, output: Path) -> dict[str, object]:
    canonical_version = _canonical_version(version)
    canonical_sha = _source_sha(source_sha)
    wheel = _guard_wheel(dist_dir, canonical_version)
    subject: dict[str, object] = {
        "schema_version": SCHEMA,
        "project": PROJECT,
        "version": canonical_version,
        "source_sha": canonical_sha,
        "wheel": {"filename": wheel.name, "sha256": sha256_file(wheel)},
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    _ = output.write_text(json.dumps(subject, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return subject


def load_subject(path: Path, *, version: str, source_sha: str) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise InstalledCanaryError("Installed canary proof subject is required")
    try:
        value = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstalledCanaryError("Installed canary proof subject is invalid") from exc
    if not isinstance(value, dict):
        raise InstalledCanaryError("Installed canary proof subject must be an object")
    subject = cast(dict[str, object], value)
    if set(subject) != {"schema_version", "project", "version", "source_sha", "wheel"}:
        raise InstalledCanaryError("Installed canary proof subject has an unexpected shape")
    if subject["schema_version"] != SCHEMA or subject["project"] != PROJECT:
        raise InstalledCanaryError("Installed canary proof subject has the wrong identity")
    if _canonical_version(subject["version"]) != _canonical_version(version):
        raise InstalledCanaryError("Installed canary proof version does not match the PR canary")
    if _source_sha(subject["source_sha"]) != _source_sha(source_sha):
        raise InstalledCanaryError("Installed canary proof source SHA does not match the PR head")
    wheel_value = subject["wheel"]
    if not isinstance(wheel_value, dict):
        raise InstalledCanaryError("Installed canary proof wheel binding is invalid")
    wheel = cast(dict[object, object], wheel_value)
    if set(wheel) != {"filename", "sha256"}:
        raise InstalledCanaryError("Installed canary proof wheel binding is invalid")
    filename, digest = wheel["filename"], wheel["sha256"]
    if not isinstance(filename, str) or Path(filename).name != filename or not filename.endswith(".whl"):
        raise InstalledCanaryError("Installed canary proof wheel filename is invalid")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise InstalledCanaryError("Installed canary proof wheel digest is invalid")
    return subject


def verify_download(subject: Mapping[str, object], directory: Path) -> Path:
    wheel_binding = cast(dict[str, str], subject["wheel"])
    wheel = directory / wheel_binding["filename"]
    if not wheel.is_file() or wheel.is_symlink():
        raise InstalledCanaryError("Verified TestPyPI wheel is missing")
    if sha256_file(wheel) != wheel_binding["sha256"]:
        raise InstalledCanaryError("TestPyPI wheel bytes differ from the build artifact")
    return wheel


def _decode_record_hash(value: str) -> str:
    algorithm, separator, encoded = value.partition("=")
    if algorithm != "sha256" or not separator:
        raise InstalledCanaryError("Installed RECORD contains a non-SHA-256 payload entry")
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + padding).hex()


def _is_within(path: Path, parent: Path) -> bool:
    try:
        _ = path.relative_to(parent)
    except ValueError:
        return False
    return True


def _regular_file_set(root: Path, installation_root: Path, *, label: str) -> set[str]:
    if root.is_symlink() or not root.is_dir():
        raise InstalledCanaryError(f"Installed {label} root is not a regular directory")
    files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise InstalledCanaryError(f"Installed {label} contains a symbolic link")
        if path.is_file():
            files.add(path.relative_to(installation_root).as_posix())
        elif not path.is_dir():
            raise InstalledCanaryError(f"Installed {label} contains a non-regular filesystem node")
    return files


def _record_path(distribution: importlib.metadata.Distribution) -> Path:
    dist_info_name = f"{distribution.metadata['Name'].replace('-', '_')}-{distribution.version}.dist-info"
    record_path = Path(str(distribution.locate_file(f"{dist_info_name}/RECORD")))
    if not record_path.is_file():
        candidates = tuple(path for path in distribution.files or () if str(path).endswith(".dist-info/RECORD"))
        if len(candidates) != 1:
            raise InstalledCanaryError("Installed distribution has no unique RECORD")
        record_path = Path(str(distribution.locate_file(candidates[0])))
    return record_path


def verify_installed_record(distribution: importlib.metadata.Distribution) -> tuple[str, int]:
    record_path = _record_path(distribution)
    verified = 0
    with record_path.open(encoding="utf-8", newline="") as handle:
        for relative, digest, size in csv.reader(handle):
            payload = Path(str(distribution.locate_file(relative))).resolve()
            if not digest:
                if payload != record_path.resolve() and payload.suffix != ".pyc":
                    raise InstalledCanaryError(f"Installed payload lacks a RECORD digest: {relative}")
                continue
            if not payload.is_file() or sha256_file(payload) != _decode_record_hash(digest):
                raise InstalledCanaryError(f"Installed payload differs from RECORD: {relative}")
            if size and payload.stat().st_size != int(size):
                raise InstalledCanaryError(f"Installed payload size differs from RECORD: {relative}")
            verified += 1
    if verified < 1:
        raise InstalledCanaryError("Installed RECORD verified no payload files")
    return sha256_file(record_path), verified


def _wheel_origin(parsed_origin: urllib.parse.SplitResult, expected_digest: str) -> Path:
    if parsed_origin.netloc not in ("", "localhost"):
        raise InstalledCanaryError("Installed wheel origin must be a local verified artifact")
    wheel = Path(urllib.request.url2pathname(parsed_origin.path)).resolve()
    if not wheel.is_file() or wheel.is_symlink() or sha256_file(wheel) != expected_digest:
        raise InstalledCanaryError("Installed wheel origin no longer matches the verified artifact")
    return wheel


def verify_wheel_payloads(distribution: importlib.metadata.Distribution, wheel: Path) -> int:
    verified = 0
    installation_root = Path(str(distribution.locate_file(""))).resolve()
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = {member.filename for member in archive.infolist() if not member.is_dir()}
        for member in archive.infolist():
            if member.is_dir() or member.filename.endswith(".dist-info/RECORD"):
                continue
            installed_path = Path(str(distribution.locate_file(member.filename))).resolve()
            if not _is_within(installed_path, installation_root) or not installed_path.is_file():
                raise InstalledCanaryError(f"Wheel payload is absent from the installation: {member.filename}")
            expected_digest = hashlib.sha256(archive.read(member)).hexdigest()
            if sha256_file(installed_path) != expected_digest or installed_path.stat().st_size != member.file_size:
                raise InstalledCanaryError(f"Installed payload differs from the verified wheel: {member.filename}")
            verified += 1
    package_prefix = "codex_plugin_scanner/"
    installed_package_files = _regular_file_set(
        installation_root / package_prefix,
        installation_root,
        label="package",
    )
    if installed_package_files != {name for name in wheel_names if name.startswith(package_prefix)}:
        raise InstalledCanaryError("Installed package contains files not present in the verified wheel")

    record_members = {name for name in wheel_names if name.endswith(".dist-info/RECORD")}
    if len(record_members) != 1:
        raise InstalledCanaryError("Verified wheel has no unique RECORD")
    dist_info_prefix = next(iter(record_members)).removesuffix("RECORD")
    generated_metadata = {
        f"{dist_info_prefix}{name}" for name in ("INSTALLER", "REQUESTED", "direct_url.json", "uv_cache.json")
    }
    installed_dist_info = _regular_file_set(
        installation_root / dist_info_prefix,
        installation_root,
        label="metadata",
    )
    allowed_dist_info = {name for name in wheel_names if name.startswith(dist_info_prefix)} | generated_metadata
    if not installed_dist_info <= allowed_dist_info:
        raise InstalledCanaryError("Installed metadata contains files not produced by the verified wheel installer")

    record_path = _record_path(distribution)
    with record_path.open(encoding="utf-8", newline="") as handle:
        installed_record_names = {row[0] for row in csv.reader(handle)}
    scripts_dir, suffix = ("Scripts", ".exe") if os.name == "nt" else ("bin", "")
    entry_points = distribution.entry_points
    generated_scripts = {
        f"../../../{scripts_dir}/{entry.name}{suffix}" for entry in entry_points if entry.group == "console_scripts"
    }
    if not installed_record_names <= wheel_names | generated_metadata | generated_scripts:
        raise InstalledCanaryError("Installed RECORD contains payloads not produced by the verified wheel installer")
    if verified < 1:
        raise InstalledCanaryError("Verified wheel contains no installable payloads")
    return verified


def verify_install(subject: Mapping[str, object], repo_root: Path) -> dict[str, object]:
    if sys.pycache_prefix is None:
        raise InstalledCanaryError("Installed canary verification requires an isolated Python cache prefix")
    cache_root = Path(sys.pycache_prefix).resolve()
    if not cache_root.is_absolute() or _is_within(cache_root, repo_root.resolve()):
        raise InstalledCanaryError("Installed canary Python cache must be isolated outside the checkout")
    import codex_plugin_scanner

    distribution = importlib.metadata.distribution(PROJECT)
    if distribution.version != subject["version"]:
        raise InstalledCanaryError("Installed package version does not match the canary subject")
    module_origin = Path(codex_plugin_scanner.__file__ or "").resolve()
    if not module_origin.is_file() or _is_within(module_origin, repo_root.resolve()):
        raise InstalledCanaryError("Guard imported from the checkout instead of the installed wheel")
    installation_root = Path(str(distribution.locate_file(""))).resolve()
    if _is_within(cache_root, installation_root):
        raise InstalledCanaryError("Installed canary Python cache must be isolated outside the installation")
    direct_url_text = distribution.read_text("direct_url.json")
    if direct_url_text is None:
        raise InstalledCanaryError("Installed wheel has no immutable direct origin")
    direct_url = cast(object, json.loads(direct_url_text))
    wheel_binding = cast(dict[str, str], subject["wheel"])
    origin = cast(dict[str, object], direct_url).get("url") if isinstance(direct_url, dict) else None
    parsed_origin = urllib.parse.urlsplit(origin) if isinstance(origin, str) else None
    if (
        parsed_origin is None
        or parsed_origin.scheme != "file"
        or urllib.parse.unquote(parsed_origin.path).rsplit("/", 1)[-1] != wheel_binding["filename"]
        or parsed_origin.query
        or parsed_origin.fragment != f"sha256={wheel_binding['sha256']}"
    ):
        raise InstalledCanaryError("Installed wheel origin is not bound to the verified artifact digest")
    wheel_origin = _wheel_origin(parsed_origin, wheel_binding["sha256"])
    wheel_entries = verify_wheel_payloads(distribution, wheel_origin)
    record_sha256, record_entries = verify_installed_record(distribution)
    return {
        "project": PROJECT,
        "version": distribution.version,
        "source_sha": subject["source_sha"],
        "wheel_sha256": wheel_binding["sha256"],
        "module_origin": module_origin.relative_to(installation_root).as_posix(),
        "outside_checkout": True,
        "record_sha256": record_sha256,
        "record_entries_verified": record_entries,
        "wheel_entries_verified": wheel_entries,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    write_parser = subparsers.add_parser("write-subject")
    _ = write_parser.add_argument("--dist-dir", type=Path, required=True)
    _ = write_parser.add_argument("--version", required=True)
    _ = write_parser.add_argument("--source-sha", required=True)
    _ = write_parser.add_argument("--output", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify-download")
    _ = verify_parser.add_argument("--subject", type=Path, required=True)
    _ = verify_parser.add_argument("--version", required=True)
    _ = verify_parser.add_argument("--source-sha", required=True)
    _ = verify_parser.add_argument("--download-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    command = cast(str, args.command)
    version = cast(str, args.version)
    source_sha = cast(str, args.source_sha)
    try:
        if command == "write-subject":
            output = write_subject(
                cast(Path, args.dist_dir),
                version,
                source_sha,
                cast(Path, args.output),
            )
        else:
            subject = load_subject(cast(Path, args.subject), version=version, source_sha=source_sha)
            wheel = verify_download(subject, cast(Path, args.download_dir))
            digest = sha256_file(wheel)
            output = {
                "status": "exact",
                "wheel": str(wheel),
                "sha256": digest,
                "requirement": f"{PROJECT} @ {wheel.resolve().as_uri()}#sha256={digest}",
            }
    except (InstalledCanaryError, InvalidVersion, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
