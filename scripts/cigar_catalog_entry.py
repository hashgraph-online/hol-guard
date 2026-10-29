#!/usr/bin/env python3
"""Draft exact CIGAR catalog data from approved wheels; never qualify a release.

Maintainer tooling only. The native preparer repeats path, byte and tree checks.
The supplied upstream manifest must have independently established provenance.
No package installation, SDK import, resolution or source build runs here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

MAX_FILES = 8192
MAX_BYTES = 256 * 1024 * 1024


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def producer_label(value: object) -> bool:
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,127}", value) is not None
        and ".." not in value
    )


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def inspect_wheel(path: Path) -> tuple[dict, dict[str, bytes], list[str], str]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("wheel input must be a bounded regular file")
    wheel_bytes = path.read_bytes()
    files = {}
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if not 0 < len(entries) <= MAX_FILES:
            raise ValueError("wheel entry limit exceeded")
        size = 0
        for item in entries:
            name = item.filename
            parts = PurePosixPath(name).parts
            if (
                not name.isascii()
                or name.startswith("/")
                or "\\" in name
                or ":" in name
                or not parts
                or any(p in {".", ".."} for p in parts)
                or any(p.lower().endswith((".pth", ".egg-link", ".data")) for p in parts)
                or len(parts) > 24
                or item.flag_bits & 1
                or ((item.external_attr >> 16) & 0o170000) not in (0, 0o100000, 0o040000)
            ):
                raise ValueError("unsupported wheel member")
            if item.is_dir():
                continue
            size += item.file_size
            if item.file_size > 128 * 1024 * 1024 or size > MAX_BYTES or name in files:
                raise ValueError("wheel expansion or duplicate limit")
            files[name] = archive.read(item)
    metadata_paths = [name for name in files if re.fullmatch(r"[^/]+\.dist-info/METADATA", name)]
    if len(metadata_paths) != 1:
        raise ValueError("expected exactly one wheel metadata record")
    metadata = BytesParser().parsebytes(files[metadata_paths[0]], headersonly=True)
    if any(len(metadata.get_all(key, [])) != 1 for key in ("Name", "Version")):
        raise ValueError("invalid wheel identity headers")
    distribution = canonical_name(metadata["Name"])
    version = str(Version(metadata["Version"]))
    expected_info = f"{distribution.replace('-', '_')}-{version}.dist-info"
    if metadata_paths[0] != expected_info + "/METADATA":
        raise ValueError("noncanonical dist-info layout")
    wheel = BytesParser().parsebytes(files[expected_info + "/WHEEL"], headersonly=True)
    if wheel["Wheel-Version"] != "1.0":
        raise ValueError("unsupported Wheel-Version")
    python_headers = metadata.get_all("Requires-Python", [])
    if len(python_headers) > 1:
        raise ValueError("duplicate Requires-Python headers")
    python_requires = python_headers[0].strip() if python_headers else ""
    if (
        len(python_requires) > 256
        or not python_requires.isascii()
        or any(ord(c) < 32 or ord(c) == 127 for c in python_requires)
    ):
        raise ValueError("invalid Requires-Python metadata")
    if python_requires:
        SpecifierSet(python_requires)
    lock = {
        "distribution": distribution,
        "version": version,
        "filename": path.name,
        "sha256": sha256(wheel_bytes),
        "bytes": len(wheel_bytes),
        "source": {"kind": "offline_bundle"},
        "requires_python": python_requires or None,
    }
    return lock, files, metadata.get_all("Requires-Dist", []), python_requires


def apply_dependency_origins(locks: list[dict], origins: list[str]) -> None:
    dependencies = {lock["filename"]: lock for lock in locks[1:]}
    seen = set()
    for text in origins:
        filename, separator, url = text.partition("=")
        match = re.fullmatch(
            r"https://files\.pythonhosted\.org"
            r"(/packages/[0-9a-f]{2}/[0-9a-f]{2}/[0-9a-f]{60}/([A-Za-z0-9_.-]+\.whl))",
            url,
        )
        if (
            not separator
            or filename not in dependencies
            or filename in seen
            or not match
            or match[2] != filename
            or len(match[1]) > 400
        ):
            raise ValueError("dependency origin must identify one exact locked files.pythonhosted.org wheel")
        seen.add(filename)
        dependencies[filename]["source"] = {"kind": "pypi_file", "path": match[1]}


def draft(args: argparse.Namespace) -> dict:
    manifest_bytes = args.release_manifest.read_bytes()
    if len(manifest_bytes) > 1024 * 1024:
        raise ValueError("release manifest too large")
    manifest = json.loads(manifest_bytes)
    if (
        manifest["schema"] != "cigar.context-sdk-distribution-release.v1"
        or not re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"])
        or not re.fullmatch(r"[A-Za-z0-9_:-]{1,128}", args.build_id)
    ):
        raise ValueError("invalid release/source identity")
    python_version = Version(args.python_version)
    if (
        len(python_version.release) != 3
        or python_version.release[:2] != (3, 14)
        or python_version.epoch
        or python_version.is_prerelease
        or python_version.is_postrelease
        or python_version.local is not None
    ):
        raise ValueError("expected a final CPython 3.14 patch version")
    target_python = str(python_version)
    all_files = {}
    locks, requirements = [], {}
    environment = default_environment()
    environment.update(
        {
            "python_version": "3.14",
            "python_full_version": target_python,
            "implementation_version": target_python,
            "implementation_name": "cpython",
            "platform_python_implementation": "CPython",
            "extra": "",
        }
    )
    system, machine = {"darwin-arm64": ("Darwin", "arm64")}[args.platform]
    environment.update(
        {"platform_system": system, "sys_platform": "darwin", "platform_machine": machine, "os_name": "posix"}
    )
    for path in [args.sdk_wheel, *args.dependency_wheel]:
        lock, files, deps, python_requires = inspect_wheel(path)
        if lock["distribution"] in requirements:
            raise ValueError("duplicate distribution")
        if python_requires and not SpecifierSet(python_requires).contains(target_python):
            raise ValueError("wheel does not support the qualified Python")
        if all_files.keys() & files.keys():
            raise ValueError("wheel namespace collision")
        all_files.update(files)
        locks.append(lock)
        requirements[lock["distribution"]] = deps
    if locks[0]["distribution"] != "hol-cigar" or locks[0]["version"] != manifest["release"]:
        raise ValueError("SDK wheel/manifest mismatch")
    payload = next(item for item in manifest["payloads"] if item["file"] == args.sdk_wheel.name)
    if payload["sha256"] != locks[0]["sha256"] or payload["bytes"] != locks[0]["bytes"]:
        raise ValueError("SDK wheel differs from upstream manifest")
    apply_dependency_origins(locks, getattr(args, "dependency_url", []))
    versions = {lock["distribution"]: lock["version"] for lock in locks}
    for deps in requirements.values():
        for text in deps:
            req = Requirement(text)
            if req.marker and not req.marker.evaluate(environment):
                continue
            if req.url or req.extras or canonical_name(req.name) not in versions:
                raise ValueError("dependency closure is incomplete or unsupported")
            if not req.specifier.contains(versions[canonical_name(req.name)]):
                raise ValueError("dependency lock violates package requirements")
    if len(all_files) > MAX_FILES or sum(map(len, all_files.values())) > MAX_BYTES:
        raise ValueError("combined wheel expansion limit")
    digest = hashlib.sha256(b"guard-cigar-package-tree.v1\0")
    for name, content in sorted(all_files.items()):
        encoded = name.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(sha256(content).encode())
    release = json.loads(all_files["cigar_sdk/release.json"])
    native_root = "cigar_sdk/_native/" + args.platform + "/"
    worker = json.loads(all_files[native_root + "manifest.json"])
    worker_digest = sha256(all_files[native_root + "cigar-context-worker"])
    if (
        release["version"] != locks[0]["version"]
        or worker["sdk_release"] != locks[0]["version"]
        or release["local_context_core_version"] != worker["core_version"]
        or release["local_context_protocol"] != worker["protocol"]
        or worker["sha256"] != worker_digest
        or not producer_label(worker["core_version"])
    ):
        raise ValueError("SDK/worker identity mismatch")
    release_tag = getattr(args, "release_tag", None)
    if release_tag is None:
        release_tag = "v" + locks[0]["version"]
    if not producer_label(release_tag):
        raise ValueError("invalid exact release tag")
    locks[0]["source"] = {"kind": "github_cigar_release", "tag": release_tag}
    build = {
        "identity": {
            "build_id": args.build_id,
            "sdk_version": locks[0]["version"],
            "core_version": worker["core_version"],
            "source_revision": manifest["source_commit"],
            "manifest_sha256": sha256(manifest_bytes),
        },
        "profile_id": "cigar-sdk-v1",
        "channel": "preview" if Version(locks[0]["version"]).is_prerelease else "stable",
        "withdrawn": False,
        "platforms": [
            {
                "platform": args.platform,
                "worker_sha256": worker_digest,
                "package_tree_sha256": digest.hexdigest(),
                "wheel": locks[0],
                "dependencies": locks[1:],
                "qualification": "upstream_only",
                "qualification_receipt_sha256": None,
                "features": [],
            }
        ],
    }
    return {
        "schema": "guard-cigar-release-entry-draft.v1",
        "build": build,
        "files": len(all_files),
        "bytes": sum(map(len, all_files.values())),
        "dependency_closure_checked": True,
        "guard_qualified": False,
        "target_python": {"implementation": "cpython", "version": target_python},
        "provenance_note": "Verify manifest provenance independently; this draft is not catalog authority.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-wheel", type=Path, required=True)
    parser.add_argument("--dependency-wheel", type=Path, action="append", required=True)
    parser.add_argument(
        "--dependency-url",
        action="append",
        default=[],
        metavar="FILENAME=URL",
        help="Optional exact files.pythonhosted.org content-addressed origin for a supplied dependency wheel",
    )
    parser.add_argument("--release-manifest", type=Path, required=True)
    parser.add_argument("--platform", choices=["darwin-arm64"], required=True)
    parser.add_argument("--build-id", required=True)
    parser.add_argument("--release-tag", help="Exact upstream release tag; defaults to v plus the SDK version")
    parser.add_argument(
        "--python-version", required=True, help="Exact final CPython 3.14 patch version being qualified"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = draft(args)
    with args.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "files": result["files"],
                "bytes": result["bytes"],
                "tree_sha256": result["build"]["platforms"][0]["package_tree_sha256"],
                "guard_qualified": False,
            }
        )
    )


if __name__ == "__main__":
    main()
