"""Verify that HOL Guard runs from one exact, ordinary wheel installation."""

# pyright: reportAny=false, reportUnusedCallResult=false

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import site
import subprocess
import sys
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Final, cast

_SHA256: Final = re.compile(r"[0-9a-f]{64}")
_SOURCE_MARKERS: Final = ("/hol-guard-source", "/workspace/src", "/app/src")


def _is_within(path: Path, root: Path) -> bool:
    try:
        _ = path.relative_to(root)
    except ValueError:
        return False
    return True


def _module_origin(value: object) -> Path:
    if not isinstance(value, str):
        raise RuntimeError("module-origin-unavailable")
    return Path(value).resolve()


def _site_roots() -> tuple[Path, ...]:
    candidates = [Path(value).resolve() for value in site.getsitepackages()]
    user_site = site.getusersitepackages()
    candidates.append(Path(user_site).resolve())
    return tuple(dict.fromkeys(candidates))


def editable_pth_violations(site_roots: tuple[Path, ...]) -> tuple[str, ...]:
    """Return privacy-safe reason codes for source-bearing path configuration."""

    violations: set[str] = set()
    for root in site_roots:
        if not root.is_dir():
            continue
        for path in root.glob("*.pth"):
            lowered_name = path.name.casefold()
            if lowered_name.startswith("__editable__") or "editable" in lowered_name:
                violations.add("editable-pth-name")
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError):
                violations.add("unreadable-pth")
                continue
            for raw_line in lines:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                lowered = line.casefold().replace("\\", "/")
                if any(marker in lowered for marker in _SOURCE_MARKERS):
                    violations.add("source-bearing-pth")
                    continue
                if line.startswith("import "):
                    if "editable" in lowered:
                        violations.add("source-bearing-pth")
                    continue
                candidate = Path(line)
                resolved = (candidate if candidate.is_absolute() else path.parent / candidate).resolve()
                if resolved.exists() and not any(_is_within(resolved, site_root) for site_root in site_roots):
                    violations.add("external-pth-path")
    return tuple(sorted(violations))


def source_path_violations(paths: list[str], site_roots: tuple[Path, ...]) -> tuple[str, ...]:
    """Reject import paths that can shadow the installed distribution."""

    violations: set[str] = set()
    for raw_path in paths:
        if not raw_path:
            continue
        normalized = raw_path.casefold().replace("\\", "/")
        if any(marker in normalized for marker in _SOURCE_MARKERS):
            violations.add("source-marker-on-sys-path")
        candidate = Path(raw_path)
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        package_candidate = resolved / "codex_plugin_scanner"
        if package_candidate.exists() and not any(_is_within(package_candidate, root) for root in site_roots):
            violations.add("source-package-on-sys-path")
    return tuple(sorted(violations))


def direct_url_violations(distribution: importlib.metadata.Distribution) -> tuple[str, ...]:
    raw = distribution.read_text("direct_url.json")
    if raw is None:
        return ()
    try:
        raw_payload: object = json.loads(raw)
    except json.JSONDecodeError:
        return ("invalid-direct-url",)
    if not isinstance(raw_payload, dict):
        return ("invalid-direct-url",)
    payload = cast(dict[str, object], raw_payload)
    directory = payload.get("dir_info")
    if isinstance(directory, dict):
        directory_payload = cast(dict[str, object], directory)
        if directory_payload.get("editable") is True:
            return ("editable-direct-url",)
    url = payload.get("url")
    if not isinstance(url, str) or not url.casefold().endswith(".whl"):
        return ("non-wheel-direct-url",)
    return ()


def distribution_record_violations(
    distribution: importlib.metadata.Distribution,
    required_paths: Mapping[str, Path],
) -> tuple[str, ...]:
    """Prove required runtime files are owned and hashed by this distribution."""

    files = distribution.files
    if files is None:
        return ("distribution-record-missing",)
    records: dict[Path, list[importlib.metadata.PackagePath]] = {}
    for entry in files:
        try:
            installed_path = Path(str(distribution.locate_file(entry))).resolve()
        except OSError:
            continue
        records.setdefault(installed_path, []).append(entry)

    violations: set[str] = set()
    for label, required_path in required_paths.items():
        entries = records.get(required_path.resolve(), [])
        if len(entries) != 1:
            violations.add(
                f"{label}-distribution-record-ambiguous" if entries else f"{label}-not-owned-by-distribution"
            )
            continue
        file_hash = entries[0].hash
        if file_hash is None or file_hash.mode != "sha256":
            violations.add(f"{label}-distribution-hash-missing")
            continue
        observed = (
            base64.urlsafe_b64encode(hashlib.sha256(required_path.read_bytes()).digest()).rstrip(b"=").decode("ascii")
        )
        if observed != file_hash.value:
            violations.add(f"{label}-distribution-hash-mismatch")
    return tuple(sorted(violations))


def wheel_package_violations(
    distribution: importlib.metadata.Distribution,
    wheel_path: Path,
) -> tuple[str, ...]:
    """Reconcile every installed Guard package file to the exact wheel bytes."""

    expected: dict[str, str] = {}
    try:
        with zipfile.ZipFile(wheel_path) as archive:
            for info in archive.infolist():
                name = info.filename
                if info.is_dir() or not name.startswith("codex_plugin_scanner/"):
                    continue
                if name.startswith("/") or ".." in Path(name).parts:
                    return ("wheel-package-path-invalid",)
                expected[name] = _urlsafe_sha256(archive.read(info))
    except (OSError, zipfile.BadZipFile):
        return ("wheel-archive-invalid",)
    if not expected:
        return ("wheel-package-empty",)

    files = distribution.files
    if files is None:
        return ("distribution-record-missing",)
    records: dict[str, list[importlib.metadata.PackagePath]] = {}
    for entry in files:
        records.setdefault(str(entry).replace("\\", "/"), []).append(entry)

    violations: set[str] = set()
    installed_paths: set[Path] = set()
    for name, wheel_hash in expected.items():
        entries = records.get(name, [])
        if len(entries) != 1:
            violations.add("package-distribution-record-ambiguous" if entries else "package-file-unowned")
            continue
        entry = entries[0]
        installed_path = Path(str(distribution.locate_file(entry))).resolve()
        installed_paths.add(installed_path)
        if installed_path.is_symlink() or not installed_path.is_file():
            violations.add("package-file-not-regular")
            continue
        installed_hash = _urlsafe_sha256(installed_path.read_bytes())
        if installed_hash != wheel_hash:
            violations.add("package-file-wheel-hash-mismatch")
        record_hash = entry.hash
        if record_hash is None or record_hash.mode != "sha256":
            violations.add("package-distribution-hash-missing")
        elif record_hash.value != wheel_hash:
            violations.add("package-distribution-hash-mismatch")

    package_root = Path(str(distribution.locate_file("codex_plugin_scanner"))).resolve()
    if package_root.is_dir():
        actual_paths = {
            path.resolve()
            for path in package_root.rglob("*")
            if path.is_file() and not path.is_symlink() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        }
        if actual_paths != installed_paths:
            violations.add("package-file-inventory-mismatch")
    else:
        violations.add("package-root-missing")
    return tuple(sorted(violations))


def _urlsafe_sha256(payload: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")


def verify_installation(expected_version: str, expected_wheel_sha256: str, wheel_path: Path) -> dict[str, object]:
    if _SHA256.fullmatch(expected_wheel_sha256) is None:
        raise ValueError("expected wheel SHA-256 is invalid")
    observed_wheel_sha256 = hashlib.sha256(wheel_path.read_bytes()).hexdigest()
    if observed_wheel_sha256 != expected_wheel_sha256:
        raise RuntimeError("wheel-sha256-mismatch")

    distribution = importlib.metadata.distribution("hol-guard")
    if distribution.version != expected_version:
        raise RuntimeError("installed-version-mismatch")
    import codex_plugin_scanner

    module_file = _module_origin(codex_plugin_scanner.__file__)
    site_roots = _site_roots()
    if not any(_is_within(module_file, root) for root in site_roots):
        raise RuntimeError("module-not-in-site-packages")

    executable = shutil.which("hol-guard")
    if executable is None:
        raise RuntimeError("console-entrypoint-missing")
    executable_path = Path(executable).resolve()

    violations = (
        *editable_pth_violations(site_roots),
        *source_path_violations(list(sys.path), site_roots),
        *direct_url_violations(distribution),
        *distribution_record_violations(distribution, {"module": module_file, "console": executable_path}),
        *wheel_package_violations(distribution, wheel_path),
    )
    if violations:
        raise RuntimeError("origin-ambiguity:" + ",".join(sorted(set(violations))))
    if os.environ.get("PYTHONPATH", "").strip():
        raise RuntimeError("pythonpath-not-empty")

    version_result = subprocess.run(
        [str(executable_path), "--version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    expected_output = f"hol-guard {expected_version}"
    if version_result.stdout.strip() != expected_output:
        raise RuntimeError("console-version-mismatch")

    return {
        "status": "verified",
        "distribution": "hol-guard",
        "version": distribution.version,
        "wheel_sha256": observed_wheel_sha256,
        "origin_class": "ordinary-site-packages",
        "editable": False,
        "pythonpath_empty": True,
        "console_version": expected_output,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-wheel-sha256", required=True)
    parser.add_argument("--wheel-path", type=Path, required=True)
    args = parser.parse_args()
    result = verify_installation(args.expected_version, args.expected_wheel_sha256, args.wheel_path)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
