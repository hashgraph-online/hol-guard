"""DeepSeek Harness ecosystem checks."""

from __future__ import annotations

from ..ecosystems.types import NormalizedPackage
from ..models import CheckResult, Finding, Severity
from ..path_support import is_safe_relative_path
from .ecosystem_common import SEMVER_RE


def _result(name: str, passed: bool, message: str, rule_id: str, description: str) -> CheckResult:
    findings = (
        ()
        if passed
        else (
            Finding(
                rule_id=rule_id,
                severity=Severity.MEDIUM,
                category="deepseek-harness",
                title=message,
                description=description,
                remediation="Update the native DSH declaration in package.json.",
                file_path="package.json",
            ),
        )
    )
    return CheckResult(
        name=name, passed=passed, points=5 if passed else 0, max_points=5, message=message, findings=findings
    )


def run_deepseek_harness_checks(package: NormalizedPackage) -> tuple[CheckResult, ...]:
    """Validate a native DSH package and its Cordis bundle declaration."""

    manifest = package.raw_manifest
    required_ok = all(isinstance(manifest.get(key), str) and manifest[key].strip() for key in ("name", "version"))
    version = manifest.get("version")
    semver_ok = isinstance(version, str) and bool(SEMVER_RE.match(version))
    dsh = manifest.get("dsh")
    bundle = dsh.get("bundle") if isinstance(dsh, dict) else None
    bundle_ok = isinstance(bundle, dict) and bool(bundle)
    patch = bundle.get("patch") if isinstance(bundle, dict) else None
    patch_ok = patch is None or (
        isinstance(patch, str)
        and bool(patch.strip())
        and is_safe_relative_path(package.root_path, patch, require_exists=True)
    )
    return (
        _result(
            "DSH package metadata",
            required_ok and semver_ok,
            "DSH package metadata is valid"
            if required_ok and semver_ok
            else "DSH package requires a name and semantic version",
            "DSH_PACKAGE_METADATA_INVALID",
            "package.json must declare a non-empty name and semantic version.",
        ),
        _result(
            "DSH bundle declaration",
            bundle_ok,
            "DSH bundle declaration is valid" if bundle_ok else "dsh.bundle must be a non-empty object",
            "DSH_BUNDLE_INVALID",
            "Native DSH packages must declare at least one bundle entry.",
        ),
        _result(
            "DSH bundle paths",
            patch_ok,
            "DSH bundle paths are safe" if patch_ok else "dsh.bundle.patch must resolve inside the package",
            "DSH_BUNDLE_PATH_UNSAFE",
            "The declared bundle patch is missing or escapes the package root.",
        ),
    )
