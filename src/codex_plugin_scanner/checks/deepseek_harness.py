"""DeepSeek Harness ecosystem checks."""

from __future__ import annotations

from ..deepseek_harness_support import validate_dsh_package
from ..ecosystems.types import NormalizedPackage
from ..models import CheckResult, Finding, Severity


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

    validation = validate_dsh_package(package)
    return (
        _result(
            "DSH package metadata",
            validation.metadata_ok,
            "DSH package metadata is valid"
            if validation.metadata_ok
            else "DSH package requires a name and semantic version",
            "DSH_PACKAGE_METADATA_INVALID",
            "package.json must declare a non-empty name and semantic version.",
        ),
        _result(
            "DSH bundle declaration",
            validation.bundle_ok,
            "DSH bundle declaration is valid" if validation.bundle_ok else "dsh.bundle must be a non-empty object",
            "DSH_BUNDLE_INVALID",
            "Native DSH packages must declare at least one bundle entry.",
        ),
        _result(
            "DSH bundle paths",
            validation.patch_ok,
            "DSH bundle paths are safe"
            if validation.patch_ok
            else "dsh.bundle.patch must reference a regular in-package file",
            "DSH_BUNDLE_PATH_UNSAFE",
            "The declared bundle patch is missing or escapes the package root.",
        ),
        _result(
            "DSH Cordis runtime entry point",
            validation.runtime_ok,
            "DSH runtime exports apply(ctx)"
            if validation.runtime_ok
            else "DSH runtime entry point must export apply(ctx)",
            "DSH_RUNTIME_APPLY_MISSING",
            "package.json main/exports must reference a regular in-package module exporting Cordis apply(ctx).",
        ),
    )
