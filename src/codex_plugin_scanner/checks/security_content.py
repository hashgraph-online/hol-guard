"""Bounded security scan traversal, results, and document checks."""

from __future__ import annotations


def _raise_walk_error(error: OSError) -> None:
    reason = error.strerror or type(error).__name__
    raise _security.ScanInputUnreadableError(f"filesystem traversal failed: {reason}") from error


def _scan_all_files(
    plugin_dir: _security.Path, files: tuple[_security.Path, ...] | None = None
) -> list[_security.Path]:
    """Recursively find all files, skipping excluded dirs."""
    if files is not None:
        discovered = []
        try:
            for path in files:
                metadata = path.lstat()
                if (
                    _security.stat.S_ISREG(metadata.st_mode)
                    and path.suffix.lower() not in _security.BINARY_EXTS
                    and _security.resolves_within_root(plugin_dir, path, require_exists=True)
                ):
                    discovered.append(path.resolve(strict=True))
        except OSError as error:
            reason = error.strerror or type(error).__name__
            raise _security.ScanInputUnreadableError(f"explicit scan input unavailable: {reason}") from error
    else:
        discovered = []
        entries_seen = 0
        try:
            resolved_root = plugin_dir.resolve(strict=True)
        except OSError as error:
            reason = error.strerror or type(error).__name__
            raise _security.ScanInputUnreadableError(f"plugin directory unavailable: {reason}") from error
        for root, dirs, names in _security.os.walk(
            resolved_root,
            topdown=True,
            onerror=_security._raise_walk_error,
            followlinks=False,
        ):
            current = _security.Path(root)
            depth = len(current.relative_to(resolved_root).parts)
            if depth > _security.MAX_SCAN_DEPTH:
                raise _security.ScanBudgetExceededError(f"directory depth exceeded {_security.MAX_SCAN_DEPTH}")
            dirs[:] = sorted(
                name for name in dirs if name not in _security.EXCLUDED_DIRS and not (current / name).is_symlink()
            )
            entries_seen += len(dirs) + len(names)
            if entries_seen > _security.MAX_SCAN_ENTRIES:
                raise _security.ScanBudgetExceededError(f"filesystem entries exceeded {_security.MAX_SCAN_ENTRIES}")
            for name in sorted(names):
                path = current / name
                if path.is_symlink() or not path.is_file() or path.suffix.lower() in _security.BINARY_EXTS:
                    continue
                if not _security.resolves_within_root(resolved_root, path, require_exists=True):
                    continue
                discovered.append(path)

    if len(discovered) > _security.MAX_SCAN_FILES:
        raise _security.ScanBudgetExceededError(f"scannable files exceeded {_security.MAX_SCAN_FILES}")
    total_bytes = 0
    for path in discovered:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > _security.MAX_SCAN_FILE_BYTES:
            raise _security.ScanBudgetExceededError(f"{path.name} exceeded {_security.MAX_SCAN_FILE_BYTES} bytes")
        total_bytes += size
        if total_bytes > _security.MAX_SCAN_TOTAL_BYTES:
            raise _security.ScanBudgetExceededError(f"aggregate input exceeded {_security.MAX_SCAN_TOTAL_BYTES} bytes")
    return discovered


def _has_canonical_apache_license_reference(content: str) -> bool:
    for candidate in _security.LICENSE_URL_RE.findall(content):
        parsed = _security.urlparse(candidate.rstrip(".,;:"))
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.rstrip("/")
        if hostname == "www.apache.org" and path == "/licenses/LICENSE-2.0":
            return True
    return False


def _resource_budget_failure(name: str, *, max_points: int, reason: str) -> _security.CheckResult:
    return _security.CheckResult(
        name=name,
        passed=False,
        points=0,
        max_points=max_points,
        message=f"Security analysis incomplete: {reason}.",
        findings=(
            _security.Finding(
                rule_id="SCAN_RESOURCE_BUDGET_EXCEEDED",
                severity=_security.Severity.MEDIUM,
                category="security",
                title="Security scan resource budget exceeded",
                description=f"The scanner stopped before complete analysis because {reason}.",
                remediation="Reduce generated or vendored scan input, or scan the intended plugin directory directly.",
            ),
        ),
    )


def check_security_md(plugin_dir: _security.Path) -> _security.CheckResult:
    exists = (plugin_dir / "SECURITY.md").exists()
    return _security.CheckResult(
        name="SECURITY.md found",
        passed=exists,
        points=3 if exists else 0,
        max_points=3,
        message="SECURITY.md found" if exists else "SECURITY.md not found",
        findings=()
        if exists
        else (
            _security.Finding(
                rule_id="SECURITY_MD_MISSING",
                severity=_security.Severity.LOW,
                category="security",
                title="SECURITY.md is missing",
                description=(
                    "Plugins should publish a SECURITY.md file for responsible disclosure and support guidance."
                ),
                remediation="Add a SECURITY.md file with reporting guidance and supported versions.",
                file_path="SECURITY.md",
            ),
        ),
    )


def check_license(plugin_dir: _security.Path) -> _security.CheckResult:
    lp = plugin_dir / "LICENSE"
    if not lp.exists():
        return _security.CheckResult(
            name="LICENSE found",
            passed=False,
            points=0,
            max_points=3,
            message="LICENSE file not found",
            findings=(
                _security.Finding(
                    rule_id="LICENSE_MISSING",
                    severity=_security.Severity.LOW,
                    category="security",
                    title="LICENSE file is missing",
                    description="Plugins should ship a LICENSE file so consumers can review usage rights.",
                    remediation="Add a LICENSE file that matches the manifest license metadata.",
                    file_path="LICENSE",
                ),
            ),
        )
    try:
        content = _security.read_text_file_within_root(
            plugin_dir.resolve(strict=True),
            lp,
            max_bytes=_security.MAX_SCAN_FILE_BYTES,
            errors="ignore",
        )
        if "apache" in content.lower() and (
            _security.APACHE_LICENSE_VERSION_RE.search(content)
            or _security._has_canonical_apache_license_reference(content)
        ):
            return _security.CheckResult(
                name="LICENSE found", passed=True, points=3, max_points=3, message="LICENSE found (Apache-2.0)"
            )
        if "MIT" in content and "Permission is hereby granted" in content:
            return _security.CheckResult(
                name="LICENSE found", passed=True, points=3, max_points=3, message="LICENSE found (MIT)"
            )
        return _security.CheckResult(name="LICENSE found", passed=True, points=3, max_points=3, message="LICENSE found")
    except OSError:
        return _security.CheckResult(
            name="LICENSE found", passed=False, points=0, max_points=3, message="LICENSE exists but could not be read"
        )


def _hardcoded_secret_result(findings: list[tuple[str, int]]) -> _security.CheckResult:
    if not findings:
        return _security.CheckResult(
            name="No hardcoded secrets", passed=True, points=7, max_points=7, message="No hardcoded secrets detected"
        )
    shown = [path for path, _line_number in findings[:5]]
    suffix = f" and {len(findings) - 5} more" if len(findings) > 5 else ""
    return _security.CheckResult(
        name="No hardcoded secrets",
        passed=False,
        points=0,
        max_points=7,
        message=f"Hardcoded secrets found in: {', '.join(shown)}{suffix}",
        findings=tuple(
            _security.Finding(
                rule_id="HARDCODED_SECRET",
                severity=_security.Severity.HIGH,
                category="security",
                title="Hardcoded secret detected",
                description=f"Potential secret material was detected in {path}.",
                remediation="Remove the secret from source control and load it securely at runtime.",
                file_path=path,
                line_number=line_number,
            )
            for path, line_number in findings
        ),
    )


def _approval_bypass_result(findings: list[str]) -> _security.CheckResult:
    if not findings:
        return _security.CheckResult(
            name="No approval bypass defaults",
            passed=True,
            points=3,
            max_points=3,
            message="No risky approval or sandbox defaults detected.",
        )

    return _security.CheckResult(
        name="No approval bypass defaults",
        passed=False,
        points=0,
        max_points=3,
        message=f"Risky approval defaults found in: {', '.join(findings)}",
        findings=tuple(
            _security.Finding(
                rule_id="RISKY_APPROVAL_DEFAULT",
                severity=_security.Severity.MEDIUM,
                category="security",
                title="Risky approval or sandbox default detected",
                description=f"{path} contains a dangerous approval or sandbox default.",
                remediation=(
                    "Avoid shipping configurations that default to bypassed approvals or unrestricted sandboxes."
                ),
                file_path=path,
            )
            for path in findings
        ),
    )


def _scan_content_checks(
    plugin_dir: _security.Path,
    files: tuple[_security.Path, ...] | None = None,
    *,
    scan_secrets: bool = True,
    scan_bypass: bool = True,
) -> tuple[_security.CheckResult, _security.CheckResult]:
    """Enumerate once and give both checks the same bounded immutable text.

    Content is retained for one file only. A failure remains attached to its
    check while the other check finishes its applicable input. Independent
    callers can select a single check without changing read/exclusion behavior.
    """

    resolved_plugin_dir = plugin_dir.resolve()
    secret_findings: list[tuple[str, int]] = []
    bypass_findings: list[str] = []
    failures: dict[str, _security.CheckResult] = {}
    checks = {
        "secrets": ("No hardcoded secrets", 7, scan_secrets),
        "bypass": ("No approval bypass defaults", 3, scan_bypass),
    }
    try:
        for file_path in _security._scan_all_files(resolved_plugin_dir, files):
            relative_path = file_path.relative_to(resolved_plugin_dir)
            wants_secrets = scan_secrets and "secrets" not in failures
            wants_bypass = (
                scan_bypass
                and "bypass" not in failures
                and file_path.name.endswith((".json", ".md", ".yaml", ".yml", ".toml"))
            )
            if not wants_secrets and not wants_bypass:
                continue
            try:
                content = _security.read_text_file_within_root(
                    resolved_plugin_dir,
                    file_path,
                    max_bytes=_security.MAX_SCAN_FILE_BYTES,
                    errors="ignore",
                )
            except (OSError, UnicodeError):
                for key, wanted in (("secrets", wants_secrets), ("bypass", wants_bypass)):
                    if wanted:
                        name, points, _enabled = checks[key]
                        failures[key] = _security.unreadable_scan_input_failure(
                            name, max_points=points, path=relative_path.as_posix()
                        )
                continue
            if wants_secrets:
                try:
                    line_number = _security._first_hardcoded_secret_line(relative_path, content)
                    if line_number is not None:
                        secret_findings.append((relative_path.as_posix(), line_number))
                except _security.ScanBudgetExceededError as error:
                    failures["secrets"] = _security._resource_budget_failure(
                        "No hardcoded secrets", max_points=7, reason=str(error)
                    )
            if wants_bypass and any(pattern.search(content) for pattern in _security.RISKY_APPROVAL_PATTERNS):
                bypass_findings.append(relative_path.as_posix())
    except (_security.ScanInputUnreadableError, _security.ScanBudgetExceededError) as error:
        for key, (name, points, enabled) in checks.items():
            if enabled and key not in failures:
                failure = (
                    _security._resource_budget_failure
                    if isinstance(error, _security.ScanBudgetExceededError)
                    else _security.unreadable_scan_input_failure
                )
                failures[key] = failure(name, max_points=points, reason=str(error))
    return (
        failures.get("secrets") or _security._hardcoded_secret_result(secret_findings),
        failures.get("bypass") or _security._approval_bypass_result(bypass_findings),
    )


def check_no_hardcoded_secrets(
    plugin_dir: _security.Path, files: tuple[_security.Path, ...] | None = None
) -> _security.CheckResult:
    return _security._scan_content_checks(plugin_dir, files, scan_bypass=False)[0]


def check_no_approval_bypass_defaults(
    plugin_dir: _security.Path, files: tuple[_security.Path, ...] | None = None
) -> _security.CheckResult:
    return _security._scan_content_checks(plugin_dir, files, scan_secrets=False)[1]


def run_security_checks(plugin_dir: _security.Path) -> tuple[_security.CheckResult, ...]:
    security_md = _security.check_security_md(plugin_dir)
    license_result = _security.check_license(plugin_dir)
    secrets, approval_defaults = _security._scan_content_checks(plugin_dir)
    return (
        security_md,
        license_result,
        secrets,
        _security.check_no_dangerous_mcp(plugin_dir),
        _security.check_mcp_transport_security(plugin_dir),
        approval_defaults,
    )


# Bind after definitions so either the facade or this helper can be imported first.
from . import security as _security  # noqa: E402
