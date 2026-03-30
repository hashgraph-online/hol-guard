"""Operational security checks for automation and supply-chain hygiene."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import CheckResult, Finding, Severity

USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", re.MULTILINE)
WRITE_ALL_RE = re.compile(r"^\s*permissions:\s*write-all\b", re.MULTILINE)
PRIVILEGED_TRIGGER_RE = re.compile(r"\bpull_request_target\b|\bworkflow_run\s*:", re.MULTILINE)
UNTRUSTED_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.event\.workflow_run\.head_(?:sha|branch)",
    re.MULTILINE,
)
SHA_PIN_RE = re.compile(r"^[0-9a-fA-F]{40}$")
REQUIREMENTS_PIN_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^=\s]+$")
DEPENDABOT_ECOSYSTEM_RE = re.compile(r'package-ecosystem:\s*["\']?github-actions["\']?', re.IGNORECASE)

NODE_LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")
PYTHON_LOCKFILES = ("uv.lock", "poetry.lock", "Pipfile.lock", "requirements.lock")
DEPENDENCY_MANIFESTS = ("package.json", "pyproject.toml", "requirements.txt")


def _not_applicable(name: str, message: str) -> CheckResult:
    return CheckResult(
        name=name,
        passed=True,
        points=0,
        max_points=0,
        message=message,
        applicable=False,
    )


def _workflow_files(plugin_dir: Path) -> tuple[Path, ...]:
    workflows_dir = plugin_dir / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return ()
    return tuple(sorted(path for path in workflows_dir.rglob("*") if path.suffix in {".yml", ".yaml"}))


def _read_workflow_text(workflow_files: tuple[Path, ...]) -> list[tuple[Path, str]]:
    contents: list[tuple[Path, str]] = []
    for workflow in workflow_files:
        try:
            contents.append((workflow, workflow.read_text(encoding="utf-8", errors="ignore")))
        except OSError:
            continue
    return contents


def _dependency_surface(plugin_dir: Path) -> dict[str, bool]:
    return {name: (plugin_dir / name).exists() for name in DEPENDENCY_MANIFESTS}


def _requirements_exactly_pinned(requirements_file: Path) -> bool:
    try:
        lines = requirements_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return False

    pinned: list[str] = []
    for line in lines:
        normalized = line.strip()
        if not normalized or normalized.startswith("#") or normalized.startswith(("-e ", "--")):
            continue
        if normalized.startswith(("git+", "http://", "https://")):
            return False
        pinned.append(normalized)
    return bool(pinned) and all(REQUIREMENTS_PIN_RE.match(line) for line in pinned)


def _has_lockfiles(plugin_dir: Path, dependency_surface: dict[str, bool]) -> bool:
    node_locked = not dependency_surface["package.json"] or any((plugin_dir / name).exists() for name in NODE_LOCKFILES)
    python_lock_exists = any((plugin_dir / name).exists() for name in PYTHON_LOCKFILES)
    requirements_pinned = dependency_surface["requirements.txt"] and _requirements_exactly_pinned(
        plugin_dir / "requirements.txt"
    )

    python_locked = True
    if dependency_surface["pyproject.toml"] or dependency_surface["requirements.txt"]:
        python_locked = python_lock_exists or requirements_pinned
    return node_locked and python_locked


def check_actions_pinned(plugin_dir: Path) -> CheckResult:
    workflow_files = _workflow_files(plugin_dir)
    if not workflow_files:
        return _not_applicable("Third-party GitHub Actions pinned to SHAs", "No GitHub Actions workflows found.")

    unpinned: list[tuple[str, str]] = []
    for workflow, content in _read_workflow_text(workflow_files):
        for match in USES_RE.findall(content):
            reference = match.strip()
            if reference.startswith(("./", "docker://")):
                continue
            if "@" not in reference:
                unpinned.append((str(workflow.relative_to(plugin_dir)), reference))
                continue
            _, ref = reference.rsplit("@", 1)
            if not SHA_PIN_RE.match(ref):
                unpinned.append((str(workflow.relative_to(plugin_dir)), reference))

    if not unpinned:
        return CheckResult(
            name="Third-party GitHub Actions pinned to SHAs",
            passed=True,
            points=5,
            max_points=5,
            message="All third-party GitHub Actions and reusable workflows are pinned to immutable SHAs.",
        )

    return CheckResult(
        name="Third-party GitHub Actions pinned to SHAs",
        passed=False,
        points=0,
        max_points=5,
        message=f"Unpinned GitHub Actions found: {', '.join(f'{path}:{ref}' for path, ref in unpinned[:3])}",
        findings=tuple(
            Finding(
                rule_id="GITHUB_ACTION_UNPINNED",
                severity=Severity.MEDIUM,
                category="operational-security",
                title="GitHub Action is not pinned to an immutable commit SHA",
                description=f'{path} references "{reference}" instead of a full 40-character commit SHA.',
                remediation="Pin third-party GitHub Actions and reusable workflows to a full commit SHA.",
                file_path=path,
                source="native",
            )
            for path, reference in unpinned
        ),
    )


def check_no_write_all_permissions(plugin_dir: Path) -> CheckResult:
    workflow_files = _workflow_files(plugin_dir)
    if not workflow_files:
        return _not_applicable("No write-all GitHub Actions permissions", "No GitHub Actions workflows found.")

    issues: list[str] = []
    for workflow, content in _read_workflow_text(workflow_files):
        if WRITE_ALL_RE.search(content):
            issues.append(str(workflow.relative_to(plugin_dir)))

    if not issues:
        return CheckResult(
            name="No write-all GitHub Actions permissions",
            passed=True,
            points=4,
            max_points=4,
            message="No GitHub Actions workflow requests write-all permissions.",
        )

    return CheckResult(
        name="No write-all GitHub Actions permissions",
        passed=False,
        points=0,
        max_points=4,
        message=f"Broad workflow permissions found in: {', '.join(issues)}",
        findings=tuple(
            Finding(
                rule_id="GITHUB_ACTIONS_WRITE_ALL",
                severity=Severity.MEDIUM,
                category="operational-security",
                title="GitHub Actions workflow requests write-all permissions",
                description=f"{path} requests write-all permissions for the workflow token.",
                remediation="Replace write-all with the narrowest required permissions block.",
                file_path=path,
                source="native",
            )
            for path in issues
        ),
    )


def check_no_privileged_untrusted_checkout(plugin_dir: Path) -> CheckResult:
    workflow_files = _workflow_files(plugin_dir)
    if not workflow_files:
        return _not_applicable("No privileged untrusted checkout patterns", "No GitHub Actions workflows found.")

    issues: list[str] = []
    for workflow, content in _read_workflow_text(workflow_files):
        if not PRIVILEGED_TRIGGER_RE.search(content):
            continue
        if "actions/checkout" not in content and "git checkout" not in content:
            continue
        if UNTRUSTED_REF_RE.search(content):
            issues.append(str(workflow.relative_to(plugin_dir)))

    if not issues:
        return CheckResult(
            name="No privileged untrusted checkout patterns",
            passed=True,
            points=5,
            max_points=5,
            message="No privileged workflow checks out untrusted branch content.",
        )

    return CheckResult(
        name="No privileged untrusted checkout patterns",
        passed=False,
        points=0,
        max_points=5,
        message=f"Privileged workflow checks out untrusted code in: {', '.join(issues)}",
        findings=tuple(
            Finding(
                rule_id="GITHUB_ACTIONS_UNTRUSTED_CHECKOUT",
                severity=Severity.HIGH,
                category="operational-security",
                title="Privileged workflow checks out untrusted code",
                description=(
                    f"{path} combines a privileged trigger with a pull-request or workflow-run head ref checkout."
                ),
                remediation="Avoid checking out untrusted refs from privileged workflow contexts.",
                file_path=path,
                source="native",
            )
            for path in issues
        ),
    )


def check_dependabot_configured(plugin_dir: Path) -> CheckResult:
    workflow_files = _workflow_files(plugin_dir)
    dependency_surface = _dependency_surface(plugin_dir)
    if not workflow_files and not any(dependency_surface.values()):
        return _not_applicable(
            "Dependabot configured for automation surfaces",
            "No workflows or dependency manifests found.",
        )

    dependabot_files = [plugin_dir / ".github" / "dependabot.yml", plugin_dir / ".github" / "dependabot.yaml"]
    dependabot_file = next((path for path in dependabot_files if path.exists()), None)
    if dependabot_file is None:
        return CheckResult(
            name="Dependabot configured for automation surfaces",
            passed=False,
            points=0,
            max_points=3,
            message="Dependabot is not configured for workflows or dependency manifests.",
            findings=(
                Finding(
                    rule_id="DEPENDABOT_MISSING",
                    severity=Severity.LOW,
                    category="operational-security",
                    title="Dependabot configuration is missing",
                    description="Automation or dependency surfaces exist, but .github/dependabot.yml is missing.",
                    remediation="Add Dependabot updates for GitHub Actions and dependency manifests.",
                    file_path=".github/dependabot.yml",
                    source="native",
                ),
            ),
        )

    try:
        content = dependabot_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        content = ""

    has_github_actions_updates = DEPENDABOT_ECOSYSTEM_RE.search(content) is not None
    if workflow_files and not has_github_actions_updates:
        return CheckResult(
            name="Dependabot configured for automation surfaces",
            passed=False,
            points=0,
            max_points=3,
            message="Dependabot config is present but does not include GitHub Actions updates.",
            findings=(
                Finding(
                    rule_id="DEPENDABOT_GITHUB_ACTIONS_MISSING",
                    severity=Severity.LOW,
                    category="operational-security",
                    title="Dependabot is not configured for GitHub Actions",
                    description="Workflow files exist, but Dependabot does not declare the github-actions ecosystem.",
                    remediation="Add a github-actions update entry to .github/dependabot.yml.",
                    file_path=str(dependabot_file.relative_to(plugin_dir)),
                    source="native",
                ),
            ),
        )

    return CheckResult(
        name="Dependabot configured for automation surfaces",
        passed=True,
        points=3,
        max_points=3,
        message="Dependabot is configured for the detected automation surfaces.",
    )


def check_dependency_lockfiles(plugin_dir: Path) -> CheckResult:
    dependency_surface = _dependency_surface(plugin_dir)
    if not any(dependency_surface.values()):
        return _not_applicable("Dependency manifests have lockfiles", "No dependency manifests found.")

    if _has_lockfiles(plugin_dir, dependency_surface):
        return CheckResult(
            name="Dependency manifests have lockfiles",
            passed=True,
            points=3,
            max_points=3,
            message="Detected dependency manifests are paired with lockfiles or pinned requirements.",
        )

    missing: list[str] = []
    if dependency_surface["package.json"] and not any((plugin_dir / name).exists() for name in NODE_LOCKFILES):
        missing.append("package.json")
    if dependency_surface["pyproject.toml"] and not any((plugin_dir / name).exists() for name in PYTHON_LOCKFILES):
        missing.append("pyproject.toml")
    if dependency_surface["requirements.txt"] and not _requirements_exactly_pinned(plugin_dir / "requirements.txt"):
        missing.append("requirements.txt")

    return CheckResult(
        name="Dependency manifests have lockfiles",
        passed=False,
        points=0,
        max_points=3,
        message=f"Dependency lockfiles or pinned requirements missing for: {', '.join(missing)}",
        findings=tuple(
            Finding(
                rule_id="DEPENDENCY_LOCKFILE_MISSING",
                severity=Severity.MEDIUM,
                category="operational-security",
                title="Dependency manifest is missing a lockfile",
                description=f"{name} is present without a corresponding lockfile or pinned dependency snapshot.",
                remediation=(
                    "Commit a lockfile or use fully pinned requirements for reproducible dependency resolution."
                ),
                file_path=name,
                source="native",
            )
            for name in missing
        ),
    )


def run_operational_security_checks(plugin_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_actions_pinned(plugin_dir),
        check_no_write_all_permissions(plugin_dir),
        check_no_privileged_untrusted_checkout(plugin_dir),
        check_dependabot_configured(plugin_dir),
        check_dependency_lockfiles(plugin_dir),
    )
