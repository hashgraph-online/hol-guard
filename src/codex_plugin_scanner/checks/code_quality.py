"""Code quality checks (10 points)."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import CheckResult, Finding, Severity
from ..path_support import resolves_within_root

CODE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
EXCLUDED_DIRS = {"node_modules", ".git", "dist", ".next", "coverage", "__pycache__", ".venv", "venv"}

EVAL_RE = re.compile(r"\beval\s*\(")
FUNCTION_RE = re.compile(r"new\s+Function\s*\(")
INTERPOLATED_TEMPLATE_PATTERN = r"`[^`]*\$\{[^}]+\}[^`]*`"
TS_TEMPLATE_SUFFIX_PATTERN = r"(?:[ \t]+(?:as|satisfies)[ \t]+[^;\n]+)?"
SHELL_CALL_PATTERN = r"(?:execSync|spawnSync|exec|spawn)"
SHELL_RECEIVER_PATTERN = (
    r"(?<![\w$])(?:child_process|childProcess|cp|"
    r"require\s*\(\s*['\"](?:node:)?child_process['\"]\s*\))"
)
DIRECT_SHELL_TEMPLATE_RE = re.compile(
    rf"(?<![\w.]){SHELL_CALL_PATTERN}\s*\(\s*{INTERPOLATED_TEMPLATE_PATTERN}",
    re.S,
)
MEMBER_SHELL_TEMPLATE_RE = re.compile(
    rf"{SHELL_RECEIVER_PATTERN}\s*\.\s*{SHELL_CALL_PATTERN}\s*\(\s*{INTERPOLATED_TEMPLATE_PATTERN}",
    re.S,
)
INTERPOLATED_TEMPLATE_ASSIGNMENT_RE = re.compile(
    rf"\b(?:export\s+)?(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)"
    rf"(?:\s*:\s*[^=;\n]+)?\s*=\s*{INTERPOLATED_TEMPLATE_PATTERN}"
    rf"{TS_TEMPLATE_SUFFIX_PATTERN}[ \t]*;?",
    re.S,
)


def _find_code_files(plugin_dir: Path, files: tuple[Path, ...] | None = None) -> list[Path]:
    if files is not None:
        return [
            path
            for path in files
            if path.is_file()
            and not path.is_symlink()
            and path.suffix in CODE_EXTS
            and resolves_within_root(plugin_dir, path, require_exists=True)
        ]
    discovered: list[Path] = []
    for p in plugin_dir.rglob("*"):
        if not p.is_file() or p.suffix not in CODE_EXTS:
            continue
        if any(part in EXCLUDED_DIRS for part in p.parts):
            continue
        if not resolves_within_root(plugin_dir, p, require_exists=True):
            continue
        discovered.append(p)
    return discovered


def _shell_call_uses_variable(content: str, variable: str) -> bool:
    escaped_variable = re.escape(variable)
    variable_boundary = r"(?![\w$])"
    direct_call = re.compile(rf"(?<![\w.]){SHELL_CALL_PATTERN}\s*\(\s*{escaped_variable}{variable_boundary}")
    member_call = re.compile(
        rf"{SHELL_RECEIVER_PATTERN}\s*\.\s*{SHELL_CALL_PATTERN}\s*\(\s*"
        rf"{escaped_variable}{variable_boundary}"
    )
    return bool(direct_call.search(content) or member_call.search(content))


def _has_shell_injection_pattern(content: str) -> bool:
    if DIRECT_SHELL_TEMPLATE_RE.search(content) or MEMBER_SHELL_TEMPLATE_RE.search(content):
        return True

    for assignment in INTERPOLATED_TEMPLATE_ASSIGNMENT_RE.finditer(content):
        if _shell_call_uses_variable(content[assignment.end() :], assignment.group("name")):
            return True
    return False


def check_no_eval(plugin_dir: Path, files: tuple[Path, ...] | None = None) -> CheckResult:
    findings: list[str] = []
    for fpath in _find_code_files(plugin_dir, files):
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if EVAL_RE.search(content):
            findings.append(f"{fpath.relative_to(plugin_dir)}: eval()")
        if FUNCTION_RE.search(content):
            findings.append(f"{fpath.relative_to(plugin_dir)}: new Function()")
    if not findings:
        return CheckResult(
            name="No eval or Function constructor",
            passed=True,
            points=5,
            max_points=5,
            message="No eval() or new Function() usage detected",
        )
    return CheckResult(
        name="No eval or Function constructor",
        passed=False,
        points=0,
        max_points=5,
        message=f"Found: {', '.join(findings[:3])}",
        findings=tuple(
            Finding(
                rule_id="DANGEROUS_DYNAMIC_EXECUTION",
                severity=Severity.HIGH,
                category="code-quality",
                title="Dynamic code execution detected",
                description=f"{entry} uses eval() or new Function().",
                remediation="Remove dynamic code evaluation and replace it with explicit control flow.",
                file_path=entry.split(":")[0],
            )
            for entry in findings
        ),
    )


def check_no_shell_injection(plugin_dir: Path, files: tuple[Path, ...] | None = None) -> CheckResult:
    findings: list[str] = []
    for fpath in _find_code_files(plugin_dir, files):
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if _has_shell_injection_pattern(content):
            findings.append(str(fpath.relative_to(plugin_dir)))
    if not findings:
        return CheckResult(
            name="No shell injection patterns",
            passed=True,
            points=5,
            max_points=5,
            message="No shell injection patterns detected",
        )
    return CheckResult(
        name="No shell injection patterns",
        passed=False,
        points=0,
        max_points=5,
        message=f"Shell injection patterns in: {', '.join(findings)}",
        findings=tuple(
            Finding(
                rule_id="SHELL_INJECTION_PATTERN",
                severity=Severity.HIGH,
                category="code-quality",
                title="Potential shell injection pattern detected",
                description=f"{path} interpolates untrusted values into a shell execution call.",
                remediation="Pass arguments as structured arrays and validate user-controlled input before execution.",
                file_path=path,
            )
            for path in findings
        ),
    )


def run_code_quality_checks(plugin_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_no_eval(plugin_dir),
        check_no_shell_injection(plugin_dir),
    )
