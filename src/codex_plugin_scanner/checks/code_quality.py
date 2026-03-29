"""Code quality checks (10 points)."""

from __future__ import annotations

import re
from pathlib import Path

from ..models import CheckResult

CODE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
EXCLUDED_DIRS = {"node_modules", ".git", "dist", ".next", "coverage", "__pycache__", ".venv", "venv"}

EVAL_RE = re.compile(r"\beval\s*\(")
FUNCTION_RE = re.compile(r"new\s+Function\s*\(")
SHELL_INJECT_RE = re.compile(
    r"`[^`]*\$\{[^}]+\}[^`]*`"
    r"[\s\S]{0,30}"
    r"\b(exec|spawn|execSync|spawnSync|os\.system|subprocess)\b"
)


def _find_code_files(plugin_dir: Path) -> list[Path]:
    files = []
    for p in plugin_dir.rglob("*"):
        if not p.is_file() or p.suffix not in CODE_EXTS:
            continue
        if any(part in EXCLUDED_DIRS for part in p.parts):
            continue
        files.append(p)
    return files


def check_no_eval(plugin_dir: Path) -> CheckResult:
    findings: list[str] = []
    for fpath in _find_code_files(plugin_dir):
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
    )


def check_no_shell_injection(plugin_dir: Path) -> CheckResult:
    findings: list[str] = []
    for fpath in _find_code_files(plugin_dir):
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if SHELL_INJECT_RE.search(content):
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
    )


def run_code_quality_checks(plugin_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_no_eval(plugin_dir),
        check_no_shell_injection(plugin_dir),
    )
