"""Codex Plugin Scanner - security and best-practices scanner for Codex CLI plugins."""

from .models import (
    GRADE_LABELS,
    CategoryResult,
    CheckResult,
    Finding,
    ScanOptions,
    ScanResult,
    Severity,
    get_grade,
)
from .scanner import scan_plugin
from .version import __version__

__all__ = [
    "GRADE_LABELS",
    "CategoryResult",
    "CheckResult",
    "Finding",
    "ScanOptions",
    "ScanResult",
    "Severity",
    "__version__",
    "get_grade",
    "scan_plugin",
]
