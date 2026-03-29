"""Codex Plugin Scanner - security and best-practices scanner for Codex CLI plugins."""

from .models import GRADE_LABELS, CategoryResult, CheckResult, Finding, ScanOptions, ScanResult, Severity, get_grade
from .scanner import scan_plugin

__version__ = "1.1.0"
__all__ = [
    "GRADE_LABELS",
    "CategoryResult",
    "CheckResult",
    "Finding",
    "ScanOptions",
    "ScanResult",
    "Severity",
    "get_grade",
    "scan_plugin",
]
