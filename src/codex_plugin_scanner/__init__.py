"""Codex Plugin Scanner - security and best-practices scanner for Codex CLI plugins."""

from .models import GRADE_LABELS, CategoryResult, CheckResult, ScanResult, get_grade
from .scanner import scan_plugin

__version__ = "1.0.1"
__all__ = [
    "GRADE_LABELS",
    "CategoryResult",
    "CheckResult",
    "ScanResult",
    "get_grade",
    "scan_plugin",
]
