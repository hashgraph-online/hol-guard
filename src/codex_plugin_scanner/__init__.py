"""Plugin Scanner package exports."""

from typing import TYPE_CHECKING

from .version import __version__

if TYPE_CHECKING:
    from .models import (
        GRADE_LABELS,
        CategoryResult,
        CheckResult,
        Finding,
        PackageSummary,
        ScanOptions,
        ScanResult,
        Severity,
        get_grade,
    )
    from .scanner import scan_plugin

_MODEL_EXPORTS = frozenset(
    {
        "GRADE_LABELS",
        "CategoryResult",
        "CheckResult",
        "Finding",
        "PackageSummary",
        "ScanOptions",
        "ScanResult",
        "Severity",
        "get_grade",
    }
)

__all__ = [
    "GRADE_LABELS",
    "CategoryResult",
    "CheckResult",
    "Finding",
    "PackageSummary",
    "ScanOptions",
    "ScanResult",
    "Severity",
    "__version__",
    "get_grade",
    "scan_plugin",
]


def __getattr__(name: str) -> object:
    if name in _MODEL_EXPORTS:
        from . import models

        value = getattr(models, name)
        globals()[name] = value
        return value
    if name == "scan_plugin":
        from .scanner import scan_plugin

        globals()[name] = scan_plugin
        return scan_plugin
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
