"""Plugin Scanner package exports."""

from typing import TYPE_CHECKING, Any

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
from .version import __version__

# Reload must resolve the current scanner function, not a previously cached one.
globals().pop("scan_plugin", None)

if TYPE_CHECKING:
    from .scanner import scan_plugin


def __getattr__(name: str) -> Any:
    """Load scanning dependencies when the public scanner is requested."""

    if name == "scan_plugin":
        from .scanner import scan_plugin

        globals()[name] = scan_plugin
        return scan_plugin
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """Keep the lazy scanner visible alongside the eager public exports."""

    return sorted(set(globals()) | set(__all__))


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
