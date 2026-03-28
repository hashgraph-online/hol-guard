"""Codex Plugin Scanner - core scanning engine."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import CategoryResult, CheckResult, ScanResult, get_grade
from .checks.manifest import run_manifest_checks
from .checks.security import run_security_checks
from .checks.best_practices import run_best_practice_checks
from .checks.marketplace import run_marketplace_checks
from .checks.code_quality import run_code_quality_checks


def scan_plugin(plugin_dir: str | Path) -> ScanResult:
    """Scan a Codex plugin directory and return a scored result."""
    resolved = Path(plugin_dir).resolve()

    categories: list[CategoryResult] = [
        CategoryResult(name="Manifest Validation", checks=run_manifest_checks(resolved)),
        CategoryResult(name="Security", checks=run_security_checks(resolved)),
        CategoryResult(name="Best Practices", checks=run_best_practice_checks(resolved)),
        CategoryResult(name="Marketplace", checks=run_marketplace_checks(resolved)),
        CategoryResult(name="Code Quality", checks=run_code_quality_checks(resolved)),
    ]

    score = sum(c.points for cat in categories for c in cat.checks)
    grade = get_grade(score)

    return ScanResult(
        score=score,
        grade=grade,
        categories=tuple(categories),
        timestamp=datetime.now(timezone.utc).isoformat(),
        plugin_dir=str(resolved),
    )


def load_manifest(plugin_dir: Path) -> dict | None:
    """Load plugin.json from .codex-plugin/ directory."""
    manifest_path = plugin_dir / ".codex-plugin" / "plugin.json"
    if not manifest_path.exists():
        return None
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
