"""Opt a test Guard home into reviewing package signals the default only records.

By default an install pauses only on risk (an advisory, malware, an integrity
failure or a suspicious install script). Tests that exercise the review path
for an unknown package, an unpinned dependency, a direct source or a custom
registry opt into it the way a user would, through ``[risk_actions]``.
"""

from __future__ import annotations

import re
from pathlib import Path

PACKAGE_REVIEW_KEYS = (
    "package_unknown",
    "package_lockfile_drift",
    "package_direct_source",
    "package_custom_registry",
    "package_script",
)

_RISK_ACTIONS_HEADER = re.compile(r"(?m)^\[risk_actions\]\n")


def review_package_signals(guard_home: Path, *keys: str, action: str = "require-reapproval") -> Path:
    """Set each package risk key (all of them by default) to ``action`` in ``config.toml``."""

    guard_home.mkdir(parents=True, exist_ok=True)
    config = guard_home / "config.toml"
    lines = "".join(f'{key} = "{action}"\n' for key in keys or PACKAGE_REVIEW_KEYS)
    existing = config.read_text(encoding="utf-8") if config.exists() else ""
    if _RISK_ACTIONS_HEADER.search(existing):
        updated = _RISK_ACTIONS_HEADER.sub(lambda match: match.group(0) + lines, existing, count=1)
    else:
        separator = "\n" if existing and not existing.endswith("\n") else ""
        updated = f"{existing}{separator}[risk_actions]\n{lines}"
    config.write_text(updated, encoding="utf-8")
    return config
