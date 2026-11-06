"""Opt a test Guard home into reviewing package signals the default only records.

By default an install pauses only on risk (an advisory, malware, an integrity
failure or a suspicious install script). Tests that exercise the review path
for an unknown package, an unpinned dependency, a direct source or a custom
registry opt into it the way a user would, through ``[risk_actions]``.
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest

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


def prove_npm_install(monkeypatch: pytest.MonkeyPatch, version: str = "11.9.0") -> None:
    """Stand in for the resident's npm proof so the daemon settles an install.

    The daemon applies an allowing verdict only when the resident proves the
    npm that runs; that proof depends on the host's npm layout and is covered
    by the Rust tests, so hook tests supply it the same on every host. The rest
    of the resident's plan runs as shipped.
    """

    from codex_plugin_scanner.guard.daemon import hook_native_package_review

    planned = hook_native_package_review.package_review_plan

    def proven(*args: object, **kwargs: object) -> tuple[object, bool]:
        artifact, _may_allow = planned(*args, **kwargs)
        metadata = {} if artifact is None else artifact.metadata
        if (metadata.get("package_manager"), metadata.get("intent_kind")) != ("npm", "install"):
            return artifact, False
        return replace(artifact, metadata={**artifact.metadata, "verified_npm_version": version}), True

    monkeypatch.setattr(hook_native_package_review, "package_review_plan", proven)
