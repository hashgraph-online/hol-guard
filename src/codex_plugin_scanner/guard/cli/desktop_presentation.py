"""Presentation projection and mutation helpers for the Desktop CLI contract."""

from __future__ import annotations

import argparse
import json
import sys
from typing import TYPE_CHECKING, TextIO

from ..presentation_mode import PRESENTATION_SCHEMA_VERSION, UNSUPPORTED_PRESENTATION_SCHEMA_DIAGNOSTIC

if TYPE_CHECKING:
    from pathlib import Path

    from ..config import GuardConfig


def unsupported_presentation_projection() -> dict[str, object]:
    return {
        "mode": "everyday",
        "source": "default",
        "explicit": False,
        "canWrite": False,
        "schemaVersion": PRESENTATION_SCHEMA_VERSION,
        "revision": 0,
        "diagnostic": "presentation_not_supported_by_core",
    }


def presentation_projection(config: object) -> dict[str, object]:
    if not hasattr(config, "presentation_mode"):
        return unsupported_presentation_projection()
    explicit = getattr(config, "presentation_mode_explicit", False) is True
    diagnostic = getattr(config, "presentation_diagnostic", None)
    source = getattr(config, "presentation_source", "local-explicit" if explicit else "default")
    return {
        "mode": getattr(config, "presentation_mode", "everyday"),
        "source": source,
        "explicit": explicit,
        "canWrite": diagnostic != UNSUPPORTED_PRESENTATION_SCHEMA_DIAGNOSTIC,
        "schemaVersion": getattr(config, "presentation_schema_version", PRESENTATION_SCHEMA_VERSION),
        "revision": getattr(config, "presentation_revision", 0),
        "diagnostic": diagnostic,
    }


def run_presentation_set_command(
    args: argparse.Namespace,
    *,
    guard_home: Path | None,
    config: GuardConfig | None,
    output_stream: TextIO | None,
) -> int:
    if config is None:
        raise RuntimeError("Guard Desktop presentation update requires local Guard config")
    from ..config import update_guard_settings

    resolved_home = getattr(args, "guard_home", None) or guard_home or config.guard_home
    update_payload: dict[str, object] = {
        "presentation_mode": args.mode,
        "presentation_mode_explicit": True,
    }
    if getattr(args, "expected_revision", None) is not None:
        update_payload["presentation_revision"] = args.expected_revision
    updated = update_guard_settings(
        resolved_home,
        update_payload,
        event_source="desktop-presentation",
        skip_approval_gate=True,
    )
    projected = presentation_projection(updated)
    if bool(getattr(args, "json", False)):
        print(json.dumps(projected, sort_keys=True), file=output_stream or sys.stdout)
    return 0
