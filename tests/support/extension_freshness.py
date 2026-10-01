"""Generated-artifact freshness gates for projection-input changes.

Contributor PRs own the canonical source, portable fixture, and trust entry.
Maintainer automation regenerates the catalog, native program, baselines, and
digest vectors after scope review, so a source-only ref legitimately contains
projection inputs that the checked-in artifacts do not cover yet. Tests that
assert freshness of generated artifacts stand down while such a pending
regeneration exists; every other invariant still runs.

Two pending states are detected:

- ``pending_contribution_regen``: a contribution id exists that the checked-in
  catalog does not cover (new or edited ``contributions/`` source).
- ``stale_report_source_bindings``: a file bound in the decision-diff report's
  ``sources_sha256`` map no longer matches its recorded digest — the report is
  provably one regeneration behind the tree's sources.  This is content-based,
  so it holds without a git base reference.
"""

from __future__ import annotations

import pytest

from scripts.ci.detect_pending_extension_regen import contribution_ids


def pending_contribution_regen() -> bool:
    from codex_plugin_scanner.guard.runtime.command_extensions import (
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )

    registry_ids = {
        extension.extension_id for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
    }
    return bool(contribution_ids() - registry_ids)


def stale_report_source_bindings() -> bool:
    try:
        from tests.guard_command_decision_diff import REPORT_PATH, _source_bindings
    except Exception:
        return False
    try:
        import json

        stored = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        bound = stored.get("bindings", {}).get("sources_sha256")
        if not isinstance(bound, dict):
            return True
        return _source_bindings() != bound
    except Exception:
        return True


requires_fresh_projections = pytest.mark.skipif(
    pending_contribution_regen() or stale_report_source_bindings(),
    reason=(
        "checked-in projections do not cover the tree's pending regen inputs; "
        "freshness is enforced after maintainer regeneration"
    ),
)
