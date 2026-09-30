"""Generated-artifact freshness gates for contribution-only changes.

Contributor PRs own the canonical source, portable fixture, and trust entry.
Maintainer automation regenerates the catalog, native program, baselines, and
digest vectors after scope review, so a source-only ref legitimately contains a
contribution id that the checked-in projections do not cover yet. Tests that
assert freshness of generated artifacts stand down while such a pending
contribution exists; every other invariant still runs.
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


requires_fresh_projections = pytest.mark.skipif(
    pending_contribution_regen(),
    reason=(
        "checked-in projections do not cover a pending contribution source; "
        "freshness is enforced after maintainer regeneration"
    ),
)
