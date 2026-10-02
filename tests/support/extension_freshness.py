"""Local contribution previews and always-on decision-evidence validation.

Contributor PRs own the canonical source, portable fixture, and trust entry.
Local source previews may not yet include regenerated projections. Required
CI verifies native projections before starting pytest, so a pending source
preview cannot pass the merge gate. Decision-evidence freshness is never
deferred: maintainers review source and generated changes in the same PR.
"""

from __future__ import annotations

import pytest

from scripts.ci.detect_pending_extension_regen import contribution_ids


def pending_contribution_regen() -> bool:
    from codex_plugin_scanner.guard.runtime.command_extensions import (
        BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    )

    registry_ids = {extension.extension_id for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions}
    return bool(contribution_ids() - registry_ids)


def pending_decision_diff_regen() -> bool:
    """Never defer report freshness to a later commit or a different branch.

    Retained for report-generator callers. Source PRs, repair PRs, main, and
    local checks must all validate the evidence for the same source snapshot.
    """
    return False


requires_fresh_projections = pytest.mark.skipif(
    pending_contribution_regen(),
    reason=(
        "checked-in projections do not cover a pending contribution source; "
        "freshness is enforced after maintainer regeneration"
    ),
)

# Preserve the public decorator without installing a skip condition. Full
# reproducibility and environment-independence tests run on ordinary PRs too.
requires_fresh_decision_diff = pytest.mark.usefixtures()
