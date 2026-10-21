"""Verifier trust follows the live destination, not stale pull request metadata."""

from __future__ import annotations

import pytest

from ci.gauntlet.trust import validate_producer_revision

OLD = "a" * 40
CURRENT = "b" * 40
NEWER = "c" * 40


class API:
    """Serve independently supplied ancestry facts without trusting a candidate."""

    repo = "hashgraph-online/hol-guard"

    def __init__(self, comparisons=None):
        """Keep the expected API requests explicit for each ancestry scenario."""
        self.comparisons = comparisons or {}
        self.requests = []

    def request(self, path):
        """Return only the exact default-branch and comparison fixtures provided."""
        self.requests.append(path)
        if path == "":
            return {"default_branch": "main"}
        assert path in self.comparisons, path
        return {"status": self.comparisons[path]}


def test_verifier_equal_to_stale_pr_base_is_rejected():
    """A formerly trusted revision must not bypass a newer target-branch verifier."""
    api = API({f"/compare/{CURRENT}...{OLD}": "behind", f"/compare/{OLD}...main": "ahead"})
    with pytest.raises(RuntimeError, match="current trusted base"):
        validate_producer_revision(api, 3479, {"base": {"sha": OLD}, "gauntlet_base_sha": CURRENT}, {"head_sha": OLD})
    assert f"/compare/{CURRENT}...{OLD}" in api.requests


def test_current_destination_verifier_does_not_consult_stale_pr_base():
    """An exact independently resolved current tip is trusted without ancestry fallback."""
    api = API()
    validate_producer_revision(api, 3479, {"base": {"sha": OLD}, "gauntlet_base_sha": CURRENT}, {"head_sha": CURRENT})
    assert api.requests == []


@pytest.mark.parametrize("tip", [None, "not-a-sha", 42])
def test_missing_or_invalid_current_base_fails_closed(tip):
    """Never fall back to stale PR metadata when the current destination is unavailable."""
    with pytest.raises(RuntimeError, match="current trusted base"):
        validate_producer_revision(API(), 3479, {"base": {"sha": OLD}, "gauntlet_base_sha": tip}, {"head_sha": OLD})


def test_newer_verifier_must_also_belong_to_the_default_branch():
    """Handle a branch advancing during verification without trusting candidate-only commits."""
    comparisons = {f"/compare/{CURRENT}...{NEWER}": "ahead", f"/compare/{NEWER}...main": "identical"}
    pull = {"base": {"sha": OLD}, "gauntlet_base_sha": CURRENT}
    validate_producer_revision(API(comparisons), 3479, pull, {"head_sha": NEWER})
    comparisons[f"/compare/{NEWER}...main"] = "behind"
    with pytest.raises(RuntimeError, match="current trusted base"):
        validate_producer_revision(API(comparisons), 3479, pull, {"head_sha": NEWER})
