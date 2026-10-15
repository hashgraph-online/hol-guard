"""Shared-vector end-to-end check of the resident MCP proxy decision op.

``tests/fixtures/mcp_proxy_decision/parity_vectors.json`` is language neutral and
was recorded from the Python proxy decision methods before they moved into the
resident (see its provenance block). The Rust crate replays it against the
decision functions; this test replays it through the real Python transport and
the real resident, including the lazy-fact ``need`` round trips. There is no
Python oracle: the vectors are the contract.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_mcp_proxy_decision as bridge
from codex_plugin_scanner.guard.native_mcp_proxy_decision import (
    NativeMcpProxyDecisionError,
    native_mcp_proxy_decide,
)

DOCUMENT = json.loads(
    (Path(__file__).parent / "fixtures" / "mcp_proxy_decision" / "parity_vectors.json").read_text(encoding="utf-8")
)
BY_CHECK: dict[str, list[dict[str, Any]]] = defaultdict(list)
for _vector in DOCUMENT["vectors"]:
    BY_CHECK[_vector["check"]].append(_vector)

# The lazily supplied fact (need name -> request key), per check family.
LAZY_FACTS = {
    "route_tool_call": {
        "package_policy": "package_saved_policy_blocks",
        "native_prompt": "native_prompt_allows",
        "inline_approval": "inline_approval",
    },
    "tool_postclaim": {"fresh_claim_allows_reapproval": "fresh_claim_allows_reapproval"},
    "package_postclaim": {"postclaim_package": "package"},
}

pytestmark = pytest.mark.skipif(
    os.environ.get("HOL_GUARD_NATIVE_REGRESSION") != "1",
    reason="needs the resident runtime (HOL_GUARD_NATIVE_REGRESSION=1)",
)


def _is_subset(expected: Any, actual: Any) -> bool:
    if isinstance(expected, dict) and isinstance(actual, dict):
        return all(key in actual and _is_subset(value, actual[key]) for key, value in expected.items())
    return expected == actual


def _replay(vector: dict[str, Any], guard_home: Path) -> dict[str, Any]:
    request = dict(vector["request"])
    lazy = LAZY_FACTS.get(vector["check"], {})
    supplied = {name: request.pop(key) for name, key in lazy.items() if key in request}
    suppliers = {name: (lambda _need, key=lazy[name], value=value: {key: value}) for name, value in supplied.items()}
    return native_mcp_proxy_decide(request, guard_home=guard_home, supply=suppliers)


@pytest.fixture(scope="module")
def guard_home(tmp_path_factory: pytest.TempPathFactory) -> Path:
    home = tmp_path_factory.mktemp("mcp-proxy-decision-home")
    return home


@pytest.mark.parametrize("check", sorted(BY_CHECK))
def test_resident_matches_every_recorded_vector(check: str, guard_home: Path) -> None:
    vectors = BY_CHECK[check]
    assert vectors
    for vector in vectors:
        payload = _replay(vector, guard_home)
        assert _is_subset(vector["expected"], payload), (
            f"{vector['id']} diverged\nexpected {vector['expected']}\nactual   {payload}"
        )


def test_an_unsupplied_need_fails_closed(guard_home: Path) -> None:
    vector = next(item for item in BY_CHECK["route_tool_call"] if "native_prompt_allows" in item["request"])
    request = {key: value for key, value in vector["request"].items() if key != "native_prompt_allows"}

    with pytest.raises(NativeMcpProxyDecisionError, match="need_unsupplied"):
        native_mcp_proxy_decide(request, guard_home=guard_home)


def test_an_unbound_reply_fails_closed(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real = bridge._resident_request

    def tampered(**kwargs: Any) -> dict[str, Any] | None:
        response = real(**kwargs)
        return None if response is None else {**response, "request_sha256": "sha256:" + "0" * 64}

    monkeypatch.setattr(bridge, "_resident_request", tampered)

    with pytest.raises(NativeMcpProxyDecisionError, match="unavailable"):
        native_mcp_proxy_decide(BY_CHECK["evidence_item"][0]["request"], guard_home=guard_home)


def test_native_unavailability_fails_closed(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge, "ensure_resident_prerequisite", lambda _home: False)

    with pytest.raises(NativeMcpProxyDecisionError, match="prerequisite_unavailable"):
        native_mcp_proxy_decide(BY_CHECK["evidence_item"][0]["request"], guard_home=guard_home)
