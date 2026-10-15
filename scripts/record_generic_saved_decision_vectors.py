"""Record generic-hook saved-decision vectors from the Python owner before it retires.

Run with ``PYTHONPATH`` pointing at a source tree that still composes the
generic hook's saved-decision probes in Python. Each vector freezes the probe
groups (artifact id/hash pairs with their exact-command and memory ids), the
per-candidate store lookups, and the composed ``{decision,
ignored_local_integrity}`` the generic hook selected.
"""

from __future__ import annotations

import argparse
import copy
import gzip
import json
import random
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard import store_policy
from codex_plugin_scanner.guard.cli import commands_hook_native_generic
from codex_plugin_scanner.guard.cli.commands_hook_native_generic import _generic_hook_saved_decision
from codex_plugin_scanner.guard.store_policy import StorePolicyMixin
from codex_plugin_scanner.guard.store_portable_project_memory import StorePortableProjectMemoryMixin

ACTIONS = ["allow", "warn", "review", "ask", "require-reapproval", "sandbox-required", "block", "frobnicate"]
WORKSPACE = "/work/repo"
PORTABLE = "guard:project:git:example"
DEGRADED_TRUST = {"remembered_rules": "disabled_degraded", "trusted": False}


class _Table:
    """Stand-in for the resident probe: answers each candidate from a recorded table."""

    table: dict[str, Any]
    degraded: bool

    def resolve_policy_decision_lookup(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        consume_one_shot: bool = True,
        local_once_only: bool = False,
    ) -> dict[str, Any]:
        del harness, publisher, now, runtime_exact_match_context, local_once_only
        assert not consume_one_shot
        if self.degraded:
            return {
                "decision": None,
                "ignored_local_integrity": None,
                "trust_status": DEGRADED_TRUST,
                "authority_revision": -1,
            }
        return copy.deepcopy(self.table[_key(artifact_id, artifact_hash, workspace)])


class _Fake(StorePortableProjectMemoryMixin, _Table, StorePolicyMixin):
    guard_home = "/guard-home"


def _key(artifact_id: str | None, artifact_hash: str | None, workspace: str | None) -> str:
    return json.dumps([artifact_id, artifact_hash, workspace], separators=(",", ":"))


def _lookup(rng: random.Random, artifact_id: str, density: float) -> dict[str, Any]:
    decision = None
    if rng.random() < density:
        decision = {"action": rng.choice(ACTIONS), "scope": "workspace", "artifact_id": artifact_id}
        if rng.random() < 0.3:
            decision["approval_id"] = f"approval-{rng.randrange(1000)}"
    ignored = None
    if rng.random() < 0.25:
        ignored = {"reason": f"integrity-{rng.randrange(100)}", "artifact_id": artifact_id}
    return {
        "decision": decision,
        "ignored_local_integrity": ignored,
        "trust_status": {"remembered_rules": "enabled", "trusted": True},
        "authority_revision": rng.choice([3, 3, 3, 4]),
    }


def _vector(rng: random.Random, index: int) -> dict[str, Any]:
    artifact_id = rng.choice([f"claude-code:tool:Bash:{index}", f"codex:tool:shell:{index}"])
    artifact_hash = f"hash-{index}"
    legacy_hash = rng.choice([None, artifact_hash, f"legacy-{index}"])
    portable = rng.choice([None, PORTABLE, WORKSPACE])
    workspace = rng.choice([WORKSPACE, WORKSPACE, f" {WORKSPACE} "]) if portable == WORKSPACE else WORKSPACE
    degraded = rng.random() < 0.08
    density = rng.choice([0.05, 0.15, 0.3, 0.6])
    candidates: dict[str, list[Any]] = {}
    probes: list[list[str]] = []

    def memory_lookup_candidates(harness: str, candidate_id: str | None, **_kwargs: Any) -> tuple[list[str], Any]:
        del harness
        assert candidate_id is not None
        if candidate_id not in candidates:
            exact = [f"{candidate_id}#exact-{n}" for n in range(rng.choice([0, 0, 1, 2]))]
            memory = f"{candidate_id}#memory" if rng.random() < 0.5 else None
            candidates[candidate_id] = [exact, memory]
        exact, memory = candidates[candidate_id]
        return list(exact), memory

    store = _Fake()
    store.degraded = degraded
    store.table = {}
    store._portable_project_workspace = lambda _workspace: portable  # type: ignore[method-assign]
    original_resolve = store.resolve_policy_decision_lookup_with_memory_pattern

    def tracked(harness: str, candidate_id: str | None, **kwargs: Any) -> Any:
        probes.append([str(candidate_id), str(kwargs["artifact_hash"])])
        return original_resolve(harness, candidate_id, **kwargs)

    store.resolve_policy_decision_lookup_with_memory_pattern = tracked  # type: ignore[method-assign]

    # Pre-fill every candidate lookup the composition may probe.
    def fill(candidate_id: str, candidate_hash: str) -> None:
        exact, memory = memory_lookup_candidates("claude-code", candidate_id)
        for probe_id in [candidate_id, *exact, *([memory] if memory else [])]:
            for at in {WORKSPACE, workspace, PORTABLE, portable}:
                key = _key(probe_id, candidate_hash, at)
                store.table.setdefault(key, _lookup(rng, probe_id, density))

    from codex_plugin_scanner.guard.store import runtime_tool_action_policy_artifact_id

    policy_id = runtime_tool_action_policy_artifact_id(artifact_id) or artifact_id
    for candidate_id, candidate_hash in [
        (artifact_id, artifact_hash),
        (policy_id, artifact_hash),
        (artifact_id, legacy_hash or artifact_hash),
    ]:
        fill(candidate_id, candidate_hash)

    store_policy.memory_lookup_candidates = memory_lookup_candidates  # type: ignore[assignment]
    # The command text only feeds the memory candidates, which are fixed above.
    commands_hook_native_generic._generic_hook_memory_command = lambda _payload: f"echo {index}"  # type: ignore[attr-defined]
    decision, ignored = _generic_hook_saved_decision(
        artifact_hash=artifact_hash,
        artifact_id=artifact_id,
        artifact_name="Bash",
        harness="claude-code",
        legacy_artifact_hash=legacy_hash,
        payload={"tool_name": "Bash", "tool_input": {"command": f"echo {index}"}},
        publisher=None,
        runtime_workspace=Path(workspace),
        store=store,  # type: ignore[arg-type]
    )
    groups = []
    for candidate_id, candidate_hash in probes:
        exact, memory = candidates.get(candidate_id, [[], None])
        groups.append(
            {
                "artifact_hash": candidate_hash,
                "candidate_artifact_ids": [candidate_id, *exact, *([memory] if memory else [])],
            }
        )
    return {
        "name": f"generic-{index}",
        "artifact_id": artifact_id,
        "artifact_hash": artifact_hash,
        "legacy_artifact_hash": legacy_hash,
        "workspace": str(Path(workspace)),
        "portable_workspace": portable,
        "degraded": degraded,
        "groups": groups,
        "table": store.table,
        "expected": {"decision": decision, "ignored_local_integrity": ignored},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=400)
    args = parser.parse_args()
    rng = random.Random(4363)
    vectors = [_vector(rng, index) for index in range(args.count)]
    document = {"schema": "guard-generic-saved-decision-vectors.v1", "vectors": vectors}
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(payload, mtime=0))


if __name__ == "__main__":
    main()
