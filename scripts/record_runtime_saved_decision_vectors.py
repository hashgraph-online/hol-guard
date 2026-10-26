"""Record runtime-hook saved-decision vectors from the Python owner before it retires.

Run with ``PYTHONPATH`` pointing at a source tree that still composes the cold
hook evaluation's saved decision in Python (``_runtime_stored_policy_decision``
and the legacy-hash merge in ``commands_hook_native_eval.py``), with the native
runtime available for the memory-pattern candidates and the approval-context
token checks. Each vector freezes the probes, every store lookup the Python
composition made, and the selected ``{lookup, decision}``.
"""

from __future__ import annotations

import argparse
import copy
import gzip
import json
import os
import random
import tempfile
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.action_lattice import guard_action_severity
from codex_plugin_scanner.guard.cli import commands_support_runtime_policy as runtime_policy
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.approval_context import build_approval_context_token
from codex_plugin_scanner.guard.store_base import (
    _runtime_scoped_exact_match_key,
    runtime_tool_action_exact_match_context,
    runtime_tool_action_portable_match_context,
)
from codex_plugin_scanner.guard.store_policy import StorePolicyMixin
from codex_plugin_scanner.guard.store_portable_project_memory import StorePortableProjectMemoryMixin

ACTIONS = ["allow", "allow", "warn", "review", "ask", "require-reapproval", "block", " allow ", "frobnicate", None]
SCOPES = ["artifact", "workspace", "workspace", "publisher", "harness", "harness", "global", " global ", None]
WORKSPACE = "/work/repo"
PORTABLE = "guard:project:git:example"
ARTIFACT_IDS = [
    "codex:project:tool-action:npm-test",
    "claude-code:project:tool-action:rm-rf",
    "claude-code:project:file-read:env",
    "codex:project:mcp-tool:github.create_issue",
    "codex:project:prompt:secret",
    "codex:project:package-request:left-pad",
    "codex:project:mcp:github",
    "codex:skill:helper",
]
COMMANDS = [None, "npm test", "rm -rf build", "cat .env", "git push origin main", "echo ünïcode"]


class _Table:
    """Stand-in for the resident probe: answers each lookup from a lazily filled table."""

    table: dict[str, Any]
    rng: random.Random
    choices: dict[str, list[Any]]

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
        del publisher, now, local_once_only
        assert not consume_one_shot
        key = _key(harness, artifact_id, artifact_hash, workspace, runtime_exact_match_context)
        if key not in self.table:
            self.table[key] = _lookup(self.rng, self.choices, str(artifact_id))
        return copy.deepcopy(self.table[key])


class _Fake(StorePortableProjectMemoryMixin, _Table, StorePolicyMixin):
    # The native memory-pattern op opens the context-digest prerequisites here.
    guard_home = Path(os.environ.get("HOL_GUARD_HOME") or tempfile.mkdtemp(prefix="guard-runtime-saved-"))


def _key(*parts: str | None) -> str:
    return json.dumps(list(parts), separators=(",", ":"), ensure_ascii=False)


def _lookup(rng: random.Random, choices: dict[str, list[Any]], artifact_id: str) -> dict[str, Any]:
    decision = None
    if rng.random() < 0.55:
        decision = {
            "action": rng.choice(ACTIONS),
            "scope": rng.choice(SCOPES),
            "artifact_id": rng.choice([artifact_id, *choices["ids"], None, " " + artifact_id]),
            "artifact_hash": rng.choice(choices["hashes"]),
            "source": rng.choice(["local", "cloud-sync"]),
        }
        if rng.random() < 0.2:
            decision["approval_id"] = f"approval-{rng.randrange(1000)}"
    ignored = None
    if rng.random() < 0.15:
        ignored = {"reason": f"integrity-{rng.randrange(100)}", "artifact_id": artifact_id}
    return {
        "decision": decision,
        "ignored_local_integrity": ignored,
        "trust_status": {"remembered_rules": "enabled", "trusted": True, "tag": rng.randrange(5)},
        "authority_revision": rng.choice([3, 3, 3, 4]),
    }


def _token(rng: random.Random) -> str:
    return build_approval_context_token(
        identity={"id": rng.randrange(4)},
        content=f"sha256:{rng.randrange(1 << 64):064x}",
        capabilities={},
        policy={"v": rng.randrange(3)},
        sandbox={},
    )


def _context(rng: random.Random, command: str | None) -> str | None:
    kind = rng.choice(["none", "none", "tool", "tool", "location", "garbage"])
    if kind == "none":
        return None
    if kind == "garbage":
        return rng.choice(["not json", "{}", "[]", '{"raw_command_text": ""}'])
    return runtime_tool_action_exact_match_context(
        config_path="/work/repo/.codex/config.toml" if rng.random() < 0.6 else None,
        source_scope=rng.choice(["project", "user", None]),
        raw_command_text=(command or "ls") if kind == "tool" else None,
        wrapper_chain=rng.choice([None, ["sudo"], ["env", ""]]),
        permission_mode=rng.choice([None, "default", "acceptEdits"]),
    )


def _probe(
    rng: random.Random,
    *,
    harness: str,
    artifact_id: str,
    artifact_hash: str,
    workspace: str | None,
    portable: str | None,
    memory: bool,
) -> tuple[dict[str, Any], GuardArtifact]:
    command = rng.choice(COMMANDS)
    artifact = GuardArtifact(
        artifact_id=artifact_id,
        name=rng.choice(["Bash", "shell", "Read", "github"]),
        harness=harness,
        artifact_type=rng.choice(["tool_action_request", "tool_action_request", "file_read_request", "mcp_server"]),
        source_scope="project",
        config_path="/work/repo/.codex/config.toml",
        command=command,
        publisher=rng.choice([None, "acme"]),
    )
    probe: dict[str, Any] = {
        "harness": harness,
        "artifact_id": artifact_id,
        "artifact_hash": artifact_hash,
        "workspace": workspace,
        "portable_workspace": portable,
        "publisher": artifact.publisher,
        "exact_match_context": _context(rng, command),
        "risk_scoped": rng.random() < 0.7,
    }
    if memory:
        probe["memory"] = {
            "command": artifact.command,
            "artifact_type": artifact.artifact_type,
            "artifact_name": artifact.name,
        }
    return probe, artifact


def _hash_choices(rng: random.Random, probes: list[dict[str, Any]]) -> list[Any]:
    hashes: list[Any] = [None, "legacy-hex", _token(rng)]
    for probe in probes:
        artifact_id = probe["artifact_id"]
        context = probe["exact_match_context"]
        hashes.append(probe["artifact_hash"])
        hashes.append(_runtime_scoped_exact_match_key(artifact_id))
        hashes.append(_runtime_scoped_exact_match_key(artifact_id, context))
        hashes.append(_runtime_scoped_exact_match_key(artifact_id, runtime_tool_action_portable_match_context(context)))
    return [value for value in hashes if value is not None] + [None]


def _old_composition(
    store: _Fake,
    probes: dict[str, tuple[dict[str, Any], GuardArtifact]],
) -> dict[str, Any]:
    """The saved-decision step of ``commands_hook_native_eval.py`` before the port."""

    def lookup(probe: dict[str, Any], artifact: GuardArtifact) -> Any:
        return store.resolve_policy_decision_lookup_with_memory_pattern(
            probe["harness"],
            probe["artifact_id"],
            artifact_hash=probe["artifact_hash"],
            workspace=probe["workspace"],
            publisher=artifact.publisher,
            runtime_exact_match_context=probe["exact_match_context"],
            memory_command=artifact.command,
            memory_artifact_type=artifact.artifact_type,
            memory_artifact_name=artifact.name,
            consume_one_shot=False,
        )

    def stored(probe: dict[str, Any], artifact: GuardArtifact, decision_lookup: Any) -> Any:
        return runtime_policy._runtime_stored_policy_decision(
            store=store,  # type: ignore[arg-type]
            harness=probe["harness"],
            artifact=artifact,
            artifact_id=probe["artifact_id"],
            artifact_hash=probe["artifact_hash"],
            workspace=probe["workspace"],
            decision_lookup=decision_lookup,
            consume_one_shot=False,
        )

    current, current_artifact = probes["current"]
    legacy, legacy_artifact = probes["legacy"]
    policy_lookup = lookup(current, current_artifact)
    stored_policy_decision = stored(current, current_artifact, policy_lookup)
    legacy_lookup = lookup(legacy, legacy_artifact)
    legacy_decision = stored(legacy, legacy_artifact, legacy_lookup)
    if legacy_lookup.get("ignored_local_integrity") is not None:
        policy_lookup = {
            **policy_lookup,
            "ignored_local_integrity": legacy_lookup["ignored_local_integrity"],
        }
    if legacy_decision is not None and (
        stored_policy_decision is None
        or guard_action_severity(legacy_decision.get("action"), unknown_action="block")
        > guard_action_severity(stored_policy_decision.get("action"), unknown_action="block")
    ):
        merged_integrity = policy_lookup.get("ignored_local_integrity")
        policy_lookup = dict(legacy_lookup)
        if merged_integrity is not None:
            policy_lookup["ignored_local_integrity"] = merged_integrity
        stored_policy_decision = legacy_decision
    if stored_policy_decision is None and "alias" in probes:
        alias, alias_artifact = probes["alias"]
        stored_policy_decision = stored(alias, alias_artifact, None)
    return {"lookup": policy_lookup, "decision": stored_policy_decision}


def _vector(rng: random.Random, index: int) -> dict[str, Any]:
    harness = rng.choice(["codex", "claude-code"])
    artifact_id = rng.choice(ARTIFACT_IDS)
    current_hash = rng.choice([_token(rng), _token(rng), f"hash-{index}"])
    legacy_hash = rng.choice([current_hash, f"legacy-{index}"])
    portable = rng.choice([None, None, PORTABLE, WORKSPACE])
    workspace = rng.choice([WORKSPACE, f" {WORKSPACE} ", None]) if portable == WORKSPACE else WORKSPACE
    legacy_workspace = rng.choice([workspace, "/work/other", None])
    current, artifact = _probe(
        rng,
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=current_hash,
        workspace=workspace,
        portable=portable,
        memory=True,
    )
    legacy = {**current, "artifact_hash": legacy_hash, "workspace": legacy_workspace}
    probes: dict[str, tuple[dict[str, Any], GuardArtifact]] = {
        "current": (current, artifact),
        "legacy": (legacy, artifact),
    }
    if rng.random() < 0.3:
        alias_id = "claude:" + artifact_id.split(":", 1)[1]
        probes["alias"] = _probe(
            rng,
            harness="claude",
            artifact_id=alias_id,
            artifact_hash=rng.choice([current_hash, _token(rng)]),
            workspace=WORKSPACE,
            portable=None,
            memory=False,
        )
    specs = {name: probe for name, (probe, _artifact) in probes.items()}
    contexts = {probe["artifact_id"]: probe["exact_match_context"] for probe in specs.values()}
    risky = {probe["artifact_id"]: probe["risk_scoped"] for probe in specs.values()}
    runtime_policy._runtime_artifact_exact_match_context = lambda item: contexts[item.artifact_id]  # type: ignore[assignment]
    runtime_policy._runtime_artifact_risk_classes = (  # type: ignore[assignment]
        lambda item: ["destructive_shell"] if risky[item.artifact_id] else []
    )

    store = _Fake()
    store.rng = rng
    store.table = {}
    store.choices = {
        "ids": [probe["artifact_id"] for probe in specs.values()] + ["codex:project:tool-action:other"],
        "hashes": _hash_choices(rng, list(specs.values())),
    }
    store._portable_project_workspace = lambda at: (  # type: ignore[method-assign]
        portable if isinstance(at, str) and at.strip() == WORKSPACE else None
    )
    for probe in specs.values():
        probe["portable_workspace"] = store._portable_project_workspace(probe["workspace"])
    expected = _old_composition(store, probes)
    return {"name": f"runtime-{index}", "runtime": specs, "table": store.table, "expected": expected}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=1500)
    args = parser.parse_args()
    rng = random.Random(4701)
    vectors = [_vector(rng, index) for index in range(args.count)]
    document = {"schema": "guard-runtime-saved-decision-vectors.v1", "vectors": vectors}
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    args.output.write_bytes(gzip.compress(payload, mtime=0))


if __name__ == "__main__":
    main()
