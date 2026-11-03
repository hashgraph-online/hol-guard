"""Seed data for the dashboard policy integration specs.

Writes remembered rules through ``GuardStore.upsert_policy``, the call every
saved approval goes through. The harnesses are chosen so no other area's seed
or spec evaluates a live action against them.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from codex_plugin_scanner.guard.models import PolicyDecision

from . import SeedContext


@dataclass(frozen=True)
class _Rule:
    key: str
    decision: PolicyDecision
    # Rows from Guard Cloud arrive through the validated sync path, never as a
    # local write.
    remote: bool = False


def _rules(workspace: str) -> tuple[_Rule, ...]:
    shop = f"{workspace}/shop-app"
    return (
        _Rule(
            "workspace_allow",
            PolicyDecision(
                harness="gemini",
                scope="workspace",
                action="allow",
                artifact_id="family:tool-action",
                workspace=shop,
                reason="git push origin main",
            ),
        ),
        _Rule(
            "artifact_block",
            PolicyDecision(
                harness="opencode",
                scope="artifact",
                action="block",
                artifact_id="opencode:project:tool-action:rm-rf-build",
                workspace=shop,
                reason="rm -rf build",
            ),
        ),
        _Rule(
            "global_allow",
            PolicyDecision(
                harness="opencode",
                scope="global",
                action="allow",
                reason="any shell command",
            ),
        ),
        _Rule(
            "publisher_allow",
            PolicyDecision(
                harness="gemini",
                scope="publisher",
                action="allow",
                publisher="acme-tools",
                reason="Trust acme-tools",
            ),
        ),
        _Rule(
            "harness_block",
            PolicyDecision(
                harness="gemini",
                scope="harness",
                action="block",
                artifact_id="family:package-request",
                reason="npm install of unreviewed packages",
            ),
        ),
        # The mutating spec removes this one through the UI.
        _Rule(
            "removal_target",
            PolicyDecision(
                harness="opencode",
                scope="workspace",
                action="allow",
                artifact_id="family:package-request",
                workspace=f"{workspace}/removal-lab",
                reason="pip install requests",
            ),
        ),
        _Rule(
            "cloud_block",
            PolicyDecision(
                harness="opencode",
                scope="workspace",
                action="block",
                artifact_id="family:tool-action",
                workspace=shop,
                reason="curl piped to shell",
                source="cloud-sync",
            ),
            remote=True,
        ),
    )


def seed(context: SeedContext) -> dict[str, Any]:
    # Recent timestamps keep every rule well inside the dashboard's 90-day
    # "not changed in a while" window, whenever the suite runs.
    base = datetime.now(UTC) - timedelta(minutes=30)
    rules = _rules(str(context.workspace))
    seeded: dict[str, Any] = {}
    for index, rule in enumerate(rules):
        stamp = (base + timedelta(minutes=index)).strftime("%Y-%m-%dT%H:%M:%SZ")
        context.store.upsert_policy(rule.decision, stamp, remote_write_authorized=rule.remote)
        seeded[rule.key] = {
            "title": rule.decision.reason,
            "harness": rule.decision.harness,
            "scope": rule.decision.scope,
            "action": rule.decision.action,
            "source": rule.decision.source,
            "workspace": rule.decision.workspace,
            "publisher": rule.decision.publisher,
        }
    listed = context.store.list_policy_decisions()
    seeded["total"] = len(rules)
    seeded["allowCount"] = sum(1 for rule in rules if rule.decision.action == "allow")
    seeded["blockCount"] = sum(1 for rule in rules if rule.decision.action == "block")
    seeded["listedCount"] = len(listed)
    return seeded
