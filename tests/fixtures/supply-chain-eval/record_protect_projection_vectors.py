"""Record package-protect projection vectors from the Python projection.

Provenance tool, not part of the test suite. It must run against a checkout
that still contains the Python projection (``_apply_package_protect_projection``
in ``guard/local_supply_chain.py`` at commit c091b8782f), for example::

    PYTHONPATH=<base-worktree>/src python record_protect_projection_vectors.py out.json.gz

Each vector holds the wire query the resident receives and the Python result
with the per-call receipt id and timestamp masked.
"""

from __future__ import annotations

import gzip
import itertools
import json
import sys
from pathlib import Path

from codex_plugin_scanner.guard import local_supply_chain as lsc
from codex_plugin_scanner.guard.package_execution_context import (
    PackageExecutionContext,
    PackageExecutionContextComponent,
)
from codex_plugin_scanner.guard.runtime.package_intent_common import (
    PackageIntent,
    PackageIntentTarget,
    build_package_request_artifact,
)
from codex_plugin_scanner.guard.runtime.package_request_evaluation import (
    PackageRequestEvaluation,
    SupplyChainUserCopy,
)

MASK = "<masked>"
TARGETS = (
    PackageIntentTarget("npm", "left-pad", "left-pad@1.3.0", "1.3.0"),
    PackageIntentTarget(
        "npm",
        None,
        "https://user:secret@example.test/pkg.tgz?token=abc",
        None,
        source_url="https://user:secret@example.test/pkg.tgz?token=abc",
        source_kind="url",
    ),
    PackageIntentTarget(
        "pypi",
        "requests",
        "requests[socks]>=2",
        ">=2",
        extras=("socks",),
        editable=True,
        alias="r",
        dependency_group="dev",
    ),
)
COMMANDS = (
    ("npm", "install", "npm install left-pad@1.3.0", ["npm", "install", "left-pad@1.3.0"]),
    ("pip", "execute", "pip install 'requests[socks]>=2'", []),
    ("npm", "sync", "npm ci", ["npm", "ci"]),
)
ACTIONS = ("allow", "warn", "review", "block", "require-reapproval", "ask", "bogus", "")
REASONS = (
    (),
    ({"message": "Known malware", "code": "malware"}, {"message": ""}, {"code": "x"}),
    ({"code": "no-message", "approval_reuse": {"approval_id": "a1", "scope": "exact"}},),
)
PACKAGES = (
    (),
    (
        {"name": "left-pad", "version": "1.3.0", "decision": "block", "related_advisory_ids": ["GHSA-1", "GHSA-2", 7]},
        {"name": "other", "related_advisory_ids": "nope"},
        "skip",
    ),
)
CONTEXTS = (
    PackageExecutionContext("a" * 64, True, (PackageExecutionContextComponent("repository_identity", "b" * 64),)),
    PackageExecutionContext("c" * 64, False, (), non_portable_reason="global_package_request"),
)
ADDITIONAL = (None, {"scope": "workspace", "n": 1})


def evaluation_for(action: str, reasons: tuple, packages: tuple, variant: int) -> PackageRequestEvaluation:
    return PackageRequestEvaluation(
        decision="allow" if action in {"allow", "warn"} else "block",
        policy_action=action,  # type: ignore[arg-type]
        enforcement="enforce",
        entitlement_state="active",
        cache_status="fresh",
        package_intent_hash="h" * 8,
        policy_version="2026.1",
        bundle_version=None if variant % 2 else "bundle-7",
        workspace_fingerprint=None,
        reasons=reasons,
        packages=packages,
        risk_summary="" if variant % 3 == 0 else "Risky package",
        user_copy=SupplyChainUserCopy("Title", f"Summary {variant}", None, None, f"Harness {variant}"),
        matched_rule_id=None if variant % 2 else "rule-1",
    )


def record() -> list[dict]:
    vectors: list[dict] = []
    grid = itertools.product(
        range(len(COMMANDS)),
        ACTIONS,
        range(len(REASONS)),
        range(len(PACKAGES)),
        (False, True),
        ("guard-cli", "codex"),
        (False, True),
    )
    for index, (cmd, action, reasons, packages, observe, harness, derive) in enumerate(grid):
        manager, kind, redacted, command = COMMANDS[cmd]
        targets = tuple(TARGETS[: 1 + (index % 3)])
        intent = PackageIntent(
            package_manager=manager,
            intent_kind=kind,
            command_tokens=tuple(redacted.split()),  # type: ignore[arg-type]
            redacted_command=redacted,
            targets=targets,
            manifest_paths=("package.json",) if index % 2 else (),
            lockfile_paths=("lock",) if index % 5 == 0 else (),
        )
        artifact = build_package_request_artifact("guard-cli", intent, config_path="/ws", source_scope="project")
        context = CONTEXTS[index % 2]
        additional = ADDITIONAL[index % 2]
        evaluation = evaluation_for(action, REASONS[reasons], PACKAGES[packages], index)
        authority = lsc._PackageProtectAuthority(
            intent=intent,
            artifact=artifact,
            evaluation=evaluation,
            current_action="allow",
            execution_context=context,
            artifact_hash=f"{index:064x}",
            launch_identity={},
            launch_cwd=Path("."),
            launch_environment={},
            additional_current_action=None,
            additional_policy_context=additional,
            observe_mode=observe,
            invoking_harness=harness,
        )
        execution = lsc._package_execution_policy_action(authority, evaluation)
        payload: dict[str, object] = {"generated_at": "t", "executed": False, "dry_run": False}
        permitted = lsc.is_execution_permitted(execution)
        blocking = (not permitted) if index % 4 else bool(index % 8)
        executed = bool(index % 3 == 0)
        projection = lsc._apply_package_protect_projection(
            payload=payload,
            authority=authority,
            evaluation=evaluation,
            command=command,
            blocking=blocking,
            executed=executed,
            execution_policy_action=execution if derive else None,
        )
        fields = {
            key: payload[key]
            for key in (
                "request",
                "targets",
                "verdict",
                "receipt",
                "matched_advisories",
                "supply_chain_evaluation",
                "executed",
            )
        }
        vectors.append(
            {
                "query": {
                    "query": "protect_projection",
                    "intent": {
                        "package_manager": intent.package_manager,
                        "intent_kind": intent.intent_kind,
                        "redacted_command": intent.redacted_command,
                        "manifest_paths": list(intent.manifest_paths),
                        "lockfile_paths": list(intent.lockfile_paths),
                        "targets": [target.to_execution_dict() for target in intent.targets],
                    },
                    "artifact": {
                        "artifact_id": artifact.artifact_id,
                        "name": artifact.name,
                        "source_scope": artifact.source_scope,
                    },
                    "execution_context": context.to_evidence(),
                    "artifact_hash": authority.artifact_hash,
                    "additional_policy_context": additional,
                    "observe_mode": observe,
                    "invoking_harness": harness,
                    "evaluation": evaluation.to_dict(),
                    "command": list(command),
                    "blocking": blocking if index % 4 == 0 else None,
                    "executed": executed,
                    "project_execution_action": derive,
                },
                "expected": _expected(
                    fields,
                    projection,
                    permitted,
                    execution,
                    evaluation,
                    lsc._install_time_event_payload(
                        authority=authority,
                        command=command,
                        action=projection.verdict_action,
                        risk_signals=projection.risk_signals,
                    ),
                ),
            }
        )
    return vectors


def _expected(fields, projection, permitted, execution, evaluation, event_payload) -> dict:
    fields = json.loads(json.dumps(fields))
    fields["receipt"]["receipt_id"] = MASK
    fields["receipt"]["timestamp"] = MASK
    return {
        "fields": fields,
        "verdict_action": projection.verdict_action,
        "risk_signals": list(projection.risk_signals),
        "event_payload": event_payload,
        "execution_permitted": permitted,
        "execution_exit_code": lsc._package_execution_exit_code(execution),
        "policy_exit_code": lsc._package_execution_exit_code(evaluation.policy_action),
    }


if __name__ == "__main__":
    vectors = record()
    with gzip.open(Path(sys.argv[1]), "wt", encoding="utf-8", compresslevel=9) as handle:
        json.dump(vectors, handle, sort_keys=True, separators=(",", ":"))
    print(len(vectors))
