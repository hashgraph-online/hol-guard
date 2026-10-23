"""Seed data for the dashboard evidence integration specs.

Receipts go through ``GuardStore.add_receipt`` (the write every harness hook
ends in) and command activity through ``GuardStore.record_command_activity``
(the write the command-protection runtime ends in), so the daemon reads them
back the way it reads live evidence.

Every receipt carries ``SOURCE_SCOPE`` and every command row uses a harness and
rule the spec filters on, so the specs can ignore receipts and activity other
areas seed into the same store.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.command_activity_contract import (
    ActivityApprovalReuseStatus,
    ActivityDecisionReason,
    ActivityLatencyBucket,
    ActivityMatchClass,
    ActivityParseConfidence,
    CommandActivity,
    CommandActivityEvidence,
    CommandActivityMatch,
    CommandExecutionStatus,
    CommandHookPhase,
    CommandProofLevel,
    CorrelationHandle,
    CorrelationKind,
    ReceiptLinkStatus,
)
from codex_plugin_scanner.guard.runtime.effect_contract import EffectKind
from codex_plugin_scanner.guard.runtime.extension_evidence import EvidenceSeverity, ExtensionRuleIdentity

from . import SeedContext

SOURCE_SCOPE = "evidence-e2e"
# Receipts behind reviewed and blocked command rows carry their own scope, so
# the receipt specs filtering on SOURCE_SCOPE keep their exact counts.
COMMAND_RECEIPT_SCOPE = "command-activity-e2e"
FILLER_COUNT = 46
HARNESS_CYCLE = ("codex", "claude-code", "cursor", "opencode")
SHELL_ENVELOPE_COMMANDS = {"rm -rf ./dist", "npm install left-pad"}


@dataclass(frozen=True)
class _Receipt:
    key: str
    name: str
    harness: str
    decision: str
    age_days: int
    category: str
    summary: str = "Runs a command on the machine"
    provenance: str = "Seeded evidence receipt"


# Names are chosen so the dashboard's text-based category detection lands on the
# listed category (dashboard/src/evidence/categories.tsx).
_FEATURED: tuple[_Receipt, ...] = (
    _Receipt("env", "Read .env.production", "codex", "block", 3, "secret"),
    _Receipt("fetch", "Fetch release notes from example.org", "claude-code", "review", 3, "network"),
    _Receipt("rm", "rm -rf ./dist", "cursor", "block", 3, "destructive"),
    _Receipt("write", "Write config file", "codex", "allow", 3, "file-write"),
    _Receipt("format", "tool.format source files", "claude-code", "allow", 3, "tool-call"),
    _Receipt("hidden", "Run base64 decoded installer", "opencode", "require-reapproval", 20, "hidden"),
    _Receipt("mcp", "mcp github create_issue", "claude-code", "warn", 20, "mcp"),
    _Receipt("skill", "Run lint skill", "cursor", "sandbox-required", 20, "skill"),
    _Receipt("ssh", "Read ~/.ssh/id_ed25519", "codex", "block", 20, "secret"),
    _Receipt("npm", "npm install left-pad", "codex", "review", 45, "supply-chain"),
    _Receipt("sqlite", "Query sqlite database", "opencode", "allow", 46, "data"),
    _Receipt("readme", "Read README.md", "cursor", "allow", 47, "other"),
)


def _disposition(decision: str) -> str:
    if decision in {"allow", "warn"}:
        return "allowed"
    if decision == "block":
        return "blocked"
    return "reviewed"


def _receipt(
    *,
    index: int,
    key: str,
    name: str,
    harness: str,
    decision: str,
    when: datetime,
    summary: str,
    provenance: str,
) -> tuple[GuardReceipt, GuardActionEnvelope | None]:
    receipt_id = f"evidence-e2e-receipt-{index:02d}"
    artifact_id = f"evidence-e2e:{key}"
    receipt = GuardReceipt(
        receipt_id=receipt_id,
        timestamp=when.isoformat(),
        harness=harness,
        artifact_id=artifact_id,
        artifact_hash=hashlib.sha256(artifact_id.encode()).hexdigest(),
        policy_decision=decision,  # type: ignore[arg-type]
        capabilities_summary=summary,
        changed_capabilities=("first_seen",),
        provenance_summary=provenance,
        artifact_name=name,
        source_scope=SOURCE_SCOPE,
        approval_source="hook" if decision != "allow" else None,
    )
    envelope = None
    if name in SHELL_ENVELOPE_COMMANDS:
        envelope = GuardActionEnvelope(
            schema_version=1,
            action_id=f"evidence-e2e-action-{index:02d}",
            harness=harness,
            event_name="PreToolUse",
            action_type="shell_command",
            workspace="/workspace/evidence-e2e",
            workspace_hash=None,
            tool_name="Bash",
            command=name,
            prompt_excerpt=None,
            prompt_text=None,
            target_paths=(),
            network_hosts=(),
            mcp_server=None,
            mcp_tool=None,
            package_manager=None,
            package_name=None,
            pre_execution_result=decision,
        )
    return receipt, envelope


def _seed_receipts(context: SeedContext) -> dict[str, Any]:
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    rows: list[dict[str, str]] = []
    for position, featured in enumerate(_FEATURED):
        # Featured rows are a few minutes apart so every sort order is strict.
        when = now - timedelta(days=featured.age_days, minutes=position)
        receipt, envelope = _receipt(
            index=position + 1,
            key=featured.key,
            name=featured.name,
            harness=featured.harness,
            decision=featured.decision,
            when=when,
            summary=featured.summary,
            provenance=featured.provenance,
        )
        context.store.add_receipt(receipt, action_envelope=envelope)
        rows.append(
            {
                "receipt_id": receipt.receipt_id,
                "name": featured.name,
                "harness": featured.harness,
                "decision": featured.decision,
                "category": featured.category,
                "disposition": _disposition(featured.decision),
                "age_days": str(featured.age_days),
            }
        )
    # Fillers sit four days back, behind the 3-day rows, and push the list past
    # the 50-row page so "Load more" has a second page to fetch.
    for offset in range(FILLER_COUNT):
        position = len(_FEATURED) + offset
        harness = HARNESS_CYCLE[offset % len(HARNESS_CYCLE)]
        name = f"Format code pass {offset + 1:02d}"
        receipt, envelope = _receipt(
            index=position + 1,
            key=f"filler-{offset + 1:02d}",
            name=name,
            harness=harness,
            decision="allow",
            when=now - timedelta(days=4, minutes=offset),
            summary="Runs a command on the machine",
            provenance="Seeded evidence receipt",
        )
        context.store.add_receipt(receipt, action_envelope=envelope)
        rows.append(
            {
                "receipt_id": receipt.receipt_id,
                "name": name,
                "harness": harness,
                "decision": "allow",
                "category": "other",
                "disposition": "allowed",
                "age_days": "4",
            }
        )

    def count(field: str, value: str) -> int:
        return sum(1 for row in rows if row[field] == value)

    by_harness = {harness: count("harness", harness) for harness in HARNESS_CYCLE}
    by_harness_disposition = {
        harness: {
            disposition: sum(1 for row in rows if row["harness"] == harness and row["disposition"] == disposition)
            for disposition in ("allowed", "reviewed", "blocked")
        }
        for harness in HARNESS_CYCLE
    }
    by_category = {category: count("category", category) for category in sorted({row["category"] for row in rows})}
    by_decision = {decision: count("decision", decision) for decision in sorted({row["decision"] for row in rows})}
    by_disposition = {
        disposition: count("disposition", disposition) for disposition in ("allowed", "reviewed", "blocked")
    }
    within = {days: sum(1 for row in rows if int(row["age_days"]) <= days) for days in (7, 30)}
    return {
        "source_scope": SOURCE_SCOPE,
        "total": len(rows),
        "page_size": 50,
        "by_harness": by_harness,
        "by_harness_disposition": by_harness_disposition,
        "by_category": by_category,
        "by_decision": by_decision,
        "by_disposition": by_disposition,
        "within_7_days": within[7],
        "within_30_days": within[30],
        "featured": {
            feature.key: {
                "receipt_id": f"evidence-e2e-receipt-{position + 1:02d}",
                "name": feature.name,
                "harness": feature.harness,
                "decision": feature.decision,
                "category": feature.category,
            }
            for position, feature in enumerate(_FEATURED)
        },
        # Oldest and newest across the whole seeded set, for sort assertions.
        "newest_name": "Read .env.production",
        "oldest_name": "Read README.md",
    }


@dataclass(frozen=True)
class _Rule:
    extension_id: str
    rule_id: str
    title: str
    severity: EvidenceSeverity
    effects: frozenset[EffectKind]


_GIT_FORCE_PUSH = _Rule(
    "command.git",
    "command.git.force-push",
    "Forced Git push",
    EvidenceSeverity.HIGH,
    frozenset({EffectKind.REMOTE_STATE_MUTATION}),
)
_GIT_HARD_RESET = _Rule(
    "command.git",
    "command.git.hard-reset",
    "Destructive Git reset",
    EvidenceSeverity.HIGH,
    frozenset({EffectKind.DESTRUCTIVE_OR_IRREVERSIBLE_OPERATION}),
)
_GIT_FORCE_CLEAN = _Rule(
    "command.git",
    "command.git.force-clean",
    "Forced Git clean",
    EvidenceSeverity.HIGH,
    frozenset({EffectKind.DESTRUCTIVE_OR_IRREVERSIBLE_OPERATION}),
)
_FS_DELETE = _Rule(
    "command.filesystem",
    "command.filesystem.recursive-delete",
    "Recursive filesystem deletion",
    EvidenceSeverity.HIGH,
    frozenset({EffectKind.DESTRUCTIVE_OR_IRREVERSIBLE_OPERATION}),
)
_K8S_DELETE = _Rule(
    "command.kubernetes-operations",
    "command.kubernetes-operations.delete-resources",
    "Kubernetes resource deletion",
    EvidenceSeverity.HIGH,
    frozenset({EffectKind.REMOTE_STATE_MUTATION}),
)
_PG_DROP = _Rule(
    "command.database.postgresql",
    "command.database.postgresql.drop",
    "PostgreSQL database removal",
    EvidenceSeverity.CRITICAL,
    frozenset({EffectKind.DESTRUCTIVE_OR_IRREVERSIBLE_OPERATION}),
)
_AWS_DELETE = _Rule(
    "command.cloud.aws",
    "command.cloud.aws.resource-deletion",
    "AWS resource deletion",
    EvidenceSeverity.CRITICAL,
    frozenset({EffectKind.REMOTE_STATE_MUTATION}),
)


@dataclass(frozen=True)
class _Command:
    number: int
    harness: str
    command: str
    status: CommandExecutionStatus
    action: str | None
    rules: tuple[_Rule, ...] = ()
    prompted: bool = False
    reused: bool = False


# Rows 1 to 11, minute 20:NN UTC on the previous day. See _seed_commands.
_COMMANDS: tuple[_Command, ...] = (
    _Command(
        1,
        "claude-code",
        "git push --force origin main",
        CommandExecutionStatus.ATTEMPTED,
        "review",
        (_GIT_FORCE_PUSH,),
        prompted=True,
    ),
    _Command(
        2, "claude-code", "git reset --hard HEAD~3", CommandExecutionStatus.PREVENTED, "block", (_GIT_HARD_RESET,)
    ),
    _Command(
        3, "cursor", "rm -rf build/", CommandExecutionStatus.ALLOWED_UNCONFIRMED, "review", (_FS_DELETE,), prompted=True
    ),
    _Command(4, "cursor", "ls -la src", CommandExecutionStatus.ALLOWED_UNCONFIRMED, "allow"),
    _Command(
        5,
        "opencode",
        "kubectl delete pod web-1",
        CommandExecutionStatus.ATTEMPTED,
        "review",
        (_K8S_DELETE,),
        prompted=True,
    ),
    _Command(6, "opencode", "psql -c 'DROP DATABASE staging'", CommandExecutionStatus.PREVENTED, "block", (_PG_DROP,)),
    _Command(7, "claude-code", "npm test", CommandExecutionStatus.CONFIRMED_SUCCESS, "allow"),
    _Command(8, "cursor", "npm run lint", CommandExecutionStatus.CONFIRMED_FAILURE, "allow"),
    _Command(9, "opencode", "make build", CommandExecutionStatus.UNPAIRED_POST, None),
    _Command(
        10,
        "claude-code",
        "aws s3 rb s3://staging-assets --force",
        CommandExecutionStatus.ATTEMPTED,
        "review",
        (_AWS_DELETE,),
        reused=True,
    ),
    _Command(
        11,
        "cursor",
        "git clean -fdx && git reset --hard",
        CommandExecutionStatus.PREVENTED,
        "block",
        (_GIT_HARD_RESET, _GIT_FORCE_CLEAN),
    ),
)


def _activity_id(number: int) -> str:
    return f"evidence-e2e-cmd-{number:02d}"


def _needs_receipt(command: _Command) -> bool:
    # The activity contract requires a linked receipt for review or stronger.
    return command.action in {"review", "block"}


def _command_receipt_id(command: _Command) -> str:
    return f"evidence-e2e-cmd-receipt-{command.number:02d}"


def _command_receipt(command: _Command, day: datetime) -> GuardReceipt:
    artifact_id = f"{COMMAND_RECEIPT_SCOPE}:{command.number:02d}"
    return GuardReceipt(
        receipt_id=_command_receipt_id(command),
        timestamp=day.replace(hour=20, minute=command.number).isoformat(),
        harness=command.harness,
        artifact_id=artifact_id,
        artifact_hash=hashlib.sha256(artifact_id.encode()).hexdigest(),
        policy_decision=command.action,  # type: ignore[arg-type]
        capabilities_summary="Runs a command on the machine",
        changed_capabilities=("first_seen",),
        provenance_summary="Seeded command activity receipt",
        artifact_name=command.command,
        source_scope=COMMAND_RECEIPT_SCOPE,
        approval_source="hook",
    )


def _command_evidence(command: _Command, day: datetime) -> CommandActivityEvidence:
    activity_id = _activity_id(command.number)
    occurred_at = day.replace(hour=20, minute=command.number)
    status = command.status
    unpaired = status is CommandExecutionStatus.UNPAIRED_POST
    confirmed = status in {CommandExecutionStatus.CONFIRMED_SUCCESS, CommandExecutionStatus.CONFIRMED_FAILURE}
    if unpaired:
        hook_phase, proof = CommandHookPhase.POST_SUCCESS, CommandProofLevel.UNPAIRED_POST
    elif status is CommandExecutionStatus.CONFIRMED_SUCCESS:
        hook_phase, proof = CommandHookPhase.POST_SUCCESS, CommandProofLevel.POST_HOOK
    elif status is CommandExecutionStatus.CONFIRMED_FAILURE:
        hook_phase, proof = CommandHookPhase.POST_FAILURE, CommandProofLevel.POST_HOOK
    else:
        hook_phase, proof = CommandHookPhase.PRE, CommandProofLevel.PRE_HOOK
    request_correlation = (
        CorrelationHandle(CorrelationKind.REQUEST, command.harness, "key.v1", "a" * 64) if confirmed else None
    )
    needs_receipt = _needs_receipt(command)
    if unpaired:
        activity = CommandActivity(
            activity_id=activity_id,
            occurred_at=occurred_at,
            harness=command.harness,
            hook_phase=hook_phase,
            execution_status=status,
            proof_level=proof,
            policy_action=None,
            decision_reason_code=None,
            controlling_rule_id=None,
            parse_confidence=None,
            uncertainty_class=None,
            match_count=0,
            prompted=False,
            approval_reuse_status=ActivityApprovalReuseStatus.NOT_APPLICABLE,
            request_correlation=None,
            session_correlation=None,
            receipt_link_status=ReceiptLinkStatus.NOT_APPLICABLE,
            receipt_id=None,
            evaluation_latency_bucket=ActivityLatencyBucket.NOT_MEASURED,
            persistence_latency_bucket=ActivityLatencyBucket.LE_2_MS,
        )
        return CommandActivityEvidence(activity, ())
    if command.reused:
        reason = ActivityDecisionReason.APPROVAL_REUSE
    elif command.rules:
        reason = ActivityDecisionReason.EXTENSION_MATCH
    else:
        reason = ActivityDecisionReason.NO_MATCH
    activity = CommandActivity(
        activity_id=activity_id,
        occurred_at=occurred_at,
        harness=command.harness,
        hook_phase=hook_phase,
        execution_status=status,
        proof_level=proof,
        policy_action=command.action,  # type: ignore[arg-type]
        decision_reason_code=reason,
        controlling_rule_id=command.rules[0].rule_id if command.rules else None,
        parse_confidence=ActivityParseConfidence.EXACT,
        uncertainty_class=None,
        match_count=len(command.rules),
        prompted=command.prompted,
        approval_reuse_status=(
            ActivityApprovalReuseStatus.ACCEPTED if command.reused else ActivityApprovalReuseStatus.NOT_APPLICABLE
        ),
        request_correlation=request_correlation,
        session_correlation=None,
        receipt_link_status=ReceiptLinkStatus.LINKED if needs_receipt else ReceiptLinkStatus.NOT_APPLICABLE,
        receipt_id=_command_receipt_id(command) if needs_receipt else None,
        evaluation_latency_bucket=ActivityLatencyBucket.LE_5_MS,
        persistence_latency_bucket=ActivityLatencyBucket.LE_2_MS,
    )
    matches = tuple(
        CommandActivityMatch(
            activity_id=activity_id,
            ordinal=ordinal,
            identity=ExtensionRuleIdentity(rule.extension_id, "1.0.0", rule.rule_id, "1.0.0"),
            match_class=ActivityMatchClass.UNSAFE,
            severity=rule.severity,
            default_floor="review",
            effect_claims=rule.effects,
        )
        for ordinal, rule in enumerate(command.rules)
    )
    return CommandActivityEvidence(activity, matches)


def _seed_commands(context: SeedContext) -> dict[str, Any]:
    # Activity older than ninety days is pruned when the daemon starts, so the
    # rows sit on yesterday (UTC) at 20:01 to 20:11, well inside the window and
    # always in the past.
    day = (datetime.now(timezone.utc) - timedelta(days=1)).replace(second=0, microsecond=0)
    for command in _COMMANDS:
        if _needs_receipt(command):
            context.store.add_receipt(_command_receipt(command, day))
        context.store.record_command_activity(
            _command_evidence(command, day),
            invocation_preview=command.command,
        )
    return {
        "total": len(_COMMANDS),
        "records": {
            _activity_id(command.number): {
                "command": command.command,
                "harness": command.harness,
                "status": command.status.value,
                "action": command.action,
                "prompted": command.prompted,
                "rules": [rule.rule_id for rule in command.rules],
                "rule_titles": [rule.title for rule in command.rules],
                "extensions": sorted({rule.extension_id for rule in command.rules}),
            }
            for command in _COMMANDS
        },
        "by_harness": {
            harness: sum(1 for command in _COMMANDS if command.harness == harness)
            for harness in ("claude-code", "cursor", "opencode")
        },
    }


def seed(context: SeedContext) -> dict[str, Any]:
    return {"receipts": _seed_receipts(context), "commands": _seed_commands(context)}
