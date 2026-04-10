"""Interactive Guard approval prompts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..consumer import artifact_hash
from ..models import GuardArtifact, PolicyDecision
from ..receipts import build_receipt
from ..store import GuardStore

PromptChoice = str


@dataclass(frozen=True, slots=True)
class PromptArtifact:
    """Resolved artifact context for an interactive Guard decision."""

    harness: str
    artifact_id: str
    artifact_name: str
    artifact_hash: str
    policy_action: str
    changed_fields: tuple[str, ...]
    provenance_summary: str
    recommendation: str
    publisher: str | None
    config_path: str | None
    source_scope: str | None
    artifact_type: str | None
    command: str | None
    transport: str | None
    metadata: dict[str, object]
    current_snapshot: dict[str, object] | None
    removed: bool = False


def resolve_interactive_decisions(
    store: GuardStore,
    evaluation: dict[str, object],
    prompt_artifacts: list[PromptArtifact],
    workspace: str | None,
    now: str,
    console: Console | None = None,
    input_func: Callable[[str], str] | None = None,
) -> dict[str, object]:
    """Prompt for changed artifacts and apply the chosen Guard override."""

    review_items = [
        artifact
        for artifact in prompt_artifacts
        if artifact.policy_action in {"warn", "review", "require-reapproval", "block"}
    ]
    if not review_items:
        evaluation["blocked"] = False
        return evaluation

    terminal = console or Console()
    ask = input_func or terminal.input
    blocked = False
    decisions_by_artifact = {
        str(item.get("artifact_id")): item for item in _coerce_artifact_results(evaluation.get("artifacts"))
    }

    for artifact in review_items:
        try:
            choice = _prompt_for_artifact(artifact, terminal, ask)
        except (EOFError, KeyboardInterrupt):
            evaluation["review_hint"] = (
                "Guard needs an interactive terminal to approve changes. "
                f"Run `plugin-guard guard diff {artifact.harness}` and allow or deny the artifact before launch."
            )
            evaluation["blocked"] = True
            return evaluation
        if choice == "allow_once":
            _record_override_receipt(store, artifact, "allow", "allow-once", now)
            _set_decision_payload(decisions_by_artifact, artifact.artifact_id, "allow", "allow-once")
            continue
        if choice == "allow_artifact":
            store.upsert_policy(
                PolicyDecision(
                    harness=artifact.harness,
                    scope="artifact",
                    artifact_id=artifact.artifact_id,
                    action="allow",
                    reason="interactive-allow-artifact",
                ),
                now,
            )
            _persist_allowed_artifact(store, artifact, now)
            _record_override_receipt(store, artifact, "allow", "allow-artifact", now)
            _set_decision_payload(decisions_by_artifact, artifact.artifact_id, "allow", "allow-artifact")
            continue
        if choice == "allow_publisher":
            if artifact.publisher is None:
                store.upsert_policy(
                    PolicyDecision(
                        harness=artifact.harness,
                        scope="harness",
                        action="allow",
                        reason="interactive-allow-harness",
                    ),
                    now,
                )
                decision_scope = "allow-harness"
            else:
                store.upsert_policy(
                    PolicyDecision(
                        harness=artifact.harness,
                        scope="publisher",
                        publisher=artifact.publisher,
                        action="allow",
                        reason="interactive-allow-publisher",
                    ),
                    now,
                )
                decision_scope = "allow-publisher"
            _persist_allowed_artifact(store, artifact, now)
            _record_override_receipt(store, artifact, "allow", decision_scope, now)
            _set_decision_payload(decisions_by_artifact, artifact.artifact_id, "allow", decision_scope)
            continue

        store.upsert_policy(
            PolicyDecision(
                harness=artifact.harness,
                scope="artifact",
                artifact_id=artifact.artifact_id,
                action="block",
                reason="interactive-block",
            ),
            now,
        )
        _record_override_receipt(store, artifact, "block", "block", now)
        _set_decision_payload(decisions_by_artifact, artifact.artifact_id, "block", "block")
        blocked = True

    evaluation["artifacts"] = list(decisions_by_artifact.values())
    evaluation["blocked"] = blocked
    return evaluation


def _prompt_for_artifact(
    artifact: PromptArtifact,
    console: Console,
    ask: Callable[[str], str],
) -> PromptChoice:
    while True:
        console.print(_build_prompt_panel(artifact))
        prompt = (
            "[bold cyan]Choose[/bold cyan] "
            "[[green]1[/green]/[green]2[/green]/[green]3[/green]/[red]4[/red]/[yellow]5[/yellow]]: "
        )
        choice = ask(prompt).strip()
        normalized = choice.lower()
        if normalized in {"1", "allow-once", "allow_once"}:
            return "allow_once"
        if normalized in {"2", "always-artifact", "allow-artifact", "allow_artifact"}:
            return "allow_artifact"
        if normalized in {"3", "always-publisher", "allow-publisher", "allow_publisher"}:
            return "allow_publisher"
        if normalized in {"4", "block"}:
            return "block"
        if normalized in {"5", "details", "show-details", "show_details"}:
            console.print(_build_detail_panel(artifact))
            continue
        console.print("[yellow]Enter 1, 2, 3, 4, or 5.[/yellow]")


def _build_prompt_panel(artifact: PromptArtifact) -> Panel:
    table = Table.grid(padding=(0, 1))
    table.add_row("Artifact", f"[bold]{artifact.artifact_name}[/bold] ({artifact.artifact_id})")
    table.add_row("Harness", artifact.harness)
    table.add_row("Changed", ", ".join(artifact.changed_fields) or "none")
    table.add_row("Recommendation", artifact.recommendation)
    table.add_row("Provenance", artifact.provenance_summary)
    capabilities = _capabilities_summary(artifact)
    table.add_row("Capabilities", capabilities)
    publisher_label = artifact.publisher or artifact.harness
    menu = [
        "[green]1[/green] allow once",
        "[green]2[/green] always allow this artifact",
        f"[green]3[/green] always allow {publisher_label}",
        "[red]4[/red] block",
        "[yellow]5[/yellow] show details",
    ]
    content = Group(table, Text(""), *[Text.from_markup(item) for item in menu])
    return Panel(content, title="Guard review", border_style="yellow")


def _build_detail_panel(artifact: PromptArtifact) -> Panel:
    table = Table.grid(padding=(0, 1))
    table.add_row("Artifact type", artifact.artifact_type or "unknown")
    table.add_row("Source", artifact.source_scope or "unknown")
    table.add_row("Config", artifact.config_path or "unknown")
    table.add_row("Transport", artifact.transport or "unknown")
    table.add_row("Command", artifact.command or "n/a")
    table.add_row("Hash", artifact.artifact_hash)
    if artifact.publisher is not None:
        table.add_row("Publisher", artifact.publisher)
    env_keys = artifact.metadata.get("env_keys")
    if isinstance(env_keys, list) and env_keys:
        table.add_row("Env keys", ", ".join(str(item) for item in env_keys))
    return Panel(table, title="Guard details", border_style="blue")


def _capabilities_summary(artifact: PromptArtifact) -> str:
    parts = []
    if artifact.artifact_type is not None:
        parts.append(artifact.artifact_type.replace("_", " "))
    if artifact.transport is not None:
        parts.append(artifact.transport)
    if artifact.command is not None:
        parts.append(artifact.command)
    return " • ".join(parts) if parts else "local harness artifact"


def _persist_allowed_artifact(store: GuardStore, artifact: PromptArtifact, now: str) -> None:
    if artifact.removed:
        store.delete_snapshot(artifact.harness, artifact.artifact_id)
        return
    if artifact.current_snapshot is None:
        return
    store.save_snapshot(
        artifact.harness,
        artifact.artifact_id,
        {**artifact.current_snapshot, "artifact_hash": artifact.artifact_hash},
        artifact.artifact_hash,
        now,
    )


def _record_override_receipt(
    store: GuardStore,
    artifact: PromptArtifact,
    policy_decision: str,
    user_override: str,
    now: str,
) -> None:
    receipt = build_receipt(
        harness=artifact.harness,
        artifact_id=artifact.artifact_id,
        artifact_hash=artifact.artifact_hash,
        policy_decision=policy_decision,
        changed_capabilities=list(artifact.changed_fields),
        provenance_summary=artifact.provenance_summary,
        artifact_name=artifact.artifact_name,
        source_scope=artifact.source_scope,
        user_override=user_override,
    )
    store.add_receipt(receipt)


def _set_decision_payload(
    decision_map: dict[str, dict[str, object]],
    artifact_id: str,
    policy_action: str,
    user_override: str,
) -> None:
    item = decision_map.get(artifact_id)
    if item is None:
        return
    item["policy_action"] = policy_action
    item["user_override"] = user_override


def build_prompt_artifacts(
    harness: str,
    artifacts: list[GuardArtifact],
    evaluation_artifacts: list[dict[str, object]],
) -> list[PromptArtifact]:
    """Combine detected artifacts with evaluation results for prompting."""

    artifacts_by_id = {artifact.artifact_id: artifact for artifact in artifacts}
    prompt_artifacts: list[PromptArtifact] = []
    for item in evaluation_artifacts:
        artifact_id = str(item.get("artifact_id"))
        artifact = artifacts_by_id.get(artifact_id)
        changed_fields = tuple(str(field) for field in item.get("changed_fields", []) if isinstance(field, str))
        if artifact is None:
            prompt_artifacts.append(
                PromptArtifact(
                    harness=harness,
                    artifact_id=artifact_id,
                    artifact_name=str(item.get("artifact_name") or artifact_id),
                    artifact_hash=str(item.get("artifact_hash") or "removed"),
                    policy_action=str(item.get("policy_action") or "review"),
                    changed_fields=changed_fields,
                    provenance_summary=f"artifact removed from {harness}",
                    recommendation=str(item.get("policy_action") or "review"),
                    publisher=None,
                    config_path=None,
                    source_scope=None,
                    artifact_type=None,
                    command=None,
                    transport=None,
                    metadata={},
                    current_snapshot=None,
                    removed=bool(item.get("removed")),
                )
            )
            continue
        prompt_artifacts.append(
            PromptArtifact(
                harness=harness,
                artifact_id=artifact.artifact_id,
                artifact_name=artifact.name,
                artifact_hash=artifact_hash(artifact),
                policy_action=str(item.get("policy_action") or "review"),
                changed_fields=changed_fields,
                provenance_summary=f"{artifact.source_scope} artifact defined at {artifact.config_path}",
                recommendation=str(item.get("policy_action") or "review"),
                publisher=artifact.publisher,
                config_path=artifact.config_path,
                source_scope=artifact.source_scope,
                artifact_type=artifact.artifact_type,
                command=artifact.command,
                transport=artifact.transport,
                metadata=dict(artifact.metadata),
                current_snapshot=artifact.to_dict(),
                removed=False,
            )
        )
    return prompt_artifacts


def _coerce_artifact_results(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


__all__ = [
    "PromptArtifact",
    "build_prompt_artifacts",
    "resolve_interactive_decisions",
]
