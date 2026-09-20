"""run presentation for Guard CLI output."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .render import Console, Table
    from .render_context import RenderContext


def _render_run(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    blocked = bool(payload.get("blocked"))
    launched = bool(payload.get("launched"))
    dry_run = bool(payload.get("dry_run"))
    authority_error = payload.get("authority_error")
    has_authority_error = isinstance(authority_error, str) and bool(authority_error.strip())
    artifacts = view._coerce_dict_list(payload.get("artifacts"))
    visible_artifacts = (
        []
        if has_authority_error
        else [artifact for artifact in artifacts if view._run_artifact_should_be_visible(artifact)]
    )
    summarized_artifacts = view._summarize_run_artifacts(visible_artifacts)
    title = (
        "Launch refused: inconsistent decision"
        if has_authority_error
        else view._run_title(blocked=blocked, dry_run=dry_run)
    )
    border_style = "red" if blocked else "green"
    body = view.Table.grid(padding=(0, 1))
    approval_delivery = payload.get("approval_delivery")
    body.add_row("Harness", f"[bold]{payload.get('harness', 'unknown')}[/bold]")
    body.add_row("Mode", "dry run" if dry_run else "launch")
    authority_message = payload.get("authority_error_message")
    outcome = (
        str(authority_message)
        if has_authority_error and isinstance(authority_message, str) and authority_message.strip()
        else view._run_outcome_text(blocked=blocked, dry_run=dry_run, launched=launched)
    )
    body.add_row("Outcome", outcome)
    if has_authority_error:
        body.add_row("Authority error", str(authority_error))
    body.add_row("Artifacts", str(len(summarized_artifacts)))
    if blocked and not has_authority_error:
        needs_review = sum(1 for artifact in visible_artifacts if view._artifact_needs_review(artifact))
        body.add_row("Needs review", str(needs_review))
    body.add_row("Receipts", str(payload.get("receipts_recorded", 0)))
    if isinstance(approval_delivery, dict) and approval_delivery.get("summary"):
        body.add_row("Prompt route", str(approval_delivery.get("summary")))
    if payload.get("approval_center_url"):
        body.add_row("Approval center", str(payload.get("approval_center_url")))
    if payload.get("review_hint"):
        body.add_row("Review", str(payload.get("review_hint")))
    if launched:
        body.add_row("Command", view._command_text(payload.get("launch_command")))
    console.print(view.Panel(body, title=title, border_style=border_style))
    if summarized_artifacts:
        console.print(view._build_run_artifact_table(summarized_artifacts))
    steps = view._build_run_steps(payload, blocked=blocked, dry_run=dry_run)
    if steps:
        console.print(view._build_steps_panel(steps))
    approval_requests = view._coerce_dict_list(payload.get("approval_requests"))
    if approval_requests:
        console.print(view._build_approval_table(approval_requests, title="Queued approvals"))


def _render_diff(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    changed = bool(payload.get("changed"))
    title = "Changes detected" if changed else "No changes detected"
    border_style = "yellow" if changed else "green"
    console.print(
        view.Panel.fit(
            f"[bold]{title}[/bold]\n{len(view._coerce_dict_list(payload.get('artifacts')))} artifacts in diff view",
            border_style=border_style,
        )
    )
    console.print(view._build_artifact_result_table(view._coerce_dict_list(payload.get("artifacts"))))


def _build_artifact_table(view: RenderContext, artifacts: list[dict[str, object]]) -> Table:
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Artifact", style="bold")
    table.add_column("Type")
    table.add_column("Scope")
    table.add_column("Transport")
    table.add_column("Source")
    for artifact in artifacts:
        table.add_row(
            str(artifact.get("name") or artifact.get("artifact_id") or "unknown"),
            str(artifact.get("artifact_type") or "unknown"),
            str(artifact.get("source_scope") or "unknown"),
            str(artifact.get("transport") or "config"),
            view._artifact_source_text(artifact),
        )
    return table


def _build_artifact_result_table(view: RenderContext, artifacts: list[dict[str, object]]) -> Table:
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Artifact", style="bold")
    table.add_column("Changed")
    table.add_column("Policy")
    table.add_column("Fields")
    table.add_column("Risk")
    for artifact in artifacts:
        table.add_row(
            str(artifact.get("artifact_name") or artifact.get("artifact_id") or "unknown"),
            view._bool_label(bool(artifact.get("changed"))),
            view._action_text(str(artifact.get("policy_action", "warn"))),
            ", ".join(view._coerce_string_list(artifact.get("changed_fields"))) or "none",
            str(artifact.get("risk_summary") or "no obvious secret/network signal"),
        )
    return table


def _build_run_artifact_table(view: RenderContext, artifacts: list[dict[str, str]]) -> Table:
    table = view.Table(title="What changed", box=view.box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Artifact", style="bold")
    table.add_column("Guard saw")
    table.add_column("Reason")
    table.add_column("Risk")
    for artifact in artifacts:
        table.add_row(
            artifact["artifact_name"],
            artifact["change_summary"],
            artifact["reason_summary"],
            artifact["risk_summary"],
        )
    return table


def _run_title(view: RenderContext, *, blocked: bool, dry_run: bool) -> str:
    if blocked and dry_run:
        return "Dry run paused for review"
    if blocked:
        return "Blocked before launch"
    if dry_run:
        return "Dry run complete"
    return "Launch allowed"


def _run_outcome_text(view: RenderContext, *, blocked: bool, dry_run: bool, launched: bool) -> str:
    if blocked and dry_run:
        return "Guard found artifacts that need review before a real launch."
    if blocked:
        return "Guard paused the launch until you review the artifacts that need attention."
    if dry_run:
        return "Guard reviewed the current config without launching the harness."
    if launched:
        return "Guard approved the launch and handed control to the harness."
    return "Guard finished the check without launching the harness."


def _build_run_steps(
    view: RenderContext,
    payload: dict[str, object],
    *,
    blocked: bool,
    dry_run: bool,
) -> list[dict[str, str]]:
    harness = str(payload.get("harness") or "codex")
    authority_error = payload.get("authority_error")
    if isinstance(authority_error, str) and authority_error:
        return [
            {
                "title": "Repair and rescan Guard authority",
                "command": f"hol-guard doctor {harness}",
                "detail": (
                    "Guard refused to use contradictory decision fields. Diagnose or repair the local Guard "
                    "installation, then retry the original guarded command."
                ),
            }
        ]
    approval_center_url = payload.get("approval_center_url")
    review_hint = payload.get("review_hint")
    rerun_command = payload.get("rerun_command")
    diff_command = payload.get("diff_command")
    approvals_command = payload.get("approvals_command")
    if blocked and dry_run:
        review_command = (
            str(rerun_command) if isinstance(rerun_command, str) and rerun_command else f"hol-guard run {harness}"
        )
        inspect_command = (
            str(diff_command) if isinstance(diff_command, str) and diff_command else f"hol-guard diff {harness}"
        )
        review_detail = (
            str(review_hint)
            if isinstance(review_hint, str) and review_hint
            else "Rerun without --dry-run to review the full blocker set and continue into the harness launch."
        )
        steps = [
            {
                "title": "Resolve the blocked launch",
                "command": review_command,
                "detail": review_detail,
            },
        ]
        if approval_center_url:
            approval_command = (
                str(approvals_command)
                if isinstance(approvals_command, str) and approvals_command
                else "hol-guard approvals"
            )
            steps.append(
                {
                    "title": "Open the approvals queue",
                    "command": approval_command,
                    "detail": (
                        "Review any queued approval requests after the prompt appears, then retry the guarded command."
                    ),
                }
            )
        steps.append(
            {
                "title": "Inspect only the changed config entries (optional)",
                "command": inspect_command,
                "detail": (
                    "See the config-level diff only. This view can omit policy-only blockers "
                    "Guard still needs you to review."
                ),
            },
        )
        return steps
    if blocked and isinstance(review_hint, str) and review_hint:
        if approval_center_url:
            command = (
                str(approvals_command)
                if isinstance(approvals_command, str) and approvals_command
                else "hol-guard approvals"
            )
        elif isinstance(rerun_command, str) and rerun_command:
            command = str(rerun_command)
        else:
            command = f"hol-guard run {harness}"
        return [{"title": "Resolve the blocked launch", "command": command, "detail": review_hint}]
    if dry_run:
        launch_command = (
            str(rerun_command) if isinstance(rerun_command, str) and rerun_command else f"hol-guard run {harness}"
        )
        return [
            {
                "title": "Launch for real",
                "command": launch_command,
                "detail": "Dry run finished cleanly; rerun without --dry-run when you are ready to launch.",
            }
        ]
    return []


def _summarize_run_artifacts(view: RenderContext, artifacts: list[dict[str, object]]) -> list[dict[str, str]]:
    summarized: list[dict[str, str]] = []
    used_indexes: set[int] = set()
    for index, artifact in enumerate(artifacts):
        if index in used_indexes:
            continue
        partner_index = view._find_replaced_artifact_partner(artifacts, index, used_indexes)
        if partner_index is not None:
            used_indexes.add(index)
            used_indexes.add(partner_index)
            primary, secondary = view._replacement_pair(artifact, artifacts[partner_index])
            summarized.append(
                {
                    "artifact_name": view._artifact_display_name(primary),
                    "change_summary": "definition replaced",
                    "reason_summary": (
                        "Guard saw the previous definition disappear and a new definition with the same name appear, "
                        "so it is asking for a fresh approval."
                    ),
                    "risk_summary": view._artifact_risk_text(primary, secondary),
                    "policy_action": str(primary.get("policy_action") or "review"),
                }
            )
            continue
        used_indexes.add(index)
        summarized.append(
            {
                "artifact_name": view._artifact_display_name(artifact),
                "change_summary": view._artifact_change_summary(artifact),
                "reason_summary": view._artifact_reason_text(artifact),
                "risk_summary": view._artifact_risk_text(artifact),
                "policy_action": str(artifact.get("policy_action") or "review"),
            }
        )
    return summarized


def _find_replaced_artifact_partner(
    view: RenderContext,
    artifacts: list[dict[str, object]],
    index: int,
    used_indexes: set[int],
) -> int | None:
    artifact = artifacts[index]
    fields = set(view._coerce_string_list(artifact.get("changed_fields")))
    if fields not in ({"first_seen"}, {"removed"}):
        return None
    target_fields = {"removed"} if fields == {"first_seen"} else {"first_seen"}
    artifact_name = view._artifact_display_name(artifact)
    policy_action = str(artifact.get("policy_action") or "")
    artifact_label = str(artifact.get("artifact_label") or "")
    artifact_identity = view._artifact_replacement_identity(artifact)
    for partner_index in range(index + 1, len(artifacts)):
        if partner_index in used_indexes:
            continue
        partner = artifacts[partner_index]
        if view._artifact_display_name(partner) != artifact_name:
            continue
        if set(view._coerce_string_list(partner.get("changed_fields"))) != target_fields:
            continue
        if policy_action and str(partner.get("policy_action") or "") != policy_action:
            continue
        if artifact_label and str(partner.get("artifact_label") or "") != artifact_label:
            continue
        if view._artifact_replacement_identity(partner) != artifact_identity:
            continue
        return partner_index
    return None


def _replacement_pair(
    view: RenderContext,
    first: dict[str, object],
    second: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    if set(view._coerce_string_list(first.get("changed_fields"))) == {"first_seen"}:
        return first, second
    return second, first


def _artifact_display_name(view: RenderContext, artifact: dict[str, object]) -> str:
    return str(artifact.get("artifact_name") or artifact.get("artifact_id") or "unknown")


def _artifact_replacement_identity(view: RenderContext, artifact: dict[str, object]) -> tuple[tuple[str, str], ...]:
    identity_keys = ("source_scope", "config_path", "publisher")
    identity: list[tuple[str, str]] = []
    for key in identity_keys:
        value = artifact.get(key)
        if value in (None, ""):
            continue
        identity.append((key, str(value)))
    return tuple(identity)


def _artifact_change_summary(view: RenderContext, artifact: dict[str, object]) -> str:
    fields = set(view._coerce_string_list(artifact.get("changed_fields")))
    if fields == {"first_seen"}:
        return "new artifact"
    if fields == {"removed"}:
        return "removed from config"
    if "prompt_request" in fields:
        return "prompt requested secret access"
    if "file_read_request" in fields:
        return "protected file read requested"
    if "command" in fields or "args" in fields:
        return "launch command changed"
    if "url" in fields or "transport" in fields:
        return "connection target changed"
    if "publisher" in fields or "source_scope" in fields:
        return "publisher or source changed"
    if "env_keys" in fields:
        return "environment access changed"
    labels = [view._field_label(field) for field in view._coerce_string_list(artifact.get("changed_fields"))]
    if not labels:
        return "no material change"
    if len(labels) == 1:
        return f"{labels[0]} changed"
    if len(labels) == 2:
        return f"{labels[0]} and {labels[1]} changed"
    return "multiple settings changed"


def _field_label(view: RenderContext, field: str) -> str:
    labels = {
        "artifact_type": "artifact type",
        "args": "launch arguments",
        "command": "launch command",
        "config_path": "config location",
        "env_keys": "environment access",
        "publisher": "publisher",
        "source_scope": "source scope",
        "transport": "transport",
        "url": "remote endpoint",
    }
    return labels.get(field, field.replace("_", " "))


def _artifact_reason_text(view: RenderContext, artifact: dict[str, object]) -> str:
    reason = artifact.get("why_now")
    if isinstance(reason, str) and reason:
        return reason
    policy_action = str(artifact.get("policy_action") or "review")
    if policy_action == "allow":
        return "Guard matched an existing allow rule for this exact definition."
    if policy_action == "block":
        return "Guard blocked this definition because the configured policy does not trust it yet."
    if policy_action == "sandbox-required":
        return "Guard requires extra isolation before this launch can continue."
    return "Guard found a meaningful config change and paused the launch for review."


def _artifact_risk_text(view: RenderContext, *artifacts: dict[str, object]) -> str:
    for artifact in artifacts:
        for key in ("risk_summary", "risk_headline"):
            value = artifact.get(key)
            if isinstance(value, str) and value:
                return value
    return "No obvious secret-access or network signal was detected in the launch definition."


def _run_artifact_should_be_visible(view: RenderContext, artifact: dict[str, object]) -> bool:
    if bool(artifact.get("changed")):
        return True
    return str(artifact.get("policy_action") or "allow") in {
        "review",
        "require-reapproval",
        "sandbox-required",
        "block",
    }


def _artifact_needs_review(view: RenderContext, artifact: dict[str, object]) -> bool:
    return str(artifact.get("policy_action") or "allow") in {
        "review",
        "require-reapproval",
        "sandbox-required",
        "block",
    }


def _artifact_source_text(view: RenderContext, artifact: dict[str, object]) -> str:
    url = artifact.get("url")
    if isinstance(url, str) and url:
        return url
    command = artifact.get("command")
    args = view._coerce_string_list(artifact.get("args"))
    if isinstance(command, str) and command:
        return " ".join([command, *args]).strip()
    return view._short_path(str(artifact.get("config_path") or "unknown"))
