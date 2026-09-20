"""Onboarding and cloud-connect guidance with caller-owned presentation bindings."""

from __future__ import annotations

from collections.abc import Callable


def build_next_steps(
    recommended: dict[str, object] | None,
    payload: dict[str, object],
    *,
    guard_command: str,
    default_connect_url: str,
    default_dashboard_url: str,
    install_or_review_step: Callable[[dict[str, object]], dict[str, str]],
    run_step: Callable[[dict[str, object]], dict[str, str]],
    receipts_step: Callable[[], dict[str, str]],
    approvals_step: Callable[[], dict[str, str]],
    connect_or_dashboard_step: Callable[[str, str, str], dict[str, str]],
) -> list[dict[str, str]]:
    if recommended is None:
        return [
            {
                "title": "Install a supported harness",
                "command": f"{guard_command} detect",
                "detail": (
                    "Guard did not find a local harness config yet. Start by installing "
                    "Codex, Claude Code, Copilot CLI, Hermes, Cursor, Antigravity, Gemini, or OpenCode."
                ),
            }
        ]
    steps = [install_or_review_step(recommended), run_step(recommended), receipts_step()]
    steps.append(approvals_step())
    steps.append(
        connect_or_dashboard_step(
            str(payload.get("cloud_state") or "local_only"),
            str(payload.get("connect_url") or default_connect_url),
            str(payload.get("dashboard_url") or default_dashboard_url),
        )
    )
    return steps


def build_connect_steps(
    payload: dict[str, object],
    *,
    guard_command: str,
    default_dashboard_url: str,
    default_connect_url: str,
    default_inbox_url: str,
    default_fleet_url: str,
    recommended_summary: Callable[[dict[str, object]], dict[str, object] | None],
    run_step: Callable[[dict[str, object]], dict[str, str]],
    int_payload_value: Callable[[dict[str, object], str, int], int],
    approvals_step: Callable[[], dict[str, str]],
    install_or_review_step: Callable[[dict[str, object]], dict[str, str]],
) -> list[dict[str, str]]:
    cloud_state = str(payload.get("cloud_state") or "local_only")
    recommended = recommended_summary(payload)
    dashboard_url = str(payload.get("dashboard_url") or default_dashboard_url)
    connect_url = str(payload.get("connect_url") or default_connect_url)
    inbox_url = str(payload.get("inbox_url") or default_inbox_url)
    fleet_url = str(payload.get("fleet_url") or default_fleet_url)
    steps: list[dict[str, str]]
    if cloud_state == "local_only":
        steps = [
            {
                "title": "Run Guard connect",
                "command": str(payload.get("connect_command") or f"{guard_command} connect"),
                "detail": (
                    "Start the local pairing flow, open the browser automatically, and wait for Guard Cloud to pair "
                    "this machine."
                ),
            },
            {
                "title": "Complete browser sign-in",
                "command": connect_url,
                "detail": (
                    "Sign in on the Guard connect page if prompted. Guard will resume and run the first sync once the "
                    "browser pairing finishes."
                ),
            },
        ]
        if recommended is not None:
            steps.append(run_step(recommended))
        steps.append(
            {
                "title": "Open Guard Home",
                "command": dashboard_url,
                "detail": (
                    "Home stays useful before sync is on. Use it to watch this machine "
                    "and decide when shared memory becomes worth it."
                ),
            }
        )
        return steps
    if cloud_state == "paired_waiting":
        steps = [
            {
                "title": "Finish the first cloud sync",
                "command": str(payload.get("sync_command") or f"{guard_command} sync"),
                "detail": (
                    "Keep Local Guard running so it can finish the first cloud sync automatically. "
                    "Use the sync command only when you want to force the retry now."
                ),
            }
        ]
        if int_payload_value(payload, "receipt_count", 0) == 0 and recommended is not None:
            steps.append(run_step(recommended))
        steps.append(
            {
                "title": "Open Guard Fleet",
                "command": fleet_url,
                "detail": (
                    "Fleet is the fastest place to confirm the connected machine while "
                    "the first shared proof is still warming up."
                ),
            }
        )
        return steps
    if int_payload_value(payload, "pending_approvals", 0) > 0:
        steps = [
            {
                "title": "Open Guard Inbox",
                "command": inbox_url,
                "detail": "Inbox is the fastest place to resolve live review pressure after this machine connects.",
            },
            approvals_step(),
        ]
    elif recommended is not None and str(recommended.get("next_action")) == "review":
        steps = [
            {
                "title": "Open Guard Inbox",
                "command": inbox_url,
                "detail": (
                    "Guard already sees review pressure. Start in Inbox, then drop back "
                    "to the local approval center only when needed."
                ),
            },
            install_or_review_step(recommended),
        ]
    else:
        steps = [
            {
                "title": "Check local Guard status",
                "command": f"{guard_command} status",
                "detail": "Review local protection health, recent sync, and Guard's recommended next step.",
            }
        ]
    steps.insert(
        0,
        {
            "title": "Open Guard Home",
            "command": dashboard_url,
            "detail": "Review Home, Inbox, Fleet, Evidence, and upgrade prompts from the signed-in command center.",
        },
    )
    if bool(payload.get("team_policy_active")):
        steps.append(
            {
                "title": "Inspect synced team policy",
                "command": f"{guard_command} policies",
                "detail": "Confirm the shared workspace policy Guard pulled down for this machine.",
            }
        )
    elif int_payload_value(payload, "advisory_count", 0) > 0:
        steps.append(
            {
                "title": "Review Guard advisories",
                "command": f"{guard_command} advisories",
                "detail": "Inspect the latest premium trust signals and publisher changes Guard cached locally.",
            }
        )
    return steps


def connect_or_dashboard_step(
    cloud_state: str,
    connect_url: str,
    dashboard_url: str,
    *,
    guard_command: str,
) -> dict[str, str]:
    if cloud_state == "local_only":
        return {
            "title": "Optional cloud connect",
            "command": f"{guard_command} connect",
            "detail": (
                "Keep local protection free by default, then run one command when you want shared inbox state, "
                "fleet continuity, evidence, or team policy."
            ),
        }
    return {
        "title": "Open Guard Home",
        "command": dashboard_url,
        "detail": (
            "Guard Cloud is already paired. Use the signed-in command center for Home, Fleet, Evidence, and upgrades."
        ),
    }


def cloud_state_detail(
    cloud_state: str,
    connect_url: str,
    dashboard_url: str,
    *,
    oauth_repair_required: bool = False,
    connect_retry_required: bool = False,
    connect_retry_refresh_race: bool = False,
    shared_proof_recorded: bool = False,
    guard_command: str,
    resolve_guard_cloud_repair_detail: Callable[..., str],
) -> str:
    if oauth_repair_required:
        return (
            "Guard Cloud sign-in on this machine is incomplete. "
            f"Run `{guard_command} connect` or reopen {connect_url} to repair local authorization and resume sync."
        )
    if connect_retry_refresh_race:
        return (
            "Local Guard remains available. The first shared Guard Cloud proof stalled after a refresh-token "
            f"race. Run `{guard_command} connect` or reopen {connect_url} when you want shared proof restored."
        )
    if connect_retry_required:
        return resolve_guard_cloud_repair_detail(
            shared_proof_recorded=shared_proof_recorded,
            first_sync_message=(
                "Guard Cloud connection on this machine needs repair before the first shared proof can land. "
                f"Run `{guard_command} connect` or reopen {connect_url} to repair the first sync."
            ),
            resume_message=(
                "Guard Cloud connection on this machine needs repair before shared proof can resume. "
                f"Run `{guard_command} connect` or reopen {connect_url} to restore sync."
            ),
        )
    if cloud_state == "paired_waiting":
        return (
            "Guard Cloud credentials are saved, but this machine has not finished the first shared sync yet. "
            f"Keep Local Guard running so it can retry automatically, or run "
            f"`{guard_command} sync` to force a retry now."
        )
    if cloud_state == "paired_active":
        return (
            "Guard is paired with Guard Cloud. Use the local CLI for protection and the signed-in command center "
            f"at {dashboard_url} for Home, Inbox, Fleet, Evidence, upgrades, and team workflows."
        )
    return (
        "Local Guard is active and keeps receipts on this machine. Guard Cloud is optional; "
        f"run `{guard_command} connect` when you want shared history, live advisories, or team policy."
    )
