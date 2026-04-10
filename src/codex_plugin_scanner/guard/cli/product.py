"""Guard product-facing onboarding and status payloads."""

from __future__ import annotations

from datetime import datetime, timezone

from ..adapters.base import HarnessContext
from ..config import GuardConfig
from ..consumer import detect_all, evaluate_detection
from ..models import HarnessDetection
from ..store import GuardStore

HARNESS_PRIORITY = ("codex", "claude-code", "cursor", "gemini", "opencode")
GUARD_COMMAND = "hol-guard"


def build_guard_start_payload(
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
) -> dict[str, object]:
    """Build a first-run Guard onboarding payload."""

    return _build_guard_product_payload(context, store, config, include_steps=True)


def build_guard_status_payload(
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
) -> dict[str, object]:
    """Build an ongoing Guard status payload."""

    return _build_guard_product_payload(context, store, config, include_steps=False)


def _build_guard_product_payload(
    context: HarnessContext,
    store: GuardStore,
    config: GuardConfig,
    *,
    include_steps: bool,
) -> dict[str, object]:
    detections = detect_all(context)
    harnesses = [_summarize_harness(detection, store, config) for detection in detections]
    recommended = _recommended_harness(harnesses)
    receipt_count = store.count_receipts()
    managed_harnesses = sum(1 for item in harnesses if item["managed"] is True)
    payload: dict[str, object] = {
        "generated_at": _now(),
        "guard_home": str(context.guard_home),
        "workspace": str(context.workspace_dir) if context.workspace_dir is not None else None,
        "sync_configured": store.get_sync_credentials() is not None,
        "receipt_count": receipt_count,
        "managed_harnesses": managed_harnesses,
        "recommended_harness": recommended["harness"] if recommended is not None else None,
        "harnesses": harnesses,
    }
    if include_steps:
        payload["next_steps"] = _build_next_steps(recommended)
    return payload


def _summarize_harness(
    detection: HarnessDetection,
    store: GuardStore,
    config: GuardConfig,
) -> dict[str, object]:
    evaluation = evaluate_detection(detection, store, config, default_action="allow", persist=False)
    managed_install = store.get_managed_install(detection.harness)
    review_count = sum(1 for artifact in evaluation["artifacts"] if bool(artifact["changed"]))
    managed = bool(managed_install and managed_install.get("active"))
    shim_path = None
    if managed_install is not None:
        manifest = managed_install.get("manifest")
        if isinstance(manifest, dict):
            shim_path = manifest.get("shim_path")
    next_action = _resolve_next_action(detection, managed, review_count)
    return {
        "harness": detection.harness,
        "installed": detection.installed,
        "command_available": detection.command_available,
        "artifact_count": len(detection.artifacts),
        "review_count": review_count,
        "warning_count": len(detection.warnings),
        "managed": managed,
        "shim_path": str(shim_path) if isinstance(shim_path, str) else None,
        "config_paths": list(detection.config_paths),
        "next_action": next_action,
        "install_command": f"{GUARD_COMMAND} install {detection.harness}",
        "run_command": f"{GUARD_COMMAND} run {detection.harness} --dry-run",
        "review_command": f"{GUARD_COMMAND} diff {detection.harness}",
        "receipts_command": f"{GUARD_COMMAND} receipts",
    }


def _recommended_harness(harnesses: list[dict[str, object]]) -> dict[str, object] | None:
    if not harnesses:
        return None
    priority = {name: index for index, name in enumerate(HARNESS_PRIORITY)}
    return min(
        harnesses,
        key=lambda item: (
            0 if bool(item["installed"]) else 1,
            0 if bool(item["command_available"]) else 1,
            priority.get(str(item["harness"]), len(HARNESS_PRIORITY)),
        ),
    )


def _resolve_next_action(detection: HarnessDetection, managed: bool, review_count: int) -> str:
    if not managed:
        if not detection.installed and not detection.command_available:
            return "install-harness"
        return "install"
    if review_count > 0:
        return "review"
    return "run"


def _build_next_steps(recommended: dict[str, object] | None) -> list[dict[str, str]]:
    if recommended is None:
        return [
            {
                "title": "Install a supported harness",
                "command": f"{GUARD_COMMAND} detect",
                "detail": (
                    "Guard did not find a local harness config yet. Start by installing "
                    "Codex, Claude Code, Cursor, Gemini, or OpenCode."
                ),
            }
        ]
    steps = [_install_or_review_step(recommended), _run_step(recommended), _receipts_step()]
    steps.append(
        {
            "title": "Optional sync later",
            "command": f"{GUARD_COMMAND} login --sync-url <url> --token <token>",
            "detail": (
                "Keep receipts local by default, then connect sync only when you want "
                "shared history or premium trust checks."
            ),
        }
    )
    return steps


def _install_or_review_step(recommended: dict[str, object]) -> dict[str, str]:
    harness = str(recommended["harness"])
    next_action = str(recommended["next_action"])
    if next_action == "review":
        return {
            "title": f"Review changed {harness} tools",
            "command": str(recommended["review_command"]),
            "detail": "Guard found changes since the last approval. Review them before the next launch.",
        }
    if next_action == "install-harness":
        return {
            "title": f"Install {harness}",
            "command": f"{GUARD_COMMAND} detect",
            "detail": "Guard needs a local harness install before it can protect launches.",
        }
    return {
        "title": f"Install Guard for {harness}",
        "command": str(recommended["install_command"]),
        "detail": "Create a local launcher shim so Guard runs before the harness starts.",
    }


def _run_step(recommended: dict[str, object]) -> dict[str, str]:
    harness = str(recommended["harness"])
    return {
        "title": "Run Guard before launch",
        "command": str(recommended["run_command"]),
        "detail": f"Dry-run {harness} once so Guard records the current tool state before you rely on it.",
    }


def _receipts_step() -> dict[str, str]:
    return {
        "title": "Inspect receipts",
        "command": f"{GUARD_COMMAND} receipts",
        "detail": "See what Guard approved, blocked, or flagged after local runs.",
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


__all__ = ["build_guard_start_payload", "build_guard_status_payload"]
