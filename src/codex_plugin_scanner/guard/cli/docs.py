"""Shared Guard install/connect documentation payloads."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class GuardDocCommand:
    stage: str
    command: str
    title: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "stage": self.stage,
            "command": self.command,
            "title": self.title,
            "detail": self.detail,
        }


def install_connect_command_catalog() -> tuple[GuardDocCommand, ...]:
    return (
        GuardDocCommand(
            stage="local-setup",
            command="hol-guard bootstrap",
            title="Bootstrap local protection",
            detail="Detect the best local harness, start the approval center, and install Guard locally.",
        ),
        GuardDocCommand(
            stage="local-setup",
            command="hol-guard install codex",
            title="Install a harness launcher",
            detail="Use the harness you rely on most; Codex is the common first local target.",
        ),
        GuardDocCommand(
            stage="local-baseline",
            command="hol-guard run codex --dry-run",
            title="Record the baseline",
            detail="Capture current local tool state before a real launch.",
        ),
        GuardDocCommand(
            stage="local-run",
            command="hol-guard run codex",
            title="Launch through Guard",
            detail="Review changed tools before the harness receives control.",
        ),
        GuardDocCommand(
            stage="local-approval",
            command="hol-guard approvals",
            title="Resolve queued approvals",
            detail="Use this when a non-interactive shell cannot render native approval.",
        ),
        GuardDocCommand(
            stage="local-audit",
            command="hol-guard receipts",
            title="Review local receipts",
            detail="Inspect the local audit trail for prior allow/block decisions.",
        ),
        GuardDocCommand(
            stage="local-status",
            command="hol-guard status",
            title="Check current posture",
            detail="See local protection, cloud pairing state, and the next safe command.",
        ),
        GuardDocCommand(
            stage="cloud-optional",
            command="hol-guard connect",
            title="Pair Guard Cloud later",
            detail="Open browser pairing only when shared history or team coordination is needed.",
        ),
        GuardDocCommand(
            stage="cloud-recovery",
            command="hol-guard connect status",
            title="Inspect pairing recovery",
            detail="Show the latest pairing milestone and retry command without opening a browser.",
        ),
        GuardDocCommand(
            stage="cloud-recovery",
            command="hol-guard connect repair",
            title="Start re-pair guidance",
            detail="Print the recovery path for stale, failed, or incomplete cloud pairing.",
        ),
        GuardDocCommand(
            stage="cloud-sync",
            command="hol-guard sync",
            title="Sync local receipts",
            detail="Send local receipts only after credentials are configured.",
        ),
        GuardDocCommand(
            stage="docs",
            command="hol-guard explain install-connect",
            title="Share install/connect docs",
            detail="Generate the same install and connect command catalog from the CLI.",
        ),
    )


def build_install_connect_docs_payload() -> dict[str, object]:
    commands = [item.to_dict() for item in install_connect_command_catalog()]
    return {
        "target": "install-connect",
        "category": "guard-docs",
        "summary": "Local Guard setup works offline; Guard Cloud pairing is optional and recoverable.",
        "commands": commands,
        "share_commands": {
            "terminal": "hol-guard explain install-connect",
            "json": "hol-guard explain install-connect --json",
            "cloud": "hol-guard connect status",
        },
    }
