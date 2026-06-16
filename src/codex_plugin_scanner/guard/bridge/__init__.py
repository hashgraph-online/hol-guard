"""Guard Bridge - notification daemon for polling pending approval requests and handling approve/deny commands."""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import requests

from ..config import resolve_guard_home
from ..daemon.manager import load_guard_daemon_auth_token
from ..store import GuardStore


@dataclass
class BridgeConfig:
    """Configuration for the Guard Bridge."""

    guard_url: str | None = None
    poll_interval: int = 10
    dry_run: bool = False


@dataclass
class PendingRequest:
    """Parsed pending approval request."""

    request_id: str
    artifact_id: str
    artifact_name: str
    artifact_type: str = "unknown"
    policy_action: str = "block"
    harness: str = "unknown"
    source_scope: str = "unknown"
    risk_summary: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""


class NotificationBackend(ABC):
    """Abstract base for notification backends."""

    @abstractmethod
    def send_notification(self, request: PendingRequest, message: str) -> bool:
        """Send a notification for a pending request. Returns True if successful."""
        pass

    @abstractmethod
    def parse_command(self, text: str) -> tuple[str | None, str | None]:
        """Parse approve/deny commands from text. Returns (command, request_id)."""
        pass


class StderrBackend(NotificationBackend):
    """Fallback backend that always succeeds - prints to stderr."""

    def send_notification(self, request: PendingRequest, message: str) -> bool:
        print(f"[Guard Bridge] {message}", file=sys.stderr)
        return True

    def parse_command(self, text: str) -> tuple[str | None, str | None]:
        return (None, None)


class HermesBackend(NotificationBackend):
    """Send notifications via Hermes CLI messaging."""

    def __init__(self, chat_id: str | None = None):
        self.chat_id = chat_id

    def send_notification(self, request: PendingRequest, message: str) -> bool:
        try:
            cmd = ["hermes", "message"]
            if self.chat_id:
                cmd.extend(["--chat", self.chat_id])
            result = subprocess.run(cmd, input=message, capture_output=True, text=True, timeout=30)
            return result.returncode == 0
        except Exception:
            return False

    def parse_command(self, text: str) -> tuple[str | None, str | None]:
        match = re.match(r"/(approve|deny)\s+([a-f0-9-]+)", text)
        if match:
            return (match.group(1), match.group(2))
        return (None, None)


class TelegramBackend(NotificationBackend):
    """Send notifications via Telegram bot."""

    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{token}"

    def send_notification(self, request: PendingRequest, message: str) -> bool:
        try:
            resp = requests.post(
                f"{self.api_url}/sendMessage",
                json={"chat_id": self.chat_id, "text": message, "parse_mode": "Markdown"},
                timeout=10,
            )
            return resp.status_code == 200
        except Exception:
            return False

    def parse_command(self, text: str) -> tuple[str | None, str | None]:
        match = re.match(r"/(approve|deny)\s+([a-f0-9-]+)", text)
        if match:
            return (match.group(1), match.group(2))
        return (None, None)


class WebhookBackend(NotificationBackend):
    """Send notifications via HTTP webhook."""

    def __init__(self, url: str, *, include_artifact_details: bool = False):
        self.url = _validate_webhook_url(url)
        self.include_artifact_details = include_artifact_details

    def send_notification(self, request: PendingRequest, message: str) -> bool:
        payload = {
            "text": "HOL Guard approval pending. Review locally to see artifact details.",
            "request_id": request.request_id,
        }
        if self.include_artifact_details:
            payload["text"] = message
        try:
            resp = requests.post(self.url, json=payload, timeout=10)
            return resp.status_code in (200, 201)
        except Exception:
            return False

    def parse_command(self, text: str) -> tuple[str | None, str | None]:
        match = re.match(r"/(approve|deny)\s+([a-f0-9-]+)", text)
        if match:
            return (match.group(1), match.group(2))
        return (None, None)


def _parse_pending_request(data: dict[str, Any]) -> PendingRequest | None:
    """Parse API response into PendingRequest."""
    try:
        risk = data.get("risk_summary", {})
        if isinstance(risk, str):
            risk = json.loads(risk) if risk else {}
        return PendingRequest(
            request_id=data.get("request_id", ""),
            artifact_id=data.get("artifact_id", ""),
            artifact_name=data.get("artifact_name", ""),
            artifact_type=data.get("artifact_type", "unknown"),
            policy_action=data.get("policy_action", "block"),
            harness=data.get("harness", "unknown"),
            source_scope=data.get("source_scope", "unknown"),
            risk_summary=risk,
            created_at=data.get("created_at", ""),
        )
    except Exception:
        return None


def _format_notification(request: PendingRequest) -> str:
    """Format a notification message for a pending request."""
    risk_level = request.risk_summary.get("overall_risk_level", "unknown")
    emoji = {"high": "🟠", "medium": "🟡", "low": "🟢"}.get(risk_level, "⚪")
    short_id = request.request_id[:8]

    lines = [
        "🚫 *Guard Blocked*",
        "",
        f"*Artifact:* `{request.artifact_name}`",
        f"*Type:* {request.artifact_type}",
        f"*Action:* {request.policy_action}",
        f"*Risk:* {emoji} {risk_level}",
        "",
        "To approve, run:",
        f"`/approve {short_id}`",
        "",
        "To deny, run:",
        f"`/deny {short_id}`",
    ]
    return "\n".join(lines)


def _validate_webhook_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Guard Bridge webhook URL must use https.")
    if not parsed.hostname:
        raise ValueError("Guard Bridge webhook URL must include a host.")
    if parsed.username or parsed.password:
        raise ValueError("Guard Bridge webhook URL must not embed credentials.")
    hostname = parsed.hostname.lower()
    if hostname in {"localhost", "0.0.0.0", "169.254.169.254"}:
        raise ValueError("Guard Bridge webhook URL must not target loopback.")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return parsed.geturl()
    mapped_address = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    if mapped_address is not None and (mapped_address.is_loopback or mapped_address.is_link_local):
        raise ValueError("Guard Bridge webhook URL must not target loopback.")
    if address.is_loopback or address.is_link_local:
        raise ValueError("Guard Bridge webhook URL must not target loopback.")
    return parsed.geturl()


class GuardBridge:
    """Bridge daemon that polls Guard daemon and sends notifications."""

    def __init__(
        self,
        config: BridgeConfig,
        store: GuardStore,
        backend: NotificationBackend | None = None,
    ):
        self.config = config
        self.store = store
        self.backend = backend or StderrBackend()
        self._running = False
        self._seen_ids: set[str] = set()

    def _fetch_pending_requests(self, guard_url: str) -> list[PendingRequest]:
        """Fetch pending requests from Guard daemon."""
        auth_token = load_guard_daemon_auth_token(self.store.guard_home)
        if auth_token is None:
            print("[Guard Bridge] No daemon auth token found - skipping poll.", file=sys.stderr)
            return []
        try:
            resp = requests.get(
                f"{guard_url}/v1/requests",
                headers={"X-Guard-Token": auth_token},
                timeout=10,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            items = data.get("items", [])
            return [r for r in (_parse_pending_request(i) for i in items) if r]
        except Exception:
            return []

    def _execute_resolution(self, action: str, request_id: str) -> bool:
        """Resolve requests through the Guard daemon contract."""
        guard_url = self.config.guard_url or "http://127.0.0.1:4999"
        action_path = "approve" if action == "approve" else "block"
        auth_token = load_guard_daemon_auth_token(self.store.guard_home)
        if auth_token is None:
            return False
        try:
            response = requests.post(
                f"{guard_url}/v1/requests/{request_id}/{action_path}",
                json={
                    "scope": "artifact",
                    "reason": "resolved from Guard Bridge",
                },
                headers={"X-Guard-Token": auth_token},
                timeout=30,
            )
            if response.status_code != 200:
                return False
            payload = response.json()
            return bool(payload.get("resolved"))
        except Exception:
            return False

    def run(self) -> None:
        """Run the polling loop."""
        guard_url = self.config.guard_url or "http://127.0.0.1:4999"
        poll_interval = self.config.poll_interval
        self._running = True

        print(f"[Guard Bridge] Starting, polling {guard_url}/v1/requests every {poll_interval}s", file=sys.stderr)

        while self._running:
            try:
                requests_list = self._fetch_pending_requests(guard_url)
                # Prune to only currently pending IDs to avoid memory leak
                current_ids = {req.request_id for req in requests_list}
                self._seen_ids &= current_ids

                for req in requests_list:
                    if req.request_id in self._seen_ids:
                        continue
                    # Add AFTER successful notification to allow retry on failure

                    message = _format_notification(req)
                    if self.config.dry_run:
                        print("[Guard Bridge] DRYRUN: would send notification", file=sys.stderr)
                        self._seen_ids.add(req.request_id)  # Track even in dry-run
                    else:
                        success = self.backend.send_notification(req, message)
                        if success:
                            self._seen_ids.add(req.request_id)
                        else:
                            print(f"[Guard Bridge] Failed to send notification for {req.request_id}", file=sys.stderr)

            except Exception as e:
                print(f"[Guard Bridge] Error: {e}", file=sys.stderr)

            time.sleep(poll_interval)

    def stop(self) -> None:
        """Stop the polling loop."""
        self._running = False


def run_bridge(
    guard_url: str | None = None,
    poll_interval: int = 10,
    dry_run: bool = False,
    store: GuardStore | None = None,
    backend: NotificationBackend | None = None,
) -> None:
    """Run the Guard Bridge daemon."""
    config = BridgeConfig(guard_url=guard_url, poll_interval=poll_interval, dry_run=dry_run)
    if store is None:
        store = GuardStore(resolve_guard_home())

    bridge = GuardBridge(config=config, store=store, backend=backend)
    bridge.run()
