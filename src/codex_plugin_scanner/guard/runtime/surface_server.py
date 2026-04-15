"""Guard Surface Server runtime helpers."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timezone

from ..approvals import queue_blocked_approvals
from ..models import GuardArtifact, HarnessDetection
from ..schemas import build_surface_server_contract
from ..schemas.surface_server import (
    CURRENT_PROTOCOL_VERSION,
    SCHEMA_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
)
from ..store import GuardStore

SERVER_METHODS = (
    "initialize",
    "session/list",
    "session/start",
    "session/attach",
    "session/resume",
    "session/archive",
    "operation/start",
    "operation/status",
    "operation/resume",
    "approval/list",
    "approval/get",
    "approval/respond",
    "approval/subscribe",
    "receipt/list",
    "receipt/get",
    "policy/get",
)
SERVER_NOTIFICATIONS = (
    "session/started",
    "session/attached",
    "operation/started",
    "operation/waitingApproval",
    "operation/resumed",
    "operation/completed",
    "item/completed",
    "approval/requested",
    "approval/resolved",
    "receipt/created",
    "policy/changed",
)


class GuardSurfaceRuntime:
    """Shared runtime contract used by the daemon and CLI."""

    def __init__(self, store: GuardStore) -> None:
        self.store = store

    def initialize_client(
        self,
        *,
        client_name: str,
        client_title: str | None,
        version: str | None,
        surface: str,
        capabilities: tuple[str, ...],
        supported_protocol_versions: tuple[str, ...] = (),
    ) -> dict[str, object]:
        negotiated_version = _negotiate_protocol_version(supported_protocol_versions)
        client_id = uuid.uuid4().hex
        contract = build_surface_server_contract()
        protocol_bundle = dict(contract["protocol"]) if isinstance(contract.get("protocol"), dict) else {}
        protocol_bundle["negotiated_version"] = negotiated_version
        return {
            "protocol_version": negotiated_version,
            "schema_version": SCHEMA_VERSION,
            "schema": contract,
            "client_id": client_id,
            "protocol": protocol_bundle,
            "server_capabilities": {
                "methods": list(SERVER_METHODS),
                "notifications": list(SERVER_NOTIFICATIONS),
                "surfaces": ["cli", "approval-center", "harness-adapter", "cloud-dashboard", "agent-sdk"],
            },
            "client": {
                "client_name": client_name,
                "client_title": client_title,
                "version": version,
                "surface": surface,
                "capabilities": list(capabilities),
            },
            "sessions": self.store.list_guard_sessions(limit=20),
        }

    def start_session(
        self,
        *,
        harness: str,
        surface: str,
        workspace: str | None,
        client_name: str,
        client_title: str | None = None,
        client_version: str | None = None,
        capabilities: tuple[str, ...] = (),
    ) -> dict[str, object]:
        session = self.store.upsert_guard_session(
            session_id=uuid.uuid4().hex,
            harness=harness,
            surface=surface,
            status="active",
            client_name=client_name,
            client_title=client_title,
            client_version=client_version,
            workspace=workspace,
            capabilities=list(capabilities),
            now=_now(),
        )
        self.store.add_event("session/started", {"session": session}, _now())
        return session

    def attach_client(
        self,
        *,
        client_id: str,
        surface: str,
        session_id: str | None = None,
        metadata: dict[str, object] | None = None,
        lease_seconds: int = 60,
    ) -> dict[str, object]:
        if session_id is not None and self.store.get_guard_session(session_id) is None:
            raise ValueError(f"Unknown guard session: {session_id}")
        attachment = self.store.attach_guard_client(
            client_id=client_id,
            surface=surface,
            session_id=session_id,
            metadata=metadata or {},
            lease_seconds=lease_seconds,
            now=_now(),
        )
        if session_id is not None:
            self._set_session_status(session_id, "attached")
        self.store.add_event("session/attached", {"attachment": attachment}, _now())
        return attachment

    def renew_client(
        self,
        *,
        client_id: str,
        lease_id: str,
        lease_seconds: int = 60,
    ) -> dict[str, object]:
        attachment = self.store.renew_guard_client_attachment(
            client_id=client_id,
            lease_id=lease_id,
            lease_seconds=lease_seconds,
            now=_now(),
        )
        if attachment is None:
            raise ValueError(f"Unknown guard client lease: {client_id}")
        self.store.add_event("session/attached", {"attachment": attachment}, _now())
        return attachment

    def has_live_surface(self, surface: str) -> bool:
        return len(self.store.list_guard_client_attachments(surface=surface)) > 0

    def has_surface_opened(self, surface: str, open_key: str) -> bool:
        return self.store.has_guard_surface_open(surface=surface, open_key=open_key)

    def record_surface_open(self, *, surface: str, open_key: str) -> None:
        self.store.record_guard_surface_open(surface=surface, open_key=open_key, now=_now())

    def resume_session(self, session_id: str) -> dict[str, object]:
        session = self.store.get_guard_session(session_id)
        if session is None:
            raise ValueError(f"Unknown guard session: {session_id}")
        attachments = self.store.list_guard_client_attachments(session_id=session_id)
        operations = self.store.list_guard_operations(session_id=session_id)
        return {
            "session": session,
            "attachments": attachments,
            "operations": operations,
        }

    def start_operation(
        self,
        *,
        session_id: str,
        operation_type: str,
        harness: str,
        metadata: dict[str, object] | None = None,
    ) -> dict[str, object]:
        if self.store.get_guard_session(session_id) is None:
            raise ValueError(f"Unknown guard session: {session_id}")
        operation = self.store.upsert_guard_operation(
            operation_id=uuid.uuid4().hex,
            session_id=session_id,
            harness=harness,
            operation_type=operation_type,
            status="started",
            approval_request_ids=[],
            resume_token=None,
            metadata=metadata or {},
            now=_now(),
        )
        self._set_session_status(session_id, "active")
        self.store.add_event("operation/started", {"operation": operation}, _now())
        return operation

    def queue_blocked_operation(
        self,
        *,
        session_id: str,
        operation_type: str,
        harness: str,
        metadata: dict[str, object] | None,
        detection: dict[str, object],
        evaluation: dict[str, object],
        approval_center_url: str,
        approval_surface_policy: str,
        open_key: str | None,
        opener: Callable[[str], object],
    ) -> dict[str, object]:
        if self.store.get_guard_session(session_id) is None:
            raise ValueError(f"Unknown guard session: {session_id}")
        parsed_detection = _parse_detection(detection)
        queued = queue_blocked_approvals(
            detection=parsed_detection,
            evaluation=evaluation,
            store=self.store,
            approval_center_url=approval_center_url,
            now=_now(),
        )
        operation = self.start_operation(
            session_id=session_id,
            operation_type=operation_type,
            harness=harness,
            metadata=metadata,
        )
        self.add_item(
            operation_id=str(operation["operation_id"]),
            item_type="approval_requested",
            payload={"approval_requests": queued},
        )
        waiting_operation = self.mark_waiting_on_approval(
            str(operation["operation_id"]),
            [str(item["request_id"]) for item in queued if isinstance(item.get("request_id"), str)],
        )
        surface = self.ensure_surface(
            surface="approval-center",
            approval_center_url=approval_center_url,
            approval_surface_policy=approval_surface_policy,
            open_key=open_key or str(waiting_operation["operation_id"]),
            opener=opener,
        )
        return {
            "operation": waiting_operation,
            "approval_requests": queued,
            "surface": surface,
        }

    def update_operation_status(
        self,
        *,
        operation_id: str,
        status: str,
        approval_request_ids: list[str] | None = None,
    ) -> dict[str, object]:
        if status == "waiting_on_approval":
            return self.mark_waiting_on_approval(operation_id, approval_request_ids or [])
        return self.mark_operation_outcome(operation_id, status)

    def mark_waiting_on_approval(self, operation_id: str, approval_request_ids: list[str]) -> dict[str, object]:
        current = self.store.get_guard_operation(operation_id)
        if current is None:
            raise ValueError(f"Unknown guard operation: {operation_id}")
        operation = self.store.upsert_guard_operation(
            operation_id=operation_id,
            session_id=str(current["session_id"]),
            harness=str(current["harness"]),
            operation_type=str(current["operation_type"]),
            status="waiting_on_approval",
            approval_request_ids=approval_request_ids,
            resume_token=uuid.uuid4().hex,
            metadata=dict(current["metadata"]) if isinstance(current["metadata"], dict) else {},
            now=_now(),
        )
        self.store.add_event("operation/waitingApproval", {"operation": operation}, _now())
        return operation

    def mark_operation_outcome(self, operation_id: str, status: str) -> dict[str, object]:
        current = self.store.get_guard_operation(operation_id)
        if current is None:
            raise ValueError(f"Unknown guard operation: {operation_id}")
        operation = self.store.upsert_guard_operation(
            operation_id=operation_id,
            session_id=str(current["session_id"]),
            harness=str(current["harness"]),
            operation_type=str(current["operation_type"]),
            status=status,
            approval_request_ids=list(current["approval_request_ids"])
            if isinstance(current["approval_request_ids"], list)
            else [],
            resume_token=str(current["resume_token"]) if current["resume_token"] is not None else None,
            metadata=dict(current["metadata"]) if isinstance(current["metadata"], dict) else {},
            now=_now(),
        )
        event_name = "operation/completed" if status in {"completed", "blocked", "failed"} else "operation/resumed"
        self.store.add_event(event_name, {"operation": operation}, _now())
        return operation

    def add_item(self, *, operation_id: str, item_type: str, payload: dict[str, object]) -> dict[str, object]:
        if self.store.get_guard_operation(operation_id) is None:
            raise ValueError(f"Unknown guard operation: {operation_id}")
        item = self.store.add_guard_operation_item(
            item_id=uuid.uuid4().hex,
            operation_id=operation_id,
            item_type=item_type,
            lifecycle="completed",
            payload=payload,
            now=_now(),
        )
        self.store.add_event("item/completed", {"item": item}, _now())
        return item

    def ensure_surface(
        self,
        *,
        surface: str,
        approval_center_url: str,
        approval_surface_policy: str,
        open_key: str,
        opener: Callable[[str], object],
    ) -> dict[str, object]:
        if approval_surface_policy in {"notify-only", "never-auto-open"}:
            return {"surface": surface, "opened": False, "reason": "policy-disabled", "open_key": open_key}
        if approval_surface_policy == "auto-open-once" and self.has_surface_opened(surface, open_key):
            return {"surface": surface, "opened": False, "reason": "already-opened", "open_key": open_key}
        if self.has_live_surface(surface):
            return {"surface": surface, "opened": False, "reason": "live-client", "open_key": open_key}
        try:
            opened = opener(approval_center_url)
        except Exception:
            return {"surface": surface, "opened": False, "reason": "open-failed", "open_key": open_key}
        if opened is False:
            return {"surface": surface, "opened": False, "reason": "open-failed", "open_key": open_key}
        if approval_surface_policy == "auto-open-once":
            self.record_surface_open(surface=surface, open_key=open_key)
        return {"surface": surface, "opened": True, "reason": "opened", "open_key": open_key}

    def _set_session_status(self, session_id: str, status: str) -> None:
        current = self.store.get_guard_session(session_id)
        if current is None:
            raise ValueError(f"Unknown guard session: {session_id}")
        self.store.upsert_guard_session(
            session_id=session_id,
            harness=str(current["harness"]),
            surface=str(current["surface"]),
            status=status,
            client_name=str(current["client_name"]),
            client_title=str(current["client_title"]) if current["client_title"] is not None else None,
            client_version=str(current["client_version"]) if current["client_version"] is not None else None,
            workspace=str(current["workspace"]) if current["workspace"] is not None else None,
            capabilities=[str(item) for item in current["capabilities"] if isinstance(item, str)]
            if isinstance(current["capabilities"], list)
            else [],
            now=_now(),
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _negotiate_protocol_version(supported_protocol_versions: tuple[str, ...]) -> str:
    if not supported_protocol_versions:
        return CURRENT_PROTOCOL_VERSION
    supported = tuple(value for value in supported_protocol_versions if isinstance(value, str))
    compatible_versions = [
        version
        for version in SUPPORTED_PROTOCOL_VERSIONS
        if version in supported or any(_major(version) == _major(candidate) for candidate in supported)
    ]
    if compatible_versions:
        return sorted(compatible_versions, key=_version_key, reverse=True)[0]
    raise ValueError("unsupported_protocol_version")


def _major(version: str) -> str:
    return version.split(".", maxsplit=1)[0]


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _parse_detection(payload: dict[str, object]) -> HarnessDetection:
    artifacts_payload = payload.get("artifacts")
    config_paths_payload = payload.get("config_paths")
    if not isinstance(artifacts_payload, list) or not isinstance(config_paths_payload, list):
        raise ValueError("invalid_detection_payload")
    artifacts = tuple(_parse_artifact(item) for item in artifacts_payload if isinstance(item, dict))
    return HarnessDetection(
        harness=str(payload.get("harness") or ""),
        installed=bool(payload.get("installed")),
        command_available=bool(payload.get("command_available")),
        config_paths=tuple(str(item) for item in config_paths_payload if isinstance(item, str)),
        artifacts=artifacts,
        warnings=tuple(str(item) for item in payload.get("warnings", []) if isinstance(item, str))
        if isinstance(payload.get("warnings"), list)
        else (),
    )


def _parse_artifact(payload: dict[str, object]) -> GuardArtifact:
    return GuardArtifact(
        artifact_id=str(payload.get("artifact_id") or ""),
        name=str(payload.get("name") or ""),
        harness=str(payload.get("harness") or ""),
        artifact_type=str(payload.get("artifact_type") or "artifact"),
        source_scope=str(payload.get("source_scope") or "project"),
        config_path=str(payload.get("config_path") or ""),
        command=str(payload.get("command")) if isinstance(payload.get("command"), str) else None,
        args=tuple(str(item) for item in payload.get("args", []) if isinstance(item, str))
        if isinstance(payload.get("args"), list)
        else (),
        url=str(payload.get("url")) if isinstance(payload.get("url"), str) else None,
        transport=str(payload.get("transport")) if isinstance(payload.get("transport"), str) else None,
        publisher=str(payload.get("publisher")) if isinstance(payload.get("publisher"), str) else None,
        metadata=dict(payload.get("metadata")) if isinstance(payload.get("metadata"), dict) else {},
    )
