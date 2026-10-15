"""Client, session and operation route handlers for the daemon control plane."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

from ..approvals import (
    _append_guard_token_to_url,
    build_approval_browser_url,
)
from ..browser_opener import open_browser_url
from .server_common import (
    _is_string_object_dict,
)


class _ControlOperationRoutes:
    """Handler methods for control-plane routes."""

    def _handle_initialize(self, payload: dict[str, object]) -> None:
        client_name = self._optional_string(payload.get("client_name")) or "guard-client"
        surface = self._optional_string(payload.get("surface")) or "cli"
        capabilities = payload.get("capabilities")
        capability_items = (
            tuple(str(item) for item in capabilities if isinstance(item, str)) if isinstance(capabilities, list) else ()
        )
        supported_versions = payload.get("supported_protocol_versions")
        try:
            response = self.server.runtime.initialize_client(  # type: ignore[attr-defined]
                client_name=client_name,
                client_title=self._optional_string(payload.get("client_title")),
                version=self._optional_string(payload.get("version")),
                surface=surface,
                capabilities=capability_items,
                supported_protocol_versions=tuple(str(item) for item in supported_versions if isinstance(item, str))
                if isinstance(supported_versions, list)
                else (),
                include_sessions=self._header_token_is_valid(payload=payload),
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        refreshed_session_token = self._refresh_dashboard_session_token(surface=surface)
        if refreshed_session_token is not None:
            response["dashboard_session_token"] = refreshed_session_token
        self._write_json(response)

    def _handle_client_attach(self, payload: dict[str, object]) -> None:
        client_id = self._optional_string(payload.get("client_id"))
        surface = self._optional_string(payload.get("surface"))
        if client_id is None or surface is None:
            self._write_json({"attached": False, "error": "missing_required_fields"}, status=400)
            return
        try:
            attachment = self.server.runtime.attach_client(  # type: ignore[attr-defined]
                client_id=client_id,
                surface=surface,
                session_id=self._optional_string(payload.get("session_id")),
                metadata={"title": self._optional_string(payload.get("client_title")) or surface},
                lease_seconds=self._optional_int(payload.get("lease_seconds")) or 60,
            )
        except ValueError as error:
            self._write_json({"attached": False, "error": str(error)}, status=400)
            return
        self._write_json({"attached": True, "item": attachment})

    def _handle_client_heartbeat(self, payload: dict[str, object]) -> None:
        client_id = self._optional_string(payload.get("client_id"))
        lease_id = self._optional_string(payload.get("lease_id"))
        if client_id is None or lease_id is None:
            self._write_json({"renewed": False, "error": "missing_required_fields"}, status=400)
            return
        try:
            attachment = self.server.runtime.renew_client(  # type: ignore[attr-defined]
                client_id=client_id,
                lease_id=lease_id,
                lease_seconds=self._optional_int(payload.get("lease_seconds")) or 60,
            )
        except ValueError as error:
            self._write_json({"renewed": False, "error": str(error)}, status=404)
            return
        self._write_json({"renewed": True, "item": attachment})

    def _handle_session_start(self, payload: dict[str, object]) -> None:
        harness = self._optional_string(payload.get("harness"))
        surface = self._optional_string(payload.get("surface"))
        client_name = self._optional_string(payload.get("client_name"))
        if harness is None or surface is None or client_name is None:
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        capabilities = payload.get("capabilities")
        session = self.server.runtime.start_session(  # type: ignore[attr-defined]
            harness=harness,
            surface=surface,
            workspace=self._optional_string(payload.get("workspace")),
            client_name=client_name,
            client_title=self._optional_string(payload.get("client_title")),
            client_version=self._optional_string(payload.get("client_version")),
            capabilities=tuple(str(item) for item in capabilities if isinstance(item, str))
            if isinstance(capabilities, list)
            else (),
        )
        self._write_json(session)

    def _handle_operation_start(self, payload: dict[str, object]) -> None:
        session_id = self._optional_string(payload.get("session_id"))
        operation_type = self._optional_string(payload.get("operation_type"))
        harness = self._optional_string(payload.get("harness"))
        if session_id is None or operation_type is None or harness is None:
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        metadata = payload.get("metadata")
        try:
            operation = self.server.runtime.start_operation(  # type: ignore[attr-defined]
                session_id=session_id,
                operation_type=operation_type,
                harness=harness,
                metadata=metadata if isinstance(metadata, dict) else {},
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json(operation)

    def _handle_operation_block(self, payload: dict[str, object]) -> None:
        session_id = self._optional_string(payload.get("session_id"))
        operation_type = self._optional_string(payload.get("operation_type"))
        harness = self._optional_string(payload.get("harness"))
        approval_center_url = self._optional_string(payload.get("approval_center_url"))
        approval_surface_policy = self._optional_string(payload.get("approval_surface_policy"))
        detection = payload.get("detection")
        evaluation = payload.get("evaluation")
        if (
            session_id is None
            or operation_type is None
            or harness is None
            or approval_center_url is None
            or approval_surface_policy is None
            or not _is_string_object_dict(detection)
            or not _is_string_object_dict(evaluation)
        ):
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        metadata = payload.get("metadata")
        try:
            redaction_level = self._optional_string(payload.get("redaction_level")) or "full"
            response = self.server.runtime.queue_blocked_operation(  # type: ignore[attr-defined]
                session_id=session_id,
                operation_type=operation_type,
                harness=harness,
                metadata=metadata if _is_string_object_dict(metadata) else {},
                detection=detection,
                evaluation=evaluation,
                approval_center_url=approval_center_url,
                browser_url=_append_guard_token_to_url(approval_center_url, self.server.auth_token),  # type: ignore[attr-defined]
                approval_surface_policy=approval_surface_policy,
                open_key=self._optional_string(payload.get("open_key")),
                opener=open_browser_url,
                redaction_level=redaction_level,
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        surface = response.get("surface")
        operation = response.get("operation")
        requests = response.get("approval_requests")
        if (
            isinstance(surface, dict)
            and surface.get("reason") == "attention-deferred"
            and isinstance(operation, dict)
            and isinstance(operation.get("operation_id"), str)
            and isinstance(requests, list)
        ):
            typed_requests = [request for request in requests if _is_string_object_dict(request)]
            first_url: str | None = None
            for request in typed_requests:
                candidate_url = request.get("approval_url")
                if isinstance(candidate_url, str):
                    first_url = candidate_url
                    break
            browser_url = build_approval_browser_url(first_url, auth_token=self.server.auth_token)  # type: ignore[attr-defined]
            if browser_url is not None:
                self.server.approval_attention.schedule(  # type: ignore[attr-defined]
                    operation_id=str(operation["operation_id"]),
                    requests=typed_requests,
                    browser_url=browser_url,
                )
        self._write_json(response)

    def _handle_operation_item(self, operation_id: str, payload: dict[str, object]) -> None:
        item_type = self._optional_string(payload.get("item_type"))
        item_payload = payload.get("payload")
        if item_type is None or not isinstance(item_payload, dict):
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        try:
            item = self.server.runtime.add_item(  # type: ignore[attr-defined]
                operation_id=operation_id,
                item_type=item_type,
                payload=item_payload,
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json({"item": item})

    def _handle_operation_status(self, operation_id: str, payload: dict[str, object]) -> None:
        status = self._optional_string(payload.get("status"))
        if status is None:
            self._write_json({"error": "missing_required_fields"}, status=400)
            return
        request_ids = payload.get("approval_request_ids")
        try:
            operation = self.server.runtime.update_operation_status(  # type: ignore[attr-defined]
                operation_id=operation_id,
                status=status,
                approval_request_ids=[str(item) for item in request_ids if isinstance(item, str)]
                if isinstance(request_ids, list)
                else [],
            )
        except ValueError as error:
            self._write_json({"error": str(error)}, status=400)
            return
        self._write_json({"operation": operation})

    def _handle_session_resume(self, session_id: str) -> None:
        try:
            payload = self.server.runtime.resume_session(session_id)  # type: ignore[attr-defined]
        except ValueError:
            self._write_json({"error": "not_found"}, status=404)
            return
        self._write_json(payload)
