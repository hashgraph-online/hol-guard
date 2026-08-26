"""HTTP helpers for custom-extension listing."""

from __future__ import annotations

from typing import Protocol

from .local_cli_api import LocalCliApiService


class _LocalCliDiagnostics(Protocol):
    def record_exception(self, event: str, *, detail: str | None = None) -> bool: ...


class _LocalCliDaemon(Protocol):
    local_cli_api: LocalCliApiService
    diagnostics: _LocalCliDiagnostics


class _LocalCliListHandler(Protocol):
    def _daemon_server(self) -> _LocalCliDaemon: ...

    def _write_json(
        self,
        payload: dict[str, object],
        *,
        status: int = 200,
        extra_headers: dict[str, str] | None = None,
    ) -> None: ...


def handle_local_cli_list(handler: _LocalCliListHandler) -> None:
    daemon = handler._daemon_server()
    try:
        payload = daemon.local_cli_api.list_items()
    except Exception as error:
        daemon.diagnostics.record_exception("local_cli_list_failed", detail=type(error).__name__)
        handler._write_json(
            {
                "error": "local_cli_unavailable",
                "message": "Guard could not load custom extensions.",
            },
            status=500,
            extra_headers={"Cache-Control": "no-store"},
        )
        return
    handler._write_json(payload, extra_headers={"Cache-Control": "no-store"})
