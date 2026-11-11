"""Public response version and errors shared by local CLI API handlers."""

from __future__ import annotations

LOCAL_CLI_API_SCHEMA = "guard.daemon.local-clis.v1"


class LocalCliApiError(Exception):
    def __init__(self, status: int, code: str, message: str | None = None) -> None:
        self.status = status
        self.code = code
        super().__init__(message or code)

    def to_payload(self) -> dict[str, object]:
        return {"error": self.code, "message": str(self)}
