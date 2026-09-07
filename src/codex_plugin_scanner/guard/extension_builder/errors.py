"""Bounded diagnostics for untrusted authoring input."""

from __future__ import annotations


class BuilderError(ValueError):
    """A safe-to-display error; never construct messages from source payloads."""

    def __init__(self, code: str, message: str, *, conflict: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.exit_code = 3 if conflict else 2

    def to_dict(self) -> dict[str, object]:
        return {"ok": False, "error": {"code": self.code, "message": str(self)}}
