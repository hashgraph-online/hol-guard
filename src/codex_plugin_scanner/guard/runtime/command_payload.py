"""Shared normalization helpers for durable command executors."""

from __future__ import annotations


def mapping(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def optional_text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def result(data: dict[str, object], *, generated_at: str) -> dict[str, object]:
    return {"data": data, "generatedAt": generated_at}


__all__ = ["mapping", "optional_text", "result"]
