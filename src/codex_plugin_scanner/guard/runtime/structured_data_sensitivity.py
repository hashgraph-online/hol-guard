"""Public declared-data DTOs; native code owns validation and classification."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass
from typing import Literal

from ..native_content_sensitivity import content_query

ScanStatus = Literal["matched", "no_declared_match", "unsupported"]
FieldRole = Literal["protected_personal", "ordinary"]
FieldType = Literal["string", "integer"]
PersonalCategory = Literal["person_name", "email_address", "employee_id"]
CLASSIFIER_VERSION = "structured-sensitive-v1"
MAX_INPUT_BYTES = 64 * 1024
MAX_DEPTH = 8
MAX_NODES = 128
MAX_FIELDS = 64
MAX_MATCHES = 16
MAX_DURATION_SECONDS = 0.2


@dataclass(frozen=True, slots=True)
class DeclaredField:
    path: tuple[str, ...]
    role: FieldRole
    value_type: FieldType = "string"
    category: PersonalCategory | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.path, tuple):
            raise ValueError("declared field path is invalid")
        content_query("fields", {"schema": [asdict(self)]})


@dataclass(frozen=True, slots=True)
class DeclaredSchema:
    fields: tuple[DeclaredField, ...]

    def __post_init__(self) -> None:
        content_query("fields", {"schema": [asdict(field) for field in self.fields]})


@dataclass(frozen=True, slots=True)
class SensitiveMatch:
    category: str
    sensitivity: str
    field_path: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class SensitiveScanResult:
    status: ScanStatus
    matches: tuple[SensitiveMatch, ...]
    complete: bool
    reason_code: str
    bytes_scanned: int
    fields_scanned: int
    rule_version: str


def classifier_rule_version(schema: DeclaredSchema | None = None) -> str:
    return content_query(
        "classifier_version", {"schema": [asdict(field) for field in schema.fields] if schema is not None else None}
    )


def classify_declared_content(
    content: bytes | str, *, schema: DeclaredSchema | None = None, deadline_monotonic: float | None = None
) -> SensitiveScanResult:
    raw = (
        content
        if isinstance(content, bytes)
        else content.encode("utf-8", errors="surrogatepass")
        if isinstance(content, str)
        else b""
    )
    body = {
        "content_type": "bytes" if isinstance(content, bytes) else "str" if isinstance(content, str) else "other",
        "content_bytes": base64.b64encode(raw[: MAX_INPUT_BYTES + 1]).decode("ascii"),
        "content_length": len(raw),
        "schema": [asdict(field) for field in schema.fields] if schema is not None else None,
    }
    result = content_query("declared_bytes", body, deadline_monotonic=deadline_monotonic)
    result["matches"] = tuple(
        SensitiveMatch(item["category"], item["sensitivity"], tuple(item["field_path"]), item["reason"])
        for item in result["matches"]
    )
    return SensitiveScanResult(**result)
