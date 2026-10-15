"""Public declared-data DTOs; native code owns validation and classification."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from ..native_content_sensitivity import content_query

FieldRole = Literal["protected_personal", "ordinary"]
FieldType = Literal["string", "integer"]
PersonalCategory = Literal["person_name", "email_address", "employee_id"]


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
