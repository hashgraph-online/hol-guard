"""Versioned, inert public benchmark contracts (JSON Schema 2020-12).

No record selects a Python module, plugin, or executable. Validation is bounded
before schema traversal; callers must never import candidate evidence as code.
Version changes require explicit migration outside this reader.
"""

from __future__ import annotations

import copy
import json
from enum import Enum
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, validators
from referencing import Registry, Resource

from .json_data import MAX_DEPTH as MAX_DEPTH
from .json_data import MAX_NODES as MAX_NODES
from .json_data import MAX_RECORD_BYTES as MAX_RECORD_BYTES
from .json_data import ContractError as ContractError
from .json_data import _bounded as _bounded
from .json_data import canonical_json as canonical_json
from .json_data import digest as digest
from .json_data import strict_json_loads as strict_json_loads

SCHEMA_VERSION = "1.0"
SCHEMA_DIR = Path(__file__).with_name("schemas")


class EvidenceStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    INCONCLUSIVE = "inconclusive"


class TaskStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    PENDING_APPROVAL = "pending-approval"
    FAILED = "failed"


class SecurityStatus(str, Enum):
    HELD = "held"
    VIOLATED = "violated"
    UNKNOWN = "unknown"


class ExposureStatus(str, Enum):
    NOT_APPLICABLE = "not-applicable"
    PLACED = "placed"
    REQUESTED = "requested"
    DELIVERED = "delivered"
    INGESTED = "ingested"
    UNKNOWN = "unknown"


class Intervention(str, Enum):
    NONE = "none"
    ALLOW = "allow"
    DENY = "deny"
    TRANSFORM = "transform"
    REQUIRE_APPROVAL = "require-approval"
    UNSUPPORTED = "unsupported"


class Attribution(str, Enum):
    PRODUCT = "product"
    MODEL = "model"
    SERVICE = "service"
    HARNESS = "harness"
    INFRASTRUCTURE = "infrastructure"
    NOT_EXERCISED = "not-exercised"
    UNKNOWN = "unknown"


# JSON's integer type is deliberately strict here: 1.0 is a mistyped integer.
_TYPE_CHECKER = Draft202012Validator.TYPE_CHECKER.redefine("integer", lambda _checker, value: type(value) is int)
_Validator = validators.extend(Draft202012Validator, type_checker=_TYPE_CHECKER)


def _schemas() -> tuple[dict, Registry]:
    schemas = {}
    resources = []
    for path in sorted(SCHEMA_DIR.glob("*.v1.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        _Validator.check_schema(data)
        schemas[path.name.removesuffix(".v1.json")] = data
        resources.append((data["$id"], Resource.from_contents(data)))
    return schemas, Registry().with_resources(resources)


_SCHEMAS, _REGISTRY = _schemas()


def validate_record(kind: str, value: Any) -> dict:
    """Return a detached validated record; unknown/mistyped fields fail closed."""
    if kind not in _SCHEMAS:
        raise ContractError(f"unknown contract: {kind}")
    canonical_json(value)
    errors = sorted(
        _Validator(_SCHEMAS[kind], registry=_REGISTRY).iter_errors(value),
        key=lambda error: str(list(error.absolute_path)),
    )
    if errors:
        error = errors[0]
        location = "/".join(map(str, error.absolute_path)) or "<root>"
        raise ContractError(f"{kind}:{location}: {error.message}")
    return copy.deepcopy(value)


def load_record(kind: str, raw: str | bytes) -> dict:
    """Decode and validate one versioned contract."""
    return validate_record(kind, strict_json_loads(raw))
