"""Bound transport for fused native continuation authority."""

from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .native_runner_authority import native_runner_authority

if TYPE_CHECKING:
    from .continuation_contract import ContinuationOffer, ContinuationResult


def _wire(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {key: _wire(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_wire(item) for item in value]
    return value


def offer_wire(offer: ContinuationOffer) -> dict[str, Any]:
    return cast(dict[str, Any], _wire(asdict(offer)))


def result_wire(result: ContinuationResult) -> dict[str, Any]:
    return cast(dict[str, Any], _wire(asdict(result)))


def result_dto(value: object) -> ContinuationResult | None:
    from .continuation_contract import ContinuationResult

    if value is None:
        return None
    fields = dict(cast(Mapping[str, Any], value))
    fields["completed_at"] = datetime.fromisoformat(fields["completed_at"])
    return ContinuationResult(**fields)


def continuation_authority(call: str, *, guard_home: Path | None = None, **args: Any) -> dict[str, Any]:
    carrier = {"call": call, **args}
    for field, marker in (("operation", "operation_metadata_nonfinite"), ("operation_update", "metadata_nonfinite")):
        operation = carrier.get(field)
        if isinstance(operation, Mapping) and isinstance(operation.get("metadata"), Mapping):
            normalized, nonfinite = _metadata_carrier(operation["metadata"])
            carrier[field] = {**operation, "metadata": normalized}
            carrier[marker] = nonfinite
    if call.startswith("store_") and guard_home is not None:
        carrier["guard_home"] = str(guard_home)
    result = native_runner_authority("continuation_authority", carrier, guard_home)
    projected = result.get("operation_update")
    if isinstance(projected, dict) and isinstance(projected.get("metadata"), dict):
        metadata = projected["metadata"]
        for path, token in carrier.get("operation_metadata_nonfinite", []):
            parent = metadata
            try:
                for key in path[:-1]:
                    parent = parent[key]
                if path and parent[path[-1]] is None:
                    parent[path[-1]] = json.loads(token)
            except (KeyError, IndexError, TypeError):
                continue
    exception_type = {
        "RuntimeError": RuntimeError,
        "ValueError": ValueError,
        "MemoryError": MemoryError,
        "sqlite3.IntegrityError": sqlite3.IntegrityError,
        "sqlite3.DatabaseError": sqlite3.DatabaseError,
        "sqlite3.OperationalError": sqlite3.OperationalError,
        "sqlite3.InternalError": sqlite3.InternalError,
        "sqlite3.DataError": sqlite3.DataError,
        "sqlite3.InterfaceError": sqlite3.InterfaceError,
    }.get(result.get("exception", ""))
    if exception_type is not None:
        error = exception_type(result["error"])
        code, prefix = result.get("sqlite_errorcode"), result.get("sqlite_errorname_prefix")
        if isinstance(error, sqlite3.Error) and isinstance(code, int) and isinstance(prefix, str):
            name = next(
                (
                    name
                    for name, value in vars(sqlite3).items()
                    if value == code and (name == prefix or name.startswith(prefix + "_"))
                ),
                "unknown",
            )
            vars(error).update(sqlite_errorcode=code, sqlite_errorname=name)
        raise error
    return result


def _metadata_carrier(value: object) -> tuple[object, list[tuple[list[str | int], str]]]:
    """Carry legacy metadata the strict UTF-8 envelope cannot hold as JSON literals.

    Nonfinite floats travel as their ``json.dumps`` token and strings holding a
    lone surrogate as their ASCII-escaped ``json.dumps`` literal, so the native
    writer persists the bytes the Python store wrote.
    """
    nonfinite: list[tuple[list[str | int], str]] = []

    def normalize(item: Any, path: list[str | int]) -> Any:
        if isinstance(item, float) and not math.isfinite(item):
            if math.isnan(item):
                token = "NaN"
            elif item > 0:
                token = "Infinity"
            else:
                token = "-Infinity"
            nonfinite.append((path, token))
            return None
        if isinstance(item, str) and not _utf8_encodable(item):
            nonfinite.append((path, json.dumps(item)))
            return None
        if isinstance(item, Mapping):
            return {key: normalize(nested, [*path, key]) for key, nested in item.items()}
        if isinstance(item, (list, tuple)):
            return [normalize(nested, [*path, index]) for index, nested in enumerate(item)]
        return item

    return normalize(value, []), nonfinite


def _utf8_encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def project(
    offer: ContinuationOffer,
    result: ContinuationResult,
    *,
    operation: Mapping[str, object] | None = None,
    request_id: str = "",
    action: str = "allow_once",
    now: str = "",
    guard_home: Path | None = None,
) -> dict[str, Any]:
    if operation is None and not request_id and action == "allow_once" and not now and guard_home is None:
        carrier = json.dumps(
            {"offer": offer_wire(offer), "result": result_wire(result)},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return deepcopy(_public_projection(carrier))
    return continuation_authority(
        "project",
        offer=offer_wire(offer),
        result=result_wire(result),
        operation=operation,
        request_id=request_id,
        action=action,
        now=now,
        guard_home=guard_home,
    )


@lru_cache(maxsize=128)
def _public_projection(carrier: str) -> dict[str, Any]:
    """Reuse one bound pure projection for the immutable public carrier pair."""
    return continuation_authority(
        "project",
        **json.loads(carrier),
        operation=None,
        request_id="",
        action="allow_once",
        now="",
    )
