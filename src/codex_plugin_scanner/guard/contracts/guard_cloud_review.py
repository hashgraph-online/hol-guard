"""Shared adapter for Guard Cloud Review wire-contract artifacts."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Final, Protocol, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

COMMAND_RESULT_CONTRACT_VERSION: Final = "guard-cloud-review-command-result-v2"
_SOURCE_ROOT: Final = Path(__file__).resolve().parents[4]
_PACKAGE_DATA_ROOT: Final = Path(__file__).resolve().parent / "data" / "guard-cloud-review"
_SOURCE_ARTIFACTS: Final = {
    "v2/contract.json": _SOURCE_ROOT / "contracts" / "guard-cloud-review" / "v2" / "contract.json",
    "v2/fixtures.json": _SOURCE_ROOT / "contracts" / "guard-cloud-review" / "v2" / "fixtures.json",
    "v2/command-result.json": _SOURCE_ROOT / "contracts" / "guard-cloud-review" / "v2" / "command-result.json",
    "guard-cloud-review.md": _SOURCE_ROOT / "docs" / "guard" / "contracts" / "guard-cloud-review.md",
}


def _artifact_path(name: str) -> Path:
    packaged = _PACKAGE_DATA_ROOT / name
    if packaged.is_file():
        return packaged
    source = _SOURCE_ARTIFACTS[name]
    if source.is_file():
        return source
    raise FileNotFoundError(f"Guard Cloud Review artifact is unavailable: {name}")


COMMAND_RESULT_CONTRACT_PATH: Final = _artifact_path("v2/command-result.json")
_RFC3339_DATE_TIME: Final = re.compile(
    r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d"
    + r"(?P<fraction>\.\d+)?(?:Z|[+-](?:0\d|1\d|2[0-3]):[0-5]\d)$"
)


class _Validator(Protocol):
    def validate(self, instance: object) -> None: ...


def _read_mapping(path: Path) -> dict[str, object]:
    parsed = cast(object, json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(parsed, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    raw_mapping = cast(dict[object, object], parsed)
    if any(not isinstance(key, str) for key in raw_mapping):
        raise ValueError(f"{path.name} must use string object keys")
    return cast(dict[str, object], raw_mapping)


def _string_keyed_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    raw_mapping = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw_mapping):
        raise ValueError(f"{label} must use string object keys")
    return cast(Mapping[str, object], raw_mapping)


def _mapping_field(mapping: Mapping[str, object], name: str) -> Mapping[str, object]:
    return _string_keyed_mapping(mapping.get(name), name)


def _schema_validator(schema: Mapping[str, object]) -> _Validator:
    return cast(_Validator, Draft202012Validator(schema))


def _contract_metadata(contract: Mapping[str, object]) -> Mapping[str, object]:
    return _mapping_field(contract, "x-hol-contract")


def load_exact_command_result_contract() -> dict[str, object]:
    """Load the exact-command result contract used by the active transport."""

    contract = _read_mapping(COMMAND_RESULT_CONTRACT_PATH)
    metadata = _contract_metadata(contract)
    if metadata.get("contractVersion") != COMMAND_RESULT_CONTRACT_VERSION:
        raise ValueError("unsupported Guard Cloud Review command-result contract version")
    Draft202012Validator.check_schema(contract)
    return contract


def _is_rfc3339_date_time(value: object) -> bool:
    if not isinstance(value, str):
        return False
    match = _RFC3339_DATE_TIME.fullmatch(value)
    if match is None:
        return False
    fraction = match.group("fraction")
    parse_value = value
    if fraction is not None:
        parse_value = value[: match.start("fraction")] + value[match.end("fraction") :]
    try:
        _ = datetime.fromisoformat(parse_value[:-1] + "+00:00" if parse_value.endswith("Z") else parse_value)
    except ValueError:
        return False
    return True


def validate_exact_command_result(result: Mapping[str, object]) -> None:
    """Validate a terminal exact-command result emitted to Cloud aggregation."""

    try:
        _schema_validator(load_exact_command_result_contract()).validate(dict(result))
    except ValidationError as error:
        raise ValueError(error.message) from error
    for field in ("applicationUpdatedAt", "continuationUpdatedAt"):
        if not _is_rfc3339_date_time(result.get(field)):
            raise ValueError(f"{field} must be an RFC3339 date-time")
