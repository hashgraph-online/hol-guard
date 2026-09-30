"""Strict redacted native extension evidence and receipt binding validation."""

from __future__ import annotations

import hashlib
import json
import re
from typing import cast

_DIGEST = re.compile(r"[0-9a-f]{64}")
_CATALOG_ID = re.compile(r"command\.[a-z0-9]+(?:[.-][a-z0-9]+)*")
_VERSION = re.compile(r"[1-9][0-9]*\.[0-9]+\.[0-9]+")
_VARIANT = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,255}")
_EXECUTABLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
_DETAIL = "Matched bounded structured command constraints."
_MAX_OBSERVATIONS = 2_048
_MAX_EVIDENCE = 8_192
_BINDING_FIELDS = frozenset(
    {
        "schema",
        "program_digest",
        "catalog_digest",
        "trust_digest",
        "control_revision",
        "managed_control_revision",
        "control_effective_digest",
        "observations_digest",
        "observation_count",
        "uncertainty_count",
    }
)
_OBSERVATION_FIELDS = frozenset(
    {
        "extension_id",
        "extension_version",
        "rule_id",
        "rule_version",
        "match_class",
        "match_classes",
        "matcher_evidence",
        "safe_variants",
        "uncertainty_reasons",
        "effective_segment_indexes",
    }
)


def _matches(value: object, pattern: re.Pattern[str], maximum: int) -> bool:
    return isinstance(value, str) and len(value) <= maximum and pattern.fullmatch(value) is not None


def _integer(value: object, maximum: int) -> bool:
    return type(value) is int and 0 <= value <= maximum


def valid_native_command_receipt_binding(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != _BINDING_FIELDS:
        return False
    if value["schema"] != "guard.native-command-receipt-binding.v1":
        return False
    if any(
        not _matches(value[key], _DIGEST, 64)
        for key in (
            "program_digest",
            "catalog_digest",
            "trust_digest",
            "control_effective_digest",
            "observations_digest",
        )
    ):
        return False
    return (
        _integer(value["control_revision"], 2**64 - 1)
        and _integer(value["managed_control_revision"], 2**64 - 1)
        and _integer(value["observation_count"], _MAX_OBSERVATIONS)
        and _integer(value["uncertainty_count"], _MAX_OBSERVATIONS + 1)
    )


def _evidence_indexes(value: object, budget: list[int]) -> list[int] | None:
    if not isinstance(value, list) or len(value) > _MAX_EVIDENCE:
        return None
    budget[0] -= len(value)
    if budget[0] < 0:
        return None
    indexes: list[int] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"segment_index", "executable", "detail"}:
            return None
        if not _integer(item["segment_index"], 127) or item["detail"] != _DETAIL:
            return None
        if item["executable"] is not None and not _matches(item["executable"], _EXECUTABLE, 128):
            return None
        indexes.append(cast(int, item["segment_index"]))
    return indexes


def _valid_observation(value: object, budget: list[int]) -> bool:
    if not isinstance(value, dict) or set(value) != _OBSERVATION_FIELDS:
        return False
    if any(not _matches(value[key], _CATALOG_ID, 256) for key in ("extension_id", "rule_id")):
        return False
    if not str(value["rule_id"]).startswith(f"{value['extension_id']}."):
        return False
    if any(not _matches(value[key], _VERSION, 64) for key in ("extension_version", "rule_version")):
        return False
    base = _evidence_indexes(value["matcher_evidence"], budget)
    variants = value["safe_variants"]
    uncertainty = value["uncertainty_reasons"]
    if base is None or not isinstance(variants, list) or len(variants) > 64:
        return False
    if uncertainty not in ([], ["matcher-failure"]):
        return False
    expected_classes = ["unsafe"] if base else []
    if uncertainty:
        expected_classes.append("uncertainty")
    if value["match_classes"] != expected_classes or value["match_class"] != (
        "uncertainty" if uncertainty else "unsafe"
    ):
        return False
    if not expected_classes or (not base and variants):
        return False
    variant_ids: set[str] = set()
    safe_indexes: set[int] = set()
    for variant in variants:
        if not isinstance(variant, dict) or set(variant) != {"match_class", "variant_id", "matcher_evidence"}:
            return False
        if variant["match_class"] != "safe-variant" or not _matches(variant["variant_id"], _VARIANT, 256):
            return False
        variant_id = cast(str, variant["variant_id"])
        if variant_id in variant_ids:
            return False
        variant_ids.add(variant_id)
        indexes = _evidence_indexes(variant["matcher_evidence"], budget)
        if not indexes:
            return False
        safe_indexes.update(indexes)
    effective = value["effective_segment_indexes"]
    if not isinstance(effective, list) or any(not _integer(index, 127) for index in effective):
        return False
    return effective == [index for index in base if index not in safe_indexes]


def _valid_permission_observation(value: object, budget: list[int]) -> bool:
    fields = {"extension_id", "permission_id", "matcher_evidence", "uncertainty_reasons"}
    if not isinstance(value, dict) or set(value) not in (fields, fields | {"mcp_tool"}):
        return False
    if "mcp_tool" in value and (
        not isinstance(value["mcp_tool"], str)
        or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,127}", value["mcp_tool"]) is None
        or value["matcher_evidence"]
    ):
        return False
    if not _matches(value["extension_id"], _CATALOG_ID, 256):
        return False
    permission_id = value["permission_id"]
    if not isinstance(permission_id, str) or len(permission_id) > 256:
        return False
    prefix = f"{value['extension_id']}.permission."
    if not permission_id.startswith(prefix) or not _matches(permission_id, _CATALOG_ID, 256):
        return False
    evidence = _evidence_indexes(value["matcher_evidence"], budget)
    uncertainty = value["uncertainty_reasons"]
    return (
        evidence is not None
        and uncertainty in ([], ["matcher-failure"])
        and bool(evidence or uncertainty or "mcp_tool" in value)
    )


def validate_native_command_observations(value: object) -> dict[str, object] | None:
    fields = {"schema", "binding", "observations", "permission_observations", "evaluation_error"}
    if not isinstance(value, dict) or set(value) != fields:
        return None
    if value["schema"] != "guard.native-command-observations.v1" or not valid_native_command_receipt_binding(
        value["binding"]
    ):
        return None
    observations = value["observations"]
    permission_observations = value["permission_observations"]
    error = value["evaluation_error"]
    if not isinstance(observations, list) or not isinstance(permission_observations, list):
        return None
    count = len(observations) + len(permission_observations)
    if count > _MAX_OBSERVATIONS:
        return None
    if error is not None and (error != "native_command_evaluation_failed" or count):
        return None
    budget = [_MAX_EVIDENCE]
    if not all(_valid_observation(observation, budget) for observation in observations):
        return None
    if not all(_valid_permission_observation(observation, budget) for observation in permission_observations):
        return None
    binding = cast(dict[str, object], value["binding"])
    typed_observations = cast(list[dict[str, object]], observations)
    typed_permissions = cast(list[dict[str, object]], permission_observations)
    if len({item["rule_id"] for item in typed_observations}) != len(typed_observations):
        return None
    if len({item["permission_id"] for item in typed_permissions}) != len(typed_permissions):
        return None
    uncertainty_count = sum(bool(item["uncertainty_reasons"]) for item in typed_observations + typed_permissions)
    uncertainty_count += error is not None
    if binding["observation_count"] != count or binding["uncertainty_count"] != uncertainty_count:
        return None
    canonical = json.dumps(
        {"observations": observations, "permission_observations": permission_observations, "evaluation_error": error},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    expected = hashlib.sha256(b"hol-guard.native-command-observations.v1\0" + canonical).hexdigest()
    return cast(dict[str, object], value) if binding["observations_digest"] == expected else None
