"""Keep fixed-deadline integration checks on one existing, serial coverage shard."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

DEADLINE_FAMILIES = (
    "tests/test_desktop_native_qualification.py::test_actual_cli_child_qualifies_and_retires_its_isolated_native_runtime",
    "tests/test_business_policy_dashboard_recovery.py::test_dashboard_recovery_requires_fresh_factor_and_preserves_request_status",
    "tests/test_business_policy_dashboard_recovery.py::test_inspection_discovers_saved_rules_and_recovered_request_remains_non_replayable",
)
RESOURCE_SCHEMA = "guard.pytest-shard-resources.v1"
NORMAL_WORKERS = 4
ISOLATED_WORKERS = 1


def deadline_family(node: str) -> str | None:
    """Match complete function selectors, including all their parameters."""
    parent = node.split("[", maxsplit=1)[0]
    return parent if parent in DEADLINE_FAMILIES else None


def deadline_counts(nodes: Sequence[str]) -> dict[str, int]:
    counts = Counter(deadline_family(node) for node in nodes)
    return {family: counts[family] for family in DEADLINE_FAMILIES}


def _shard_digest(nodes: Sequence[str]) -> str:
    return hashlib.sha256(("\n".join(nodes) + "\n").encode()).hexdigest()


def resource_metadata(shards: Sequence[Sequence[str]]) -> dict[str, object]:
    """Bind the isolation policy to every response file in the existing plan."""
    if len(shards) < 3 or any(not shard for shard in shards):
        raise ValueError("deadline isolation requires nonempty ordinary and isolated shards")
    isolated = shards[-1]
    counts = deadline_counts(isolated)
    if not all(counts.values()) or any(deadline_family(node) is None for node in isolated):
        raise ValueError("isolated shard must contain every deadline family and no companions")
    if any(deadline_family(node) for shard in shards[:-1] for node in shard):
        raise ValueError("deadline nodes must run only in their isolated coverage shard")
    flattened = [node for shard in shards for node in shard]
    if len(flattened) != len(set(flattened)):
        raise ValueError("resource plan cannot execute a node twice")
    return {
        "schema": RESOURCE_SCHEMA,
        "isolated_shard": len(shards) - 1,
        "family_counts": counts,
        "shard_sha256": [_shard_digest(shard) for shard in shards],
    }


def coverage_worker_count(shard_file: Path, pytest_args: Sequence[str]) -> int:
    """Fail closed on drift before preparation or pytest can start."""
    metadata = json.loads((shard_file.parent / "plan.json").read_text())
    count = metadata.get("shard_count")
    policy = metadata.get("execution_policy")
    match = re.fullmatch(r"shard-(\d{3,})\.txt", shard_file.name)
    if type(count) is not int or count < 3 or match is None or not isinstance(policy, dict):
        raise ValueError("coverage resource policy is missing or invalid")
    index = int(match[1])
    counts, digests = policy.get("family_counts"), policy.get("shard_sha256")
    if (
        set(policy) != {"schema", "isolated_shard", "family_counts", "shard_sha256"}
        or policy.get("schema") != RESOURCE_SCHEMA
        or type(policy.get("isolated_shard")) is not int
        or policy["isolated_shard"] != count - 1
        or not 0 <= index < count
        or not isinstance(counts, dict)
        or set(counts) != set(DEADLINE_FAMILIES)
        or any(type(value) is not int or value <= 0 for value in counts.values())
        or not isinstance(digests, list)
        or len(digests) != count
    ):
        raise ValueError("coverage resource policy does not match the deadline families")
    nodes = shard_file.read_text().splitlines()
    if not nodes or len(nodes) != len(set(nodes)) or digests[index] != _shard_digest(nodes):
        raise ValueError("coverage response file does not match its resource policy")
    isolated = index == count - 1
    if isolated:
        if any(deadline_family(node) is None for node in nodes) or deadline_counts(nodes) != counts:
            raise ValueError("isolated shard has missing deadline nodes or illegal companions")
    elif any(deadline_family(node) for node in nodes):
        raise ValueError("ordinary shard contains a deadline-sensitive node")
    _validate_pytest_args(shard_file, pytest_args, nodes)
    return ISOLATED_WORKERS if isolated else NORMAL_WORKERS


def _validate_pytest_args(shard_file: Path, args: Sequence[str], nodes: Sequence[str]) -> None:
    owned_reference = "@" + str(shard_file)
    # Pytest expands response files before parsing options, including tokens
    # that appear where an option value would otherwise be consumed.
    if args.count(owned_reference) != 1 or any(arg.startswith("@") and arg != owned_reference for arg in args):
        raise ValueError("coverage invocation must execute its response file exactly once")
    values = {
        "-p": {"pytest_duration_report"},
        "--dist": {"loadfile"},
        "--max-worker-restart": {"0"},
        "--reruns": {"0", "1"},
        "--reruns-delay": {"2"},
        "--tb": {"short"},
        "--durations": {"10"},
        "--cov-report": {""},
    }
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg == "@" + str(shard_file) or arg in {"--cov", "--cov-branch"}:
            continue
        option, separator, value = arg.partition("=")
        if option not in values and option != "--deselect":
            raise ValueError("coverage arguments cannot override resource policy or node ownership")
        if not separator:
            if index == len(args):
                raise ValueError("coverage option has no value")
            value = args[index]
            index += 1
        if value.startswith("@"):
            raise ValueError("coverage response file must be a standalone argument")
        if option == "--deselect":
            if any(node.startswith(value) for node in nodes):
                raise ValueError("coverage invocation cannot deselect an assigned node")
        elif value not in values[option]:
            raise ValueError("coverage option changes execution ownership or worker policy")
