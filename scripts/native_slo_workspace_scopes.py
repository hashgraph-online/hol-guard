"""Gate measured compilation coverage separately from native authority validity."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any


def scope_checks(
    phase: str,
    count: int,
    rows: Sequence[Mapping[str, Any]],
    chain: Mapping[str, Any],
) -> dict[str, bool]:
    if count not in {1, 10, 100} or type(count) is not int:
        raise ValueError("workspace scope count outside bound")
    compiled = [row for row in rows if row.get("kind") == "compile" and row.get("succeeded") is True]
    current = [row for row in compiled if row.get("publication") == chain.get("publication")]
    checks = {
        "acknowledged_compilation_observed": bool(current) and chain.get("matched") is True,
        "registered_scopes_complete": bool(current) and current[-1].get("registered_workspaces") == count,
        "compiled_cache_complete": bool(current) and current[-1].get("cache_entries") == count + 1,
    }
    loads = [row for row in rows if row.get("kind") == "compile"]
    observed: Counter[int] = Counter()
    valid = True
    total = 0
    for row in loads:
        scopes = row.get("scope_loads")
        if (
            not isinstance(scopes, list)
            or len(scopes) != count + 1
            or any(type(value) is not int or not 0 <= value <= 255 for value in scopes)
        ):
            valid = False
            continue
        observed.update({index - 1: value for index, value in enumerate(scopes) if value})
        total += sum(scopes)
    checks["load_records_valid"] = valid and all(
        row.get("succeeded") is True
        and row.get("unregistered_loads") == row.get("config_load_failures") == 0
        and row.get("scope_counts_overflow") is False
        for row in loads
    )
    checks["compile_load_counts_reconcile"] = sum(row.get("config_loads", -1) for row in loads) == total
    if phase in {"initial", "public_policy"}:
        checks["all_scopes_loaded_once"] = observed == Counter(range(-1, count))
    elif phase in {"unchanged", "resident_restart"}:
        checks["unchanged_scopes_reused"] = total == 0
    elif phase == "stricter_overlay":
        checks["only_stricter_scope_recompiled"] = observed == Counter({0: 1})
    elif phase == "coalesced_burst":
        expected = set(range(min(count, 32)))
        checks["all_changed_scopes_captured"] = set(observed) == expected and all(
            observed[index] >= 1 for index in expected
        )
    else:
        raise ValueError("workspace scope phase unknown")
    return checks
