"""Descriptive local compiler capabilities; this does not evaluate policy."""

from __future__ import annotations

from itertools import combinations

from .policy_document_compile import _MAX_COMPILED_ROWS, _SUPPORTED_MATCH_KEYS, _TOOL_SELECTOR_FAMILIES


def local_row_projection_capabilities() -> dict[str, object]:
    # These maximal selector sets describe the current row representation.
    # Exhaustive compiler tests verify every subset, effect and lifetime.
    groups = (
        ("artifacts", "harnesses", "workspaces"),
        ("harnesses", "publishers"),
        ("harnesses", "tools", "workspaces"),
    )
    supported = {
        selection for group in groups for size in range(len(group) + 1) for selection in combinations(group, size)
    }
    supported.update(
        tuple(sorted((*selection, "exactCommand"))) for selection in tuple(supported) if "artifacts" in selection
    )
    return {
        "schema": "guard.hashgraphonline.com/v1alpha1",
        "match_fields": sorted(_SUPPORTED_MATCH_KEYS),
        "supported_match_combinations": [list(keys) for keys in sorted(supported, key=lambda keys: (len(keys), keys))],
        "effects": ["allow", "block", "review"],
        "inert_effects": ["ignore"],
        "lifetimes": ["permanent", "until"],
        "tool_families": dict(_TOOL_SELECTOR_FAMILIES),
        "maximum_compiled_rows": _MAX_COMPILED_ROWS,
        "device_selection": "cloud_installation_id_filter_before_compilation",
        "command_expressions": "cli_evaluator_only; authenticated_application_unsupported",
        "required_validation": "policy validate",
        "constraints": [
            "Nonempty selector lists contain strings; tools must use a listed family alias.",
            "An empty match explicitly selects global scope. Unknown matchers never become global rules.",
            "Until requires a valid expiry; rule fanout counts toward the document-wide row limit.",
            "Local scope overrides must preserve all selected restrictions.",
            "Exact command selectors require concrete artifacts; wildcard and family artifacts are refused.",
            "Ignore and disabled rules produce no local enforcement row.",
        ],
    }
