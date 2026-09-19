"""Source-backed effective-authority explanations for builder and help copy."""

from __future__ import annotations

from typing import Final

EFFECTIVE_AUTHORITY_EXAMPLES: Final[tuple[dict[str, object], ...]] = (
    {
        "id": "newer-local-allow-vs-generic-cloud-block",
        "authority_path": "generic-policy-rows",
        "scenario": "Newer local allow versus generic Cloud block at the same specificity",
        "winner": "local allow",
        "shadowed": "cloud block",
        "reason": (
            "Eligible persisted rows order by scope specificity, then constrained versus unconstrained "
            "rows, then updated_at descending. Source is not a tie-breaker."
        ),
        "source_contract": "spec/guard-policy/v1alpha1/semantics.md#current-runtime-precedence-frozen",
    },
    {
        "id": "managed-disabled-vs-local-enabled",
        "authority_path": "managed-extension-controls",
        "scenario": "Managed disabled permission versus local enabled",
        "winner": "managed disabled",
        "shadowed": "local enabled",
        "reason": "compose_control_layers uses disable dominance across local and signed Cloud layers.",
        "source_contract": "runtime/extension_control_resolver.py::compose_control_layers",
    },
    {
        "id": "intrinsic-native-block-vs-policy-allow",
        "authority_path": "native-intrinsic-floor",
        "scenario": "Intrinsic native block versus policy allow",
        "winner": "intrinsic native block",
        "shadowed": "policy allow",
        "reason": (
            "Native policy_enforcement joins the authenticated policy floor with the intrinsic result "
            "and does not weaken intrinsic blocks. Observe mode may suppress policy-only denial."
        ),
        "source_contract": "rust/crates/guard-runtime/src/policy_enforcement.rs",
    },
)


def effective_authority_explanation(example_id: str) -> dict[str, object]:
    for example in EFFECTIVE_AUTHORITY_EXAMPLES:
        if example["id"] == example_id:
            return dict(example)
    raise KeyError(example_id)


__all__ = ["EFFECTIVE_AUTHORITY_EXAMPLES", "effective_authority_explanation"]
