"""The shipped catalog's risk classes, and what the activity record claims for one this vocabulary does not name."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.command_risk_effects import COMMAND_RISK_EFFECTS
from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import (
    load_generated_command_catalog,
)

# Every risk class the packaged catalog ships that `COMMAND_RISK_EFFECTS` does
# not name. The catalog is authored outside this table, so the gap is expected;
# pinning it means a newly shipped class is a decision someone makes rather than
# one the fallback quietly absorbs. Map a class and drop it from here.
UNMAPPED_SHIPPED_RISK_CLASSES = frozenset(
    {
        "credential_access",
        "permission_change",
        "remote_execution",
    }
)


def _shipped_risk_classes() -> frozenset[str]:
    catalog = load_generated_command_catalog()
    classes: set[str] = set()
    for extension in catalog.extensions:
        classes.update(extension.risk_classes)
        for rule in extension.rules:
            classes.update(rule.risk_classes)
    return frozenset(classes)


def test_the_packaged_catalog_ships_exactly_the_recorded_unmapped_classes() -> None:
    assert _shipped_risk_classes() - set(COMMAND_RISK_EFFECTS) == UNMAPPED_SHIPPED_RISK_CLASSES


def test_every_mapped_class_names_exactly_one_effect() -> None:
    """Rust holds the same table as `Option<EffectKind>`, one kind per class.

    A class mapped to two kinds would still build a Python record and have no
    faithful Rust spelling, so the shape is pinned where it can be seen rather
    than left to the next person to notice.
    """

    assert {name: len(effects) for name, effects in COMMAND_RISK_EFFECTS.items()} == dict.fromkeys(
        COMMAND_RISK_EFFECTS, 1
    )
