"""Test-only namespace bridge for direct imports of legacy hook modules."""

from __future__ import annotations

from collections.abc import MutableMapping


def bootstrap_compatibility_module(namespace: MutableMapping[str, object]) -> None:
    """Supply historical facade exports to an explicitly imported oracle."""

    from . import commands_support

    exports, _ = commands_support._build_export_map()
    for name, value in exports.items():
        namespace.setdefault(name, value)


__all__ = ["bootstrap_compatibility_module"]
