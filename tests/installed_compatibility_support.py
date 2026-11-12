"""Offline legacy compatibility metadata from the installed command-pack bundle.

Production decision paths never load this library; only test loaders that
emulate the legacy contribution directory read it, so the helper lives here.
"""

from __future__ import annotations

from typing import Any, cast

from codex_plugin_scanner.guard.catalog_delivery import installed_bundle, lifecycle
from codex_plugin_scanner.guard.extension_builder.native_source_compiler import (
    NativeSourceCompilerError,
    run_source_compiler,
)


def compatibility_payloads(family: str) -> tuple[dict[str, Any], ...] | None:
    """Return one family's legacy payloads, or ``None`` when no bundle is advertised.

    Only genuine legacy absence permits fallback. An advertised installed bundle
    must authenticate through both release manifests before any metadata reads.
    """
    if family not in {"commands", "mcp"}:
        raise ValueError("unknown compatibility metadata family")
    if not installed_bundle.advertised():
        return None
    bundle = installed_bundle.load_installed_bundle()

    # Offline traversals commonly read thousands of members; one session verifies
    # and copies the runtime once for all of them.
    with lifecycle.session():
        try:
            result = run_source_compiler(
                "bundle-compatibility",
                {
                    "family": family,
                    "source_sha": bundle.source_sha,
                    "engine": bundle.engine,
                    "data": bundle.data.decode("utf-8"),
                    "max_bytes": installed_bundle.MAX_BYTES,
                },
                fetch=lambda reference: bundle._fetch(
                    cast(dict[str, Any], reference["location"]), cast(int, reference["length"])
                ),
            )
        except NativeSourceCompilerError as error:
            raise ValueError(f"installed compatibility metadata unavailable: {error}") from error
    return tuple(cast(list[dict[str, Any]], result["payloads"])) if result["available"] else None
