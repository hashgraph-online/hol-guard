#!/usr/bin/env python3
"""Shared authority read for the Extension Control Center installed CI fixtures.

The browser phase applies real policy through the daemon, so by the time the
workflow restarts the daemon the committed snapshot may be bound to the catalog
the daemon serves rather than the built-in registry this fixture starts from.
Reading the authority back with a digest it was never bound to reports
``tampered``, which says nothing about whether the authority survived. Ask the
snapshot which catalog it is bound to and read with that digest instead, then
report every fact a failure needs instead of a bare health word.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore


def _committed_catalog_digest(store: GuardStore) -> str | None:
    try:
        with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
            row = connection.execute(
                "select catalog_digest from extension_control_authority_snapshot where singleton = 1"
            ).fetchone()
    except Exception:
        return None
    if row is None:
        return None
    digest = str(row["catalog_digest"])
    return digest or None


def read_authority(store: GuardStore):
    """Return the authority view, preferring the digest the snapshot is bound to."""

    built_in = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    committed = _committed_catalog_digest(store)
    if committed is not None and committed != built_in:
        view = store.read_extension_control_authority(catalog_digest=committed)
        if view.health is AuthorityHealth.PROTECTED:
            return view
    return store.read_extension_control_authority(catalog_digest=built_in)


def describe_authority(store: GuardStore) -> str:
    """Report why an authority read is not protected, in one line."""

    built_in = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    facts = [f"built_in_catalog_digest={built_in[:16]}"]
    committed = _committed_catalog_digest(store)
    facts.append(f"snapshot_catalog_digest={committed[:16] if committed else 'missing'}")
    try:
        with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
            row = connection.execute(
                "select revision from extension_control_authority_snapshot where singleton = 1"
            ).fetchone()
    except Exception as error:  # pragma: no cover - diagnostic only
        facts.append(f"snapshot_error={type(error).__name__}: {error}")
        row = None
    facts.append(f"snapshot_revision={int(row['revision']) if row is not None else 'missing'}")
    try:
        key = store._authority_key(required=False)  # pyright: ignore[reportPrivateUsage]
    except Exception as error:  # pragma: no cover - diagnostic only
        facts.append(f"key_error={type(error).__name__}: {error}")
        key = None
    facts.append(f"key={'present' if key is not None else 'missing'}")
    if key is not None:
        try:
            anchor = store._read_anchor(key=key)  # pyright: ignore[reportPrivateUsage]
        except Exception as error:  # pragma: no cover - diagnostic only
            facts.append(f"anchor_error={type(error).__name__}: {error}")
        else:
            if anchor is None:
                facts.append("anchor=missing")
            else:
                facts.append(
                    f"anchor_revision={anchor.revision} anchor_phase={anchor.phase.value} "
                    f"anchor_snapshot_digest={anchor.snapshot_digest[:16]}"
                )
    return ", ".join(facts)
