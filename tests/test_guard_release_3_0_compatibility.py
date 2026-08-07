"""Compatibility characterization tests pinning the 2.1/2.2 -> 3.0 contracts.

These tests are written as characterization tests: they pin observable contract
behavior that a 2.1/2.2 client depends on, and they fail if a future change
breaks that contract. They are the executable evidence behind
``docs/guard/release-3-0-compatibility-evidence.md``.

Covered contracts:
- The surface-schema advertised method list and the runtime ``SERVER_METHODS``
  list are negotiated together in a single ``initialize_client`` handshake, and
  a 2.x client receives both plus the negotiated protocol version.
- A 2.x-era receipt store (schema migrations 10 and 16 present, rollup bucket
  state stale) is reconstructed by ``backfill_receipt_rollups`` so archived
  receipt rollups are rebuilt rather than lost.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.surface_server import (
    SERVER_METHODS,
    GuardSurfaceRuntime,
)
from codex_plugin_scanner.guard.schemas.surface_server import build_surface_server_contract
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_receipt_rollups import backfill_receipt_rollups

from .test_guard_receipt_persistence import _make_receipt

# Methods a 2.x client can rely on being present after the handshake. These are
# the runtime-implemented methods that existed across the 2.2 -> 3.0 boundary.
_NEGOTIATED_RUNTIME_METHODS = (
    "initialize",
    "session/list",
    "session/start",
    "session/attach",
    "operation/start",
    "operation/status",
    "approval/list",
    "approval/get",
    "receipt/list",
    "receipt/get",
    "policy/get",
)

# Methods advertised in the surface schema that the runtime does not implement.
# A client must learn this from the handshake rather than assume the schema list
# is callable; this is the contract the compatibility gate pins.
_UNIMPLEMENTED_ADVERTISED_METHODS = frozenset({"operation/item/add", "client/attach", "client/heartbeat"})


def _runtime(tmp_path: Path) -> GuardSurfaceRuntime:
    return GuardSurfaceRuntime(GuardStore(tmp_path / "guard"))


class TestSurfaceRuntimeNegotiationContract:
    def test_initialize_returns_both_method_lists_and_negotiated_version(self, tmp_path: Path) -> None:
        payload = _runtime(tmp_path).initialize_client(
            client_name="legacy-adapter",
            client_title="Legacy Adapter",
            version="2.2.0",
            surface="harness-adapter",
            capabilities=(),
        )

        schema = payload["schema"]
        assert isinstance(schema, dict)
        advertised = set(schema["methods"])  # type: ignore[index]
        server_capabilities = payload["server_capabilities"]
        assert isinstance(server_capabilities, dict)
        implemented = set(server_capabilities["methods"])  # type: ignore[index]

        # Both lists are returned in one handshake so a client can reconcile them.
        assert advertised, "advertised schema method list must be present"
        assert implemented == set(SERVER_METHODS)
        # Advertised-but-unimplemented methods are not routed by the runtime.
        assert _UNIMPLEMENTED_ADVERTISED_METHODS.isdisjoint(implemented)
        assert advertised >= _UNIMPLEMENTED_ADVERTISED_METHODS
        # Every runtime method a 2.x client depends on is implemented.
        assert set(_NEGOTIATED_RUNTIME_METHODS) <= implemented

        # Protocol negotiation result is returned explicitly.
        assert payload["protocol_version"]
        assert payload["schema_version"] == build_surface_server_contract()["schema_version"]

    def test_initialize_negotiates_same_major_protocol_version(self, tmp_path: Path) -> None:
        payload = _runtime(tmp_path).initialize_client(
            client_name="legacy-adapter",
            client_title=None,
            version="2.1.0",
            surface="cli",
            capabilities=(),
            supported_protocol_versions=("1.0",),
        )
        assert payload["protocol_version"].split(".", maxsplit=1)[0] == "1"

    def test_initialize_rejects_incompatible_protocol_version(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="unsupported_protocol_version"):
            _runtime(tmp_path).initialize_client(
                client_name="legacy-adapter",
                client_title=None,
                version="2.1.0",
                surface="cli",
                capabilities=(),
                supported_protocol_versions=("99.0",),
            )


class TestLegacyReceiptRollupReconstruction:
    def test_backfill_rebuilds_archived_rollup_from_2x_receipt_store(self, tmp_path: Path) -> None:
        # Simulate a 2.x-era store: schema migrations 10 and 16 applied, but the
        # rollup bucket counters are stale (as after an archived upgrade).
        store = GuardStore(tmp_path / "guard")
        store.add_receipt(_make_receipt(receipt_id="r-legacy-warn", policy_decision="warn"))

        with store._connect() as connection:
            migration_versions = {
                int(row["version"])
                for row in connection.execute(
                    "select version from schema_migrations where version in (10, 16)"
                ).fetchall()
            }
            assert migration_versions == {10, 16}
            connection.execute("update receipt_rollup_actions set dirty = 1 where receipt_id = 'r-legacy-warn'")

        with store._connect() as connection:
            backfill_receipt_rollups(connection)

        analytics = store.receipt_analytics(top_limit=5)
        assert analytics["allowed"] == 1
        assert analytics["reviewed"] == 0
        assert analytics["blocked"] == 0

    def test_rollup_reconstruction_is_idempotent_for_archived_store(self, tmp_path: Path) -> None:
        store = GuardStore(tmp_path / "guard")
        store.add_receipt(_make_receipt(receipt_id="r-legacy-allow", policy_decision="allow"))
        store.add_receipt(_make_receipt(receipt_id="r-legacy-block", policy_decision="block"))

        with store._connect() as connection:
            backfill_receipt_rollups(connection)
        first = store.receipt_analytics(top_limit=5)

        with store._connect() as connection:
            backfill_receipt_rollups(connection)
        second = store.receipt_analytics(top_limit=5)

        assert first["allowed"] == second["allowed"]
        assert first["blocked"] == second["blocked"]
