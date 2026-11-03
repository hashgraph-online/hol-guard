"""This-device MCP custom-extension grant lookup."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypedDict, cast

from .runtime.local_cli_identity import UnlistedCliIdentity
from .store_local_cli_retention import LocalCliReplaySkippedError, utc_now_iso
from .store_local_cli_schema import ensure_local_cli_schema
from .store_mcp_provider_catalog import describe_provider_actions

if TYPE_CHECKING:
    from .store import GuardStore

_OBSERVED_MCP_ACTIONS = frozenset({"allow", "review", "block"})
_CONNECTOR_KEYS = frozenset({"harness", "namespace", "server_name", "seen_at", "tools"})


class ObservedMcpConnectorTool(TypedDict):
    name: str
    qualified_name: str


class ObservedMcpConnector(TypedDict):
    harness: str
    namespace: str
    server_name: str
    seen_at: str | None
    tools: list[ObservedMcpConnectorTool]


def _valid_connector(item: object) -> bool:
    if not isinstance(item, dict) or set(item) != _CONNECTOR_KEYS:
        return False
    connector = cast("dict[str, object]", item)
    tools = connector["tools"]
    return (
        all(isinstance(connector[key], str) for key in ("harness", "namespace", "server_name"))
        and (connector["seen_at"] is None or isinstance(connector["seen_at"], str))
        and isinstance(tools, list)
        and all(
            isinstance(tool, dict)
            and set(tool) == {"name", "qualified_name"}
            and all(isinstance(value, str) for value in cast("dict[str, object]", tool).values())
            for tool in cast("list[object]", tools)
        )
    )


class StoreLocalMcpMixin:
    if TYPE_CHECKING:

        def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...

        def _native_store_call(
            self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
        ) -> Any: ...

    def _migrate_for_read(self) -> None:
        """Bring an older store up to the schema the resident will read.

        The resident refuses a store below its minimum read version rather
        than migrating one, so the migration the Python reads used to run
        before touching these tables still has to happen here. A store that
        is already current takes no writer lock.
        """

        with self._connect() as connection:
            ensure_local_cli_schema(connection, for_read=True)

    def _native_mcp_read(self, method: str, args: Mapping[str, object], reason: str) -> dict[str, object]:
        self._migrate_for_read()
        page = self._native_store_call(method, args)
        if not isinstance(page, dict):
            raise sqlite3.DatabaseError(reason)
        return cast(dict[str, object], page)

    def _provider_rows_absent(self, probe: str) -> bool:
        """Answer an empty provider store without a resident round trip.

        The snapshot publisher reads both provider facts on every policy
        observation, and an install that has never seen a provider has no row
        for the resident to compile. Probing here keeps those compiles off the
        hook's round-trip budget, the way the observed-tool read already does.
        """

        # The resident reads only the current schema; migrate an older store first.
        with self._connect() as connection:
            ensure_local_cli_schema(connection, for_read=True)
            return connection.execute(probe).fetchone() is None

    def read_mcp_provider_choices(self) -> dict[str, str]:
        if self._provider_rows_absent("select 1 from local_mcp_provider_grant limit 1"):
            return {}
        choices = self._native_store_call("read_mcp_provider_choices", {})
        if not isinstance(choices, dict) or any(
            not isinstance(selector, str) or not isinstance(state, str)
            for selector, state in cast(dict[object, object], choices).items()
        ):
            raise sqlite3.DatabaseError("native_mcp_provider_choices_invalid")
        return cast(dict[str, str], choices)

    def observed_mcp_discovery(self, *, configured_servers: dict[str, list[str]]) -> list[ObservedMcpConnector]:
        """Return the connectors the harnesses were seen calling, as the resident groups them."""

        answer = self._native_store_call("observed_mcp_discovery", {"configured_servers": configured_servers})
        connectors = answer.get("connectors") if isinstance(answer, dict) and len(answer) == 1 else None
        if not isinstance(connectors, list) or not all(
            _valid_connector(item) for item in cast("list[object]", connectors)
        ):
            raise sqlite3.DatabaseError("native_observed_mcp_discovery_invalid")
        return cast("list[ObservedMcpConnector]", connectors)

    def read_observed_mcp_tool_actions(self) -> dict[str, str]:
        """Return the operator's exact choices for observed MCP connectors."""

        # The resident reads only the current schema; migrate an older store first.
        with self._connect() as connection:
            ensure_local_cli_schema(connection, for_read=True)
            # The snapshot publisher reads this on every policy observation.
            # Without an observed connector the resident would return no
            # actions, so skip the round trip.
            observed = connection.execute(
                "select 1 from local_cli_observation "
                "where surface = 'mcp' and server_command like 'observed-mcp:%' limit 1"
            ).fetchone()
        if observed is None:
            return {}
        actions = self._native_store_call("observed_mcp_tool_actions", {})
        if not isinstance(actions, dict) or any(
            not isinstance(key, str) or action not in _OBSERVED_MCP_ACTIONS
            for key, action in cast(dict[object, object], actions).items()
        ):
            raise sqlite3.DatabaseError("native_observed_mcp_tool_actions_invalid")
        return cast(dict[str, str], actions)

    def read_mcp_provider_authority_hash(self) -> str | None:
        if self._provider_rows_absent("select 1 from local_mcp_provider_authority limit 1"):
            return None
        digest = self._native_store_call("read_mcp_provider_authority_hash", {})
        if digest is not None and not isinstance(digest, str):
            raise sqlite3.DatabaseError("native_mcp_provider_authority_invalid")
        return digest

    def read_local_mcp_workflows(self, cli_id: str, *, offset: int = 0) -> dict[str, object]:
        return self._native_mcp_read(
            "read_local_mcp_workflows",
            {"cli_id": cli_id, "offset": offset},
            "native_mcp_workflow_page_invalid",
        )

    def read_local_mcp_provider_actions(
        self,
        cli_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        search: str = "",
        expected_token: str | None = None,
    ) -> dict[str, object]:
        result = self._native_mcp_read(
            "read_local_mcp_provider_actions",
            {
                "cli_id": cli_id,
                "limit": limit,
                "offset": offset,
                "search": search,
                "expected_token": expected_token,
            },
            "native_mcp_provider_actions_invalid",
        )
        page, declarations = result.get("page"), result.get("declarations")
        if not isinstance(page, dict) or not isinstance(declarations, list):
            raise sqlite3.DatabaseError("native_mcp_provider_actions_invalid")
        # The classification the page carries is display evidence the resident
        # does not own, so the native read returns the declarations and the
        # description still happens here.
        return describe_provider_actions(
            cast(dict[str, object], page),
            cast("Sequence[dict[str, object]]", declarations),
            guard_home=cast("GuardStore", self).guard_home,
        )

    def read_local_mcp_skills(
        self,
        cli_id: str,
        *,
        offset: int,
        search: str,
        expected_revision: int | None = None,
    ) -> dict[str, object]:
        return self._native_mcp_read(
            "read_local_mcp_skills",
            {
                "cli_id": cli_id,
                "offset": offset,
                "search": search,
                "expected_revision": expected_revision,
            },
            "native_mcp_skill_page_invalid",
        )

    def find_local_mcp_observation(
        self,
        *,
        cli_id: str | None = None,
        server_identity_hash: str | None = None,
        command: str | None = None,
        args_hash: str | None = None,
    ) -> dict[str, object] | None:
        found = self._native_store_call(
            "find_local_mcp_observation",
            {
                "cli_id": cli_id if isinstance(cli_id, str) else None,
                "server_identity_hash": server_identity_hash if isinstance(server_identity_hash, str) else None,
                "command": command if isinstance(command, str) else None,
                "args_hash": args_hash if isinstance(args_hash, str) else None,
            },
        )
        if found is not None and not isinstance(found, dict):
            raise sqlite3.DatabaseError("native_local_mcp_observation_invalid")
        return cast("dict[str, object] | None", found)

    def ensure_local_mcp_observation(
        self,
        identity: UnlistedCliIdentity,
        *,
        seen_at: str,
        server_identity_hash: str,
        server_command: str,
        server_args_hash: str,
        source_label: str | None = None,
        connection_identity_hash: str | None = None,
        replayed: bool = False,
        replay_now: str | None = None,
        remote_origin: str | None = None,
        declared_source: str | None = None,
    ) -> str:
        """Insert or refresh an MCP observation without incrementing observed_count.

        ``declared_source`` (``<harness>:<stdio|remote>``) and
        ``remote_origin`` record a harness config declaration on the same
        record a call sighting uses.

        ``replayed`` marks ``seen_at`` as a history timestamp: it never moves
        ``last_seen_at`` backward and does not run retention pruning. The
        replay check runs in the write transaction, so a concurrent Forget is
        not undone; a skipped entry raises ``LocalCliReplaySkippedError``.
        """

        args: dict[str, object] = {
            "cli_id": identity.cli_id,
            "identity_hash": identity.identity_hash,
            "kind": identity.kind,
            "name": identity.name,
            "interpreter_name": identity.interpreter_name,
            "example_label": identity.example_label,
            "seen_at": seen_at,
            "server_identity_hash": server_identity_hash,
            "server_command": server_command,
            "server_args_hash": server_args_hash,
            "source_label": source_label,
            "connection_identity_hash": connection_identity_hash,
            "replayed": replayed,
            "replay_now": replay_now,
            "clock": utc_now_iso(),
        }
        if remote_origin is not None:
            args["remote_origin"] = remote_origin
        if declared_source is not None:
            args["declared_source"] = declared_source
        result = self._native_store_call("ensure_local_mcp_observation", args)
        if isinstance(result, dict) and result.get("need_barrier") is True:
            # Carrying a legacy Deny changes policy authority: close the
            # native policy barrier around the write.
            guard_home = cast("GuardStore", self).guard_home
            with _notify_legacy_mcp_denial(guard_home):
                result = self._native_store_call("ensure_local_mcp_observation", {**args, "barrier_closed": True})
        if isinstance(result, dict) and result.get("replay_skipped") is True:
            raise LocalCliReplaySkippedError(identity.cli_id)
        cli_id = result.get("cli_id") if isinstance(result, dict) else None
        if not isinstance(cli_id, str):
            raise sqlite3.DatabaseError("native_local_mcp_observation_invalid")
        return cli_id

    def reconcile_remote_mcp_declarations(self, *, harnesses: Sequence[str], declared_cli_ids: Sequence[str]) -> int:
        """Forget remote declarations a config scan of ``harnesses`` no longer finds.

        Records stay, so permission history and decisions are kept; only the
        ``<harness>:remote`` source goes, and the stored origin once no harness
        declares the connector as remote.
        """

        result = self._native_store_call(
            "reconcile_remote_mcp_declarations",
            {"harnesses": sorted(set(harnesses)), "declared_cli_ids": sorted(set(declared_cli_ids))},
        )
        reconciled = result.get("reconciled") if isinstance(result, dict) else None
        return reconciled if isinstance(reconciled, int) else 0


@contextmanager
def _notify_legacy_mcp_denial(guard_home: Path) -> Iterator[None]:
    from .native_policy_snapshot import notify_native_policy_mutation

    notify_native_policy_mutation(guard_home)
    try:
        yield
    finally:
        notify_native_policy_mutation(guard_home)
