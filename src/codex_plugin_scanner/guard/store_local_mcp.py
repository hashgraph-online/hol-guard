"""This-device MCP custom-extension grant lookup."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from .runtime.composio_contract import composio_tool_role
from .runtime.composio_discovery import ComposioActionSchema
from .runtime.composio_workflows import ComposioWorkflowProposal
from .runtime.local_cli_identity import UnlistedCliIdentity
from .runtime.observed_mcp_tools import ObservedMcpTool, observed_mcp_tool
from .store_local_cli_retention import LocalCliReplaySkippedError, utc_now_iso
from .store_local_cli_schema import ensure_local_cli_schema
from .store_mcp_provider_catalog import describe_provider_actions

if TYPE_CHECKING:
    from .store import GuardStore

_OBSERVED_MCP_ACTIONS = frozenset({"allow", "review", "block"})


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

    def observed_mcp_history(self, *, limit: int) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        """Return the paused requests and receipts the connector scan reads.

        The resident projects each row to the tool label, the harness and the
        history timestamps, which is all the scan parses. Asking for whole
        approval rows and whole receipts encoded a store with a few hundred of
        either past the native response cap, and the refresh then failed
        instead of discovering connectors.
        """

        page = self._native_store_call("observed_mcp_history", {"limit": limit})
        if not isinstance(page, dict):
            raise sqlite3.DatabaseError("native_observed_mcp_history_invalid")
        batches: list[list[dict[str, object]]] = []
        for key in ("approvals", "receipts"):
            rows = cast(dict[str, object], page).get(key)
            if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                raise sqlite3.DatabaseError("native_observed_mcp_history_invalid")
            batches.append(cast("list[dict[str, object]]", rows))
        return batches[0], batches[1]

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

    def record_composio_discovery(
        self,
        source: ObservedMcpTool,
        actions: tuple[ComposioActionSchema, ...],
        *,
        seen_at: str,
        proposals: tuple[ComposioWorkflowProposal, ...] = (),
    ) -> str:
        if observed_mcp_tool(source.harness, source.qualified_name) != source or (
            composio_tool_role(source.qualified_name) != "discovery"
        ):
            raise ValueError("invalid provider discovery source")
        server = source.server_identity
        cli_id = self.ensure_local_mcp_observation(
            source.identity,
            seen_at=seen_at,
            server_identity_hash=server.identity_hash,
            server_command=server.command,
            server_args_hash=server.args_hash,
            source_label=f"{source.harness.title()} · observed provider metadata",
        )
        args: dict[str, object] = {
            "cli_id": cli_id,
            "identity_hash": server.identity_hash,
            "server_command": server.command,
            "source_tool": source.qualified_name,
            "seen_at": seen_at,
            "actions": [
                {
                    "toolkit": action.toolkit,
                    "tool_slug": action.tool_slug,
                    "description": action.description,
                    "input_schema": action.input_schema,
                    "full_schema": bool(action.full_schema),
                }
                for action in actions
            ],
            "proposals": [
                {
                    "primary": list(proposal.primary),
                    "supporting": list(proposal.supporting),
                    "guidance_present": proposal.guidance_present,
                }
                for proposal in proposals
            ],
        }
        result = self._native_store_call("record_composio_discovery", args)
        if isinstance(result, dict) and result.get("need_barrier") is True:
            # This batch moves the provider authority, which the native policy
            # barrier has to bracket. The resident cannot reach the publishers
            # that barrier notifies, so it wrote nothing and asked for one:
            # close it and run the same write inside it.
            with _notify_legacy_mcp_denial(cast("GuardStore", self).guard_home):
                self._native_store_call("record_composio_discovery", {**args, "barrier_closed": True})
        return cli_id

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
