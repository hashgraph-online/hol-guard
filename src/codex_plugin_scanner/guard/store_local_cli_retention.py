"""Forget and age out observed custom extensions that the user never enrolled."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from .runtime.time_support import parse_utc_timestamp

LOCAL_CLI_OBSERVATION_RETENTION_DAYS = 30


class LocalCliForgetError(ValueError):
    """Raised when an observed record cannot be forgotten."""


class LocalCliReplaySkippedError(Exception):
    """Raised when a history entry may not restore a forgotten or expired identity."""


class StoreLocalCliRetentionMixin:
    if TYPE_CHECKING:

        def _native_store_call(
            self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
        ) -> Any: ...

    def forget_local_cli_observation(self, cli_id: str, *, identity_hash: str) -> None:
        """Delete one un-enrolled observed record and its inventory rows.

        History replay skips the identity until it runs or is configured again.
        """

        try:
            _ = self._native_store_call(
                "forget_local_cli_observation",
                {"cli_id": cli_id, "identity_hash": identity_hash, "clock": utc_now_iso()},
            )
        except ValueError as error:
            raise LocalCliForgetError(str(error)) from None

    def local_cli_replay_allowed(self, identity_hash: str, seen_at: str, *, now: str | None = None) -> bool:
        """Return whether a history entry may restore or refresh this identity."""

        return bool(
            self._native_store_call(
                "local_cli_replay_allowed",
                {"identity_hash": identity_hash, "seen_at": seen_at, "now": now, "clock": utc_now_iso()},
            )
        )

    def prune_inactive_local_cli_observations(
        self,
        *,
        now: datetime | None = None,
        retention_days: int = LOCAL_CLI_OBSERVATION_RETENTION_DAYS,
        throttle: bool = False,
    ) -> list[str]:
        """Delete un-enrolled observed records not seen within the retention window."""

        pruned = self._native_store_call(
            "prune_inactive_local_cli_observations",
            {
                "now": None if now is None else now.isoformat(),
                "retention_days": retention_days,
                "throttle": throttle,
                "clock": utc_now_iso(),
            },
        )
        return [str(cli_id) for cli_id in pruned]


def later_timestamp(current: object, candidate: str) -> str:
    """Return the later of the stored and the replayed timestamp."""

    stored = parse_utc_timestamp(current)
    replayed = parse_utc_timestamp(candidate)
    if isinstance(current, str) and stored is not None and (replayed is None or replayed <= stored):
        return current
    return candidate


def mark_shared_enrolled_servers(items: Iterable[dict[str, object]], enrolled_ids: Mapping[str, object]) -> None:
    """Flag un-enrolled MCP records kept because an enrolled record shares their server."""

    listed = list(items)
    enrolled_servers = {
        item.get("server_identity_hash") or item.get("identity_hash")
        for item in listed
        if item.get("cli_id") in enrolled_ids and item.get("surface") == "mcp"
    }
    enrolled_servers.discard(None)
    for item in listed:
        if (
            item.get("surface") == "mcp"
            and item.get("cli_id") not in enrolled_ids
            and item.get("server_identity_hash") in enrolled_servers
        ):
            item["shares_enrolled_server"] = True


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
