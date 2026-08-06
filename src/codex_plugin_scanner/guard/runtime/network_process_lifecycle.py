"""Lifecycle tracking for network-mediated process trees."""

from __future__ import annotations

from codex_plugin_scanner.guard.runtime.network_policy_contract import ProcessTreeIdentity


class ProcessTreeLifecycle:
    def __init__(self) -> None:
        self._active: dict[tuple[str, str], ProcessTreeIdentity] = {}

    def start(self, identity: ProcessTreeIdentity) -> None:
        key = (identity.installation_id, identity.session_id)
        existing = self._active.get(key)
        if existing is not None and existing != identity:
            raise RuntimeError("process-tree session identity changed while active")
        self._active[key] = identity

    def resolve(self, installation_id: str, session_id: str) -> ProcessTreeIdentity | None:
        return self._active.get((installation_id, session_id))

    def stop(self, identity: ProcessTreeIdentity) -> bool:
        key = (identity.installation_id, identity.session_id)
        if self._active.get(key) != identity:
            return False
        del self._active[key]
        return True

    def active(self) -> tuple[ProcessTreeIdentity, ...]:
        return tuple(
            sorted(
                self._active.values(),
                key=lambda item: (item.installation_id, item.session_id),
            )
        )
