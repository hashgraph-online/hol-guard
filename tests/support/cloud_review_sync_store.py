"""Minimal GuardStore stand-in for Cloud Review sync worker tests."""

from __future__ import annotations

from pathlib import Path

from tests.support.policy_trust_rows import trust_rows_from_payloads


class Store:
    """Minimal GuardStore stand-in for event and worker contracts."""

    guard_source = "default"

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.path = guard_home / "guard.db"
        self._payloads: dict[str, object] = {}

    def get_sync_payload(self, key: str) -> object | None:
        return self._payloads.get(key)

    def policy_bundle_trust_rows(self, *, keys_only: bool = False):
        del keys_only
        return trust_rows_from_payloads(self.get_sync_payload, None)

    def record_review_verification_keyring(self, keys, now: str) -> None:
        self.set_sync_payload("guard_review_verification_keyring", [dict(key) for key in keys], now)

    def get_review_event_oauth_binding(self) -> None:
        return None

    def set_sync_payload(self, key: str, payload: object, now: str) -> None:
        self._payloads[key] = payload

    def exact_cloud_review_state(self) -> dict[str, object]:
        return {
            "capability": self._payloads.get("guard_exact_cloud_review_capability"),
            "revocation": self._payloads.get("guard_exact_cloud_review_revocation"),
        }

    def transition_cloud_review_sync_state(
        self, state_key: str, transition: str, *, now: str, **detail: object
    ) -> dict[str, object]:
        """Mirror the native ``failed`` step, the only one the worker loop takes."""

        assert transition == "failed"
        stored = self._payloads.get(state_key)
        state = dict(stored) if isinstance(stored, dict) else {}
        state.update({"state": "error", "last_error": detail["error"], "last_error_at": now})
        previous = state.get("last_error_code")
        auth_codes = {"cloud_auth_expired", "cloud_connect_required"}
        if not (detail.get("keep_auth_code") and previous in auth_codes):
            state["last_error_code"] = detail["error_code"]
        self._payloads[state_key] = state
        return dict(state)

    def get_cloud_sync_profile(self) -> dict[str, str]:
        return {
            "auth_mode": "oauth",
            "sync_url": "https://hol.test/api/guard/receipts/sync",
            "workspace_id": "workspace-1",
        }

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object]:
        return {
            "grant_id": "grant-1",
            "machine_id": "machine-1",
            "runtime_id": "runtime-1",
            "workspace_id": "workspace-1",
        }

    def get_or_create_installation_id(self) -> str:
        return "22222222-2222-4222-8222-222222222222"

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object]:
        return {"operation_id": request_id, "metadata": {"workspace_path": "/workspace/repo"}}
