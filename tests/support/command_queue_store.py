"""In-memory Guard store double for the command queue tests."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from tests.guard_review_signing_helpers import review_trusted_keyring_payload


class FakeStore:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self.payloads: dict[str, dict[str, object] | list[object]] = {
            "policy_bundle_keyring": review_trusted_keyring_payload(),
        }

    @contextmanager
    def connection_scope(self) -> Iterator[None]:
        yield

    def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
        # The real store answers with no key until one is created; the resident
        # reads that as ``local_signing_key_unavailable`` rather than an error.
        del create
        return None, None

    def get_sync_payload(self, key: str) -> dict[str, object] | list[object] | None:
        return self.payloads.get(key)

    def set_sync_payload(self, key: str, payload: dict[str, object] | list[object], now: str) -> None:
        self.payloads[key] = payload

    def record_command_queue_lease_limit(self, state_key: str, limit: int, *, now: str) -> bool:
        # The native store merges the limit alone into the stored row.
        stored = self.payloads.get(state_key)
        row = dict(stored) if isinstance(stored, dict) else {}
        if row.get("exact_lease_batch_limit") == limit:
            return False
        row["exact_lease_batch_limit"] = limit
        self.payloads[state_key] = row
        return True

    def get_cloud_sync_profile(self) -> dict[str, str]:
        return {
            "auth_mode": "oauth",
            "sync_url": "https://hol.test/api/guard/receipts/sync",
            "workspace_id": "workspace-1",
        }

    def get_oauth_local_credentials(self, *, allow_primary: bool = False) -> dict[str, object]:
        return {
            "device_id": "machine-1",
            "grant_id": "grant-1",
            "machine_id": "machine-1",
            "runtime_id": "runtime-1",
            "workspace_id": "workspace-1",
        }

    def get_or_create_installation_id(self) -> str:
        return "22222222-2222-4222-8222-222222222222"

    def get_device_metadata(self) -> dict[str, object]:
        return {"installation_id": self.get_or_create_installation_id()}

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object]:
        return {
            "operation_id": request_id,
            "metadata": {"workspace_path": "/workspace/repo"},
        }

    def get_approval_request(self, request_id: str) -> dict[str, object] | None:
        del request_id
        return None

    def list_policy_decisions(self, harness: str | None = None) -> list[dict[str, object]]:
        del harness
        return []

    def replace_remote_policies(
        self,
        decisions,
        generated_at: str,
        *,
        remote_write_authorized: bool = False,
    ) -> None:
        del decisions, generated_at, remote_write_authorized

    def list_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        limit: int | None = 50,
        cursor: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, object]]:
        del status, harness, limit, cursor, search
        return []
