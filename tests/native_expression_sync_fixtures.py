"""Genuine signed HTTP fixture; only the independent donor stages directly.

The fresh target receives policy through ordinary sync. HTTP and the initial
trust-anchor enrollment are synthetic; no service or OAuth acceptance is implied.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus, native_runtime_status
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_expression_resident_fixtures import (
    WORKSPACE_ID,
    ExpressionSource,
    prepare_expression_store,
    publish_expression_source,
)
from tests.support.network import stub_authenticated_urlopen

_AUTH: dict[str, object] = {
    "sync_url": "https://hol.org/api/guard/receipts/sync",
    "access_token": "synthetic-test-token",
    "dpop_key_material": None,
}


@dataclass
class SignedSyncFixture:
    store: GuardStore
    workspace: Path
    bundle: dict[str, Any]
    source: ExpressionSource
    response: dict[str, object]
    requests: list[dict[str, object]]

    def sync(self) -> dict[str, object]:
        return runner.sync_receipts(self.store, auth_context=_AUTH)


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> bool:
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


def signed_sync_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SignedSyncFixture:
    store, workspace = prepare_expression_store(tmp_path / "target")
    # Reuse the genuine signature builder in a separate donor. Its staging is
    # not target admission, and no donor policy/cache/ACK state is copied.
    donor, _ = prepare_expression_store(tmp_path / "donor")
    source = publish_expression_source(donor, workspace, block_lifetime_seconds=300)
    bundle = donor.get_sync_payload("policy_bundle")
    keyring = donor.get_sync_payload("policy_bundle_keyring")
    assert isinstance(bundle, dict) and isinstance(keyring, dict)
    now = datetime.now(timezone.utc).isoformat()
    credentials = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(credentials, dict)
    store.set_sync_payload("oauth_local_credentials", {**credentials, "workspace_id": WORKSPACE_ID}, now)
    store.set_sync_payload("policy_bundle_keyring", keyring, now)
    fixture = SignedSyncFixture(store, workspace, bundle, source, {"policyBundle": bundle}, [])

    def exchange(request: Any, timeout: object = None) -> _Response:
        if request.full_url.endswith("/api/guard/receipts/sync"):
            fixture.requests.append(json.loads(request.data))
            return _Response({"syncedAt": now, "receiptsStored": 0, **fixture.response})
        return _Response({"accepted": 0, "rejected": 0, "statuses": []})

    stub_authenticated_urlopen(monkeypatch, exchange)
    return fixture


def ordinary_sync_test_status() -> NativeRuntimeStatus:
    """Require auto on an exact real binary; stage only the capability names."""
    assert os.environ.get("HOL_GUARD_NATIVE") == "auto", "ordinary resident proof requires explicit auto mode"
    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    assert binary, "ordinary resident proof requires an exact selected native artifact"
    status = native_runtime_status()
    assert status.mode == "auto" and status.available and status.compatible, status.reason
    assert status.identity is not None and status.capabilities is not None
    assert status.identity.path.resolve() == Path(binary).resolve()
    assert hashlib.sha256(Path(binary).read_bytes()).hexdigest() == status.identity.sha256
    source_root = Path(__file__).resolve().parents[1]
    source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source_root, text=True).strip()
    assert status.capabilities.build_sha == source_sha, "native artifact must match exact checkout"
    return replace(
        status,
        capabilities=replace(
            status.capabilities,
            features=tuple(
                sorted(
                    {
                        *status.capabilities.features,
                        *SCOPED_PUBLISH_FEATURES,
                        "policy-command-expressions-v1",
                    }
                )
            ),
        ),
    )
