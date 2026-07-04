"""Tests for browserless remote agent pairing."""

from __future__ import annotations

import base64
import json
import urllib.error
from io import BytesIO
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.remote_pair_flow import (
    build_remote_pair_status_payload,
    claim_remote_pairing_intent,
    is_remote_pairing_code_shape,
    normalize_remote_pairing_code,
    redact_remote_pairing_text,
    run_guard_remote_pair_command,
)
from codex_plugin_scanner.guard.store import GuardStore


def _fake_access_token(*, grant_id: str = "grant-1", machine_id: str = "machine-1", workspace_id: str = "ws-1") -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode("ascii")).decode("ascii").rstrip("=")
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "grant": {"grantId": grant_id},
                    "machine": {"machineId": machine_id},
                    "workspace": {"workspaceId": workspace_id},
                }
            ).encode("ascii")
        )
        .decode("ascii")
        .rstrip("=")
    )
    return f"{header}.{payload}.sig"


def _context(tmp_path: Path) -> HarnessContext:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    home_dir.mkdir()
    guard_home.mkdir()
    return HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)


def test_normalize_and_validate_pairing_code_shape() -> None:
    assert normalize_remote_pairing_code(" hlg-abc123 ") == "HLG-ABC123"
    assert is_remote_pairing_code_shape("HLG-ABCI12") is False
    assert is_remote_pairing_code_shape("HLG-7K3D29") is True
    assert is_remote_pairing_code_shape("HLG-F9Y38G8EYLPQ3JUV735Y") is True
    assert is_remote_pairing_code_shape("HLG-ABC") is False
    assert is_remote_pairing_code_shape("HLG-ABCD1234EFGH5678IJKL9012MNOP3456QRST7890") is False


def test_redact_remote_pairing_text_masks_code() -> None:
    redacted = redact_remote_pairing_text("Pairing failed for HLG-7K3D29 with token sk-live-secret")
    assert "HLG-7K3D29" not in redacted
    assert "HLG-******" in redacted
    assert "sk-live-secret" not in redacted
    long_redacted = redact_remote_pairing_text("Pairing failed for HLG-F9Y38G8EYLPQ3JUV735Y with token sk-live-secret")
    assert "HLG-F9Y38G8EYLPQ3JUV735Y" not in long_redacted
    assert "HLG-******" in long_redacted


def test_claim_remote_pairing_intent_posts_expected_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "intentId": "intent-1",
                    "state": "connected",
                    "tokens": {
                        "access_token": _fake_access_token(),
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "refresh_token": "refresh-token-value",
                    },
                }
            ).encode("utf-8")

    def fake_urlopen(request, timeout=30):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["headers"] = dict(request.header_items())
        return _Response()

    payload = claim_remote_pairing_intent(
        claim_url="https://hol.org/api/guard/remote-pairing/claim",
        pair_code="hlg-7k3d29",
        runtime="openclaw",
        installation_id="install-1",
        label="Hosted OpenClaw",
        public_dpop_jwk={"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
        capability_summary={"userSpaceInstall": True},
        urlopen=fake_urlopen,
    )

    assert payload["intentId"] == "intent-1"
    assert captured["url"] == "https://hol.org/api/guard/remote-pairing/claim"
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["pairCode"] == "HLG-7K3D29"
    assert body["runtime"] == "openclaw"
    assert body["installationId"] == "install-1"
    assert body["label"] == "Hosted OpenClaw"
    assert body["capabilitySummary"] == {"userSpaceInstall": True}


def test_claim_remote_pairing_intent_accepts_server_generated_long_code(monkeypatch: pytest.MonkeyPatch) -> None:
    """Server-generated pairing codes are 20 chars, not the legacy 6."""
    captured: dict[str, object] = {}

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(
                {
                    "intentId": "intent-2",
                    "state": "connected",
                    "tokens": {
                        "access_token": _fake_access_token(),
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "refresh_token": "refresh-token-value",
                    },
                }
            ).encode("utf-8")

    def fake_urlopen(request, timeout=30):
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return _Response()

    payload = claim_remote_pairing_intent(
        claim_url="https://hol.org/api/guard/remote-pairing/claim",
        pair_code="HLG-F9Y38G8EYLPQ3JUV735Y",
        runtime="hermes",
        installation_id="install-2",
        label="Hosted Hermes",
        public_dpop_jwk={"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
        urlopen=fake_urlopen,
    )

    assert payload["intentId"] == "intent-2"
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["pairCode"] == "HLG-F9Y38G8EYLPQ3JUV735Y"


def test_run_guard_remote_pair_command_persists_credentials_and_installs_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.os.geteuid",
        lambda: 1000,
        raising=False,
    )

    def fake_claim(**_kwargs: object) -> dict[str, object]:
        return {
            "intentId": "intent-42",
            "state": "connected",
            "tokens": {
                "access_token": _fake_access_token(),
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-token-value",
                "scope": "guard:runtime.sync guard:offline_access",
            },
        }

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.claim_remote_pairing_intent",
        fake_claim,
    )

    payload = run_guard_remote_pair_command(
        store=store,
        context=context,
        connect_url="https://hol.org/guard/connect",
        runtime="openclaw",
        pair_code="HLG-7K3D29",
        label="Hosted OpenClaw",
        no_root=True,
    )

    assert payload["status"] == "connected"
    assert payload["pairing"] == "connected"
    assert payload["runtime"] == "openclaw"
    assert payload["intent_id"] == "intent-42"
    assert "refresh_token" not in payload
    assert "pair_code" not in payload

    credentials = store.get_oauth_local_credentials()
    assert credentials is not None
    assert credentials.get("runtime_id") == "openclaw"
    assert credentials.get("client_id") == "guard-local-daemon"
    assert isinstance(credentials.get("refresh_token"), str)

    managed_install = store.get_managed_install("openclaw")
    assert managed_install is not None
    assert managed_install.get("active") is True


def test_run_guard_remote_pair_command_refuses_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.os.geteuid",
        lambda: 0,
        raising=False,
    )

    with pytest.raises(ValueError, match="refuses to run as root"):
        run_guard_remote_pair_command(
            store=store,
            context=context,
            connect_url="https://hol.org/guard/connect",
            runtime="hermes",
            pair_code="HLG-7K3D29",
            label="Hosted Hermes",
            no_root=True,
        )


def test_build_remote_pair_status_payload_reports_disconnected_by_default(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    payload = build_remote_pair_status_payload(store=store, context=context)
    assert payload["pairing"] == "disconnected"
    assert payload["protection"] == "unknown"


def test_run_guard_remote_pair_command_wraps_local_save_oserror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.os.geteuid",
        lambda: 1000,
        raising=False,
    )

    def fake_claim(**_kwargs: object) -> dict[str, object]:
        return {
            "intentId": "intent-99",
            "state": "connected",
            "tokens": {
                "access_token": _fake_access_token(),
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-token-value",
            },
        }

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.claim_remote_pairing_intent",
        fake_claim,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow._persist_oauth_local_credentials",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )

    with pytest.raises(RuntimeError, match="Generate a new pairing code"):
        run_guard_remote_pair_command(
            store=store,
            context=context,
            connect_url="https://hol.org/guard/connect",
            runtime="openclaw",
            pair_code="HLG-7K3D29",
            label="Hosted OpenClaw",
            no_root=True,
        )


def test_claim_remote_pairing_intent_surfaces_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(_request, timeout=30):
        raise urllib.error.HTTPError(
            url="https://hol.org/api/guard/remote-pairing/claim",
            code=409,
            msg="Conflict",
            hdrs=None,
            fp=BytesIO(
                json.dumps(
                    {
                        "code": "pairing_code_replayed",
                        "error": "Pairing code has already been used.",
                    }
                ).encode("utf-8")
            ),
        )

    with pytest.raises(RuntimeError, match="pairing_code_replayed"):
        claim_remote_pairing_intent(
            claim_url="https://hol.org/api/guard/remote-pairing/claim",
            pair_code="HLG-7K3D29",
            runtime="hermes",
            installation_id="install-1",
            label="Hosted Hermes",
            public_dpop_jwk={"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
            urlopen=fake_urlopen,
        )


def test_run_guard_remote_pair_command_syncs_runtime_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Remote-pair must push a runtime session to Guard Cloud so the protect dashboard shows it."""
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.os.geteuid",
        lambda: 1000,
        raising=False,
    )

    def fake_claim(**_kwargs: object) -> dict[str, object]:
        return {
            "intentId": "intent-42",
            "state": "connected",
            "tokens": {
                "access_token": _fake_access_token(),
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-token-value",
                "scope": "guard:runtime.sync guard:offline_access",
            },
        }

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.claim_remote_pairing_intent",
        fake_claim,
    )

    captured_sessions: list[dict[str, object]] = []

    def fake_sync(store_arg, *, session):
        captured_sessions.append(dict(session))
        return {"synced_at": "2025-01-01T00:00:00Z", "runtime_session_id": "rt-1"}

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.sync_runtime_session",
        fake_sync,
    )

    payload = run_guard_remote_pair_command(
        store=store,
        context=context,
        connect_url="https://hol.org/guard/connect",
        runtime="hermes",
        pair_code="HLG-7K3D29",
        label="Hosted Hermes",
        no_root=True,
    )

    assert payload["status"] == "connected"
    assert len(captured_sessions) == 1
    session = captured_sessions[0]
    assert session["harness"] == "hermes"
    assert session["status"] == "active"
    assert session["surface"] == "remote-pair"
    assert session["client_title"] == "Hosted Hermes"


def test_run_guard_remote_pair_command_swallows_sync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A transient sync failure must not roll back a successful pairing."""
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.os.geteuid",
        lambda: 1000,
        raising=False,
    )

    def fake_claim(**_kwargs: object) -> dict[str, object]:
        return {
            "intentId": "intent-42",
            "state": "connected",
            "tokens": {
                "access_token": _fake_access_token(),
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-token-value",
                "scope": "guard:runtime.sync guard:offline_access",
            },
        }

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.claim_remote_pairing_intent",
        fake_claim,
    )

    def fake_sync(_store, *, _session):
        raise RuntimeError("network is down")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.sync_runtime_session",
        fake_sync,
    )

    payload = run_guard_remote_pair_command(
        store=store,
        context=context,
        connect_url="https://hol.org/guard/connect",
        runtime="hermes",
        pair_code="HLG-7K3D29",
        label="Hosted Hermes",
        no_root=True,
    )

    # Pairing still succeeds despite sync failure
    assert payload["status"] == "connected"
    assert payload["pairing"] == "connected"
