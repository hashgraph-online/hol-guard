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


def test_redact_remote_pairing_text_masks_code() -> None:
    redacted = redact_remote_pairing_text("Pairing failed for HLG-7K3D29 with token sk-live-secret")
    assert "HLG-7K3D29" not in redacted
    assert "HLG-******" in redacted
    assert "sk-live-secret" not in redacted


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


# --- HAO038-HAO044: Local remote-pair proof tests ---


def test_hao038_claim_hermes_pairing_saves_runtime_id_and_label(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HAO038: claiming Hermes pairing saves credentials with runtime id and label."""
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.os.geteuid",
        lambda: 1000,
        raising=False,
    )

    def fake_claim(**_kwargs: object) -> dict[str, object]:
        return {
            "intentId": "intent-hermes-001",
            "state": "connected",
            "tokens": {
                "access_token": _fake_access_token(grant_id="grant-hermes", machine_id="machine-hermes"),
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-hermes",
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
        runtime="hermes",
        pair_code="HLG-HERMS1",
        label="Hermes Prod",
        no_root=True,
    )

    assert payload["runtime"] == "hermes"
    assert payload["runtime_label"] == "Hermes Prod"
    assert payload["grant_id"] == "grant-hermes"
    assert payload["status"] == "connected"

    credentials = store.get_oauth_local_credentials()
    assert credentials is not None
    assert credentials.get("runtime_id") == "hermes"
    assert credentials.get("runtime_label") == "Hermes Prod"


def test_hao039_claim_openclaw_pairing_saves_runtime_id_and_label(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HAO039: claiming OpenClaw pairing saves credentials with runtime id and label."""
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.os.geteuid",
        lambda: 1000,
        raising=False,
    )

    def fake_claim(**_kwargs: object) -> dict[str, object]:
        return {
            "intentId": "intent-openclaw-001",
            "state": "connected",
            "tokens": {
                "access_token": _fake_access_token(grant_id="grant-openclaw", machine_id="machine-openclaw"),
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-openclaw",
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
        pair_code="HLG-OCLAW1",
        label="OpenClaw Gateway",
        no_root=True,
    )

    assert payload["runtime"] == "openclaw"
    assert payload["runtime_label"] == "OpenClaw Gateway"
    assert payload["grant_id"] == "grant-openclaw"
    assert payload["status"] == "connected"

    credentials = store.get_oauth_local_credentials()
    assert credentials is not None
    assert credentials.get("runtime_id") == "openclaw"
    assert credentials.get("runtime_label") == "OpenClaw Gateway"


def test_hao040_verify_distinguishes_connected_from_paired_not_protected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HAO040: first-sync proof with --verify distinguishes connected from paired_not_protected."""
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.os.geteuid",
        lambda: 1000,
        raising=False,
    )

    def fake_claim(**_kwargs: object) -> dict[str, object]:
        return {
            "intentId": "intent-verify-001",
            "state": "connected",
            "tokens": {
                "access_token": _fake_access_token(),
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-verify",
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
        runtime="hermes",
        pair_code="HLG-VERIFY1",
        label="Verify Test",
        no_root=True,
    )

    # After claim, protection status should be either "active" or "paired_not_protected"
    assert payload["protection"] in ("active", "paired_not_protected")
    # If paired_not_protected, protection_reason should explain what's wrong
    if payload["protection"] == "paired_not_protected":
        assert payload.get("protection_reason") is not None


def test_hao041_status_payload_returns_runtime_label_protection_grant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HAO041: remote-pair status --json returns runtime, label, protection, grant, status command."""
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)

    # First, set up credentials via a fake claim
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.os.geteuid",
        lambda: 1000,
        raising=False,
    )

    def fake_claim(**_kwargs: object) -> dict[str, object]:
        return {
            "intentId": "intent-status-001",
            "state": "connected",
            "tokens": {
                "access_token": _fake_access_token(grant_id="grant-status"),
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "refresh-status",
            },
        }

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.claim_remote_pairing_intent",
        fake_claim,
    )

    run_guard_remote_pair_command(
        store=store,
        context=context,
        connect_url="https://hol.org/guard/connect",
        runtime="openclaw",
        pair_code="HLG-STATS1",
        label="Status Test Agent",
        no_root=True,
    )

    # Now check status payload
    payload = build_remote_pair_status_payload(store=store, context=context)

    assert payload["runtime"] == "openclaw"
    assert payload["runtime_label"] == "Status Test Agent"
    assert payload["protection"] in ("active", "paired_not_protected", "unknown")
    assert payload["grant_id"] == "grant-status"
    assert payload["remote_pair_status_command"] == "hol-guard remote-pair status"
    assert "pair_code" not in payload
    assert "access_token" not in payload
    assert "refresh_token" not in payload


def test_hao042_runtime_mismatch_error_preserves_error_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HAO042: remote-pair failure preserves actionable error code for runtime mismatch."""
    error_body = json.dumps({
        "code": "runtime_mismatch",
        "error": "This pairing code was created for Hermes, not OpenClaw.",
    }).encode("utf-8")

    def fake_urlopen(_request, timeout=30):
        raise urllib.error.HTTPError(
            url="https://hol.org/api/guard/remote-pairing/claim",
            code=409,
            msg="Conflict",
            hdrs=None,
            fp=BytesIO(error_body),
        )

    with pytest.raises(RuntimeError, match="runtime_mismatch"):
        claim_remote_pairing_intent(
            claim_url="https://hol.org/api/guard/remote-pairing/claim",
            pair_code="HLG-ABCDEF",
            runtime="openclaw",
            installation_id="install-1",
            label="Test",
            public_dpop_jwk={"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
            urlopen=fake_urlopen,
        )


def test_hao043_expired_code_error_preserves_error_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HAO043: remote-pair failure preserves actionable error code for expired code."""
    error_body = json.dumps({
        "code": "pairing_code_expired",
        "error": "This pairing code has expired. Create a new code.",
    }).encode("utf-8")

    def fake_urlopen(_request, timeout=30):
        raise urllib.error.HTTPError(
            url="https://hol.org/api/guard/remote-pairing/claim",
            code=410,
            msg="Gone",
            hdrs=None,
            fp=BytesIO(error_body),
        )

    with pytest.raises(RuntimeError, match="pairing_code_expired"):
        claim_remote_pairing_intent(
            claim_url="https://hol.org/api/guard/remote-pairing/claim",
            pair_code="HLG-EXPXYZ",
            runtime="hermes",
            installation_id="install-1",
            label="Test",
            public_dpop_jwk={"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
            urlopen=fake_urlopen,
        )


def test_hao044_already_claimed_error_preserves_error_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HAO044: remote-pair failure preserves actionable error code for already claimed code."""
    error_body = json.dumps({
        "code": "pairing_code_replayed",
        "error": "This pairing code was already used.",
    }).encode("utf-8")

    def fake_urlopen(_request, timeout=30):
        raise urllib.error.HTTPError(
            url="https://hol.org/api/guard/remote-pairing/claim",
            code=409,
            msg="Conflict",
            hdrs=None,
            fp=BytesIO(error_body),
        )

    with pytest.raises(RuntimeError, match="pairing_code_replayed"):
        claim_remote_pairing_intent(
            claim_url="https://hol.org/api/guard/remote-pairing/claim",
            pair_code="HLG-USEDXY",
            runtime="openclaw",
            installation_id="install-1",
            label="Test",
            public_dpop_jwk={"kty": "EC", "crv": "P-256", "x": "abc", "y": "def"},
            urlopen=fake_urlopen,
        )


def test_hao045_claim_response_never_logs_pairing_code_or_oauth_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HAO045: claim response payload never includes pairing code or OAuth tokens."""
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.remote_pair_flow.os.geteuid",
        lambda: 1000,
        raising=False,
    )

    def fake_claim(**_kwargs: object) -> dict[str, object]:
        return {
            "intentId": "intent-redact-001",
            "state": "connected",
            "tokens": {
                "access_token": _fake_access_token(),
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "super-secret-refresh-token",
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
        runtime="hermes",
        pair_code="HLG-REDACT",
        label="Redaction Test",
        no_root=True,
    )

    # The sanitized payload must not contain secrets
    assert "pair_code" not in payload
    assert "pairCode" not in payload
    assert "access_token" not in payload
    assert "refresh_token" not in payload
    # The pairing code used must not appear anywhere in the payload
    payload_str = json.dumps(payload, default=str)
    assert "HLG-REDACT" not in payload_str
    assert "super-secret-refresh-token" not in payload_str
