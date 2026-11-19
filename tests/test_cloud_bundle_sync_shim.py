"""The Python side of the native ``cloud-bundle-sync`` command."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import codex_hook_launch_runtime, native_runtime
from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.cloud_bundle_sync import (
    CLOUD_BUNDLE_SYNC_COMMAND,
    CLOUD_BUNDLE_SYNC_FEATURE,
    cloud_bundle_sync,
)


def _status(tmp_path: Path, features: tuple[str, ...]) -> SimpleNamespace:
    return SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "hol-guard-runtime"),
        capabilities=SimpleNamespace(features=features),
    )


def _answer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, response: object, *, returncode: int = 0
) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []
    monkeypatch.setattr(
        native_runtime, "native_runtime_status", lambda: _status(tmp_path, (CLOUD_BUNDLE_SYNC_FEATURE,))
    )

    def run(argv: tuple[str, ...], **options: object) -> SimpleNamespace:
        assert argv[1:] == (CLOUD_BUNDLE_SYNC_COMMAND, "--stdin")
        sent.append(json.loads(str(options["input_text"])))
        return SimpleNamespace(
            returncode=returncode,
            timed_out=False,
            output_limit_exceeded=False,
            containment_failed=False,
            stdout=json.dumps(response),
        )

    monkeypatch.setattr(codex_hook_launch_runtime, "run_isolated_hook_process", run)
    return sent


def test_runtime_without_the_command_asks_for_an_update(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: _status(tmp_path, ()))
    with pytest.raises(RuntimeError, match="hol-guard update"):
        cloud_bundle_sync(tmp_path, "supply_chain")


def test_result_and_request_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _answer(monkeypatch, tmp_path, {"ok": True, "result": {"status": "synced"}})
    supplied = {"sync_url": "http://127.0.0.1:9/api/guard/receipts/sync"}

    assert cloud_bundle_sync(tmp_path, "network", auth_context=supplied) == {"status": "synced"}
    assert sent == [{"action": "network", "authContext": supplied, "guardHome": str(tmp_path)}]


def test_resolved_sign_in_key_is_sent_as_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _answer(monkeypatch, tmp_path, {"ok": True, "result": {}})
    key = GuardDpopKeyMaterial(
        algorithm="ES256",
        private_key_pem="pem",
        public_jwk={"kty": "EC"},
        public_jwk_thumbprint="thumb",
    )
    supplied = {"sync_url": "http://127.0.0.1:9/api/guard/receipts/sync", "dpop_key_material": key}

    cloud_bundle_sync(tmp_path, "supply_chain", auth_context=supplied)
    assert sent[0]["authContext"] == {
        "sync_url": "http://127.0.0.1:9/api/guard/receipts/sync",
        "dpop_key_material": {
            "algorithm": "ES256",
            "private_key_pem": "pem",
            "public_jwk": {"kty": "EC"},
            "public_jwk_thumbprint": "thumb",
        },
    }


@pytest.mark.parametrize(
    ("outcome", "error_class"),
    [
        ("not_configured", runner.GuardSyncNotConfiguredError),
        ("auth_expired", runner.GuardSyncAuthorizationExpiredError),
        ("not_available", runner.GuardSyncNotAvailableError),
        ("failed", RuntimeError),
    ],
)
def test_failure_outcome_raises_the_matching_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: str, error_class: type[Exception]
) -> None:
    _answer(monkeypatch, tmp_path, {"ok": False, "outcome": outcome, "error": "stopped", "retryable": True})
    with pytest.raises(error_class, match="stopped") as raised:
        cloud_bundle_sync(tmp_path, "supply_chain")
    if outcome == "not_available":
        assert raised.value.retryable is True  # type: ignore[attr-defined]


def test_unreadable_answer_is_a_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _answer(monkeypatch, tmp_path, {"ok": True}, returncode=2)
    with pytest.raises(RuntimeError, match="did not answer"):
        cloud_bundle_sync(tmp_path, "refresh")
