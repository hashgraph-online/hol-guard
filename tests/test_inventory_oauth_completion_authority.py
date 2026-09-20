"""Every completed provider attempt retains the captured inventory authority."""

from __future__ import annotations

import io
import json
import socket
import time
import urllib.error
from email.message import Message
from pathlib import Path
from types import SimpleNamespace, TracebackType
from typing import Any

import pytest

from codex_plugin_scanner.guard import aibom_operation_authority as authority
from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial
from codex_plugin_scanner.guard.runtime import runner
from tests.test_aibom_operation_authority import _context, _operation, _selected
from tests.test_oauth_connection_authority import NOW, _store


@pytest.mark.parametrize(
    "mode", ["success", "nonce", "invalid-grant", "forbidden", "server", "network", "parse", "cleanup", "error-body"]
)
@pytest.mark.parametrize("changed", [False, True])
def test_provider_completion_rechecks_before_return_or_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, changed: bool
) -> None:
    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Unexpected raw network operation")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(runner, "_guard_runtime_was_upgraded", lambda: False)
    store, inputs = _store(tmp_path)
    context = _context(store, tmp_path)
    operation = _operation(store, context)
    before = store.get_oauth_local_credentials()
    budgets: list[int] = []
    checks: list[bool] = []
    waits: list[float] = []

    def mutate() -> None:
        if changed:
            store.set_sync_payload(authority.INVENTORY_CONTEXT_KEY, _selected(context), NOW)

    class Response(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            value = super().read(size)
            if mode in {"success", "parse", "error-body"} and len(budgets) == 1:
                mutate()
            return value

        def __exit__(
            self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
        ) -> None:
            super().__exit__(exc_type, exc, traceback)
            if mode == "cleanup":
                mutate()
                raise OSError("controlled response cleanup")

    def transport(request: Any, *, timeout: int) -> Response:
        assert timeout == 20
        budgets.append(timeout)
        if len(budgets) == 1 and mode in {"nonce", "invalid-grant", "forbidden", "server", "network", "error-body"}:
            if mode != "error-body":
                mutate()
            if mode == "network":
                raise OSError("controlled provider failure")
            headers = Message()
            if mode == "nonce":
                headers["DPoP-Nonce"] = "controlled-nonce"
            code = {"nonce": 401, "invalid-grant": 400, "forbidden": 403, "server": 500, "error-body": 403}[mode]
            error_name = (
                "invalid_grant" if mode == "invalid-grant" else "use_dpop_nonce" if mode == "nonce" else "access_denied"
            )
            raise urllib.error.HTTPError(
                request.full_url, code, "controlled", headers, Response(json.dumps({"error": error_name}).encode())
            )
        return Response(
            b"{malformed"
            if mode == "parse"
            else b'{"access_token":"synthetic-next","token_type":"DPoP","expires_in":300}'
        )

    def validate() -> None:
        checks.append(authority.aibom_operation_is_current(store, operation))
        authority.require_current_aibom_operation(store, operation)

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner, "time", SimpleNamespace(**{**vars(time), "sleep": waits.append}))
    key = GuardDpopKeyMaterial(
        algorithm="ES256",
        private_key_pem=inputs["dpop_private_key_pem"],
        public_jwk=inputs["dpop_public_jwk"],
        public_jwk_thumbprint=inputs["dpop_public_jwk_thumbprint"],
    )

    def call() -> dict[str, object]:
        return runner._refresh_guard_oauth_access_token(
            token_endpoint="https://hol.org/oauth/token",
            client_id=inputs["client_id"],
            refresh_token=inputs["refresh_token"],
            dpop_key_material=key,
            request_validator=validate,
            completion_validator=validate,
        )

    if changed:
        with pytest.raises(RuntimeError, match="context changed"):
            call()
        assert checks[-1] is False
        assert budgets == [20]
        assert waits == []
    elif mode in {"success", "nonce", "invalid-grant"}:
        assert call()["access_token"] == "synthetic-next"
        assert budgets == ([20] if mode == "success" else [20, 20])
        assert waits == ([0.75] if mode == "invalid-grant" else [])
        assert all(checks)
    else:
        with pytest.raises(ValueError if mode == "parse" else RuntimeError):
            call()
        assert budgets == [20]
        assert len(checks) >= 2 and all(checks)
        assert waits == []
    assert store.get_oauth_local_credentials() == before
    assert store.get_sync_payload("aibom_sync_summary") is None


@pytest.mark.parametrize("outcome", ["pre", "success", "http", "network"])
def test_local_validator_failure_never_becomes_a_provider_retry(monkeypatch: pytest.MonkeyPatch, outcome: str) -> None:
    from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair

    sentinel = TimeoutError("controlled local authority timeout")
    calls: list[int] = []
    waits: list[float] = []
    monkeypatch.setattr(runner, "_guard_runtime_was_upgraded", lambda: False)

    def transport(request: Any, *, timeout: int) -> io.BytesIO:
        calls.append(timeout)
        if outcome == "network":
            raise TimeoutError("controlled provider timeout")
        if outcome == "http":
            raise urllib.error.HTTPError(
                request.full_url, 400, "controlled", Message(), io.BytesIO(b'{"error":"invalid_grant"}')
            )
        return io.BytesIO(b'{"access_token":"synthetic-next","token_type":"DPoP","expires_in":300}')

    def before_or_success() -> None:
        if outcome == "pre" or (outcome == "success" and calls):
            raise sentinel

    def completed_error() -> None:
        raise sentinel

    monkeypatch.setattr(runner, "managed_urlopen", transport)
    monkeypatch.setattr(runner, "time", SimpleNamespace(**{**vars(time), "sleep": waits.append}))
    with pytest.raises(TimeoutError) as caught:
        runner._refresh_guard_oauth_access_token(
            token_endpoint="https://hol.org/oauth/token",
            client_id="guard-local-daemon",
            refresh_token="synthetic-refresh",
            dpop_key_material=generate_dpop_key_pair(),
            request_validator=before_or_success,
            completion_validator=completed_error,
        )
    assert caught.value is sentinel
    assert calls == ([] if outcome == "pre" else [20])
    assert waits == []
