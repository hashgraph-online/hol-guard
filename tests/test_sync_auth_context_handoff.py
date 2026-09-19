"""Only the observed context from the current call scope can be reused."""

from __future__ import annotations

from contextvars import copy_context
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial
from codex_plugin_scanner.guard.oauth_connection_authority import OAuthConnectionSnapshot
from codex_plugin_scanner.guard.runtime import runner, sync_auth_handoff
from codex_plugin_scanner.guard.runtime.sync_auth_handoff import hold_sync_auth_handoff
from codex_plugin_scanner.guard.store import GuardStore
from tests.support.optional_uploads import seed_optional_upload_source


def _resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[GuardStore, dict[str, object], OAuthConnectionSnapshot]:
    store = GuardStore(tmp_path / "guard", allow_system_keyring=False)
    seed_optional_upload_source(store, monkeypatch)
    observed: list[OAuthConnectionSnapshot] = []
    context = runner._resolve_guard_sync_auth_context(store, connection_observer=observed.append)
    assert len(observed) == 1
    assert set(context) == {"sync_url", "access_token", "dpop_key_material"}
    return store, context, observed[0]


def _key(context: dict[str, object]) -> GuardDpopKeyMaterial:
    key = context["dpop_key_material"]
    assert isinstance(key, GuardDpopKeyMaterial)
    return key


def _observe_resolutions(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    calls: list[bool] = []
    resolve = runner._resolve_guard_sync_auth_context

    def observed(*args, **kwargs):
        calls.append(True)
        return resolve(*args, **kwargs)

    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", observed)
    return calls


def test_exact_observed_context_reuses_current_authority(tmp_path, monkeypatch):
    store, context, connection = _resolution(tmp_path, monkeypatch)
    calls = _observe_resolutions(monkeypatch)
    with hold_sync_auth_handoff(store, context, connection):
        resolved, source = runner._resolve_optional_upload_auth_context(store, context)
    assert resolved is context
    assert source is connection
    assert calls == []
    assert set(resolved) == {"sync_url", "access_token", "dpop_key_material"}


@pytest.mark.parametrize(
    "mutation", ["copy", "token", "token-subclass", "url", "key", "key-shape", "algorithm", "field"]
)
def test_changed_context_requires_a_new_successful_resolution(tmp_path, monkeypatch, mutation):
    store, context, connection = _resolution(tmp_path, monkeypatch)
    calls = _observe_resolutions(monkeypatch)
    with hold_sync_auth_handoff(store, context, connection):
        supplied = context
        if mutation == "copy":
            supplied = dict(context)
        elif mutation == "token":
            supplied["access_token"] = "unbound-token"
        elif mutation == "token-subclass":

            class EqualValue(str):
                def __eq__(self, _other):
                    return True

            supplied["access_token"] = EqualValue("unbound-token")
        elif mutation == "url":
            supplied["sync_url"] = "https://untrusted.example/receipts"
        elif mutation == "key":
            _key(supplied).public_jwk["kid"] = "changed-key"
        elif mutation == "key-shape":
            cast(dict[str, object], _key(supplied).public_jwk)["kid"] = {"mutable": True}
        elif mutation == "algorithm":
            key = _key(supplied)
            supplied["dpop_key_material"] = replace(key, algorithm="RS256" if key.algorithm != "RS256" else "ES256")
        else:
            supplied["connection"] = connection
        resolved, source = runner._resolve_optional_upload_auth_context(store, supplied)
    assert calls == [True]
    assert resolved is not supplied
    assert resolved["access_token"] == "synthetic-access"
    assert resolved["sync_url"] == "https://hol.org/api/guard/receipts/sync"
    assert source is not None and source.same_authority(connection)
    assert set(resolved) == {"sync_url", "access_token", "dpop_key_material"}


@pytest.mark.parametrize("mutation", ["replace", "revoke"])
def test_handoff_cannot_outlive_durable_authority(tmp_path, monkeypatch, mutation):
    store, context, connection = _resolution(tmp_path, monkeypatch)
    calls = _observe_resolutions(monkeypatch)
    with hold_sync_auth_handoff(store, context, connection):
        if mutation == "replace":
            seed_optional_upload_source(store, monkeypatch, access_token="replacement-token")
        else:
            store.clear_oauth_local_credentials()
        with pytest.raises(RuntimeError):
            runner._resolve_optional_upload_auth_context(store, context)
    assert calls == []


def test_equal_source_in_another_store_cannot_reuse_a_handoff(tmp_path, monkeypatch):
    store, context, connection = _resolution(tmp_path, monkeypatch)
    other = GuardStore(store.guard_home, allow_system_keyring=False)
    calls = _observe_resolutions(monkeypatch)
    with hold_sync_auth_handoff(store, context, connection):
        resolved, source = runner._resolve_optional_upload_auth_context(other, context)
    assert calls == [True]
    assert resolved is not context
    assert source is not None and source.same_authority(connection)


def test_exception_resets_the_scoped_handoff(tmp_path, monkeypatch):
    store, context, connection = _resolution(tmp_path, monkeypatch)
    calls = _observe_resolutions(monkeypatch)
    with pytest.raises(LookupError), hold_sync_auth_handoff(store, context, connection):
        raise LookupError("controlled")
    resolved, source = runner._resolve_optional_upload_auth_context(store, context)
    assert calls == [True]
    assert resolved is not context
    assert source is not None


def test_unbound_nested_scope_shadows_then_restores_the_outer_handoff(tmp_path, monkeypatch):
    store, context, connection = _resolution(tmp_path, monkeypatch)
    calls = _observe_resolutions(monkeypatch)
    override = {"sync_url": context["sync_url"], "access_token": "plain-override", "dpop_key_material": None}
    with hold_sync_auth_handoff(store, context, connection):
        with monkeypatch.context() as nested:
            nested.setattr(runner, "_test_sync_auth_context_override", override)
            with hold_sync_auth_handoff(store, override, None):
                resolved, source = runner._resolve_optional_upload_auth_context(store, context)
                assert resolved == override
                assert resolved is not context
                assert source is None
        restored, restored_source = runner._resolve_optional_upload_auth_context(store, context)
    assert calls == [True]
    assert restored is context
    assert restored_source is connection


def test_invalid_nested_context_shadows_the_outer_handoff(tmp_path, monkeypatch):
    store, context, connection = _resolution(tmp_path, monkeypatch)
    calls = _observe_resolutions(monkeypatch)
    invalid = {"sync_url": context["sync_url"], "access_token": "plain", "dpop_key_material": None}
    with hold_sync_auth_handoff(store, context, connection), hold_sync_auth_handoff(store, invalid, connection):
        resolved, source = runner._resolve_optional_upload_auth_context(store, context)
        assert resolved is not context
        assert source is not None
    assert calls == [True]


def test_copied_execution_context_cannot_extend_handoff_lifetime(tmp_path, monkeypatch):
    store, context, connection = _resolution(tmp_path, monkeypatch)
    calls = _observe_resolutions(monkeypatch)
    with hold_sync_auth_handoff(store, context, connection):
        inherited = copy_context()
    resolved, source = inherited.run(runner._resolve_optional_upload_auth_context, store, context)
    assert calls == [True]
    assert resolved is not context
    assert source is not None


def test_handoff_representation_does_not_include_credentials(tmp_path, monkeypatch):
    store, context, connection = _resolution(tmp_path, monkeypatch)
    with hold_sync_auth_handoff(store, context, connection):
        rendered = repr(sync_auth_handoff._HANDOFF.get())
    assert "synthetic-access" not in rendered
    assert "PRIVATE KEY" not in rendered
    assert "synthetic-refresh" not in rendered
