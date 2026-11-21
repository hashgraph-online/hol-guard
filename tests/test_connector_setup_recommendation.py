"""Connector setup hint storage and wire shape."""

from __future__ import annotations

import json
import os
import select
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime.extension_allow_hint import (
    CONNECTOR_SETUP_HINT_SCHEMA,
    connector_setup_deep_link,
    validated_connector_setup_hint,
    validated_extension_allow_hint,
)
from codex_plugin_scanner.guard.store import GuardStore

_HASH = "a" * 64
_CLI_ID = "local-cli.lanectl-0123abcd"
_GROUP = f"connector:{_HASH}:0123456789abcdef"


# A literal hint, so collecting the parametrized cases below never needs the
# native runtime; the first test proves it passes the shape check.
_RAW_HINT: dict[str, object] = {
    "schema": CONNECTOR_SETUP_HINT_SCHEMA,
    "identity_hash": _HASH,
    "cli_id": _CLI_ID,
    "surface": "cli",
    "display_name": "lanectl",
    "deep_link": connector_setup_deep_link(_CLI_ID),
    "card_recommendation": {"state": "allowed", "capabilities": []},
    "risk_classes": [],
}


def _hint(**overrides: object) -> dict[str, object]:
    return {**_RAW_HINT, **overrides}


def test_the_fixture_hint_passes_the_shape_check() -> None:
    assert validated_connector_setup_hint(_RAW_HINT) == _RAW_HINT


def test_hint_names_the_connector_with_a_host_free_link() -> None:
    hint = _hint()

    assert hint["schema"] == CONNECTOR_SETUP_HINT_SCHEMA
    assert hint["deep_link"] == f"/extensions/local-cli/{_CLI_ID}"
    assert hint["card_recommendation"] == {"state": "allowed", "capabilities": []}
    assert validated_connector_setup_hint(hint) == hint
    # The extension recommendation never mistakes a connector hint for its own.
    assert validated_extension_allow_hint(hint) is None


@pytest.mark.parametrize(
    "override",
    [
        {"identity_hash": "not-a-hash"},
        {"cli_id": "../etc"},
        {"surface": "remote"},
        {"display_name": "lanectl; rm -rf /"},
        {"deep_link": "https://mcp.example.test/extensions/local-cli/x"},
        {"card_recommendation": {"state": "blocked", "capabilities": []}},
        {"risk_classes": ["Not A Class"]},
    ],
)
def test_malformed_hints_are_dropped(override: dict[str, object]) -> None:
    assert validated_connector_setup_hint(_hint(**override)) is None


def _request() -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id="req-connector",
        harness="codex",
        artifact_id="codex:native-pretool:Bash",
        artifact_name="Bash",
        artifact_hash="binding",
        policy_action="review",
        recommended_scope="artifact",
        changed_fields=("native_pre_tool",),
        source_scope="project",
        config_path="/workspace",
        review_command="hol-guard approvals approve req-connector",
        approval_url="http://127.0.0.1/requests/req-connector",
        launch_target="lanectl status",
        queue_group_id=_GROUP,
        extension_allow_hint=_hint(),
    )


def test_store_keeps_the_connector_hint_private(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request(), "2026-10-17T10:00:00+00:00")

    assert store.get_approval_extension_allow_hint("req-connector") == _hint()
    listed = next(item for item in store.list_approval_requests() if item["request_id"] == "req-connector")
    assert listed["queue_group_id"] == _GROUP
    assert listed.get("extension_allow_hint") is None


@pytest.mark.skipif(os.name != "posix", reason="piped daemon readiness uses POSIX select")
@pytest.mark.usefixtures("native_context_digest")
def test_local_daemon_details_return_connector_advice(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.cli.daemon_serve import launch_configuration
    from codex_plugin_scanner.guard.native_daemon_client import load_running_guard_surface_daemon_client
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity

    from .mcp_policy_native_fixture import _FIXTURE_KEYS, admit_mcp_policy_home

    # A short path also fits the resident's Unix socket on macOS.
    with tempfile.TemporaryDirectory(prefix="connector-detail-", dir="/tmp") as directory:
        home = Path(directory).resolve()
        guard = home / ".hol-guard"
        monkeypatch.setenv("HOL_GUARD_HOME", str(guard))
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        material = (b"\x27" * 32, "connector-detail-fixture-key")
        monkeypatch.setattr(GuardStore, "_policy_integrity_secret_material", lambda *_a, **_k: material)
        store = GuardStore(guard)
        provision_native_verifier_key_for_store(store)
        _FIXTURE_KEYS[guard] = material[0]
        child = None
        try:
            timestamp = "2026-10-17T10:00:00Z"
            store.record_local_cli_observation(
                UnlistedCliIdentity(_CLI_ID, "lanectl", "executable", _HASH, "lanectl status"), seen_at=timestamp
            )
            request = _request()
            store.add_approval_request(request, timestamp)
            store.add_approval_request(
                replace(
                    request,
                    request_id="req-sibling",
                    artifact_hash="sibling-binding",
                    queue_group_id=f"connector:{_HASH}:9988776655443322",
                    extension_allow_hint=_hint(risk_classes=["destructive"]),
                ),
                timestamp,
            )
            admit_mcp_policy_home(guard)
            config = launch_configuration(guard, 0, user_home=home)
            config["workers"] = False
            config["idle_timeout_seconds"] = None
            with tempfile.TemporaryFile() as log:
                child = subprocess.Popen(
                    [
                        os.environ["HOL_GUARD_NATIVE_BINARY"],
                        "daemon-serve",
                        "--guard-home",
                        str(guard),
                        "--port",
                        "0",
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=log,
                )
                assert child.stdin is not None and child.stdout is not None
                child.stdin.write(json.dumps(config).encode() + b"\n")
                child.stdin.flush()
                ready, _, _ = select.select([child.stdout], [], [], 12)
                assert ready and child.stdout.readline(), f"native daemon did not become ready, exit={child.poll()}"

                client = load_running_guard_surface_daemon_client(guard, identity_timeout=3)
                detail = client._get("/v1/requests/req-connector", timeout=5)
                advice = detail.get("connector_recommendation")
                assert isinstance(advice, dict)
                assert advice["status"] == "authority_unavailable"
                assert advice["caution_risk_classes"] == ["destructive"]
                assert advice["setup_href"] == f"/extensions/local-cli/{_CLI_ID}?setup=req-connector&identity={_HASH}"
                assert "extension_allow_hint" not in detail
                assert store.read_local_cli_grant(_CLI_ID) is None
        finally:
            if child is not None:
                if child.poll() is None:
                    child.terminate()
                try:
                    child.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.communicate(timeout=5)
            close_native_residents(guard)
            _FIXTURE_KEYS.pop(guard, None)
