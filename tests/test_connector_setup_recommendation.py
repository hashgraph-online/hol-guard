"""The connector setup hint recorded at queue time and the live recommendation built from it."""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Iterable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import approval_connector_recommendation as recommendation
from codex_plugin_scanner.guard.daemon.approval_connector_recommendation import (
    CONNECTOR_RECOMMENDATION_SCHEMA,
    build_approval_connector_recommendation,
    safe_connector_recommendation,
)
from codex_plugin_scanner.guard.local_cli_hook import SetupConnector
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_allow_hint import (
    CONNECTOR_SETUP_HINT_SCHEMA,
    connector_setup_deep_link,
    validated_connector_setup_hint,
    validated_extension_allow_hint,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.store import GuardStore

_HASH = "a" * 64
_OTHER_HASH = "b" * 64
_CLI_ID = "local-cli.lanectl-0123abcd"
_GROUP = f"connector:{_HASH}:0123456789abcdef"
_CONNECTOR = SetupConnector(cli_id=_CLI_ID, identity_hash=_HASH, name="lanectl", surface="cli", queue_group_id=_GROUP)


def _hint(**overrides: object) -> dict[str, object]:
    hint = validated_connector_setup_hint(
        {
            "schema": CONNECTOR_SETUP_HINT_SCHEMA,
            "identity_hash": _HASH,
            "cli_id": _CLI_ID,
            "surface": "cli",
            "display_name": "lanectl",
            "deep_link": connector_setup_deep_link(_CLI_ID),
            "card_recommendation": {"state": "allowed", "capabilities": []},
            "risk_classes": [],
        }
    )
    assert hint is not None
    return {**hint, **overrides}


def _snapshot(health: AuthorityHealth = AuthorityHealth.PROTECTED) -> ExtensionControlRuntimeSnapshot:
    return ExtensionControlRuntimeSnapshot(
        health=health,
        revision=7,
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        effective_digest="e" * 64,
        layers=(),
    )


class _Store:
    """Read-only fake: any write raises, so a recommendation can never set a connector up."""

    def __init__(self, siblings: dict[str, dict[str, object]] | None = None, *, other_rows: int = 0) -> None:
        self.siblings = siblings or {}
        # Newer pending rows from other groups, listed before this connector's rows.
        self.rows = [{"request_id": f"other-{n}", "queue_group_id": f"other:{n}"} for n in range(other_rows)]
        self.rows += [{"request_id": key, "queue_group_id": _GROUP} for key in self.siblings]

    def list_approval_request_page(
        self, *, status: str, limit: int, cursor: str | None, include_totals: bool
    ) -> dict[str, object]:
        assert status == "pending" and not include_totals
        start = int(cursor or 0)
        end = start + limit
        return {"items": self.rows[start:end], "next_cursor": str(end) if end < len(self.rows) else None}

    def get_approval_extension_allow_hint(self, request_id: str) -> object:
        return self.siblings.get(request_id)

    def __getattr__(self, name: str) -> object:
        if name.startswith(("upsert_", "set_", "write_", "apply_", "record_", "resolve_")):
            raise AssertionError(f"recommendation must not write: {name}")
        raise AttributeError(name)


# What the resident answers for a caution query; its own tests pin the set.
_RESIDENT_CAUTION = frozenset(
    {
        "credential_exfiltration",
        "data_flow_exfiltration",
        "destructive",
        "dynamic_execution",
        "encoded_execution",
        "financial_transaction",
        "local_secret_read",
        "policy_bypass",
    }
)


@pytest.fixture(autouse=True)
def _resident_caution(monkeypatch: pytest.MonkeyPatch) -> list[tuple[frozenset[str], Path | None]]:
    """Answer caution queries as the resident would, recording what was asked and of which home."""

    asked: list[tuple[frozenset[str], Path | None]] = []

    def answer(risk_classes: Iterable[str], *, guard_home: Path | None = None) -> frozenset[str]:
        classes = frozenset(risk_classes)
        asked.append((classes, guard_home))
        return classes & _RESIDENT_CAUTION

    monkeypatch.setattr(recommendation, "native_caution_risk_classes", answer)
    return asked


def _items(
    monkeypatch: pytest.MonkeyPatch,
    *,
    state: str = "unset",
    identity_hash: str = _HASH,
    stale: bool = False,
    surface: str = "cli",
) -> None:
    item = {"cli_id": _CLI_ID, "identity_hash": identity_hash, "surface": surface, "state": state, "stale": stale}
    monkeypatch.setattr(recommendation, "listed_public_items", lambda _store: [item])


def _approval(hint: object, *, status: str = "pending", group: str = _GROUP) -> dict[str, object]:
    return {"request_id": "req-1", "status": status, "queue_group_id": group, "extension_allow_hint": hint}


def _build(approval: dict[str, object], store: object | None = None, **kwargs: object) -> dict[str, object] | None:
    return build_approval_connector_recommendation(
        approval,
        store=store or _Store(),
        snapshot=kwargs.pop("snapshot", _snapshot()),  # type: ignore[arg-type]
        approval_gate_configured=kwargs.pop("gate", True),  # type: ignore[arg-type]
    )


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


def test_a_pending_delete_keeps_caution_through_the_full_path(monkeypatch: pytest.MonkeyPatch) -> None:
    _items(monkeypatch)
    # The resident records ``destructive`` for a destructive shell rule it observed.
    hint = _hint(risk_classes=["destructive", "destructive_shell", "network_egress"])

    result = _build(_approval(hint))

    assert result is not None
    assert result["caution"] is True


def test_available_while_the_connector_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    _items(monkeypatch)

    result = _build(_approval(_hint()))

    assert result is not None
    assert result["schema"] == CONNECTOR_RECOMMENDATION_SCHEMA
    assert result["status"] == "available"
    assert result["deep_link"] == f"/extensions/local-cli/{_CLI_ID}"
    assert result["caution"] is False


@pytest.mark.parametrize("state", ["allowed", "blocked", "forgotten"])
def test_gone_once_the_connector_has_a_decision(monkeypatch: pytest.MonkeyPatch, state: str) -> None:
    _items(monkeypatch, state=state)

    assert _build(_approval(_hint())) is None


def test_offered_again_when_the_allow_covers_an_earlier_version_of_the_file(monkeypatch: pytest.MonkeyPatch) -> None:
    # The script was allowed, then edited: the grant names the old file and no
    # longer applies, so the held calls wait on a setup of this version.
    _items(monkeypatch, state="allowed", stale=True)

    result = _build(_approval(_hint()))

    assert result is not None
    assert result["status"] == "available"
    assert result["setup_request"]["state"] == "allowed"  # type: ignore[index]
    assert result["setup_request"]["connector_group_request_id"] == "req-1"  # type: ignore[index]


def test_an_earlier_block_stays_a_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    _items(monkeypatch, state="blocked", stale=True)

    assert _build(_approval(_hint())) is None


@pytest.mark.parametrize("surface", ["mcp", "package-scripts"])
def test_a_changed_server_or_package_keeps_its_full_review(monkeypatch: pytest.MonkeyPatch, surface: str) -> None:
    _items(monkeypatch, state="allowed", stale=True, surface=surface)

    assert _build(_approval(_hint(surface=surface))) is None


def test_gone_when_the_stored_identity_changed(monkeypatch: pytest.MonkeyPatch) -> None:
    _items(monkeypatch, identity_hash=_OTHER_HASH)

    assert _build(_approval(_hint())) is None


@pytest.mark.parametrize(
    "approval",
    [
        _approval(_hint(), status="approved"),
        _approval(_hint(), group=f"connector:{_OTHER_HASH}:0123456789abcdef"),
        _approval(_hint(), group="tool:abc"),
        _approval({"schema": "guard.extension-allow-hint.v1"}),
        _approval(None),
    ],
)
def test_not_offered_for_rows_outside_the_group(monkeypatch: pytest.MonkeyPatch, approval: dict[str, object]) -> None:
    _items(monkeypatch)

    assert _build(approval) is None


def test_authority_and_gate_gate_the_one_tap(monkeypatch: pytest.MonkeyPatch) -> None:
    _items(monkeypatch)

    unhealthy = _build(_approval(_hint()), snapshot=_snapshot(AuthorityHealth.TAMPERED))
    no_gate = _build(_approval(_hint()), gate=False)

    assert unhealthy is not None and unhealthy["status"] == "authority_unavailable"
    assert no_gate is not None and no_gate["status"] == "approval_gate_required"
    assert no_gate["approval_gate_configured"] is False


def test_caution_when_any_grouped_row_carries_a_caution_class(monkeypatch: pytest.MonkeyPatch) -> None:
    _items(monkeypatch)
    store = _Store({"req-2": _hint(risk_classes=["destructive"]), "req-3": _hint(identity_hash=_OTHER_HASH)})

    result = _build(_approval(_hint()), store)

    assert result is not None
    assert result["caution"] is True
    assert result["caution_risk_classes"] == ["destructive"]


def test_the_resident_of_the_stores_home_decides_the_caution(
    monkeypatch: pytest.MonkeyPatch, _resident_caution: list[tuple[frozenset[str], Path | None]], tmp_path: Path
) -> None:
    _items(monkeypatch)
    store = _Store({"req-2": _hint(risk_classes=["destructive"])})
    store.guard_home = tmp_path  # type: ignore[attr-defined]

    result = _build(_approval(_hint()), store)

    assert result is not None and result["caution_risk_classes"] == ["destructive"]
    assert _resident_caution == [(frozenset({"destructive"}), tmp_path)]


def test_no_resident_answer_means_no_recommendation_never_no_caution(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.daemon.approval_extension_recommendation import (
        NativeApprovalExtensionRecommendationError,
    )

    _items(monkeypatch)

    def unavailable(_risk_classes: Iterable[str], *, guard_home: Path | None = None) -> frozenset[str]:
        raise NativeApprovalExtensionRecommendationError("native_approval_extension_recommendation_unavailable")

    monkeypatch.setattr(recommendation, "native_caution_risk_classes", unavailable)
    store = _Store({"req-2": _hint(risk_classes=["destructive"])})

    assert (
        safe_connector_recommendation(
            _approval(_hint()), store=store, snapshot=_snapshot(), approval_gate_configured=lambda: True
        )
        is None
    )


def test_caution_reads_grouped_rows_past_the_first_page(monkeypatch: pytest.MonkeyPatch) -> None:
    _items(monkeypatch)
    store = _Store({"req-2": _hint(risk_classes=["destructive"])}, other_rows=450)

    result = _build(_approval(_hint()), store)

    assert result is not None and result["caution_risk_classes"] == ["destructive"]


def test_caution_when_the_group_scan_stops_early(monkeypatch: pytest.MonkeyPatch) -> None:
    _items(monkeypatch)
    monkeypatch.setattr(recommendation, "_MAX_GROUP_SCAN_ROWS", 200)
    store = _Store({"req-2": _hint()}, other_rows=450)

    result = _build(_approval(_hint()), store)

    # Unread rows are never treated as safe.
    assert result is not None and result["caution"] is True and result["caution_risk_classes"] == []


def test_a_failed_read_never_fails_the_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_store: object) -> list[dict[str, object]]:
        raise OSError("store unavailable")

    monkeypatch.setattr(recommendation, "listed_public_items", broken)

    assert (
        safe_connector_recommendation(
            _approval(_hint()), store=_Store(), snapshot=_snapshot(), approval_gate_configured=lambda: True
        )
        is None
    )


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


def test_daemon_request_detail_carries_the_live_recommendation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _items(monkeypatch)
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request(), "2026-10-17T10:00:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/requests/req-connector",
            headers={"X-Guard-Token": daemon._server.auth_token},
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            detail = json.loads(response.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert "extension_allow_hint" not in detail
    assert "extension_recommendation" not in detail
    connector = detail["connector_recommendation"]
    assert connector["schema"] == CONNECTOR_RECOMMENDATION_SCHEMA
    assert connector["cli_id"] == _CLI_ID
    assert connector["status"] in {"available", "authority_unavailable", "approval_gate_required"}
