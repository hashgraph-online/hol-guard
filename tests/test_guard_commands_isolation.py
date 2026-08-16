from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import cast

import pytest

from codex_plugin_scanner.guard.cli.commands_isolation import (
    IsolationStatusSnapshot,
    explain_isolation_payload,
    isolation_status_payload,
    providers_payload,
    verify_isolation_payload,
)

_SENSITIVE_TOKENS = (
    "path",
    "file_path",
    "command_content",
    "secrets",
    "password",
    "token",
    "key",
    "credential",
    "secret",
)


def _strip_keys(payload: dict[str, object]) -> dict[str, object]:
    return {k: v for k, v in payload.items() if not any(tok in k.lower() for tok in _SENSITIVE_TOKENS)}


# ---------------------------------------------------------------------------
# IsolationStatusSnapshot
# ---------------------------------------------------------------------------


class TestIsolationStatusSnapshot:
    def test_defaults(self) -> None:
        snap = IsolationStatusSnapshot(backend="x", backend_available=True, health_state="healthy")
        assert snap.backend == "x"
        assert snap.backend_available is True
        assert snap.health_state == "healthy"
        assert snap.enforced_guarantees == ()
        assert snap.absent_guarantees == ()
        assert snap.trust == "unverified"

    def test_frozen_prevents_mutation(self) -> None:
        from dataclasses import FrozenInstanceError

        snap = IsolationStatusSnapshot(backend="b", backend_available=False, health_state="h")
        with pytest.raises(FrozenInstanceError):
            snap.backend = "changed"

    def test_equality(self) -> None:
        a = IsolationStatusSnapshot(backend="b", backend_available=True, health_state="healthy")
        b = IsolationStatusSnapshot(backend="b", backend_available=True, health_state="healthy")
        c = IsolationStatusSnapshot(backend="x", backend_available=True, health_state="healthy")
        assert a == b
        assert a != c


# ---------------------------------------------------------------------------
# isolation_status_payload
# ---------------------------------------------------------------------------


class TestIsolationStatusPayload:
    def test_none_snapshot_defaults(self) -> None:
        result = isolation_status_payload()
        result_casted: Mapping[str, object] = result
        assert result_casted["command"] == "isolation.status"
        assert result_casted["status"] == "degraded"
        assert result_casted["provider"] == "none"
        assert result_casted["backend_available"] is False
        assert result_casted["health_state"] == "unconfigured"
        assert result_casted["enforced_guarantees"] == []
        assert result_casted["absent_guarantees"] == []
        assert result_casted["trust"] == "unverified"

    def test_healthy_snapshot(self) -> None:
        snap = IsolationStatusSnapshot(
            backend="sandbox",
            backend_available=True,
            health_state="healthy",
            enforced_guarantees=("network", "mcp"),
            absent_guarantees=(),
            trust="verified",
        )
        result = isolation_status_payload(snapshot=snap)
        result_casted: Mapping[str, object] = result
        assert result_casted["status"] == "ok"
        assert result_casted["provider"] == "sandbox"
        assert result_casted["backend_available"] is True
        assert result_casted["health_state"] == "healthy"
        assert list(cast(Sequence[str], result_casted["enforced_guarantees"])) == ["network", "mcp"]
        assert list(cast(Sequence[str], result_casted["absent_guarantees"])) == []
        assert result_casted["trust"] == "verified"

    def test_degraded_snapshot(self) -> None:
        snap = IsolationStatusSnapshot(
            backend="none",
            backend_available=False,
            health_state="degraded",
        )
        result = isolation_status_payload(snapshot=snap)
        result_casted: Mapping[str, object] = result
        assert result_casted["status"] == "degraded"

    def test_strips_sensitive_keys(self) -> None:
        snap = IsolationStatusSnapshot(
            backend="sandbox",
            backend_available=True,
            health_state="healthy",
        )
        result = isolation_status_payload(snapshot=snap)
        result["secrets"] = "leaked"
        result["file_path"] = "/etc/passwd"
        cleaned = _strip_keys(result)
        assert "secrets" not in cleaned
        assert "file_path" not in cleaned
        assert "command" in cleaned


# ---------------------------------------------------------------------------
# providers_payload
# ---------------------------------------------------------------------------


class TestProvidersPayload:
    def test_none_snapshots(self) -> None:
        result = providers_payload()
        result_casted: Mapping[str, object] = result
        assert result_casted["command"] == "isolation.providers"
        assert result_casted["provider_count"] == 0
        assert result_casted["providers"] == []

    def test_empty_list(self) -> None:
        result = providers_payload(snapshots=[])
        result_casted: Mapping[str, object] = result
        assert result_casted["provider_count"] == 0
        assert result_casted["providers"] == []

    def test_single_snapshot(self) -> None:
        snap = IsolationStatusSnapshot(
            backend="sandbox",
            backend_available=True,
            health_state="healthy",
        )
        result = providers_payload(snapshots=[snap])
        result_casted: Mapping[str, object] = result
        assert result_casted["provider_count"] == 1
        providers = cast(Sequence[Mapping[str, object]], result_casted["providers"])
        entry = providers[0]
        assert entry["id"] == "sandbox"
        assert entry["provider"] == "sandbox"
        assert entry["available"] is True
        assert entry["health_state"] == "healthy"

    def test_multiple_snapshots(self) -> None:
        snaps = [
            IsolationStatusSnapshot(backend="a", backend_available=True, health_state="healthy"),
            IsolationStatusSnapshot(backend="b", backend_available=False, health_state="degraded"),
        ]
        result = providers_payload(snapshots=snaps)
        result_casted: Mapping[str, object] = result
        assert result_casted["provider_count"] == 2
        providers = cast(Sequence[Mapping[str, object]], result_casted["providers"])
        assert len(providers) == 2
        assert providers[0]["id"] == "a"
        assert providers[1]["id"] == "b"

    def test_empty_guarantees(self) -> None:
        snap = IsolationStatusSnapshot(
            backend="x",
            backend_available=True,
            health_state="healthy",
            enforced_guarantees=(),
            absent_guarantees=(),
        )
        result = providers_payload(snapshots=[snap])
        result_casted: Mapping[str, object] = result
        providers = cast(Sequence[Mapping[str, object]], result_casted["providers"])
        entry = providers[0]
        assert entry["enforced_guarantees"] == []
        assert entry["absent_guarantees"] == []


# ---------------------------------------------------------------------------
# explain_isolation_payload
# ---------------------------------------------------------------------------


class TestExplainIsolationPayload:
    def test_full_map(self) -> None:
        result = explain_isolation_payload()
        result_casted: Mapping[str, object] = result
        assert result_casted["command"] == "isolation.explain"
        assert result_casted["mode"] == "description"
        explanations = cast(Mapping[str, Mapping[str, str]], result_casted["explanations"])
        assert len(explanations) == 5
        assert "sandbox" in explanations
        assert "contained" in explanations
        assert "network" in explanations
        assert "mcp" in explanations
        assert "sandbox-required" in explanations

    def test_single_target(self) -> None:
        result = explain_isolation_payload(target="sandbox")
        result_casted: Mapping[str, object] = result
        explanations = cast(Mapping[str, Mapping[str, str]], result_casted["explanations"])
        assert len(explanations) == 1
        assert "sandbox" in explanations
        info = explanations["sandbox"]
        assert info["kind"] == "sandbox"
        assert info["label"] == "Process sandbox isolation"
        assert "description" in info
        assert "evidence" in info

    def test_unknown_target(self) -> None:
        result = explain_isolation_payload(target="nonexistent")
        result_casted: Mapping[str, object] = result
        explanations = cast(Mapping[str, Mapping[str, str]], result_casted["explanations"])
        assert len(explanations) == 1
        info = explanations["nonexistent"]
        assert info["kind"] == "nonexistent"
        assert info["description"] == "Unknown guarantee kind."

    def test_whitespace_target(self) -> None:
        result = explain_isolation_payload(target="   ")
        result_casted: Mapping[str, object] = result
        explanations = cast(Mapping[str, Mapping[str, str]], result_casted["explanations"])
        assert len(explanations) == 5

    def test_none_target(self) -> None:
        result = explain_isolation_payload(target=None)
        result_casted: Mapping[str, object] = result
        explanations = cast(Mapping[str, Mapping[str, str]], result_casted["explanations"])
        assert len(explanations) == 5

    def test_explanation_contains_description(self) -> None:
        result = explain_isolation_payload(target="contained")
        result_casted: Mapping[str, object] = result
        explanations = cast(Mapping[str, Mapping[str, str]], result_casted["explanations"])
        info = explanations["contained"]
        assert "file-system writes" in info["description"]
        assert "project-approved directories" in info["description"]

    def test_explanation_contains_evidence(self) -> None:
        result = explain_isolation_payload(target="sandbox")
        result_casted: Mapping[str, object] = result
        explanations = cast(Mapping[str, Mapping[str, str]], result_casted["explanations"])
        info = explanations["sandbox"]
        assert "sandbox boundary" in info["evidence"]


# ---------------------------------------------------------------------------
# verify_isolation_payload
# ---------------------------------------------------------------------------


class TestVerifyIsolationPayload:
    def test_none_snapshot_defaults(self) -> None:
        result = verify_isolation_payload()
        result_casted: Mapping[str, object] = result
        assert result_casted["command"] == "isolation.verify"
        assert result_casted["verified"] is False
        assert result_casted["health"] == "unconfigured"
        assert result_casted["available"] is False
        assert result_casted["enforced_guarantees"] == []
        assert result_casted["absent_guarantees"] == []
        warnings = cast(Sequence[str], result_casted["warnings"])
        assert any("No isolation backend" in warning for warning in warnings)

    def test_healthy_snapshot_verified(self) -> None:
        snap = IsolationStatusSnapshot(
            backend="sandbox",
            backend_available=True,
            health_state="healthy",
            enforced_guarantees=("network",),
            absent_guarantees=(),
        )
        result = verify_isolation_payload(snapshot=snap)
        result_casted: Mapping[str, object] = result
        assert result_casted["verified"] is True
        warnings = cast(Sequence[str], result_casted["warnings"])
        assert warnings == []

    def test_healthy_ok_variant(self) -> None:
        snap = IsolationStatusSnapshot(
            backend="x",
            backend_available=True,
            health_state="ok",
            absent_guarantees=(),
        )
        result = verify_isolation_payload(snapshot=snap)
        result_casted: Mapping[str, object] = result
        assert result_casted["verified"] is True

    def test_healthy_passing_variant(self) -> None:
        snap = IsolationStatusSnapshot(
            backend="x",
            backend_available=True,
            health_state="passing",
            absent_guarantees=(),
        )
        result = verify_isolation_payload(snapshot=snap)
        result_casted: Mapping[str, object] = result
        assert result_casted["verified"] is True

    def test_unhealthy_snapshot(self) -> None:
        snap = IsolationStatusSnapshot(
            backend="x",
            backend_available=True,
            health_state="degraded",
            absent_guarantees=(),
        )
        result = verify_isolation_payload(snapshot=snap)
        result_casted: Mapping[str, object] = result
        assert result_casted["verified"] is False
        warnings = cast(Sequence[str], result_casted["warnings"])
        assert len(warnings) == 1
        assert "degraded" in warnings[0]

    def test_available_but_absent_guarantees(self) -> None:
        snap = IsolationStatusSnapshot(
            backend="x",
            backend_available=True,
            health_state="healthy",
            absent_guarantees=("mcp", "network"),
        )
        result = verify_isolation_payload(snapshot=snap)
        result_casted: Mapping[str, object] = result
        assert result_casted["verified"] is False
        warnings = cast(Sequence[str], result_casted["warnings"])
        assert len(warnings) == 1
        assert "mcp" in warnings[0]
        assert "network" in warnings[0]

    def test_unavailable_with_absent(self) -> None:
        snap = IsolationStatusSnapshot(
            backend="x",
            backend_available=False,
            health_state="degraded",
            absent_guarantees=("mcp",),
        )
        result = verify_isolation_payload(snapshot=snap)
        result_casted: Mapping[str, object] = result
        assert result_casted["verified"] is False
        warnings = cast(Sequence[str], result_casted["warnings"])
        assert len(warnings) == 3

    def test_strips_sensitive_keys(self) -> None:
        snap = IsolationStatusSnapshot(
            backend="sandbox",
            backend_available=True,
            health_state="healthy",
        )
        result = verify_isolation_payload(snapshot=snap)
        result["secret"] = "leaked"
        cleaned = _strip_keys(result)
        assert "secret" not in cleaned
        assert "command" in cleaned


# ---------------------------------------------------------------------------
# __all__
# ---------------------------------------------------------------------------


class TestAllExports:
    def test_all_exports(self) -> None:
        from codex_plugin_scanner.guard.cli import commands_isolation

        expected = {
            "IsolationStatusSnapshot",
            "explain_isolation_payload",
            "isolation_status_payload",
            "providers_payload",
            "verify_isolation_payload",
        }
        assert set(commands_isolation.__all__) == expected

    def test_all_callable(self) -> None:
        from codex_plugin_scanner.guard.cli import commands_isolation

        for name in commands_isolation.__all__:
            obj: object = getattr(commands_isolation, name)
            if name != "IsolationStatusSnapshot":
                assert callable(obj), f"{name} should be callable"
