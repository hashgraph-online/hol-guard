"""A package protect rebuild reuses the command text the first build redacted.

The final rebuild runs after a saved approval may have been claimed. The argv
is the same, so the redacted text is too; asking the resident again would only
add a request that can fail after the claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import local_supply_chain, native_policy_snapshot_publisher


@dataclass(frozen=True)
class _Intent:
    redacted_command: str
    routine_local_runner: bool = False


class _ArtifactBuiltError(Exception):
    pass


def _stub_build(monkeypatch: pytest.MonkeyPatch, seen: list[str], redactions: list[list[str]]) -> None:
    monkeypatch.setattr(native_policy_snapshot_publisher, "provision_native_verifier_key_for_store", lambda store: None)
    monkeypatch.setattr(local_supply_chain, "_package_manager_launch_environment", lambda *args, **kwargs: {})
    monkeypatch.setattr(local_supply_chain, "_parse_package_intent_native", lambda *args, **kwargs: _Intent(""))

    def redact(command: list[str], *, guard_home: Path) -> str:
        redactions.append(list(command))
        return "npm install left-pad"

    def artifact(_harness: str, intent: _Intent, **_kwargs: object) -> None:
        seen.append(intent.redacted_command)
        raise _ArtifactBuiltError

    monkeypatch.setattr(local_supply_chain, "redacted_command_text", redact)
    monkeypatch.setattr(local_supply_chain, "build_package_request_artifact", artifact)


def _build(tmp_path: Path, redacted_command: str | None = None) -> None:
    local_supply_chain._build_package_protect_authority(
        command=["npm", "install", "left-pad"],
        store=SimpleNamespace(guard_home=tmp_path / "guard"),
        workspace_dir=tmp_path,
        now="now",
        config=None,
        additional_current_action=None,
        additional_policy_context=None,
        redacted_command=redacted_command,
    )


def test_a_rebuild_reuses_the_redacted_text(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: list[str] = []
    redactions: list[list[str]] = []
    _stub_build(monkeypatch, seen, redactions)
    with pytest.raises(_ArtifactBuiltError):
        _build(tmp_path)
    with pytest.raises(_ArtifactBuiltError):
        _build(tmp_path, redacted_command="npm install left-pad")
    assert redactions == [["npm", "install", "left-pad"]]
    assert seen == ["npm install left-pad", "npm install left-pad"]
