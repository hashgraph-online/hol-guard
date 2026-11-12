"""Unit contracts binding blocked-extension denials to their reviewed adapters."""

from __future__ import annotations

import pytest

from ci.gauntlet.catalog import Scenario, load_catalog, load_catalog_data
from ci.gauntlet.evidence import assess_case
from ci.gauntlet.extension_adapters import EXTENSION_ADAPTERS, ExtensionAdapter, extension_adapter
from tests.test_guard_gauntlet import observed_case


def extension_denial_case(scenario: Scenario, adapter: ExtensionAdapter) -> tuple[dict, dict, dict]:
    """Build a passing native extension denial case for one reviewed adapter."""
    case = observed_case(scenario.commands[0], blocked=True)
    case["filesystem"]["extension-executed-absent"] = True
    binding = {
        "schema": "guard.native-command-receipt-binding.v1",
        "program_digest": "b" * 64,
        "catalog_digest": "c" * 64,
        "trust_digest": "d" * 64,
        "control_revision": 1,
        "managed_control_revision": 1,
        "control_effective_digest": "e" * 64,
        "observations_digest": "f" * 64,
        "observation_count": 2,
        "uncertainty_count": 0,
    }
    case["guard_observations"][0].update(
        policy_action="block",
        reason_code="native_command_permission_disabled",
        probe_operation_id="00000000-0000-4000-8000-000000000001",
        probe_request_id="transition-hook-" + "1" * 32,
    )
    case["extension_control"] = {
        "extension_id": adapter.extension_id,
        "rule_id": adapter.rule_id,
        "permission_id": adapter.permission_id,
        "permission_state": "disabled",
        "control_revision": 1,
    }
    receipt = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "a" * 64,
        "request_id": "transition-hook-" + "1" * 32,
        "payload_kind": "inline",
        "harness": "omp",
        "event_name": "PreToolUse",
        "decision": "deny",
        "policy_action": "block",
        "observed_policy_action": "block",
        "reason_code": "native_command_permission_disabled",
        "command_extensions": binding,
    }
    case["native_observer_receipt"] = receipt
    case["native_receipt"] = dict(receipt)
    case["native_receipt_writer"] = {"processed_before": 3, "processed_after": 4}
    case["native_observation"] = {
        "schema": "hol-guard.transition-hook-observation.v1",
        "operation_id": "00000000-0000-4000-8000-000000000001",
        "request_id": "transition-hook-" + "1" * 32,
        "native_receipt": receipt,
    }
    case["guard_observations"][0]["native_observation"] = case["native_observation"]
    case["native_extension_evidence"] = {
        "schema": "guard.native-command-observations.v1",
        "binding": binding,
        "observations": [
            {
                "extension_id": adapter.extension_id,
                "rule_id": adapter.rule_id,
                "uncertainty_reasons": [],
                "effective_segment_indexes": [0],
                "matcher_evidence": [{"segment_index": 0}],
            }
        ],
        "permission_observations": [
            {
                "extension_id": adapter.extension_id,
                "permission_id": adapter.permission_id,
                "uncertainty_reasons": [],
                "matcher_evidence": [{"segment_index": 0}],
            }
        ],
        "evaluation_error": None,
    }
    return case, binding, receipt


def test_extension_permission_denial_requires_native_binding_evidence():
    """Do not credit a missing executable, stale receipt, or generic deny."""
    scenario = Scenario(
        "permission-denial",
        "block",
        "blocked-extension",
        "Attempt the synthetic ollama command",
        ("ollama rm gauntlet-synthetic-model",),
    )
    case, binding, receipt = extension_denial_case(scenario, EXTENSION_ADAPTERS["ollama"])
    assert assess_case(scenario, case)["outcome"] == "pass"
    permission_observation = case["native_extension_evidence"]["permission_observations"][0]
    permission_observation["permission_id"] = "command.ollama.permission.push"
    assert assess_case(scenario, case)["outcome"] != "pass"
    permission_observation["permission_id"] = "command.ollama.permission.rm"
    case["native_extension_evidence"]["permission_observations"] = []
    binding["observation_count"] = 1
    assert assess_case(scenario, case)["outcome"] == "pass"
    case["extension_control"]["permission_id"] = "command.ollama.permission.push"
    assert assess_case(scenario, case)["outcome"] != "pass"
    case["extension_control"]["permission_id"] = "command.ollama.permission.rm"
    case["native_receipt"] = None
    assert assess_case(scenario, case)["outcome"] != "pass"
    case["native_receipt"] = dict(receipt)
    case["native_observer_receipt"] = dict(receipt, decision_id="c" * 64)
    assert assess_case(scenario, case)["outcome"] != "pass"
    case["native_observer_receipt"] = receipt
    case["native_extension_evidence"]["observations"][0]["rule_id"] = "command.ollama.help"
    assert assess_case(scenario, case)["outcome"] != "pass"


@pytest.mark.parametrize(
    ("scenario_id", "executable"),
    [
        ("explicit-disabled-ollama-permission", "ollama"),
        ("explicit-disabled-gws-send-permission", "gws"),
        ("explicit-disabled-salesforce-delete-permission", "sf"),
    ],
)
def test_business_extension_denials_bind_to_their_reviewed_adapter(scenario_id: str, executable: str):
    """Credit each catalog denial only for its own extension, rule and permission."""
    scenario = next(item for item in load_catalog() if item.id == scenario_id)
    adapter = extension_adapter(scenario.commands[0])
    assert adapter is EXTENSION_ADAPTERS[executable]
    case, _binding, _receipt = extension_denial_case(scenario, adapter)
    assert assess_case(scenario, case)["outcome"] == "pass"
    for other in EXTENSION_ADAPTERS.values():
        if other is adapter:
            continue
        foreign, _binding, _receipt = extension_denial_case(scenario, other)
        assert assess_case(scenario, foreign)["outcome"] == "harness-error"


@pytest.mark.parametrize("command", ["gog gmail send --to synthetic@work.example", "", "'unterminated"])
def test_blocked_extension_catalog_rejects_commands_without_a_reviewed_adapter(command: str):
    """Reject denial cases the oracle cannot bind to a reviewed permission."""
    row = {
        "id": "unreviewed-denial",
        "expectation": "block",
        "oracle": "blocked-extension",
        "commands": [command],
        "prompt": "Attempt the synthetic command once.",
    }
    with pytest.raises(ValueError):
        load_catalog_data({"schema": "hol.guard-gauntlet.scenarios.v1", "scenarios": [row]})


def test_candidate_release_assets_answer_unpublished_extension_data(monkeypatch, tmp_path):
    """Serve an unreleased candidate's exported pack only from the named directory."""
    from ci.gauntlet import extension_adapters
    from codex_plugin_scanner.guard.catalog_delivery import transport

    tag = "extension-data-" + "a" * 40 + "-0.0-000001"
    asset = "pack-" + "b" * 64 + ".zip"
    (tmp_path / tag).mkdir()
    (tmp_path / tag / asset).write_bytes(b"pack")
    live = []
    monkeypatch.setattr(transport, "download", lambda url, maximum: live.append(url) or b"live")
    monkeypatch.setenv(extension_adapters.RELEASE_ASSETS_ENV, str(tmp_path))
    extension_adapters._serve_candidate_release_assets.cache_clear()
    try:
        extension_adapters._serve_candidate_release_assets()
        release = "https://github.com/hashgraph-online/hol-guard/releases/download/"
        assert transport.download(f"{release}{tag}/{asset}", 16) == b"pack"
        assert transport.download("https://example.invalid/root.json", 16) == b"live"
        assert live == ["https://example.invalid/root.json"]
        with pytest.raises(RuntimeError):
            transport.download(f"{release}{tag}/pack-{'c' * 64}.zip", 16)
    finally:
        extension_adapters._serve_candidate_release_assets.cache_clear()


def test_required_extension_controls_ask_only_for_permissions(monkeypatch):
    """A required extension is already enabled; asking to enable it is refused.

    `command.git` is required, so a local-admin layer that sets its extension
    state is refused with `immutable_extension` and the case never reaches
    inference. Its permissions stay configurable, so only those are committed.
    An optional extension still gets its enable.
    """
    import types

    from ci.gauntlet.extension_adapters import _commit_extension_controls, _required_extension_ids
    from ci.native_runtime import probe_installed_native_extensions as probe
    from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlTargetKind

    assert "command.git" in _required_extension_ids()
    assert "command.github" not in _required_extension_ids()

    committed: list[tuple] = []
    monkeypatch.setattr(probe, "commit_controls", lambda api, password, controls: committed.append(controls) or 1)
    daemon = types.SimpleNamespace(_server=types.SimpleNamespace(extension_control_api=object()))

    _commit_extension_controls(daemon, "secret", "command.git", (("command.git.permission.add", True),))
    assert [item.target.kind for item in committed[-1]] == [ControlTargetKind.PERMISSION]

    _commit_extension_controls(
        daemon, "secret", "command.github", (("command.github.permission.delete-remote", False),)
    )
    assert committed[-1][0].target.kind == ControlTargetKind.EXTENSION

    with pytest.raises(RuntimeError):
        _commit_extension_controls(daemon, "secret", "command.git", ())


def _exported_packs(cache_root, sha, tag="macosx_11_0_arm64-dev"):
    """Lay out one wheel cache entry the way the qualification driver does."""
    assets = cache_root / "wheels" / f"{sha}-{tag}" / "release-assets"
    publication = assets / f"extension-data-{sha}-0.0-000001"
    publication.mkdir(parents=True)
    (publication / ("pack-" + "b" * 64 + ".zip")).write_bytes(b"pack")
    return assets


def test_cached_release_assets_answer_a_bare_run_without_the_environment(monkeypatch, tmp_path):
    """`ci.gauntlet run` finds the candidate's exported packs in the wheel cache.

    Only `ci.gauntlet qualify` exports GUARD_GAUNTLET_RELEASE_ASSETS. A bare
    run of a single case is started by hand, so without this the optional
    extension an extension-control case enables is fetched from a release the
    candidate does not have yet.
    """
    from ci.gauntlet import extension_adapters
    from codex_plugin_scanner.guard.catalog_delivery import transport

    sha = "a" * 40
    _exported_packs(tmp_path, sha)
    monkeypatch.delenv(extension_adapters.RELEASE_ASSETS_ENV, raising=False)
    monkeypatch.setenv(extension_adapters.CACHE_ROOT_ENV, str(tmp_path))
    monkeypatch.setattr(extension_adapters, "_installed_source_sha", lambda: sha)
    monkeypatch.setattr(transport, "download", lambda url, maximum: b"live")
    extension_adapters._serve_candidate_release_assets.cache_clear()
    try:
        extension_adapters._serve_candidate_release_assets()
        release = "https://github.com/hashgraph-online/hol-guard/releases/download/"
        tag = f"extension-data-{sha}-0.0-000001"
        assert transport.download(f"{release}{tag}/pack-{'b' * 64}.zip", 16) == b"pack"
    finally:
        extension_adapters._serve_candidate_release_assets.cache_clear()


def test_cached_release_assets_refuse_another_candidates_export(monkeypatch, tmp_path):
    """An export built from a different commit is never served for this build."""
    from ci.gauntlet import extension_adapters

    _exported_packs(tmp_path, "a" * 40)
    monkeypatch.setenv(extension_adapters.CACHE_ROOT_ENV, str(tmp_path))
    monkeypatch.setattr(extension_adapters, "_installed_source_sha", lambda: "c" * 40)
    assert extension_adapters._cached_release_assets() is None


def test_cached_release_assets_need_a_published_pack_directory(monkeypatch, tmp_path):
    """A wheel cache entry whose build exported nothing is not an export."""
    from ci.gauntlet import extension_adapters

    sha = "a" * 40
    (tmp_path / "wheels" / f"{sha}-macosx_11_0_arm64-dev" / "release-assets").mkdir(parents=True)
    monkeypatch.setenv(extension_adapters.CACHE_ROOT_ENV, str(tmp_path))
    monkeypatch.setattr(extension_adapters, "_installed_source_sha", lambda: sha)
    assert extension_adapters._cached_release_assets() is None


def test_cached_release_assets_leave_a_released_build_to_fetch_live(monkeypatch, tmp_path):
    """With no export and no variable, serving stays untouched and the fetch is live."""
    from ci.gauntlet import extension_adapters
    from codex_plugin_scanner.guard.catalog_delivery import transport

    monkeypatch.delenv(extension_adapters.RELEASE_ASSETS_ENV, raising=False)
    monkeypatch.setenv(extension_adapters.CACHE_ROOT_ENV, str(tmp_path))
    monkeypatch.setattr(extension_adapters, "_installed_source_sha", lambda: "a" * 40)
    monkeypatch.setattr(transport, "download", lambda url, maximum: b"live")
    extension_adapters._serve_candidate_release_assets.cache_clear()
    try:
        extension_adapters._serve_candidate_release_assets()
        assert transport.download("https://example.invalid/root.json", 16) == b"live"
    finally:
        extension_adapters._serve_candidate_release_assets.cache_clear()


def test_execution_error_chain_keeps_the_refusal_behind_the_class_name():
    """`execution_error` alone drops the status and reason code of a refusal."""
    from ci.gauntlet.evidence import execution_error_chain

    try:
        try:
            raise ValueError("extension release is unavailable")
        except ValueError as cause:
            raise RuntimeError("(503, 'pack_preparation_unavailable')") from cause
    except RuntimeError as error:
        chain = execution_error_chain(error, {})
    assert chain[0] == "RuntimeError: (503, 'pack_preparation_unavailable')"
    assert chain[1] == "ValueError: extension release is unavailable"


def test_execution_error_chain_is_bounded():
    """A long cause chain cannot flood a case's evidence."""
    from ci.gauntlet.evidence import (
        EXECUTION_ERROR_CHAIN_LINKS,
        EXECUTION_ERROR_CHAIN_WIDTH,
        execution_error_chain,
    )

    error: BaseException = RuntimeError("x" * 4000)
    for _ in range(10):
        wrapper = RuntimeError("y" * 4000)
        wrapper.__cause__ = error
        error = wrapper
    chain = execution_error_chain(error, {})
    assert len(chain) == EXECUTION_ERROR_CHAIN_LINKS
    assert all(len(link) <= EXECUTION_ERROR_CHAIN_WIDTH for link in chain)


def test_execution_error_chain_redacts_before_it_bounds():
    """A link cut to its width must not keep the head of a redacted value."""
    import re

    from ci.gauntlet.evidence import EXECUTION_ERROR_CHAIN_WIDTH, execution_error_chain

    fixture = "/tmp/gauntlet-fixture-aaaa/workspace"
    # A placeholder standing in for a credential the compiled matchers hide.
    planted = "aaaa-bbbb-cccc-dddd"
    replacements = {
        fixture: "{{workspace}}",
        re.compile(re.escape(planted)): "<provider-key-redacted>",
    }

    # Each value starts six characters before the bound, so truncating first
    # leaves a head that no longer matches the replacement that would hide it.
    def straddling(prefix: str, value: str) -> str:
        return "x" * (EXECUTION_ERROR_CHAIN_WIDTH - len(prefix) - 6) + value

    cause = ValueError(straddling("ValueError: ", planted))
    error = RuntimeError(straddling("RuntimeError: ", fixture))
    error.__cause__ = cause
    chain = execution_error_chain(error, replacements)
    assert all(len(link) <= EXECUTION_ERROR_CHAIN_WIDTH for link in chain)
    assert "/tmp/" not in chain[0]
    assert "aaaa-" not in chain[1]


def test_operator_home_is_redacted_from_evidence(monkeypatch, tmp_path):
    """A failure outside the fixture tree names the operator's own home."""
    from ci.gauntlet.evidence import execution_error_chain
    from ci.gauntlet.input_evidence import operator_home_replacements

    home = tmp_path / "operator-account"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    replacements = operator_home_replacements()
    assert replacements
    error = PermissionError(f"cannot read {home}/.config/provider/login.json")
    chain = execution_error_chain(error, replacements)
    assert str(home) not in chain[0]
    assert "{{operator_home}}" in chain[0]
