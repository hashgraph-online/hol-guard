from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import supply_chain_workspace_audit as audit
from codex_plugin_scanner.guard.runtime.package_intent_common import PackageIntentTarget
from tests.test_native_supply_chain_eval import _Artifact


def _target(index: int) -> PackageIntentTarget:
    name = f"package-{index:05d}"
    return PackageIntentTarget(
        ecosystem="npm",
        package_name=name,
        raw_spec=f"{name}@1.0.{index}",
        requested_specifier=f"1.0.{index}",
    )


def _evaluate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    targets: tuple[PackageIntentTarget, ...],
    verdicts: dict[str, str],
) -> tuple[dict[str, object], list[tuple[PackageIntentTarget, ...]]]:
    """Run the workspace evaluation with a resident stand-in that answers per intent."""

    intents: list[tuple[PackageIntentTarget, ...]] = []

    def build(harness: str, intent: object, **kwargs: object) -> _Artifact:
        intents.append(intent.targets)
        return _Artifact()

    def evaluate(**kwargs: object) -> SimpleNamespace:
        chunk = intents[-1]
        decision = next((verdicts[t.package_name] for t in chunk if t.package_name in verdicts), "monitor")
        result = {
            "decision": decision,
            "risk_summary": f"chunk {len(intents)}",
            "reasons": [{"code": "no_cached_match"}],
            "packages": [{"name": t.package_name, "decision": verdicts.get(t.package_name, "monitor")} for t in chunk],
            "evidence_ids": [],
            "refresh_required": len(intents) == 1,
        }
        return SimpleNamespace(to_dict=lambda: result)

    scanned = SimpleNamespace(inventory_digest="digest", scan_targets=targets)
    monkeypatch.setattr(audit, "native_workspace_inventory", lambda *args, **kwargs: scanned)
    monkeypatch.setattr(audit, "build_package_request_artifact", build)
    monkeypatch.setattr(audit._lsc, "evaluate_package_request_artifact", evaluate)
    evaluation = audit._workspace_local_evaluation(
        store=SimpleNamespace(guard_home=tmp_path),
        workspace_dir=tmp_path,
        sbom_paths=(),
        before_workspace_dir=None,
        manifest_paths=("package.json",),
        lockfile_paths=("pnpm-lock.yaml",),
        command_name="workspace-assessment",
        inventory_digest="digest",
        now="2026-05-19T00:00:00Z",
        record_evidence=False,
    )
    return evaluation, intents


def _bytes(targets: tuple[PackageIntentTarget, ...]) -> int:
    return sum(len(json.dumps(asdict(t), separators=(",", ":")).encode("utf-8")) for t in targets)


def test_a_large_workspace_is_evaluated_in_intents_the_resident_can_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Thousands of lockfile packages in one intent make the resident's artifact
    # reply outgrow its limit, and the whole audit failed. Each intent now stays
    # within the bound and together they cover every package once, in order.
    targets = tuple(_target(index) for index in range(6000))
    assert _bytes(targets) > 2 * audit._TARGET_CHUNK_BYTES
    blocked = targets[-1].package_name
    evaluation, intents = _evaluate(monkeypatch, tmp_path, targets, {blocked: "block"})
    assert len(intents) >= 3
    assert all(_bytes(chunk) <= audit._TARGET_CHUNK_BYTES for chunk in intents)
    assert tuple(t for chunk in intents for t in chunk) == targets
    # The strictest chunk decides, every package is listed, repeated reasons
    # appear once and a flag any chunk raised stays raised.
    assert evaluation["decision"] == "block"
    assert evaluation["risk_summary"] == f"chunk {len(intents)}"
    assert [package["name"] for package in evaluation["packages"]] == [t.package_name for t in targets]
    assert evaluation["reasons"] == [{"code": "no_cached_match"}]
    assert evaluation["refresh_required"] is True


def test_a_workspace_within_the_bound_keeps_its_single_intent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    targets = tuple(_target(index) for index in range(20))
    evaluation, intents = _evaluate(monkeypatch, tmp_path, targets, {})
    assert intents == [targets]
    assert evaluation["risk_summary"] == "chunk 1"


def test_a_workspace_with_no_targets_still_asks_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evaluation, intents = _evaluate(monkeypatch, tmp_path, (), {})
    assert intents == [()]
    assert evaluation["packages"] == []
