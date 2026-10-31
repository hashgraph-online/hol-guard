"""Running runtime instances: probe bridge, carried store and posture.

A process keeps the build it started from. Replacing the runtime on disk must
not rewrite what an old process reports, and a process that exits is reported
exited, never silently dropped.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import runtime_identity_probe, runtime_posture
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime_identity_assessment import RuntimeIdentityError
from codex_plugin_scanner.guard.runtime_identity_candidates import RuntimeCandidates
from codex_plugin_scanner.guard.runtime_identity_probe import (
    RuntimeProbe,
    probe_runtime_launches,
)
from codex_plugin_scanner.guard.runtime_instance_store import (
    INSTANCE_STORE_NAME,
    load_known_instances,
    remember_instances,
)
from codex_plugin_scanner.guard.runtime_posture import build_runtime_posture

NOW = "2026-01-01T00:00:00+00:00"
LAUNCH = [{"command": "node", "launch_dir": "/"}]
ARTIFACT = {
    "artifact_id": "artifact:node",
    "family": "node",
    "vendor": None,
    "version": "20.11.1",
    "build_id": None,
    "os": "linux",
    "arch": "x86_64",
    "executable_sha256": "a" * 64,
    "component_identity_sha256": None,
    "identity_assurance": "self_reported",
}


def _instance(state: str = "running", *, pid: int = 7, location_id: str | None = "path:node") -> dict[str, object]:
    return {
        "instance_id": f"instance:{pid}",
        "boot_identity": "boot:1",
        "pid": pid,
        "start_identity": f"posix:{pid}",
        "artifact_id": ARTIFACT["artifact_id"],
        "location_id": location_id,
        "state": state,
        "coverage": "observed_only",
    }


def _reply(*, instances: list[dict[str, object]] | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "schema": "guard.runtime-identity-probe.v1",
        "artifacts": [ARTIFACT],
        "locations": [{"location_id": "path:node", "artifact_id": ARTIFACT["artifact_id"], "state": "present"}],
        "observations": [],
        "launches": [{"index": 0, "state": "resolved", "lookup": "path", "targets": []}],
        "candidate_limit_reached": False,
    }
    if instances is not None:
        result.update(instances=instances, unbound_processes=0, instance_limit_reached=False)
    return {"ok": True, "result": result}


def _known(pid: int = 7, location_id: str = "path:node") -> dict[str, object]:
    return {
        "boot_identity": "boot:1",
        "pid": pid,
        "start_identity": f"posix:{pid}",
        "location_id": location_id,
        "artifact": ARTIFACT,
    }


def _probe(calls: list[tuple[str, dict[str, object]]], monkeypatch: pytest.MonkeyPatch, answer) -> None:
    def fake(feature: str, command: str, request: dict[str, object], **_: object) -> dict[str, object]:
        calls.append((feature, request))
        return answer(feature, request)

    monkeypatch.setattr(runtime_identity_probe, "run_native_identity_command", fake)


def test_a_damaged_record_costs_what_it_carried_not_the_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def answer(feature: str, request: dict[str, object]) -> dict[str, object]:
        if request["known_instances"]:
            return {"ok": False, "error": "runtime_identity_probe_known_instance_invalid"}
        return _reply(instances=[])

    _probe(calls, monkeypatch, answer)
    probe = probe_runtime_launches(LAUNCH, environment={}, candidate_limit=8, known_instances=[_known()])

    assert probe.instances == ()
    assert [request["known_instances"] for _, request in calls] == [[_known()], []]


@pytest.mark.parametrize(
    "row",
    [
        {**_instance(), "artifact_id": "artifact:missing"},
        {**_instance(), "location_id": "path:elsewhere"},
        {**_instance(), "pid": True},
        {**_instance(), "state": "fixed"},
        {**_instance(), "coverage": "bound_launch"},
    ],
)
def test_an_instance_row_the_reply_cannot_back_is_rejected(monkeypatch: pytest.MonkeyPatch, row) -> None:
    _probe([], monkeypatch, lambda feature, request: _reply(instances=[row]))

    with pytest.raises(RuntimeIdentityError):
        probe_runtime_launches(LAUNCH, environment={}, candidate_limit=8, known_instances=[])


def test_the_store_keeps_running_instances_and_other_scopes(tmp_path: Path) -> None:
    probe = RuntimeProbe(
        artifacts=(ARTIFACT,),
        locations=({"location_id": "path:node", "artifact_id": ARTIFACT["artifact_id"], "state": "present"},),
        observations=(),
        instances=(_instance(pid=7), _instance("exited", pid=8)),
    )
    elsewhere = _known(pid=9, location_id="path:other")
    _store(tmp_path, [_known(pid=8), elsewhere])

    remember_instances(tmp_path, probe)

    assert load_known_instances(tmp_path) == [_known(pid=7), elsewhere]


def _store(home: Path, items: list[dict[str, object]]) -> None:
    payload = {"schema": "guard.runtime-instances.v1", "instances": items}
    (home / INSTANCE_STORE_NAME).write_text(json.dumps(payload), encoding="utf-8")


def test_a_write_keeps_what_another_scan_stored_after_this_one_loaded(tmp_path: Path) -> None:
    probe = RuntimeProbe(
        artifacts=(ARTIFACT,),
        locations=({"location_id": "path:node", "artifact_id": ARTIFACT["artifact_id"], "state": "present"},),
        observations=(),
        instances=(_instance(pid=7),),
    )
    _store(tmp_path, [])
    loaded = load_known_instances(tmp_path)
    other_scan = _known(pid=9, location_id="path:other")
    _store(tmp_path, [*loaded, other_scan])

    remember_instances(tmp_path, probe)

    assert load_known_instances(tmp_path) == [_known(pid=7), other_scan]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("pid", "7"),
        ("pid", True),
        ("pid", 0),
        ("boot_identity", ""),
        ("location_id", 7),
        ("artifact", {**ARTIFACT, "vendor": 7}),
        ("artifact", {**ARTIFACT, "executable_sha256": "a"}),
        ("artifact", {**ARTIFACT, "version": " "}),
        ("artifact", {**ARTIFACT, "identity_assurance": "vendor_verified"}),
        ("artifact", {**ARTIFACT, "extra": None}),
    ],
)
def test_a_record_the_probe_would_refuse_costs_only_its_own_process(tmp_path: Path, field: str, value: object) -> None:
    _store(tmp_path, [{**_known(pid=8), field: value}, _known(pid=9)])

    assert load_known_instances(tmp_path) == [_known(pid=9)]


def test_a_damaged_store_reads_as_empty(tmp_path: Path) -> None:
    (tmp_path / INSTANCE_STORE_NAME).write_text("{not json", encoding="utf-8")
    assert load_known_instances(tmp_path) == []
    (tmp_path / INSTANCE_STORE_NAME).write_text(json.dumps({"schema": "other", "instances": [_known()]}))
    assert load_known_instances(tmp_path) == []


def _detection() -> HarnessDetection:
    artifact = GuardArtifact(
        artifact_id="claude-code:files",
        name="files",
        harness="claude-code",
        artifact_type="mcp_server",
        source_scope="project",
        config_path="config.json",
        command="node",
        args=(),
        transport="stdio",
        metadata={"env": {}},
    )
    return HarnessDetection("claude-code", True, True, ("config.json",), (artifact,))


def _install(node: Path, source: str) -> None:
    node.parent.mkdir(parents=True, exist_ok=True)
    staged = node.with_name("node.staged")
    shutil.copyfile(source, staged)
    staged.chmod(0o755)
    staged.replace(node)


@pytest.fixture
def running_node(tmp_path: Path) -> Iterator[tuple[Path, subprocess.Popen[bytes]]]:
    node = tmp_path / ".nvm" / "versions" / "node" / "v20.11.1" / "bin" / "node"
    _install(node, "/bin/sleep")
    # The probe binds a process to the file only when it started a whole second after the last change.
    time.sleep(2.1)
    child = subprocess.Popen([str(node), "30"])
    try:
        yield node, child
    finally:
        child.kill()
        child.wait()


@pytest.mark.skipif(sys.platform == "win32", reason="replaces a running executable in place")
def test_a_replaced_runtime_still_reports_its_old_process(
    native_hook_force: Path, tmp_path: Path, running_node: tuple[Path, subprocess.Popen[bytes]]
) -> None:
    node, child = running_node
    home = tmp_path / "guard-home"

    def posture() -> dict[str, object]:
        return build_runtime_posture(
            [_detection()], generated_at=NOW, environment={"PATH": str(node.parent)}, instance_home=home
        )

    def mine(payload: dict[str, object]) -> dict[str, object]:
        [row] = [row for row in payload["instances"]["rows"] if row["pid"] == child.pid]
        return row

    first = posture()
    assert first["coverage"]["instances_enumerated"] is True
    assert (mine(first)["state"], mine(first)["version"], mine(first)["identified"]) == ("running", "20.11.1", True)

    _install(node, "/bin/cat")
    replaced = posture()
    assert mine(replaced)["instance_id"] == mine(first)["instance_id"]
    assert mine(replaced)["state"] == "running"
    assert mine(replaced)["artifact_id"] == mine(first)["artifact_id"]
    assert mine(replaced)["version"] == "20.11.1"
    [runtime] = replaced["runtimes"]
    assert runtime["artifact_id"] != mine(first)["artifact_id"]

    child.kill()
    child.wait()
    gone = posture()
    assert mine(gone)["state"] == "exited"
    assert mine(gone)["artifact_id"] == mine(first)["artifact_id"]
    assert all(item["pid"] != child.pid for item in load_known_instances(home))


def test_processes_the_assessment_refuses_cost_only_themselves(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    probe = RuntimeProbe(
        artifacts=(ARTIFACT,),
        locations=({"location_id": "path:node", "artifact_id": ARTIFACT["artifact_id"], "state": "present"},),
        observations=(),
        instances=(_instance(),),
    )
    requests: list[dict[str, object]] = []

    def assess(request: dict[str, object]) -> SimpleNamespace:
        requests.append(request)
        if "instances" in request:
            raise RuntimeIdentityError("runtime_identity_artifact_invalid")
        return SimpleNamespace(advisory_source=None, artifacts=(), advisories=())

    monkeypatch.setattr(
        runtime_posture, "collect_runtime_candidates", lambda *_, **__: (RuntimeCandidates((), (), False), probe)
    )
    monkeypatch.setattr(runtime_posture, "assess_runtime_identity", assess)
    payload = build_runtime_posture(
        [_detection()], generated_at=NOW, environment={}, instance_home=tmp_path, advisory_bundle={"fixture": True}
    )

    assert "instances" in requests[0]
    assert "instances" not in requests[-1]
    assert payload["status"] == "ok"
    assert payload["coverage"]["instances_enumerated"] is True
    assert payload["instances"]["enumerated"] is True
    assert payload["instances"]["assessed"] is False
    assert payload["instances"]["assessment_error"] == "runtime_identity_artifact_invalid"


def test_posture_without_a_guard_home_enumerates_nothing(native_hook_force: Path, tmp_path: Path) -> None:
    node = tmp_path / ".nvm" / "versions" / "node" / "v20.11.1" / "bin" / "node"
    _install(node, "/bin/sleep" if sys.platform != "win32" else sys.executable)

    payload = build_runtime_posture([_detection()], generated_at=NOW, environment={"PATH": str(node.parent)})

    assert payload["coverage"]["instances_enumerated"] is False
    assert payload["instances"]["enumerated"] is False
