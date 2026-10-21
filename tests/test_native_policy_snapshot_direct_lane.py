from __future__ import annotations

import json
import os
import shlex
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_direct_lane as direct_lane
from codex_plugin_scanner.guard.adapters import zcode_contained_tests
from codex_plugin_scanner.guard.native_policy_snapshot_contract import _policy_snapshot_push_bytes_v3
from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane import (
    DIRECT_HOOK_CONTAINED_ROUTE_FEATURE,
    DIRECT_HOOK_EVIDENCE_FEATURE,
    DIRECT_HOOK_PERMISSION_NOTICE_FEATURE,
    DIRECT_LANE_ACK_LEASE_MS,
    DIRECT_LANE_ACK_SCHEMA,
    NativePolicySnapshotDirectLaneAck,
    contained_sink_command,
    direct_lane_binding,
    direct_lane_integrity_key,
    local_cli_block_rules_present,
    with_direct_hook_state,
)

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the direct lane is Unix-only")

DIGEST = "a" * 64


class _Publisher(NativePolicySnapshotDirectLaneAck):
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home
        self._acked = False


def _publisher(tmp_path: Path) -> _Publisher:
    (tmp_path / "native-runtime").mkdir(mode=0o700)
    return _Publisher(tmp_path)


def test_binding_excludes_hint_only_files_and_keeps_stat_identity(tmp_path: Path) -> None:
    config = str(tmp_path / "config.toml")
    binding = direct_lane_binding(
        inputs=(
            (config, (1, 2, 3, 4)),
            (str(tmp_path / "guard.db"), (5, 6, 7, 8)),
            (str(tmp_path / "guard.db-wal"), None),
            (str(tmp_path / "native-runtime" / "command-control-authority.v1.json"), (9, 9, 9, 9)),
            (str(tmp_path / "absent.toml"), None),
        ),
        workspaces=(tmp_path / "repo-b", tmp_path / "repo-a", Path("relative")),
    )

    assert binding == {
        "workspaces": [str(tmp_path / "repo-a"), str(tmp_path / "repo-b")],
        "inputs": [
            {"path": config, "stat": {"mtime_ns": 1, "size": 2, "ino": 3, "ctime_ns": 4}},
            {"path": str(tmp_path / "absent.toml"), "stat": None},
        ],
    }


@pytest.mark.parametrize(
    "inputs",
    [
        (("relative.toml", None),),
        (("/a\0b", None),),
        (("/a", None), ("/a", None)),
        (("/a", (-1, -1, 0, 0)),),
        (("/a", (0, 0, 1 << 64, 0)),),
    ],
)
def test_binding_closes_the_lane_for_inputs_the_resident_cannot_recheck(inputs) -> None:
    assert direct_lane_binding(inputs=inputs, workspaces=()) is None


def test_binding_closes_the_lane_over_resident_limits() -> None:
    inputs = tuple((f"/inputs/{index}", None) for index in range(257))
    assert direct_lane_binding(inputs=inputs, workspaces=()) is None
    workspaces = tuple(Path(f"/work/{index}") for index in range(513))
    assert direct_lane_binding(inputs=(), workspaces=workspaces) is None


def test_ack_follows_the_barrier(tmp_path: Path) -> None:
    publisher = _publisher(tmp_path)
    ack = publisher._direct_lane_ack_path()

    publisher._publish_direct_lane_ack({"generation": 3, "policy_digest": DIGEST})
    assert not ack.exists()

    publisher._acked = True
    publisher._publish_direct_lane_ack({"generation": 3, "policy_digest": DIGEST})
    body = json.loads(ack.read_bytes())
    assert body["schema"] == DIRECT_LANE_ACK_SCHEMA
    assert (body["generation"], body["policy_digest"]) == (3, DIGEST)
    assert 0 < body["lease_expires_at_ms"] - direct_lane._now_ms() <= DIRECT_LANE_ACK_LEASE_MS
    assert stat.S_IMODE(ack.stat().st_mode) == 0o600
    assert stat.S_IMODE(ack.parent.stat().st_mode) == 0o700
    assert [entry.name for entry in ack.parent.iterdir()] == [ack.name]

    publisher._acked = False
    assert not ack.exists()
    publisher._renew_direct_lane_ack()
    assert not ack.exists()


def test_init_withdraws_an_ack_left_by_a_previous_daemon(tmp_path: Path) -> None:
    first = _publisher(tmp_path)
    first._acked = True
    first._publish_direct_lane_ack({"generation": 3, "policy_digest": DIGEST})
    assert first._direct_lane_ack_path().exists()

    _Publisher(tmp_path)

    assert not first._direct_lane_ack_path().exists()


def test_lease_renews_only_near_expiry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    publisher = _publisher(tmp_path)
    clock = [1_000_000]
    monkeypatch.setattr(direct_lane, "_now_ms", lambda: clock[0])
    publisher._acked = True
    publisher._publish_direct_lane_ack({"generation": 3, "policy_digest": DIGEST})
    ack = publisher._direct_lane_ack_path()

    clock[0] += 1_000
    publisher._renew_direct_lane_ack()
    assert json.loads(ack.read_bytes())["lease_expires_at_ms"] == 1_000_000 + DIRECT_LANE_ACK_LEASE_MS

    clock[0] += DIRECT_LANE_ACK_LEASE_MS
    publisher._renew_direct_lane_ack()
    assert json.loads(ack.read_bytes())["lease_expires_at_ms"] == clock[0] + DIRECT_LANE_ACK_LEASE_MS


def test_ack_refuses_a_directory_it_does_not_own_as_private(tmp_path: Path) -> None:
    publisher = _publisher(tmp_path)
    target = tmp_path / "elsewhere"
    target.mkdir()
    publisher._direct_lane_ack_path().parent.symlink_to(target, target_is_directory=True)
    publisher._acked = True

    publisher._publish_direct_lane_ack({"generation": 3, "policy_digest": DIGEST})

    assert list(target.iterdir()) == []
    assert publisher._direct_lane_lease_expires_at_ms == 0


def test_push_envelope_carries_the_binding_and_drops_it_when_too_large() -> None:
    snapshot = {"generation": 1}
    binding = {"workspaces": ["/work/repo"], "inputs": []}

    request = json.loads(_policy_snapshot_push_bytes_v3(snapshot, direct_lane=binding))["request"]
    assert request["direct_lane"] == binding
    assert "direct_lane" not in json.loads(_policy_snapshot_push_bytes_v3(snapshot))["request"]

    oversized = {"workspaces": [f"/work/{'x' * 4000}/{index}" for index in range(512)], "inputs": []}
    request = json.loads(_policy_snapshot_push_bytes_v3(snapshot, direct_lane=oversized))["request"]
    assert "direct_lane" not in request


def test_direct_hook_state_binds_only_what_the_resident_accepts() -> None:
    binding = {"workspaces": ["/work/repo"], "inputs": []}
    bound = with_direct_hook_state(
        binding,
        home_dir="/home/guard",
        harness_postures={"cursor": "watch", "codex": "protected"},
        local_cli_block_rules=False,
        evidence_drain=True,
    )
    assert bound == {
        **binding,
        "home_dir": "/home/guard",
        "harness_postures": {"codex": "protected", "cursor": "watch"},
        "local_cli_block_rules": False,
        "evidence_drain": True,
    }
    assert list(bound["harness_postures"]) == ["codex", "cursor"]
    assert (
        with_direct_hook_state(
            None, home_dir="/h", harness_postures={}, local_cli_block_rules=False, evidence_drain=True
        )
        is None
    )

    # Unacceptable fields are left out so the resident defers as incomplete.
    for home_dir, postures in (
        ("relative/home", {}),
        ("", {}),
        ("/home/guard", {"codex": "relaxed"}),
        ("/home/guard", {"": "watch"}),
        ("/home/guard", {"x" * 65: "watch"}),
        ("/home/guard", {f"h{index}": "watch" for index in range(33)}),
    ):
        bound = with_direct_hook_state(
            binding, home_dir=home_dir, harness_postures=postures, local_cli_block_rules=True, evidence_drain=False
        )
        assert bound is not None and bound["local_cli_block_rules"] is True
        assert bound["evidence_drain"] is False
        assert ("home_dir" in bound) == (home_dir == "/home/guard")
        assert ("harness_postures" in bound) == (home_dir != "/home/guard")


def test_local_cli_rule_probe_fails_toward_the_daemon() -> None:
    class _Store:
        def __init__(self, result: object) -> None:
            self.result = result

        def has_local_cli_block_rules(self) -> bool:
            if isinstance(self.result, Exception):
                raise self.result
            return bool(self.result)

    assert local_cli_block_rules_present(object()) is False
    assert local_cli_block_rules_present(_Store(False)) is False
    assert local_cli_block_rules_present(_Store(True)) is True
    assert local_cli_block_rules_present(_Store(RuntimeError("locked"))) is True


def test_local_cli_rule_change_closes_only_the_direct_lane(tmp_path: Path) -> None:
    publisher = _publisher(tmp_path)
    ack = publisher._direct_lane_ack_path()
    publisher._acked = True
    publisher._direct_lane_local_cli_revision = 4
    publisher._publish_direct_lane_ack({"generation": 3, "policy_digest": DIGEST})

    publisher._recheck_direct_lane_local_cli(4)
    assert ack.exists()

    publisher._recheck_direct_lane_local_cli(5)
    assert not ack.exists()
    assert publisher._acked is True
    publisher._renew_direct_lane_ack()
    assert not ack.exists()

    # The next publish rebinds the new revision and reopens the lane.
    publisher._direct_lane_local_cli_revision = 5
    publisher._publish_direct_lane_ack({"generation": 4, "policy_digest": DIGEST})
    assert json.loads(ack.read_bytes())["generation"] == 4
    publisher._recheck_direct_lane_local_cli(-1)
    assert not ack.exists()


def test_evidence_drain_binds_only_while_enabled_and_supported(tmp_path: Path) -> None:
    publisher = _publisher(tmp_path)
    ack = publisher._direct_lane_ack_path()
    assert not publisher.direct_evidence_bound([DIRECT_HOOK_EVIDENCE_FEATURE])

    publisher.enable_direct_evidence_drain(True)
    assert publisher.direct_evidence_bound([DIRECT_HOOK_EVIDENCE_FEATURE])
    assert not publisher.direct_evidence_bound(["hook-direct-v1"])

    publisher._acked = True
    publisher._publish_direct_lane_ack({"generation": 3, "policy_digest": DIGEST})
    assert ack.exists()
    publisher.enable_direct_evidence_drain(False)
    assert not ack.exists()
    assert not publisher.direct_evidence_bound([DIRECT_HOOK_EVIDENCE_FEATURE])


def test_a_stopped_drain_rejects_an_in_flight_evidence_ack(tmp_path: Path) -> None:
    publisher = _publisher(tmp_path)
    ack = publisher._direct_lane_ack_path()
    publisher.enable_direct_evidence_drain(True)
    publisher._acked = True
    publisher.enable_direct_evidence_drain(False)
    publisher._publish_direct_lane_ack(
        {"generation": 3, "policy_digest": DIGEST},
        evidence_drain=True,
    )
    assert not ack.exists()
    publisher._renew_direct_lane_ack()
    assert not ack.exists()


def test_evidence_transport_needs_a_resident_with_the_drain(tmp_path: Path) -> None:
    publisher = _publisher(tmp_path)
    assert publisher.direct_evidence_transport() is None

    def client(**_kwargs: object) -> bytes:
        return b""

    status = SimpleNamespace(
        identity=SimpleNamespace(path=str(tmp_path / "guard-runtime")),
        capabilities=SimpleNamespace(features=("hook-direct-v1",)),
    )
    publisher._last_runtime_status = status  # pyright: ignore[reportAttributeAccessIssue]
    publisher._client_request = client  # pyright: ignore[reportAttributeAccessIssue]
    assert publisher.direct_evidence_transport() is None

    status.capabilities.features = ("hook-direct-v1", DIRECT_HOOK_EVIDENCE_FEATURE)
    assert publisher.direct_evidence_transport() == (tmp_path / "guard-runtime", client)


def test_evidence_transport_leaves_a_cold_resident_to_callers_that_budget_a_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import native_resident_client

    publisher = _publisher(tmp_path)
    publisher._last_runtime_status = SimpleNamespace(  # pyright: ignore[reportAttributeAccessIssue]
        identity=SimpleNamespace(path=str(tmp_path / "guard-runtime")),
        capabilities=SimpleNamespace(features=("hook-direct-v1", DIRECT_HOOK_EVIDENCE_FEATURE)),
    )
    ready: list[tuple[Path, Path]] = []
    pooled = False

    def client_ready(executable: Path, guard_home: Path) -> bool:
        ready.append((executable, guard_home))
        return pooled

    monkeypatch.setattr(native_resident_client, "native_resident_client_ready", client_ready)
    assert publisher.direct_evidence_transport() is None
    pooled = True
    assert publisher.direct_evidence_transport() == (
        tmp_path / "guard-runtime",
        native_resident_client.native_resident_client_request,
    )
    assert ready == [(tmp_path / "guard-runtime", tmp_path)] * 2


def test_the_lane_binds_a_home_only_when_the_daemon_gives_hooks_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    publisher = _publisher(tmp_path)
    publishes: list[None] = []
    monkeypatch.setattr(publisher, "request_publish", lambda: publishes.append(None), raising=False)
    resolved = str(home.resolve(strict=False))
    assert publisher._direct_lane_home_dir() == resolved

    publisher.bind_direct_lane_daemon_home(home / ".")
    assert publisher._direct_lane_home_dir() == resolved
    publisher.bind_direct_lane_daemon_home(home)
    assert len(publishes) == 1

    # Hooks without a home would get one `~` does not expand to.
    publisher.bind_direct_lane_daemon_home(tmp_path / "other")
    assert publisher._direct_lane_home_dir() == ""
    assert len(publishes) == 2


def test_the_sink_command_binds_only_for_a_resident_that_routes_containment() -> None:
    binding = {"workspaces": ["/work/repo"], "inputs": []}
    assert contained_sink_command(()) is None
    command = contained_sink_command((DIRECT_HOOK_CONTAINED_ROUTE_FEATURE,))
    assert command is not None

    def bind(sink: tuple[str, ...] | None) -> dict[str, object]:
        bound = with_direct_hook_state(
            binding,
            home_dir="/home/guard",
            harness_postures={},
            local_cli_block_rules=False,
            evidence_drain=False,
            contained_sink_command=sink,
        )
        assert bound is not None
        return bound

    assert bind(command)["contained_sink_command"] == list(command)
    assert "contained_sink_command" not in bind(None)
    # A command the resident would reject is left out, so containment defers.
    for rejected in (
        (),
        ("relative/python",),
        ("/usr/bin/python", ""),
        ("/usr/bin/python", "a\0b"),
        ("/usr/bin/python", "x" * 16_385),
        ("/usr/bin/python", *("-I",) * 8),
    ):
        assert "contained_sink_command" not in bind(rejected)


def test_the_integrity_key_binds_only_for_a_resident_that_answers_permission_notices() -> None:
    calls: list[bool] = []

    class _Store:
        def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
            calls.append(create)
            return b"\x07" * 32, "synthetic:0707"

    assert direct_lane_integrity_key(_Store(), ()) is None
    assert calls == []
    key = direct_lane_integrity_key(_Store(), (DIRECT_HOOK_PERMISSION_NOTICE_FEATURE,))
    assert key == (b"\x07" * 32, "synthetic:0707")
    # The key is read, never minted for the resident.
    assert calls == [False]

    class _Keyless:
        def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
            return None, None

    class _Failing:
        def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes | None, str | None]:
            raise RuntimeError("keyring unavailable")

    for store in (_Keyless(), _Failing(), object()):
        assert direct_lane_integrity_key(store, (DIRECT_HOOK_PERMISSION_NOTICE_FEATURE,)) is None

    def bind(integrity_key: tuple[bytes, str] | None) -> dict[str, object]:
        bound = with_direct_hook_state(
            {"workspaces": ["/work/repo"], "inputs": []},
            home_dir="/home/guard",
            harness_postures={},
            local_cli_block_rules=False,
            evidence_drain=False,
            integrity_key=integrity_key,
        )
        assert bound is not None
        return bound

    bound = bind((b"\x07" * 32, "synthetic:0707"))
    assert bound["integrity_key_b64"] == "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
    assert bound["integrity_key_id"] == "synthetic:0707"
    assert "integrity_key_b64" not in bind(None)
    # A key the resident would reject is left out whole, so notices defer.
    for rejected in (
        (b"", "synthetic:0707"),
        (b"\x07", ""),
        (b"\x07", "a\nb"),
        (b"\x07", "a\x85b"),
        (b"\x07", "k" * 257),
        (b"\x07" * 1537, "synthetic:0707"),
    ):
        assert "integrity_key_b64" not in bind(rejected)
        assert "integrity_key_id" not in bind(rejected)


def test_the_bound_sink_command_starts_the_command_the_daemon_routes(
    containment_resident: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    workspace = tmp_path / "repo"
    workspace.mkdir()
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "pytest -q"}}
    response = {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
        "required_execution_profile": "workspace-contained-v1",
    }
    routed = zcode_contained_tests.route_zcode_containment(
        response,
        harness="claude-code",
        payload=payload,
        guard_home=tmp_path / "guard",
        home_dir=tmp_path,
        workspace=workspace,
    )
    output = routed["hookSpecificOutput"]
    assert isinstance(output, dict)
    argv = shlex.split(output["updatedInput"]["command"])
    prefix = zcode_contained_tests.contained_sink_command_prefix()
    assert argv[: len(prefix)] == list(prefix)
    assert argv[len(prefix) : len(prefix) + 2] == ["guard", "execute-contained-test"]
    request = Path(argv[argv.index("--request-file") + 1])
    request.unlink()
    request.parent.rmdir()
