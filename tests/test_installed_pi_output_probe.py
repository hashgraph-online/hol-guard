"""Unit coverage for the installed Pi/native output probe contract."""

from __future__ import annotations

import base64
import json
import threading
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.native_runtime import probe_installed_pi_output as probe
from ci.native_runtime.probe_installed_pi_output import (
    ProbeCleanupError,
    ProbeCleanupUnsafeError,
    ProbeError,
    _assert_fetch_evidence,
    _assert_native_route_metrics,
    _assert_negative_results,
    _assert_no_positive_cli_fallback,
    _assert_real_results,
    _canonical_content_digest,
    _cases,
    _installed_package_path,
    _is_source_checkout_package,
    _negative_cases,
    _prepare_installed_daemon_workspace,
    _probe_python_path,
    _retain_cleanup_receipt,
    _retain_private_native_retry_state,
    _retain_unsafe_cleanup_marker,
    _run_probe,
    _start_installed_daemon,
    _text_digest,
)
from codex_plugin_scanner.guard import store as store_module
from codex_plugin_scanner.guard.daemon import server as daemon_server


def _record(
    case: dict[str, object],
    response: dict[str, object] | None,
    *,
    returncode: int = 0,
) -> dict[str, object]:
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_call_id": case["id"],
        "tool_response": case["content"],
    }
    stdout = b"" if response is None else (json.dumps(response) + "\n").encode("utf-8")
    return {
        "case_id": case["id"],
        "returncode": returncode,
        "stdin_b64": base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii"),
        "stdout_b64": base64.b64encode(stdout).decode("ascii"),
        "stderr_b64": base64.b64encode(b"").decode("ascii"),
    }


def _preserved_result(case: dict[str, object]) -> dict[str, object]:
    digest = _canonical_content_digest(case["content"])
    return {
        "id": case["id"],
        "preserved": True,
        "result": None,
        "input_content_before_sha256": digest,
        "input_content_after_sha256": digest,
        "input_content_unchanged": True,
    }


def test_installed_origin_guard_rejects_checkout_package_only(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    checkout_package = repo_root / "src" / "codex_plugin_scanner" / "__init__.py"
    wheel_package = tmp_path / "venv" / "lib" / "site-packages" / "codex_plugin_scanner" / "__init__.py"

    assert _is_source_checkout_package(checkout_package, repo_root)
    assert not _is_source_checkout_package(wheel_package, repo_root)


def test_installed_origin_requires_manifest_membership_and_noneditable_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    site_packages = tmp_path / "site-packages"
    package_file = site_packages / "codex_plugin_scanner" / "__init__.py"
    package_file.parent.mkdir(parents=True)
    package_file.write_text("", encoding="utf-8")
    direct_url = None

    class Distribution:
        files = (Path("codex_plugin_scanner/__init__.py"),)

        def locate_file(self, path: Path) -> Path:
            return site_packages / path

        def read_text(self, name: str) -> str | None:
            assert name == "direct_url.json"
            return direct_url

    monkeypatch.setattr(
        probe.importlib,
        "import_module",
        lambda name: SimpleNamespace(__file__=str(package_file)),
    )
    monkeypatch.setattr(probe.metadata, "distribution", lambda name: Distribution())

    assert _installed_package_path(tmp_path / "checkout") == package_file

    direct_url = json.dumps({"dir_info": {"editable": True}})
    with pytest.raises(ProbeError, match="editable"):
        _installed_package_path(tmp_path / "checkout")

    for invalid in (
        "",
        "[]",
        json.dumps({"dir_info": []}),
        json.dumps({"dir_info": {"editable": "true"}}),
        "not-json",
    ):
        direct_url = invalid
        with pytest.raises(ProbeError, match=r"direct URL metadata|editable"):
            _installed_package_path(tmp_path / "checkout")


def test_installed_origin_rejects_module_outside_distribution_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    package_file = tmp_path / "site-packages" / "codex_plugin_scanner" / "__init__.py"
    package_file.parent.mkdir(parents=True)
    package_file.write_text("", encoding="utf-8")
    (tmp_path / "site-packages" / "other_package").mkdir()
    (tmp_path / "site-packages" / "other_package" / "__init__.py").write_text("", encoding="utf-8")

    class Distribution:
        files = (Path("other_package/__init__.py"),)

        def locate_file(self, path: Path) -> Path:
            return tmp_path / "site-packages" / path

        def read_text(self, name: str) -> None:
            return None

    monkeypatch.setattr(
        probe.importlib,
        "import_module",
        lambda name: SimpleNamespace(__file__=str(package_file)),
    )
    monkeypatch.setattr(probe.metadata, "distribution", lambda name: Distribution())

    with pytest.raises(ProbeError, match="outside the hol-guard distribution manifest"):
        _installed_package_path(tmp_path / "checkout")


def test_installed_origin_rejects_symlinked_module_and_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    site_packages = tmp_path / "site-packages"
    package_dir = site_packages / "codex_plugin_scanner"
    package_dir.mkdir(parents=True)
    target = site_packages / "real.py"
    target.write_text("", encoding="utf-8")
    package_file = package_dir / "__init__.py"
    package_file.symlink_to(target)

    class Distribution:
        files = (Path("codex_plugin_scanner/__init__.py"),)

        def locate_file(self, path: Path) -> Path:
            return site_packages / path

        def read_text(self, name: str) -> None:
            return None

    monkeypatch.setattr(
        probe.importlib,
        "import_module",
        lambda name: SimpleNamespace(__file__=str(package_file)),
    )
    monkeypatch.setattr(probe.metadata, "distribution", lambda name: Distribution())

    with pytest.raises(ProbeError, match="module is symlinked"):
        _installed_package_path(tmp_path / "checkout")

    package_file.unlink()
    package_file.write_text("", encoding="utf-8")
    manifest_target = site_packages / "manifest-target.py"
    manifest_target.write_text("", encoding="utf-8")
    manifest_link = site_packages / "manifest-link.py"
    manifest_link.symlink_to(manifest_target)

    class SymlinkManifestDistribution(Distribution):
        def locate_file(self, path: Path) -> Path:
            return manifest_link

    monkeypatch.setattr(probe.metadata, "distribution", lambda name: SymlinkManifestDistribution())
    with pytest.raises(ProbeError, match="manifest contains a symlink"):
        _installed_package_path(tmp_path / "checkout")


def test_probe_keeps_venv_launcher_path_unresolved(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    launcher = tmp_path / "venv" / "bin" / ".." / "python"
    monkeypatch.setattr(probe.sys, "executable", str(launcher))

    assert _probe_python_path() == launcher
    assert _probe_python_path() != launcher.resolve()


def _patch_node_capability_probe(
    monkeypatch: pytest.MonkeyPatch,
    returncodes: list[int],
    markers: list[bytes] | None = None,
) -> list[list[str]]:
    attempts: list[list[str]] = []
    markers = markers or [b"node-capability-probe"] * len(returncodes)
    assert len(markers) == len(returncodes)
    monkeypatch.setattr(probe.shutil, "which", lambda _: "/usr/bin/node")

    def fake_run(argv: list[str], **kwargs: object) -> SimpleNamespace:
        module = Path(argv[-1])
        assert module.suffix == ".ts"
        assert ": string" in module.read_text(encoding="utf-8")
        assert kwargs["timeout"] == probe._NODE_PROBE_TIMEOUT
        attempts.append(argv)
        index = len(attempts) - 1
        return SimpleNamespace(returncode=returncodes[index], stdout=markers[index])

    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    return attempts


def test_node_command_prefers_experimental_type_stripping(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = _patch_node_capability_probe(monkeypatch, [0])

    assert probe._node_command() == ["/usr/bin/node", "--no-warnings", "--experimental-strip-types"]
    assert len(attempts) == 1
    assert "--experimental-strip-types" in attempts[0]
    assert not Path(attempts[0][-1]).exists()


def test_node_command_falls_back_to_stable_type_stripping(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = _patch_node_capability_probe(monkeypatch, [1, 0])

    assert probe._node_command() == ["/usr/bin/node", "--no-warnings"]
    assert len(attempts) == 2
    assert "--experimental-strip-types" in attempts[0]
    assert "--experimental-strip-types" not in attempts[1]
    assert all(not Path(attempt[-1]).exists() for attempt in attempts)


def test_node_command_falls_back_after_wrong_experimental_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = _patch_node_capability_probe(monkeypatch, [0, 0], [b"wrong-marker", b"node-capability-probe"])

    assert probe._node_command() == ["/usr/bin/node", "--no-warnings"]
    assert len(attempts) == 2
    assert "--experimental-strip-types" in attempts[0]
    assert "--experimental-strip-types" not in attempts[1]
    assert all(not Path(attempt[-1]).exists() for attempt in attempts)


def test_node_command_rejects_unsupported_type_stripping(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = _patch_node_capability_probe(monkeypatch, [1, 1])

    with pytest.raises(ProbeError, match="cannot execute erasable TypeScript"):
        probe._node_command()

    assert len(attempts) == 2
    assert all(not Path(attempt[-1]).exists() for attempt in attempts)


def test_node_command_rejects_wrong_markers_on_both_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = _patch_node_capability_probe(monkeypatch, [0, 0], [b"wrong-marker", b"also-wrong"])

    with pytest.raises(ProbeError, match="cannot execute erasable TypeScript"):
        probe._node_command()

    assert len(attempts) == 2
    assert all(not Path(attempt[-1]).exists() for attempt in attempts)


def test_case_digest_preserves_crlf_unicode_and_ignores_metadata() -> None:
    case = _cases()[2]
    digest, chars, excerpt = _text_digest(case["content"])

    assert chars == len("first line\r\nsecond line: \U0001f600\n")
    assert excerpt == "first line\r\nsecond line: \U0001f600\n"
    assert len(digest) == 64


def test_real_validation_requires_status_zero_and_exact_full_proof() -> None:
    case = _cases()[0]
    digest, _, _ = _text_digest(case["content"])
    result = _preserved_result(case)
    valid_fetch = {
        "case_id": case["id"],
        "method": "POST",
        "pathname": "/v1/hooks/omp",
        "status": 200,
        "decision": "allow",
        "model_output_action": "allow_original",
        "reviewed_output_sha256": digest,
    }

    evidence = _assert_real_results([result], [case])
    fetch_evidence = _assert_fetch_evidence([valid_fetch], [result], [case])
    fetch_status = fetch_evidence[str(case["id"])]["status"]
    assert fetch_status == 200
    assert evidence[str(case["id"])]["preserved"] is True

    mutated = deepcopy(result)
    mutated["input_content_after_sha256"] = "0" * 64
    with pytest.raises(ProbeError, match="mutated the canonical input event"):
        _assert_real_results([mutated], [case])

    nonzero = deepcopy(valid_fetch)
    nonzero["status"] = 500
    with pytest.raises(ProbeError, match="not successful"):
        _assert_fetch_evidence([nonzero], [result], [case])

    mismatched = deepcopy(valid_fetch)
    mismatched["reviewed_output_sha256"] = "0" * 64
    with pytest.raises(ProbeError, match="proof mismatch"):
        _assert_fetch_evidence([mismatched], [result], [case])

    sensitive = deepcopy(valid_fetch)
    sensitive["headers"] = {"X-Guard-Token": "secret"}
    with pytest.raises(ProbeError, match="unapproved fields"):
        _assert_fetch_evidence([sensitive], [result], [case])


def test_large_non_source_accepts_only_bounded_reviewed_excerpt() -> None:
    case = _cases()[3]
    _, _, excerpt = _text_digest(case["content"])
    result = _preserved_result(case)
    result.update(
        {
            "preserved": False,
            "result": {"content": [{"type": "text", "text": excerpt}]},
        }
    )
    fetch = {
        "case_id": case["id"],
        "method": "POST",
        "pathname": "/v1/hooks/omp",
        "status": 200,
        "decision": "allow",
        "model_output_action": "replace_with_reviewed_excerpt",
    }

    evidence = _assert_real_results([result], [case])
    assert evidence[str(case["id"])]["preserved"] is False

    fetch_status = _assert_fetch_evidence([fetch], [result], [case])[str(case["id"])]["status"]
    assert fetch_status == 200

    arbitrary_excerpt = deepcopy(result)
    arbitrary_excerpt["result"]["content"][0]["text"] = "x" * len(excerpt)
    with pytest.raises(ProbeError, match="exact bounded reviewed excerpt"):
        _assert_real_results([arbitrary_excerpt], [case])

    mutated_input = deepcopy(result)
    mutated_input["input_content_before_sha256"] = "0" * 64
    with pytest.raises(ProbeError, match="mutated the canonical input event"):
        _assert_real_results([mutated_input], [case])


def test_result_validators_reject_duplicate_case_ids() -> None:
    real_cases = _cases()[:2]
    duplicate_real = [_preserved_result(real_cases[0]), _preserved_result(real_cases[0])]
    with pytest.raises(ProbeError, match="duplicate real case IDs"):
        _assert_real_results(duplicate_real, real_cases)

    negative_cases = _negative_cases()
    duplicate_negative = [
        {"id": negative_cases[0]["id"], "preserved": False, "result": {"isError": True}} for _ in negative_cases
    ]
    with pytest.raises(ProbeError, match="duplicate malformed-result case IDs"):
        _assert_negative_results(duplicate_negative, {})


def test_fetch_evidence_correlates_case_ids_instead_of_position() -> None:
    cases = _cases()[:2]
    results = [_preserved_result(case) for case in cases]
    digest = [_text_digest(case["content"])[0] for case in cases]
    fetches = [
        {
            "case_id": cases[0]["id"],
            "method": "POST",
            "pathname": "/v1/hooks/omp",
            "status": 200,
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": digest[0],
        },
        {
            "case_id": cases[0]["id"],
            "method": "POST",
            "pathname": "/v1/hooks/omp",
            "status": 200,
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": digest[1],
        },
    ]
    with pytest.raises(ProbeError, match="exactly one response"):
        _assert_fetch_evidence(fetches, results, cases)


def test_installed_daemon_readiness_requires_workspace_policy() -> None:
    workspace = Path("/tmp/probe-readiness-workspace")
    deadlines: list[float] = []

    class Worker:
        def prepare_workspace_policy(self, path: Path, *, deadline: float) -> object:
            assert path == workspace
            deadlines.append(deadline)
            return {"workspace": str(path)}

    daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=Worker()))
    assert _prepare_installed_daemon_workspace(daemon, workspace) == {"workspace": str(workspace)}
    assert deadlines and 0 < deadlines[0] - probe.time.monotonic() <= probe._DAEMON_READINESS_TIMEOUT

    class EmptyWorker:
        def prepare_workspace_policy(self, path: Path, *, deadline: float) -> None:
            return None

    with pytest.raises(ProbeError, match="workspace policy was not ready"):
        _prepare_installed_daemon_workspace(
            SimpleNamespace(_server=SimpleNamespace(hook_worker=EmptyWorker())), workspace
        )


def test_native_route_metrics_require_only_resident_positive_cases() -> None:
    assert _assert_native_route_metrics({"routes": {"native_resident": 4}}, 4) == {"native_resident": 4}

    with pytest.raises(ProbeError, match="not all native_resident"):
        _assert_native_route_metrics({"routes": {"native_resident": 3, "native_oneshot": 1}}, 4)


def test_positive_probe_accepts_only_absent_cli_fallback_log(tmp_path: Path) -> None:
    log = tmp_path / "real-cli.jsonl"
    _assert_no_positive_cli_fallback(log)
    log.write_text("fallback\n", encoding="utf-8")
    with pytest.raises(ProbeError, match="CLI fallback"):
        _assert_no_positive_cli_fallback(log)


def test_cleanup_failure_scrubs_raw_probe_captures(tmp_path: Path) -> None:
    root = tmp_path / "probe-root"
    root.mkdir()
    native_state = root / "guard-home" / "native-runtime"
    native_state.mkdir(parents=True)
    state_file = native_state / "generation-state.json"
    state_file.write_text("scoped state", encoding="utf-8")
    state_file.chmod(0o600)
    (root / "real-cli.jsonl").write_text('{"stdout_b64":"raw-capture"}\n', encoding="utf-8")
    (root / "stderr.txt").write_text("raw stderr", encoding="utf-8")

    _retain_cleanup_receipt(root, ProbeError("raw failure detail"))

    assert sorted(path.name for path in root.iterdir()) == ["cleanup-failure.json", "guard-home"]
    assert (native_state / "generation-state.json").read_text(encoding="utf-8") == "scoped state"
    marker = json.loads((root / "cleanup-failure.json").read_text(encoding="utf-8"))
    assert marker == {
        "error_type": "ProbeError",
        "private_native_retry_state_retained": True,
        "probe_root": str(root),
        "remaining_nonretry_paths": 0,
        "retry_required": True,
        "scrub_complete": True,
        "scrub_failures": 0,
        "schema": "hol-guard.installed-pi-cleanup-failure.v1",
    }
    assert native_state.stat().st_mode & 0o777 == 0o700
    assert "raw" not in (root / "cleanup-failure.json").read_text(encoding="utf-8")


def test_private_native_retry_state_rejects_unsafe_entries(tmp_path: Path) -> None:
    root = tmp_path / "probe-root"
    native_state = root / "guard-home" / "native-runtime"
    native_state.mkdir(parents=True)
    state_file = native_state / "generation-state.json"
    state_file.write_text("scoped state", encoding="utf-8")

    assert _retain_private_native_retry_state(root) is False

    state_file.chmod(0o600)
    assert _retain_private_native_retry_state(root) is True

    nested = native_state / "nested"
    nested.mkdir(mode=0o700)
    nested_file = nested / "state.json"
    nested_file.write_text("nested", encoding="utf-8")
    nested_file.chmod(0o600)
    assert _retain_private_native_retry_state(root) is True

    nested_file.unlink()
    nested_file.symlink_to(state_file)
    assert _retain_private_native_retry_state(root) is False


def test_installed_daemon_cleanup_failure_is_redacted() -> None:
    class FailingDaemon:
        def stop(self) -> None:
            raise RuntimeError("secret daemon detail")

    with pytest.raises(
        ProbeCleanupUnsafeError,
        match="authenticated Guard daemon cleanup failed: RuntimeError",
    ) as caught:
        probe._cleanup_installed_daemon(FailingDaemon())

    assert "secret daemon detail" not in str(caught.value)

    class FailingFinishDaemon:
        def stop(self) -> None:
            pass

        def _finish_service(self) -> bool:
            raise RuntimeError("secret finish detail")

    with pytest.raises(
        ProbeCleanupUnsafeError,
        match="authenticated Guard daemon _finish_service failed: RuntimeError",
    ):
        probe._cleanup_installed_daemon(FailingFinishDaemon())


def test_installed_daemon_cleanup_rejects_unconfirmed_quarantine() -> None:
    calls: list[str] = []

    class QuarantinedDaemon:
        def stop(self) -> None:
            calls.append("stop")

        def _finish_service(self) -> bool:
            calls.append("finish")
            return False

        def _is_quarantined(self) -> bool:
            calls.append("quarantined")
            return True

    with pytest.raises(ProbeCleanupUnsafeError, match="containment was not confirmed"):
        probe._cleanup_installed_daemon(QuarantinedDaemon())
    assert calls == ["stop", "finish"]

    class StillQuarantinedDaemon:
        def stop(self) -> None:
            pass

        def _finish_service(self) -> bool:
            return True

        def _is_quarantined(self) -> bool:
            return True

    with pytest.raises(ProbeCleanupUnsafeError, match="remained quarantined"):
        probe._cleanup_installed_daemon(StillQuarantinedDaemon())

    class LiveServeThreadDaemon:
        _thread = SimpleNamespace(is_alive=lambda: True)

        def stop(self) -> None:
            pass

        def _finish_service(self) -> bool:
            return True

        def _is_quarantined(self) -> bool:
            return False

    with pytest.raises(ProbeCleanupUnsafeError, match="serve thread remained alive"):
        probe._cleanup_installed_daemon(LiveServeThreadDaemon())


def test_installed_daemon_cleanup_bounds_stop(monkeypatch: pytest.MonkeyPatch) -> None:
    release = threading.Event()

    class HangingDaemon:
        finished = False

        def stop(self) -> None:
            release.wait()
            self.finished = True

    monkeypatch.setattr(probe, "_DAEMON_CLEANUP_TIMEOUT", 0.01)
    daemon = HangingDaemon()
    try:
        with pytest.raises(ProbeError, match="stop timed out"):
            probe._cleanup_installed_daemon(daemon)
        assert daemon.finished is False
    finally:
        release.set()


def test_daemon_constructor_failure_closes_public_resources_and_stays_unsafe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[str] = []

    class Publisher:
        def close(self) -> None:
            calls.append("publisher")

    class Store:
        policy_snapshot_publisher = Publisher()

        def close(self) -> None:
            calls.append("store")

    def make_store(*args: object, **kwargs: object) -> Store:
        return Store()

    def fail_daemon(*args: object, **kwargs: object) -> object:
        raise RuntimeError("constructor failed")

    monkeypatch.setattr(store_module, "GuardStore", make_store)
    monkeypatch.setattr(daemon_server, "GuardDaemonServer", fail_daemon)
    native_cleanup_called = False

    def unexpected_native_cleanup(identity: object, guard_home: Path) -> None:
        nonlocal native_cleanup_called
        native_cleanup_called = True

    monkeypatch.setattr(probe, "_cleanup_native", unexpected_native_cleanup)

    with pytest.raises(ProbeCleanupUnsafeError, match="startup cleanup failed"):
        _start_installed_daemon(
            guard_home=tmp_path / "guard-home",
            home=tmp_path / "home",
            workspace=tmp_path / "workspace",
            identity=SimpleNamespace(path=Path("/bin/false")),
        )

    assert calls == ["store", "publisher"]
    assert native_cleanup_called is False


def test_bounded_daemon_call_redelivers_expired_prior_timer(monkeypatch: pytest.MonkeyPatch) -> None:
    timer_calls: list[tuple[object, ...]] = []
    monotonic_values = iter((0.0, 0.02))
    monkeypatch.setattr(probe.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(probe.signal, "getsignal", lambda _signal: "previous-handler")
    monkeypatch.setattr(probe.signal, "getitimer", lambda _timer: (0.01, 0.02))
    monkeypatch.setattr(probe.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(probe.signal, "setitimer", lambda *args: timer_calls.append(args))

    probe._bounded_daemon_call(SimpleNamespace(stop=lambda: None), "stop")

    assert timer_calls[0] == (probe.signal.ITIMER_REAL, probe._DAEMON_CLEANUP_TIMEOUT)
    assert timer_calls[1] == (probe.signal.ITIMER_REAL, 0)
    assert timer_calls[2] == (probe.signal.ITIMER_REAL, 0.001, 0.02)


def test_bounded_daemon_call_restores_alarm_after_setup_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    timer_calls: list[tuple[object, ...]] = []
    signal_calls: list[object] = []

    monkeypatch.setattr(probe.signal, "getsignal", lambda _signal: "previous-handler")
    monkeypatch.setattr(probe.signal, "getitimer", lambda _timer: (0.5, 0.25))

    def setitimer(*args: object) -> None:
        timer_calls.append(args)
        if len(timer_calls) == 1:
            raise RuntimeError("timer setup failed")

    monkeypatch.setattr(probe.signal, "setitimer", setitimer)
    monkeypatch.setattr(probe.signal, "signal", lambda _signal, handler: signal_calls.append(handler))
    invoked = False

    def stop() -> None:
        nonlocal invoked
        invoked = True

    with pytest.raises(ProbeError, match="authenticated Guard daemon cleanup failed: RuntimeError"):
        probe._bounded_daemon_call(SimpleNamespace(stop=stop), "stop")

    assert invoked is False
    assert len(signal_calls) == 2
    assert signal_calls[1] == "previous-handler"
    assert timer_calls[:2] == [
        (probe.signal.ITIMER_REAL, probe._DAEMON_CLEANUP_TIMEOUT),
        (probe.signal.ITIMER_REAL, 0),
    ]
    assert timer_calls[2][0:2] == (probe.signal.ITIMER_REAL, pytest.approx(0.5, abs=0.001))
    assert timer_calls[2][2] == 0.25


def test_unsafe_cleanup_marker_preserves_mutable_root_without_scrubbing(tmp_path: Path) -> None:
    root = tmp_path / "probe-root"
    root.mkdir()
    raw_capture = root / "real-cli.jsonl"
    raw_capture.write_text("raw capture", encoding="utf-8")

    _retain_unsafe_cleanup_marker(root, ProbeCleanupError("timeout"))

    assert raw_capture.exists()
    assert (root / "cleanup-failure.json").exists()
    assert root.stat().st_mode & 0o777 == 0o700
    marker = json.loads((root / "cleanup-failure.json").read_text(encoding="utf-8"))
    assert marker["cleanup_deferred"] is True
    assert marker["private_native_retry_state_retained"] is False


def test_cleanup_scrub_failure_is_redacted_and_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "probe-root"
    root.mkdir()
    raw_capture = root / "real-cli.jsonl"
    raw_capture.write_text('{"stdout_b64":"secret-capture"}\n', encoding="utf-8")
    original_remove = probe._remove_probe_path

    def refuse_raw_capture(path: Path) -> bool:
        if path == raw_capture:
            return False
        return original_remove(path)

    monkeypatch.setattr(probe, "_remove_probe_path", refuse_raw_capture)

    with pytest.raises(ProbeError, match="scrub could not be confirmed") as caught:
        _retain_cleanup_receipt(root, ProbeError("secret failure detail"))

    assert "secret" not in str(caught.value)
    marker_text = (root / "cleanup-failure.json").read_text(encoding="utf-8")
    marker = json.loads(marker_text)
    assert marker["scrub_complete"] is False
    assert marker["scrub_failures"] == 1
    assert marker["remaining_nonretry_paths"] == 1
    assert "secret-capture" not in marker_text
    assert raw_capture.exists()


def test_cleanup_failure_does_not_write_success_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "probe-root"
    root.mkdir()
    receipt_path = tmp_path / "installed-pi-output.json"
    status = SimpleNamespace(mode="auto", reason="native_ready")
    identity = SimpleNamespace(path=Path("/bin/false"), sha256="runtime-sha")
    capabilities = SimpleNamespace(build_sha="source-sha", target="test", runtime_version="test")

    monkeypatch.setattr("ci.native_runtime.probe_installed_pi_output.tempfile.mkdtemp", lambda **_: str(root))
    monkeypatch.setattr("ci.native_runtime.probe_installed_pi_output._installed_package_path", lambda _: root)
    monkeypatch.setattr(
        "ci.native_runtime.probe_installed_pi_output._probe_native_identity",
        lambda: (status, identity, capabilities),
    )
    monkeypatch.setattr("ci.native_runtime.probe_installed_pi_output._node_command", lambda: ["node"])
    monkeypatch.setattr(
        "ci.native_runtime.probe_installed_pi_output._start_installed_daemon", lambda **kwargs: object()
    )
    monkeypatch.setattr(
        "ci.native_runtime.probe_installed_pi_output._write_node_runner", lambda path: path.write_text("")
    )
    monkeypatch.setattr(
        "ci.native_runtime.probe_installed_pi_output._generate_extension", lambda path, **kwargs: path.write_text("")
    )
    monkeypatch.setattr(
        "ci.native_runtime.probe_installed_pi_output._run_node_cases",
        lambda **kwargs: (_ for _ in ()).throw(ProbeError("real probe failed")),
    )
    monkeypatch.setattr(
        "ci.native_runtime.probe_installed_pi_output._cleanup_native",
        lambda identity, guard_home: (_ for _ in ()).throw(ProbeError("cleanup failed")),
    )
    monkeypatch.setattr(
        "ci.native_runtime.probe_installed_pi_output._cleanup_installed_daemon",
        lambda daemon: None,
    )

    with pytest.raises(ProbeError, match="cleanup failed"):
        _run_probe(json_path=receipt_path)

    assert not receipt_path.exists()
    assert (root / "cleanup-failure.json").exists()
    assert not (root / "real-cli.jsonl").exists()


def test_malformed_results_are_visible_blocks_but_observe_remains_preserved() -> None:
    cases = _negative_cases()
    results = []
    records = {}
    for case in cases:
        observe = case["id"] == "negative-observe"
        response = {"decision": "allow", "observe_mode": True} if observe else None
        results.append(
            {
                "id": case["id"],
                "preserved": observe,
                "result": None if observe else {"isError": True},
            }
        )
        records[str(case["id"])] = [
            _record(case, response, returncode=2 if case["id"] == "negative-nonzero-allow" else 0)
        ]

    evidence = _assert_negative_results(results, records)
    assert evidence["negative-observe"]["preserved"] is True
    assert evidence["negative-empty"]["is_error"] is True

    malformed_allow = next(result for result in results if result["id"] == "negative-malformed")
    malformed_allow["preserved"] = True
    with pytest.raises(ProbeError, match="silently preserved"):
        _assert_negative_results(results, records)

    observe_case = next(case for case in cases if case["id"] == "negative-observe")
    for malformed in ({"decision": "allow"}, {"decision": "allow", "observe_mode": "yes"}):
        malformed_records = deepcopy(records)
        malformed_results = deepcopy(results)
        next(result for result in malformed_results if result["id"] == "negative-malformed")["preserved"] = False
        malformed_records["negative-observe"] = [_record(observe_case, malformed)]
        with pytest.raises(ProbeError, match="canonical allow metadata"):
            _assert_negative_results(malformed_results, malformed_records)
