"""Transport contract for the native directory-trust owner.

Which directories a request may name is settled in
``guard-runtime::directory_trust`` and covered there. These cases prove Python
frames what it read, binds the answer it gets back, reads the verdicts in the
order it asked for them, and refuses a directory whenever the runtime cannot
answer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_directory_trust as module
from codex_plugin_scanner.guard.native_directory_trust import (
    NativeDirectoryTrustError,
    native_directory_trust,
)


def _force_available(monkeypatch: pytest.MonkeyPatch) -> None:
    class Features:
        features = frozenset({module._FEATURE, module._RESIDENT_PROTOCOL_FEATURE})

    class Identity:
        path = "/bin/true"
        sha256 = "0" * 64

    class Status:
        mode = "force"
        available = True
        compatible = True
        identity = Identity()
        capabilities = Features()

    monkeypatch.setattr(module, "_native_runtime_status_memo", lambda: Status())
    monkeypatch.setattr(module, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(module, "native_record_resident_failure", lambda *a, **k: None)
    monkeypatch.setattr(module, "native_record_resident_success", lambda *a, **k: None)
    monkeypatch.setattr(module, "native_record_overload", lambda *a, **k: None)


def _responder(results: list[dict[str, object]], **overrides: object):
    def client(*, payload: bytes, **_kwargs: object) -> bytes:
        envelope = json.loads(payload)
        assert envelope["operation"] == "directory_trust"
        request = envelope["request"]
        document: dict[str, object] = {
            "schema": module._RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + module._canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "canonical_guard_home": request["guard_home"],
            "results": results,
        }
        document.update(overrides)
        return json.dumps(document).encode()

    return client


def test_no_candidates_needs_no_runtime() -> None:
    assert native_directory_trust((), guard_home="/nowhere") == []


def test_an_unavailable_runtime_refuses_every_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    class Status:
        mode = "off"
        available = False
        compatible = False
        identity = None
        capabilities = None

    monkeypatch.setattr(module, "_native_runtime_status_memo", lambda: Status())
    with pytest.raises(NativeDirectoryTrustError, match="unavailable"):
        native_directory_trust([("workspace", "/tmp")], guard_home="/nowhere")


def test_a_runtime_that_cannot_be_reached_refuses_rather_than_trusts(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    for error in (RuntimeError("thread"), OSError("pipe"), TimeoutError("slow")):

        def client(error: Exception = error, **_kwargs: object) -> bytes:
            raise error

        monkeypatch.setattr(module, "native_resident_client_request", client)
        with pytest.raises(NativeDirectoryTrustError, match="unavailable"):
            native_directory_trust([("workspace", "/tmp")], guard_home="/nowhere")


def test_an_answer_bound_to_another_request_settles_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    monkeypatch.setattr(
        module,
        "native_resident_client_request",
        _responder([{"parameter": "workspace", "trusted": True, "path": "/tmp"}], request_sha256="sha256:nope"),
    )
    with pytest.raises(NativeDirectoryTrustError, match="result_invalid"):
        native_directory_trust([("workspace", "/tmp")], guard_home="/nowhere")


@pytest.mark.parametrize(
    "results",
    [
        [],
        [{"parameter": "home", "trusted": True, "path": "/tmp"}],
        [{"parameter": "workspace", "trusted": True}],
        [{"parameter": "workspace", "trusted": False}],
        [{"parameter": "workspace", "trusted": False, "reason": ""}],
    ],
)
def test_a_result_that_does_not_answer_what_was_asked_settles_nothing(
    monkeypatch: pytest.MonkeyPatch, results: list[dict[str, object]]
) -> None:
    _force_available(monkeypatch)
    monkeypatch.setattr(module, "native_resident_client_request", _responder(results))
    with pytest.raises(NativeDirectoryTrustError, match="result_invalid"):
        native_directory_trust([("workspace", "/tmp")], guard_home="/nowhere")


def test_every_candidate_is_settled_in_one_call_and_read_back_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    calls: list[list[dict[str, str]]] = []

    def client(*, payload: bytes, **kwargs: object) -> bytes:
        calls.append(json.loads(payload)["request"]["candidates"])
        return _responder(
            [
                {"parameter": "home", "trusted": True, "path": "/home/someone"},
                {"parameter": "guard-home", "trusted": False, "reason": "unexpected_guard_home"},
                {"parameter": "workspace", "trusted": True, "path": "/home/someone/work"},
            ]
        )(payload=payload, **kwargs)

    monkeypatch.setattr(module, "native_resident_client_request", client)
    verdicts = native_directory_trust(
        [("home", "~"), ("guard-home", "/elsewhere"), ("workspace", "~/work")],
        guard_home="/nowhere",
        home_dir="/home/someone",
    )

    assert len(calls) == 1
    assert [candidate["parameter"] for candidate in calls[0]] == ["home", "guard-home", "workspace"]
    assert [verdict.parameter for verdict in verdicts] == ["home", "guard-home", "workspace"]
    assert [verdict.trusted for verdict in verdicts] == [True, False, True]
    assert verdicts[0].path == "/home/someone"
    assert verdicts[1].reason == "unexpected_guard_home"
    assert verdicts[2].path == "/home/someone/work"


def test_a_path_that_cannot_cross_the_transport_is_not_a_path_to_trust(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    monkeypatch.setattr(module, "native_resident_client_request", _responder([]))
    with pytest.raises(NativeDirectoryTrustError, match="component_unencodable"):
        native_directory_trust([("workspace", "/tmp/\udcff")], guard_home="/nowhere")


def test_a_request_larger_than_the_runtime_accepts_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    monkeypatch.setattr(module, "native_resident_client_request", _responder([]))
    oversized = [("workspace", "/tmp/" + "x" * 1024) for _ in range(128)]
    with pytest.raises(NativeDirectoryTrustError, match="request_too_large"):
        native_directory_trust(oversized, guard_home="/nowhere")


def test_an_overloaded_runtime_is_recorded_as_overload(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    overloads: list[object] = []
    monkeypatch.setattr(module, "native_record_overload", lambda *a, **k: overloads.append(a))
    monkeypatch.setattr(
        module,
        "native_resident_client_request",
        lambda **_: json.dumps({"error": "native_overloaded"}).encode(),
    )
    with pytest.raises(NativeDirectoryTrustError, match="native_overloaded"):
        native_directory_trust([("workspace", "/tmp")], guard_home=Path("/nowhere"))
    assert overloads


def test_an_expired_hook_deadline_skips_the_transport_and_health_accounting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_available(monkeypatch)
    failures: list[object] = []
    monkeypatch.setattr(module, "native_record_resident_failure", lambda *args, **kwargs: failures.append(args))

    def must_not_call(**_kwargs: object) -> bytes:
        raise AssertionError("expired requests must never reach the resident")

    monkeypatch.setattr(module, "native_resident_client_request", must_not_call)
    with pytest.raises(NativeDirectoryTrustError, match="unavailable"):
        native_directory_trust(
            [("workspace", "/tmp")],
            guard_home="/nowhere",
            deadline_monotonic=module.time.monotonic() - 1,
        )
    assert not failures


def test_caller_budget_timeout_does_not_count_as_resident_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_available(monkeypatch)
    failures: list[object] = []
    monkeypatch.setattr(module, "native_record_resident_failure", lambda *args, **kwargs: failures.append(args))

    def slow_client(**_kwargs: object) -> None:
        module.time.sleep(0.1)
        return None

    monkeypatch.setattr(module, "native_resident_client_request", slow_client)
    with pytest.raises(NativeDirectoryTrustError, match="unavailable"):
        native_directory_trust(
            [("workspace", "/tmp")],
            guard_home="/nowhere",
            deadline_monotonic=module.time.monotonic() + 0.05,
        )
    assert not failures


def _counting_responder(results: list[dict[str, object]], asks: list[int]):
    answer = _responder(results)

    def client(**kwargs: object) -> bytes:
        asks[0] += 1
        return answer(**kwargs)  # type: ignore[arg-type]

    return client


def _install(tmp_path: Path) -> tuple[Path, Path, Path]:
    home = tmp_path / "home"
    guard_home = home / ".hol-guard"
    workspace = home / "project"
    for directory in (home, guard_home, workspace):
        directory.mkdir(parents=True, exist_ok=True)
    return home, guard_home, workspace


def test_an_unchanged_directory_is_not_settled_twice(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The runtime answers once; the same question about the same directory reuses it."""

    _force_available(monkeypatch)
    home, guard_home, workspace = _install(tmp_path)
    asks = [0]
    monkeypatch.setattr(
        module,
        "native_resident_client_request",
        _counting_responder([{"parameter": "workspace", "trusted": True, "path": str(workspace)}], asks),
    )

    def ask() -> list[module.DirectoryTrustVerdict]:
        return native_directory_trust([("workspace", str(workspace))], guard_home=guard_home, home_dir=home)

    first = ask()
    assert [(verdict.parameter, verdict.path) for verdict in first] == [("workspace", str(workspace))]
    assert asks == [1]
    second = ask()
    assert [(verdict.parameter, verdict.path) for verdict in second] == [("workspace", str(workspace))]
    assert asks == [1]


def test_a_replaced_directory_is_settled_again(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A remembered answer stands for the directory it was about, not for its name."""

    _force_available(monkeypatch)
    home, guard_home, workspace = _install(tmp_path)
    asks = [0]
    monkeypatch.setattr(
        module,
        "native_resident_client_request",
        _counting_responder([{"parameter": "workspace", "trusted": True, "path": str(workspace)}], asks),
    )
    native_directory_trust([("workspace", str(workspace))], guard_home=guard_home, home_dir=home)
    assert asks == [1]
    workspace.rmdir()
    (tmp_path / "elsewhere").mkdir()
    workspace.symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    native_directory_trust([("workspace", str(workspace))], guard_home=guard_home, home_dir=home)
    assert asks == [2]


def test_a_refused_directory_is_asked_about_every_time(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Only an admission is remembered, so a refusal can never outlive its reason."""

    _force_available(monkeypatch)
    home, guard_home, workspace = _install(tmp_path)
    asks = [0]
    monkeypatch.setattr(
        module,
        "native_resident_client_request",
        _counting_responder([{"parameter": "workspace", "trusted": False, "reason": "unexpected_root"}], asks),
    )
    for expected in (1, 2, 3):
        verdicts = native_directory_trust([("workspace", str(workspace))], guard_home=guard_home, home_dir=home)
        assert [verdict.reason for verdict in verdicts] == ["unexpected_root"]
        assert asks == [expected]


def test_a_spelling_this_process_must_not_resolve_is_never_remembered(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``~`` and relative spellings mean whatever the runtime expands them to."""

    _force_available(monkeypatch)
    home, guard_home, workspace = _install(tmp_path)
    asks = [0]
    monkeypatch.setattr(
        module,
        "native_resident_client_request",
        _counting_responder([{"parameter": "workspace", "trusted": True, "path": str(workspace)}], asks),
    )
    for expected in (1, 2):
        native_directory_trust([("workspace", "~/project")], guard_home=guard_home, home_dir=home)
        assert asks == [expected]


def test_a_spelling_that_hides_a_component_is_never_remembered(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """A `..` segment resolves on disk but normalizes away lexically.

    The witness walks the components a spelling writes down, so a spelling
    whose `..` steps back through a symlink would be witnessed without that
    link and would keep answering after the link was repointed. Such a
    spelling is not remembered at all.
    """

    _force_available(monkeypatch)
    home, guard_home, workspace = _install(tmp_path)
    (home / "link").symlink_to(workspace, target_is_directory=True)
    spelling = f"{home}/link/../project"
    asks = [0]
    monkeypatch.setattr(
        module,
        "native_resident_client_request",
        _counting_responder([{"parameter": "workspace", "trusted": True, "path": str(workspace)}], asks),
    )

    def ask() -> list[module.DirectoryTrustVerdict]:
        return native_directory_trust([("workspace", spelling)], guard_home=guard_home, home_dir=home)

    assert ask()[0].path == str(workspace)
    assert ask()[0].path == str(workspace)
    assert asks == [2]
