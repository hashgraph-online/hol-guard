"""Transport contract and recorded parity for the native false-positive rules owner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_false_positive_rules as module
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.native_false_positive_rules import (
    NativeFalsePositiveRulesError,
    native_false_positive_signals,
)
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.detectors import DetectorContext, FalsePositiveSuppressorDetector

_VECTORS = Path(__file__).parent / "fixtures" / "false_positive_rules" / "parity_vectors.json"


def _vectors() -> list[dict[str, object]]:
    payload = json.loads(_VECTORS.read_text(encoding="utf-8"))
    assert payload["schema"] == "guard-false-positive-rules-parity-vectors.v1"
    return payload["vectors"]


def _action(action_type: str, command: str | None, paths: list[str]) -> GuardActionEnvelope:
    return GuardActionEnvelope(
        schema_version=1,
        action_id="fp-parity",
        harness="codex",
        event_name="PreToolUse",
        action_type=action_type,  # type: ignore[arg-type]
        workspace="/repo",
        workspace_hash="workspace-hash",
        tool_name="Bash",
        command=command,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=tuple(paths),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
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


def _signals(**overrides: object) -> list[dict[str, object]]:
    arguments: dict[str, object] = {"action_type": "shell_command", "command": "ls", "target_paths": ()}
    arguments.update(overrides)
    return native_false_positive_signals(**arguments)  # type: ignore[arg-type]


def test_recorded_python_outputs_match_the_resident(tmp_path: Path) -> None:
    detector = FalsePositiveSuppressorDetector()
    context = DetectorContext(
        config=GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace"),
        workspace=tmp_path / "workspace",
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )
    vectors = _vectors()
    assert len(vectors) > 400
    mismatches = []
    for vector in vectors:
        action = _action(str(vector["action_type"]), vector["command"], list(vector["target_paths"]))  # type: ignore[arg-type]
        actual = [signal.to_dict() for signal in detector.detect(action, context)]
        if actual != vector["signals"]:
            mismatches.append((vector["command"], vector["target_paths"], vector["signals"], actual))
    assert mismatches == []


def test_resident_ignores_fields_that_do_not_belong_to_the_action_type(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    assert _signals(action_type="file_read", command="rg foo src/", target_paths=(), guard_home=home) == []
    assert _signals(action_type="shell_command", command=None, target_paths=(".nvmrc",), guard_home=home) == []
    assert [s["signal_id"] for s in _signals(command="rg foo src/", guard_home=home)] == ["fp:source-search:rg"]
    assert [
        s["signal_id"]
        for s in _signals(action_type="file_read", command=None, target_paths=(".nvmrc",), guard_home=home)
    ] == ["fp:version-file-access"]


def test_detector_gates_before_asking_the_resident(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def never(**_kwargs: object) -> list[dict[str, object]]:
        raise AssertionError("resident must not be asked")

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.detectors.native_false_positive_signals", never)
    context = DetectorContext(
        config=GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace"),
        workspace=tmp_path / "workspace",
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )
    detector = FalsePositiveSuppressorDetector()
    assert detector.detect(_action("shell_command", None, []), context) == ()
    assert detector.detect(_action("file_read", None, []), context) == ()
    assert detector.detect(_action("prompt", "ls", [".nvmrc"]), context) == ()


def test_detector_raises_instead_of_suppressing_when_the_resident_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def unavailable(**_kwargs: object) -> list[dict[str, object]]:
        raise NativeFalsePositiveRulesError("native_false_positive_rules_unavailable")

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.detectors.native_false_positive_signals", unavailable)
    context = DetectorContext(
        config=GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace"),
        workspace=tmp_path / "workspace",
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )
    with pytest.raises(NativeFalsePositiveRulesError):
        FalsePositiveSuppressorDetector().detect(_action("shell_command", "rg foo src/", []), context)


@pytest.mark.parametrize(
    "payload",
    [
        {"category": "secret"},
        {"detector": "other.detector"},
        {"signal_id": ""},
        {"severity": "bogus"},
    ],
)
def test_detector_rejects_signals_it_does_not_own(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, payload: dict[str, object]
) -> None:
    signal = {
        "signal_id": "fp:source-search:rg",
        "category": "false_positive",
        "severity": "info",
        "confidence": "strong",
        "detector": "false_positive.suppressor",
        "title": "t",
        "plain_reason": "r",
        "technical_detail": None,
        "evidence_ref": "command",
        "redaction_level": "none",
        "false_positive_hint": None,
        "advisory_id": None,
        **payload,
    }
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.detectors.native_false_positive_signals", lambda **_k: [signal]
    )
    context = DetectorContext(
        config=GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace"),
        workspace=tmp_path / "workspace",
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )
    with pytest.raises(NativeFalsePositiveRulesError, match="result_invalid"):
        FalsePositiveSuppressorDetector().detect(_action("shell_command", "rg foo src/", []), context)


def test_unavailable_native_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Status:
        mode = "off"
        available = False
        compatible = False
        identity = None
        capabilities = None

    monkeypatch.setattr(module, "_native_runtime_status_memo", lambda: Status())
    with pytest.raises(NativeFalsePositiveRulesError, match="unavailable"):
        _signals()


def test_missing_feature_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class Features:
        features = frozenset({module._RESIDENT_PROTOCOL_FEATURE})

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
    with pytest.raises(NativeFalsePositiveRulesError, match="unavailable"):
        _signals()


def test_mismatched_binding_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    monkeypatch.setattr(
        module,
        "native_resident_client_request",
        lambda **_: (
            b'{"schema":"guard-false-positive-rules-result.v1","request_id":"x","request_sha256":"y",'
            b'"status":"ok","code":"ok","payload":{"signals":[]}}'
        ),
    )
    with pytest.raises(NativeFalsePositiveRulesError):
        _signals()


def test_malformed_reply_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    for reply in (b"not json", b"[]", b"{}", b'{"status":"error"}'):
        monkeypatch.setattr(module, "native_resident_client_request", lambda reply=reply, **_: reply)
        with pytest.raises(NativeFalsePositiveRulesError):
            _signals()


def test_reply_signals_must_be_a_list_of_objects(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)

    def echo(payload_signals: object) -> None:
        def client(**kwargs: object) -> bytes:
            envelope = json.loads(kwargs["payload"])  # type: ignore[arg-type]
            request = envelope["request"]
            return json.dumps(
                {
                    "schema": module._RESULT_SCHEMA,
                    "request_id": request["request_id"],
                    "request_sha256": module._canonical_request_sha256(request),
                    "status": "ok",
                    "code": "ok",
                    "payload": {"signals": payload_signals},
                }
            ).encode()

        monkeypatch.setattr(module, "native_resident_client_request", client)

    for bad in (None, "x", [1], [[]]):
        echo(bad)
        with pytest.raises(NativeFalsePositiveRulesError, match="result_invalid"):
            _signals()
    echo([])
    assert _signals() == []


def test_oversized_request_raises_typed_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    with pytest.raises(NativeFalsePositiveRulesError, match="request_too_large"):
        _signals(command="x" * (512 * 1024))


def test_non_ascii_canonical_expansion_is_rejected_client_side(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    # ~120 KiB of UTF-8 that escapes to more than 256 KiB in the ASCII canonical form.
    with pytest.raises(NativeFalsePositiveRulesError, match="request_too_large"):
        _signals(command="\U0001f600" * 30_000)


def test_request_uses_explicit_guard_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _force_available(monkeypatch)
    seen: list[Path] = []

    def client(**kwargs: object) -> None:
        seen.append(kwargs["guard_home"])  # type: ignore[arg-type]

    monkeypatch.setattr(module, "native_resident_client_request", client)
    with pytest.raises(NativeFalsePositiveRulesError):
        native_false_positive_signals(
            action_type="shell_command", command="ls", target_paths=(), guard_home=tmp_path / "custom"
        )
    assert seen == [tmp_path / "custom"]


def test_client_exceptions_become_typed_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    for error in (RuntimeError("thread"), OSError("pipe"), TimeoutError("slow")):

        def client(error: Exception = error, **_kwargs: object) -> bytes:
            raise error

        monkeypatch.setattr(module, "native_resident_client_request", client)
        with pytest.raises(NativeFalsePositiveRulesError, match="resident_unavailable"):
            _signals()


def _reply_with(monkeypatch: pytest.MonkeyPatch, payload_signals: object) -> None:
    def client(**kwargs: object) -> bytes:
        request = json.loads(kwargs["payload"])["request"]  # type: ignore[arg-type]
        return json.dumps(
            {
                "schema": module._RESULT_SCHEMA,
                "request_id": request["request_id"],
                "request_sha256": module._canonical_request_sha256(request),
                "status": "ok",
                "code": "ok",
                "payload": {"signals": payload_signals},
            }
        ).encode()

    monkeypatch.setattr(module, "native_resident_client_request", client)


def test_malformed_signal_records_a_failure_not_a_healthy_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    recorded: list[str] = []
    monkeypatch.setattr(module, "native_record_resident_failure", lambda *_a, **k: recorded.append(k["reason"]))
    monkeypatch.setattr(module, "native_record_resident_success", lambda *_a, **_k: recorded.append("success"))
    foreign = {"signal_id": "x", "category": "secret", "detector": "other"}
    for bad in ([{"signal_id": "fp:source-search:rg"}], [foreign]):
        _reply_with(monkeypatch, bad)
        with pytest.raises(NativeFalsePositiveRulesError, match="result_invalid"):
            _signals()
    assert recorded == [module._INVALID_RESULT, module._INVALID_RESULT]


def test_deadline_is_bounded_and_shared_with_the_resident(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_available(monkeypatch)
    seen: list[tuple[int, float]] = []
    clock = 1_000.0
    monkeypatch.setattr(module.time, "monotonic", lambda: clock)

    def client(**kwargs: object) -> None:
        budget = json.loads(kwargs["payload"])["deadline_budget_ms"]  # type: ignore[arg-type]
        seen.append((budget, kwargs["deadline_monotonic"] - clock))  # type: ignore[operator]

    monkeypatch.setattr(module, "native_resident_client_request", client)
    monkeypatch.setattr(module, "native_resident_client_ready", lambda *_a: True)
    for requested, expected_ms in ((None, 500), (0.05, 500), (2.0, 2_000), (60.0, 9_000)):
        with pytest.raises(NativeFalsePositiveRulesError):
            _signals(timeout_seconds=requested)
        assert seen[-1] == (expected_ms, expected_ms / 1_000)
    monkeypatch.setattr(module, "native_resident_client_ready", lambda *_a: False)
    with pytest.raises(NativeFalsePositiveRulesError):
        _signals()
    assert seen[-1][0] == int((module._TIMEOUT_SECONDS + module._COLD_START_ALLOWANCE_SECONDS) * 1_000)


def test_detector_asks_the_configured_guard_home_within_its_budget(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: list[dict[str, object]] = []

    def record(**kwargs: object) -> list[dict[str, object]]:
        seen.append(kwargs)
        return []

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.detectors.native_false_positive_signals", record)
    home = tmp_path / "custom-home"
    context = DetectorContext(
        config=GuardConfig(guard_home=home, workspace=tmp_path / "workspace", runtime_detector_timeout_ms=1_500),
        workspace=tmp_path / "workspace",
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )
    FalsePositiveSuppressorDetector().detect(_action("shell_command", "rg foo src/", []), context)
    assert seen[0]["guard_home"] == home
    assert seen[0]["timeout_seconds"] == 1.5
