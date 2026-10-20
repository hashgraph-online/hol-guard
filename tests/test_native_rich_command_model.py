"""Real caller replay of outcomes captured before native cutover."""

from __future__ import annotations

import dataclasses
import json
import os
import time
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_rich_command_model as client
from codex_plugin_scanner.guard.runtime import command_model, command_tokens, env_wrapper

FIXTURE = json.loads((Path(__file__).parent / "fixtures/native_rich_command_model.json").read_text())


def wire(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: wire(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (tuple, list)):
        return [wire(item) for item in value]
    return value


def invoke(vector: dict[str, Any]) -> Any:
    args = dict(vector["args"])
    action = vector["action"]
    if action == "parse":
        for key in ("cwd", "home_dir"):
            if key in args:
                args[key] = Path(args[key]) if args[key] is not None else None
        model = command_model.parse_shell_command(**args)
        return {
            "raw_text": model.raw_text,
            **model.to_dict(),
            "embedded_commands": [{**item.to_dict(), "text": item.text} for item in model.embedded_commands],
        }
    if action == "tokens":
        return command_tokens.shell_tokens(**args)
    if action == "executable":
        return command_tokens.executable_name(**args)
    if action == "leading_environment":
        return command_tokens.leading_environment(tuple(args["tokens"]))
    if action == "env":
        args["cwd"] = Path(args["cwd"])
        return env_wrapper.parse_env_wrapper(**args)
    raise AssertionError(action)


@pytest.mark.skipif(os.name == "nt", reason="Original fixture records POSIX tokenization")
@pytest.mark.parametrize("vector", FIXTURE["vectors"], ids=lambda v: v["action"])
def test_original_outcomes_through_public_callers(vector: dict[str, Any]) -> None:
    if "error" in vector:
        with pytest.raises(ValueError, match="Command text cannot be empty"):
            invoke(vector)
    else:
        assert wire(invoke(vector)) == vector["result"]


def test_native_outage_has_no_python_parser_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _: False)
    with pytest.raises(client.NativeCommandModelError):
        command_model.parse_shell_command("echo hi")
    result = env_wrapper.parse_env_wrapper(["echo", "hi"])
    assert not result.complete and result.error == "native_unavailable"
    assert result.executable_argv == ()


def test_identity_cache_is_bound_to_complete_structure(monkeypatch: pytest.MonkeyPatch) -> None:
    model = command_model.parse_shell_command("echo hi")
    manual = dataclasses.replace(model, _bound_identity=None)
    assert manual.security_identity == model.security_identity
    identity = model.security_identity
    assert dataclasses.replace(model).security_identity == identity
    changed = dataclasses.replace(model, normalized_text="echo bye")
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _: False)
    assert manual.to_dict()["security_identity"] == identity
    with pytest.raises(client.NativeCommandModelError):
        _ = changed.security_identity


def test_shadow_native_identity_is_reused_without_another_transport(monkeypatch):
    from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native
    from codex_plugin_scanner.guard.runtime.command_structure import build_command_security_identity

    rich = command_model.parse_shell_command("echo hi")
    payload = {
        "normalized_text": "echo hi",
        "dialect": "posix",
        "transport": "shell_string",
        "extraction_provenance": "guard-shell",
        "wrapper_chain": [],
        "segments": [segment.to_dict() for segment in rich.segments],
        "confidence": "exact",
        "uncertainty_reason": None,
        "path_overridden": False,
        "parser_profile": "posix-simple-v1",
        "security_identity": rich.security_identity,
    }
    projected = _canonical_command_from_native("echo hi", payload)
    assert projected is not None
    assert projected.security_identity == build_command_security_identity(
        normalized_text="echo hi",
        dialect="posix",
        transport="shell_string",
        wrapper_chain=(),
        segments=projected.segments,
        redirects=(),
        embedded_commands=(),
    )
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _: False)
    assert projected.to_dict()["security_identity"] == rich.security_identity
    assert _canonical_command_from_native("echo hi", {**payload, "security_identity": "invalid"}) is None


@pytest.mark.parametrize(
    "damage",
    [
        "negative_pipeline",
        "negative_span",
        "reversed_span",
        "segment_overrun",
        "redirect_overrun",
        "embedded_overrun",
        "invalid_identity",
    ],
)
def test_malformed_bound_positions_fail_closed(monkeypatch, damage):
    model = command_model.parse_shell_command("echo hi")
    payload = {**model.to_dict(), "raw_text": model.raw_text}
    segment = payload["segments"][0]
    if damage == "negative_pipeline":
        segment["pipeline_index"] = -1
    elif damage == "negative_span":
        segment["span"]["start"] = -1
    elif damage == "reversed_span":
        segment["span"].update(start=2, end=1)
    elif damage == "segment_overrun":
        segment["span"].update(start=99, end=99)
    elif damage in {"redirect_overrun", "embedded_overrun"}:
        span = {"source": "normalized", "start": 0, "end": 99}
        if damage == "redirect_overrun":
            payload["redirects"] = [{"operator": ">", "target": "out", "span": span}]
        else:
            payload["embedded_commands"] = [
                {"kind": "substitution", "text": "hi", "execution_context": "shell", "span": span}
            ]
    else:
        payload["security_identity"] = "command-security-v2:invalid"

    def respond(**kwargs):
        material = json.loads(kwargs["payload"])["request"]
        return json.dumps(
            {
                "schema": client.RESULT_SCHEMA,
                "request_id": material["request_id"],
                "request_sha256": client._canonical_request_sha256(material),
                "status": "ok",
                "error": None,
                "result": payload,
            }
        ).encode()

    monkeypatch.setattr(client, "native_resident_client_request", respond)
    with pytest.raises(client.NativeCommandModelError):
        command_model.parse_shell_command("echo hi")


@pytest.mark.parametrize(
    "content",
    ["a" * 1_100_000, "é" * 400_000, "a" * 3_000_000],
    ids=["large-ascii", "large-unicode", "multi-megabyte-ascii"],
)
@pytest.mark.parametrize("dialect", ["posix", "powershell"])
def test_large_uncertain_command_preserves_native_identity_without_duplicate_wire_text(content, dialect):
    text = " " + content + " "
    model = command_model.parse_shell_command(text, dialect=dialect)
    assert model.raw_text == text[1:-1]
    assert model.normalized_text == text[1:-1]
    assert model.confidence == "uncertain"
    assert model.uncertainty_reason == (
        "command_byte_limit_exceeded" if dialect == "posix" else "unsupported_powershell_shell_string"
    )
    assert model.security_identity.startswith("command-security-v2:")


def test_public_tokens_preserve_stderr_to_null_redirect():
    assert command_tokens.shell_tokens("echo 2>/dev/null") == (("echo", "2>/dev/null"), True)


def test_swallowed_outage_still_records_local_identity_failure():
    from codex_plugin_scanner.guard.native_local_cli_identity import track_local_cli_identity_failures

    with track_local_cli_identity_failures() as failures:
        try:
            raise client.NativeCommandModelError("native_rich_command_model_unavailable")
        except ValueError:
            pass
    assert failures == ["native_rich_command_model_unavailable"]


def test_env_outage_returns_incomplete_transport_dto(monkeypatch):
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _: False)
    result = env_wrapper.parse_env_wrapper(("echo", "hi"))
    assert not result.complete and result.error == "native_unavailable"
    assert result.executable_argv == ()


def test_fresh_status_probe_receives_deadline_and_expired_probe_does_not_start(monkeypatch):
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import native_context

    seen = []
    now = [1.0]
    status = SimpleNamespace(identity=object())

    def probe(*, deadline_monotonic):
        seen.append(deadline_monotonic)
        return status

    monkeypatch.setattr(client, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(native_context, "_status_memo", None)
    monkeypatch.setattr(native_context, "native_runtime_status", probe)
    monkeypatch.setattr(native_context, "_status_binary_unchanged", lambda _: True)
    assert client.native_runtime_status(deadline_monotonic=3.0) is status
    assert client.native_runtime_status(deadline_monotonic=3.0) is status
    assert seen == [3.0]
    now[0] = 4.0
    with pytest.raises(client.NativeCommandModelError):
        client.native_runtime_status(deadline_monotonic=3.0)
    assert seen == [3.0]


def test_deadline_cutoff_status_does_not_poison_shared_memo(monkeypatch):
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import native_context

    now = [1.0]
    monkeypatch.setattr(client, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(native_context, "_status_memo", None)

    def cutoff(*, deadline_monotonic):
        now[0] = deadline_monotonic + 1
        return SimpleNamespace(identity=None, available=False)

    monkeypatch.setattr(native_context, "native_runtime_status", cutoff)
    assert client.native_runtime_status(deadline_monotonic=3.0).available is False
    assert native_context._status_memo is None


def test_explicit_inspection_home_identity_outage_returns_blocked_diagnostic(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard import native_context
    from codex_plugin_scanner.guard.runtime import command_inspection

    expected_home = tmp_path / "explicit-guard-home"
    seen = []
    manual = command_model.CanonicalCommand(
        "echo hi", "echo hi", "posix", "shell_string", "guard-shell", (), (), (), (), "uncertain"
    )

    def prerequisite(home):
        seen.append(home)
        return False

    def review(*args, **kwargs):
        assert kwargs["guard_home"] == expected_home
        _ = manual.security_identity

    monkeypatch.setattr(client, "ensure_resident_prerequisite", prerequisite)
    # The autouse fixture pins this accessor to a session home. Exercise the
    # production ContextVar binding for this explicit-home regression.
    monkeypatch.setattr(native_context, "context_digest_guard_home", native_context._BOUND_GUARD_HOME.get)
    monkeypatch.setattr(command_inspection, "review_command_native", review)
    result = command_inspection.inspect_command("echo hi", guard_home=expected_home, cwd=tmp_path, home_dir=tmp_path)
    assert seen == [expected_home]
    assert result["status"] == "native_unavailable"
    assert result["minimum_action"] == "block"
    assert result["command_model"] is None


@pytest.mark.parametrize("harness", ["codex", "codex-alias"])
@pytest.mark.parametrize(
    "error_type",
    ["command-model", "sensitive-request", "artifact-identity"],
)
def test_runtime_artifact_native_outage_does_not_reparse_or_fabricate_identity(
    monkeypatch, tmp_path, harness, error_type
):
    from codex_plugin_scanner.guard.cli import commands_support_runtime_artifacts as artifacts
    from codex_plugin_scanner.guard.native_runtime_artifact_identity import NativeRuntimeArtifactIdentityError
    from codex_plugin_scanner.guard.native_sensitive_request import NativeSensitiveRequestError

    monkeypatch.setattr(artifacts, "_canonical_harness_name", lambda _: "codex")

    def forbidden(*args, **kwargs):
        if error_type == "artifact-identity":
            raise NativeRuntimeArtifactIdentityError("native_runtime_artifact_identity_unavailable")
        if error_type == "sensitive-request":
            raise NativeSensitiveRequestError("native_sensitive_request_unavailable")
        raise client.NativeCommandModelError("native_rich_command_model_unavailable")

    monkeypatch.setattr(artifacts, "_hook_runtime_artifact_with_native", forbidden)
    result = artifacts._hook_runtime_artifact(
        harness=harness,
        payload={"hook_event_name": "PreToolUse", "tool_name": "Shell", "tool_input": {"command": "echo hi"}},
        workspace=tmp_path,
        home_dir=tmp_path,
        guard_home=tmp_path / "guard",
        action_envelope=None,
    )
    assert result is not None
    assert result.harness == "codex"
    assert result.metadata["native_command_evaluation_status"] == "unavailable"
    assert result.metadata["guard_default_action"] == "block"
    assert "command_security_identity" not in result.metadata


@pytest.mark.parametrize("error_type", [client.NativeCommandModelError, ValueError])
def test_command_id_resolution_never_converts_parser_errors_to_root_tokens(monkeypatch, tmp_path, error_type):
    from types import SimpleNamespace

    from codex_plugin_scanner.guard.runtime import local_cli_commands, package_json_scripts

    monkeypatch.setattr(package_json_scripts, "package_script_command_tokens", lambda *args, **kwargs: None)

    def unavailable(*args, **kwargs):
        raise error_type("parser_unavailable")

    monkeypatch.setattr(local_cli_commands, "parse_shell_command", unavailable)
    with pytest.raises(error_type):
        local_cli_commands.command_tokens_for_invocation(
            "tool --version",
            cwd=tmp_path,
            home_dir=tmp_path,
            identity=SimpleNamespace(runner=None, kind="binary"),
        )


def test_reviewed_invocation_native_outage_is_structured_builder_failure(monkeypatch):
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import native_reviewed_invocation_bindings as bindings
    from codex_plugin_scanner.guard.extension_builder import review_invocations
    from codex_plugin_scanner.guard.extension_builder.errors import BuilderError

    owner = SimpleNamespace(operation_id="fixture", path=(), flags=frozenset(), options_with_values=frozenset())
    discovery = SimpleNamespace(operations=(owner,), metadata=SimpleNamespace(executable="echo"))
    monkeypatch.setattr(bindings, "ensure_resident_prerequisite", lambda _: False)
    with pytest.raises(BuilderError) as raised:
        review_invocations.validate_native_bindings(discovery, ((owner, ("hi",)),), frozenset())
    assert raised.value.code == "native_unavailable"


@pytest.mark.parametrize("damage", ["digest", "request_id", "schema", "shape", "status", "surrogate"])
def test_transport_rejects_unbound_or_malformed_replies(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    damage: str,
) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(client, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(client, "native_resident_client_ready", lambda *_: True)
    monkeypatch.setattr(
        client,
        "native_runtime_status",
        lambda **_: SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(path="/fixture/runtime"),
            capabilities=SimpleNamespace(features=[client.FEATURE, "resident-protocol-v2"]),
        ),
    )

    def respond(**kwargs: Any) -> bytes:
        assert damage != "surrogate", "Invalid UTF-8 must be rejected before transport"
        assert 0 < kwargs["deadline_monotonic"] - time.monotonic() <= 1.0
        material = json.loads(kwargs["payload"])["request"]
        reply = {
            "schema": client.RESULT_SCHEMA,
            "request_id": material["request_id"],
            "request_sha256": client._canonical_request_sha256(material),
            "status": "ok",
            "error": None,
            "result": [["echo", "hi"], True],
        }
        if damage == "shape":
            reply["result"] = [[42], True]
        else:
            key = "request_sha256" if damage == "digest" else damage
            reply[key] = "invalid"
        return json.dumps(reply).encode()

    monkeypatch.setattr(client, "native_resident_client_request", respond)
    with pytest.raises(client.NativeCommandModelError):
        command_tokens.shell_tokens("echo \udc80" if damage == "surrogate" else "echo hi")


@pytest.mark.parametrize("setup_seconds", [2.0, 9.0, 11.0])
def test_cold_helper_setup_and_spawn_share_bounded_overall_deadline(monkeypatch, tmp_path, setup_seconds):
    from types import SimpleNamespace

    now = [100.0]
    monkeypatch.setattr(client, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(client, "_resolve_digest_home", lambda _: tmp_path)

    def prerequisite(_):
        now[0] += setup_seconds
        return True

    monkeypatch.setattr(client, "ensure_resident_prerequisite", prerequisite)
    monkeypatch.setattr(client, "native_resident_client_ready", lambda *_: False)
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "runtime", sha256="fixture"),
        capabilities=SimpleNamespace(features=[client.FEATURE, "resident-protocol-v2"]),
    )
    monkeypatch.setattr(client, "native_runtime_status", lambda **_: status)

    def respond(**kwargs):
        assert setup_seconds < 10
        assert kwargs["deadline_monotonic"] <= 110.0
        assert kwargs["deadline_monotonic"] - now[0] == min(4.0, 10.0 - setup_seconds)
        material = json.loads(kwargs["payload"])["request"]
        return json.dumps(
            {
                "schema": client.RESULT_SCHEMA,
                "request_id": material["request_id"],
                "request_sha256": client._canonical_request_sha256(material),
                "status": "ok",
                "error": None,
                "result": [["echo"], True],
            }
        ).encode()

    monkeypatch.setattr(client, "native_resident_client_request", respond)
    if setup_seconds > 10:
        with pytest.raises(client.NativeCommandModelError, match="deadline"):
            command_tokens.shell_tokens("echo")
    else:
        assert command_tokens.shell_tokens("echo") == (("echo",), True)


def test_executable_reuse_is_bounded_and_bound_to_available_native_identity(monkeypatch, tmp_path):
    from types import SimpleNamespace

    client._EXECUTABLE_CACHE.clear()
    monkeypatch.setattr(client, "_resolve_digest_home", lambda _: tmp_path)
    monkeypatch.setattr(client, "ensure_resident_prerequisite", lambda _: True)
    monkeypatch.setattr(client, "native_resident_client_ready", lambda *_: True)
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "runtime", sha256="fixture-a"),
        capabilities=SimpleNamespace(features=[client.FEATURE, "resident-protocol-v2"]),
    )
    monkeypatch.setattr(client, "native_runtime_status", lambda **_: status)
    calls = []

    def respond(**kwargs):
        material = json.loads(kwargs["payload"])["request"]
        calls.append(material)
        return json.dumps(
            {
                "schema": client.RESULT_SCHEMA,
                "request_id": material["request_id"],
                "request_sha256": client._canonical_request_sha256(material),
                "status": "ok",
                "error": None,
                "result": status.identity.sha256,
            }
        ).encode()

    monkeypatch.setattr(client, "native_resident_client_request", respond)
    assert command_tokens.executable_name("/fixture/echo") == "fixture-a"
    assert command_tokens.executable_name("/fixture/echo") == "fixture-a"
    assert len(calls) == 1
    status.identity.sha256 = "fixture-b"
    assert command_tokens.executable_name("/fixture/echo") == "fixture-b"
    assert len(calls) == 2
    status.available = False
    with pytest.raises(client.NativeCommandModelError):
        command_tokens.executable_name("/fixture/echo")
    status.available = True
    for i in range(257):
        command_tokens.executable_name(f"tool-{i}")
    assert len(client._EXECUTABLE_CACHE) <= 256
    client._EXECUTABLE_CACHE.clear()
