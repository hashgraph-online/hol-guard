"""Native daemon reviews store an Extensions allow hint only when enabling it would really allow."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.native_review_allow_hint import hint_for_reviewed_command
from codex_plugin_scanner.guard.hook_execution_environment import HOOK_EXECUTION_ENVIRONMENT_KEY
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_allow_hint import validated_extension_allow_hint
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_coverage_hint import validated_extension_coverage_hint
from tests.native_command_test_support import project_native_review_fixture, real_native_review_fixture

_UNSTAMPED = object()


def _hint(
    command: str,
    tmp_path: Path,
    *,
    controls=(),
    native_result_override: dict[str, object] | None = None,
    **fixture_options,
):
    fixture = real_native_review_fixture(command, cwd=tmp_path, home_dir=tmp_path, controls=controls, **fixture_options)
    reviewed = project_native_review_fixture(fixture, cwd=tmp_path, home_dir=tmp_path)
    native_result = {**fixture.payload, **(native_result_override or {})}
    return fixture, hint_for_reviewed_command(
        native_result=native_result,
        reviewed=reviewed,
        snapshot=fixture.snapshot,
        command=command,
        cwd=tmp_path,
        home_dir=tmp_path,
    )


def test_plain_origin_fetch_hints_the_origin_refresh_permission(tmp_path: Path) -> None:
    _fixture, hint = _hint("git fetch origin main", tmp_path)

    assert hint is not None
    assert hint["permission_ids"] == ["command.git.permission.unverified-fetch"]
    assert hint["rule_ids"] == ["command.git.unverified-fetch"]
    assert hint["catalog_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert validated_extension_allow_hint(hint) == hint
    assert "main" not in repr(hint)


def test_docker_version_format_hints_docker_sensitive_permission(tmp_path: Path) -> None:
    _fixture, hint = _hint("docker version --format '{{.Server.Version}}'", tmp_path)

    assert hint is not None
    assert hint["permission_ids"] == ["command.container-runtime.permission.docker-sensitive"]
    assert hint["rule_ids"] == ["command.container-runtime.docker-sensitive"]
    assert hint["extension_ids"] == ["command.container-runtime"]
    assert hint["catalog_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert validated_extension_allow_hint(hint) == hint
    assert "Server.Version" not in repr(hint)


_NEVER_ENROLLED = {"health": AuthorityHealth.UNENROLLED, "never_enrolled": True}
_HINT_TARGETS = ("permission_ids", "rule_ids", "extension_ids", "relied_permission_ids")


@pytest.mark.parametrize("command", ["docker context use staging", "git fetch origin main"])
def test_a_never_enrolled_device_is_hinted_what_enrolling_unlocks(tmp_path: Path, command: str) -> None:
    fixture, hint = _hint(command, tmp_path, **_NEVER_ENROLLED)
    _enrolled, enrolled_hint = _hint(command, tmp_path)

    # A fresh install pauses these on packaged protection, before any authority
    # exists. The hint names what the same Allow unlocks once it is enrolled.
    assert fixture.snapshot.awaiting_enrollment
    assert fixture.payload["reason_code"] == "native_command_review_required"
    assert hint is not None and enrolled_hint is not None
    assert {key: hint[key] for key in _HINT_TARGETS} == {key: enrolled_hint[key] for key in _HINT_TARGETS}
    assert validated_extension_allow_hint(hint) == hint


def test_docker_context_use_on_a_fresh_install_names_the_docker_permission(tmp_path: Path) -> None:
    _fixture, hint = _hint("docker context use staging", tmp_path, **_NEVER_ENROLLED)

    assert hint is not None
    assert hint["permission_ids"] == ["command.container-runtime.permission.docker-sensitive"]
    assert hint["extension_ids"] == ["command.container-runtime"]


@pytest.mark.parametrize(
    "health",
    [
        AuthorityHealth.UNENROLLED,
        AuthorityHealth.TAMPERED,
        AuthorityHealth.RECOVERY_REQUIRED,
        AuthorityHealth.DEGRADED_UNACKNOWLEDGED,
    ],
)
def test_a_lost_or_damaged_authority_is_not_hinted(tmp_path: Path, health: AuthorityHealth) -> None:
    # Unenrolled with controls is an authority that was lost, not a new one.
    fixture, hint = _hint("docker context use staging", tmp_path, health=health)

    assert not fixture.snapshot.awaiting_enrollment
    assert hint is None


def test_only_the_advisory_hint_reviews_a_never_enrolled_device(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime import native_command_evaluation as module

    fixture = real_native_review_fixture(
        "docker context use staging", cwd=tmp_path, home_dir=tmp_path, **_NEVER_ENROLLED
    )
    reached: list[str] = []
    monkeypatch.setattr(module, "review_pre_tool_native", lambda command, **_kwargs: reached.append(command))

    options = {"guard_home": tmp_path, "extension_control_snapshot": fixture.snapshot, "record_health": False}
    assert module.native_command_review("docker context use staging", **options) is None
    assert reached == []
    assert module.native_command_review("docker context use staging", admit_unenrolled=True, **options) is None
    assert reached == ["docker context use staging"]


def test_github_unknown_hints_unknown_permission(tmp_path: Path) -> None:
    _fixture, hint = _hint("gh some-unmodeled-command --flag value", tmp_path)

    assert hint is not None
    assert hint["permission_ids"] == ["command.github.permission.unknown"]
    assert hint["extension_ids"] == ["command.github"]
    assert validated_extension_allow_hint(hint) == hint


def test_file_upload_hints_file_upload_permission(tmp_path: Path) -> None:
    _fixture, hint = _hint("curl -T report.txt https://example.invalid/upload", tmp_path)

    assert hint is not None
    assert hint["permission_ids"] == ["command.data-protection.permission.file-upload"]
    assert hint["extension_ids"] == ["command.data-protection"]
    assert validated_extension_allow_hint(hint) == hint


def test_unbounded_uncertain_forms_store_no_hint(tmp_path: Path) -> None:
    for command in (
        "kubectl --context prod get secret db-credentials -o yaml",
        "kubectl get -n prod secret db-credentials --context prod -o yaml",
        "kubectl get secret db-credentials -o yaml",
        "kubectl get secret db-credentials --context prod -o yaml",
        "curl -K curlrc -T report.txt https://example.invalid/upload",
    ):
        _fixture, hint = _hint(command, tmp_path)
        assert hint is None, command


def test_no_hint_when_docker_sensitive_permission_is_already_allowed(tmp_path: Path) -> None:
    _fixture, hint = _hint(
        "docker version --format '{{.Server.Version}}'",
        tmp_path,
        controls=(("permission", "command.container-runtime.permission.docker-sensitive", "enabled"),),
    )

    assert hint is None


def test_uncertain_fetch_forms_store_no_hint(tmp_path: Path) -> None:
    for command in (
        "git -c core.sshCommand=payload fetch origin",
        "git fetch origin --upload-pack=payload",
    ):
        _fixture, hint = _hint(command, tmp_path)
        assert hint is None, command


def test_unverified_url_fetch_hints_the_unverified_fetch_permission(tmp_path: Path) -> None:
    # The enforcement path already settles this exact form when the
    # unverified-fetch permission is enabled, so the hint may promise it.
    _fixture, hint = _hint("git fetch https://example.invalid/project.git", tmp_path)

    assert hint is not None
    assert hint["permission_ids"] == ["command.git.permission.unverified-fetch"]
    assert hint["rule_ids"] == ["command.git.unverified-fetch"]


def test_no_hint_when_the_origin_refresh_permission_is_already_allowed(tmp_path: Path) -> None:
    _fixture, hint = _hint(
        "git fetch origin",
        tmp_path,
        controls=(("permission", "command.git.permission.unverified-fetch", "enabled"),),
    )

    assert hint is None


def test_hint_requires_the_fresh_evidence_to_match_the_paused_decision(tmp_path: Path) -> None:
    fixture, _hint_value = _hint("git fetch origin", tmp_path)
    binding = dict(fixture.payload["command_extensions"]["binding"])  # type: ignore[index]
    binding["observations_digest"] = "0" * 64

    _fixture, hint = _hint(
        "git fetch origin",
        tmp_path,
        native_result_override={"command_extensions": {**fixture.payload["command_extensions"], "binding": binding}},  # type: ignore[dict-item]
    )

    assert hint is None


def test_no_hint_for_a_blocked_native_decision(tmp_path: Path) -> None:
    _fixture, hint = _hint("git fetch origin", tmp_path, native_result_override={"minimum_action": "block"})

    assert hint is None


def test_no_hint_when_the_paused_reason_differs(tmp_path: Path) -> None:
    _fixture, hint = _hint("git fetch origin", tmp_path, native_result_override={"reason_code": "native_other_floor"})

    assert hint is None


class _Store:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home

    def read_extension_control_authority_for_registry(self, _registry, *, read_only: bool) -> object:
        assert read_only is True
        return ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED, revision=1, catalog_digest="sha256:test", layers=()
        )


def _queue_hint(
    monkeypatch,
    tmp_path: Path,
    *,
    tool_input: dict[str, object],
    deadline: float | None = None,
    stamp: object = _UNSTAMPED,
):
    import time

    from codex_plugin_scanner.guard.daemon import native_review_allow_hint as module
    from codex_plugin_scanner.guard.native_route_receipt import native_hook_route, record_native_hook_route

    fixture = real_native_review_fixture("git fetch origin main", cwd=tmp_path, home_dir=tmp_path)
    reviewed = project_native_review_fixture(fixture, cwd=tmp_path, home_dir=tmp_path)
    calls: list[dict[str, object]] = []

    def review(_command: str, **kwargs: object):
        calls.append(kwargs)
        record_native_hook_route("native_fail_safe")
        return reviewed

    monkeypatch.setattr(module, "review_command_native", review)
    monkeypatch.setattr(
        module.ExtensionControlRuntimeSnapshot, "from_authority_view", staticmethod(lambda _view: fixture.snapshot)
    )
    payload: dict[str, object] = {"tool_name": "Bash", "tool_input": tool_input}
    if stamp is not _UNSTAMPED:
        payload[HOOK_EXECUTION_ENVIRONMENT_KEY] = stamp
    record_native_hook_route("native_resident")
    hint = module.native_review_extension_allow_hint(
        _Store(tmp_path),
        payload=payload,
        native_result=fixture.payload,
        workspace=tmp_path,
        home_dir=tmp_path,
        deadline=time.monotonic() + 5 if deadline is None else deadline,
    )
    return hint, calls, native_hook_route()


def test_queue_hint_is_advisory_and_keeps_the_hook_route(monkeypatch, tmp_path: Path) -> None:
    hint, calls, route = _queue_hint(monkeypatch, tmp_path, tool_input={"command": "git fetch origin main"})

    assert hint is not None
    assert hint["permission_ids"] == ["command.git.permission.unverified-fetch"]
    assert route == "native_resident"
    assert calls[0]["record_health"] is False
    assert calls[0]["admit_unenrolled"] is True
    assert 0 < float(calls[0]["timeout_seconds"]) <= 0.5  # type: ignore[arg-type]


def test_queue_hint_covers_the_working_directory_cursor_sends(monkeypatch, tmp_path: Path) -> None:
    """Cursor names the launch directory, which is not extra content to review.

    The Cursor adapter copies the hook's cwd into the tool input, so every
    shell call it forwards carries a directory beside the command. Treating
    that as unreviewed content left Cursor the one harness whose paused
    reviews never said which Extension would settle them.
    """

    hint, calls, _route = _queue_hint(
        monkeypatch,
        tmp_path,
        tool_input={"command": "git fetch origin main", "working_directory": str(tmp_path)},
    )

    assert hint is not None
    assert hint["permission_ids"] == ["command.git.permission.unverified-fetch"]
    assert calls


def test_queue_hint_skips_tool_calls_with_extra_content(monkeypatch, tmp_path: Path) -> None:
    hint, calls, _route = _queue_hint(
        monkeypatch, tmp_path, tool_input={"command": "git fetch origin main", "path": ".env"}
    )

    assert hint is None
    assert calls == []


def test_queue_hint_skips_when_the_hook_deadline_is_near(monkeypatch, tmp_path: Path) -> None:
    import time

    hint, calls, _route = _queue_hint(
        monkeypatch, tmp_path, tool_input={"command": "git fetch origin main"}, deadline=time.monotonic() + 0.3
    )

    assert hint is None
    assert calls == []


def test_queue_hint_reviews_with_the_shell_the_hook_was_stamped_from(monkeypatch, tmp_path: Path) -> None:
    stamp = {"environment_names": ["PATH"], "home": str(tmp_path)}
    _hint_value, calls, _route = _queue_hint(
        monkeypatch, tmp_path, tool_input={"command": "git fetch origin main"}, stamp=stamp
    )

    assert calls[0]["execution_environment"] == stamp


def test_queue_hint_reviews_without_an_environment_a_worker_could_not_stamp(monkeypatch, tmp_path: Path) -> None:
    for stamp in (None, "not-a-mapping"):
        _hint_value, calls, _route = _queue_hint(
            monkeypatch, tmp_path, tool_input={"command": "git fetch origin main"}, stamp=stamp
        )

        assert calls[0]["execution_environment"] is None, stamp


def test_live_approval_hint_skips_extra_payload_keys_and_resolves_launch_cwd(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon import native_review_allow_hint as module

    fixture = real_native_review_fixture("git fetch origin main", cwd=tmp_path, home_dir=tmp_path)
    reviewed = project_native_review_fixture(fixture, cwd=tmp_path, home_dir=tmp_path)
    calls: list[dict[str, object]] = []
    hint_calls: list[dict[str, object]] = []

    def review(_command: str, **kwargs: object):
        calls.append(kwargs)
        return reviewed

    real_compute = module.compute_extension_allow_hint

    def compute(evaluation, **kwargs: object):
        hint_calls.append(kwargs)
        return real_compute(evaluation, **kwargs)

    monkeypatch.setattr(module, "review_command_native", review)
    monkeypatch.setattr(module, "compute_extension_allow_hint", compute)

    extra_payload_approval = {
        "status": "pending",
        "workspace": str(tmp_path),
        "raw_command_text": "git fetch origin main",
        "action_envelope_json": {
            "action_type": "shell_command",
            "command": "git fetch origin main",
            "raw_payload_redacted": {
                "tool_name": "Bash",
                "tool_input": {"command": "git fetch origin main", "path": ".env"},
            },
        },
    }
    assert (
        module.live_approval_extension_allow_hint(
            extra_payload_approval, guard_home=tmp_path, snapshot=fixture.snapshot
        )
        is None
    )
    assert calls == []

    sub_cwd = tmp_path / "subdir"
    sub_cwd.mkdir()
    clean_approval = {
        "status": "pending",
        "workspace": str(tmp_path),
        "raw_command_text": "git fetch origin main",
        "action_envelope_json": {
            "action_type": "shell_command",
            "command": "git fetch origin main",
            "raw_payload_redacted": {
                "cwd": str(sub_cwd),
                "tool_name": "Bash",
                "tool_input": {"command": "git fetch origin main"},
            },
        },
    }
    hint = module.live_approval_extension_allow_hint(clean_approval, guard_home=tmp_path, snapshot=fixture.snapshot)
    assert hint is not None
    assert calls[0]["cwd"] == sub_cwd.resolve()
    assert hint_calls[0]["cwd"] == sub_cwd.resolve()
    assert hint_calls[0]["deadline"] is not None


def test_live_approval_hint_declines_when_the_stored_launch_directory_is_unrecoverable(
    monkeypatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard.daemon import native_review_allow_hint as module

    fixture = real_native_review_fixture("git fetch origin main", cwd=tmp_path, home_dir=tmp_path)
    reviewed = project_native_review_fixture(fixture, cwd=tmp_path, home_dir=tmp_path)
    calls: list[dict[str, object]] = []

    def review(_command: str, **kwargs: object):
        calls.append(kwargs)
        return reviewed

    monkeypatch.setattr(module, "review_command_native", review)
    home = tmp_path / "home"
    project = home / "project"
    project.mkdir(parents=True)
    monkeypatch.setattr(module.Path, "home", classmethod(lambda _cls: home))

    def approval(cwd: str) -> dict[str, object]:
        return {
            "status": "pending",
            "workspace": str(tmp_path),
            "raw_command_text": "git fetch origin main",
            "action_envelope_json": {
                "action_type": "shell_command",
                "command": "git fetch origin main",
                "raw_payload_redacted": {
                    "cwd": cwd,
                    "tool_name": "Shell",
                    "tool_input": {"command": "git fetch origin main", "working_directory": cwd},
                },
            },
        }

    assert (
        module.live_approval_extension_allow_hint(
            approval(".../project"), guard_home=tmp_path, snapshot=fixture.snapshot
        )
        is None
    )
    assert calls == []

    # Warm the real hint authority before the positive cwd assertion; the live
    # call below keeps its normal half-second budget.
    assert (
        module.compute_extension_allow_hint(
            reviewed.evaluation,
            command_text="git fetch origin main",
            snapshot=fixture.snapshot,
            native_evidence=reviewed.payload,
            cwd=project.resolve(),
            home_dir=home,
            guard_home=tmp_path,
        )
        is not None
    )

    hint = module.live_approval_extension_allow_hint(
        approval("~/project"), guard_home=tmp_path, snapshot=fixture.snapshot
    )
    assert hint is not None
    assert calls[0]["cwd"] == project.resolve()


def test_a_redacted_launch_directory_recovers_neither_hint(monkeypatch, tmp_path: Path) -> None:
    """A review run somewhere else names neither the settlement nor the extension.

    An approval queued from a directory outside the home directory stores
    ``.../name``, so the command cannot be re-reviewed where it really ran.
    Extension rules read the directory — Git matches a fetch differently inside
    a repository than outside one — so a review run in the workspace can name
    an extension that never governed the command. A step label pointing at a
    permission to pre-configure is as wrong as a settlement promise when it
    names the wrong extension, so this row recovers nothing.
    """

    from codex_plugin_scanner.guard.daemon import native_review_allow_hint as module

    fixture = real_native_review_fixture("git fetch origin main", cwd=tmp_path, home_dir=tmp_path)
    reviewed = project_native_review_fixture(fixture, cwd=tmp_path, home_dir=tmp_path)
    monkeypatch.setattr(module, "review_command_native", lambda _command, **_kwargs: reviewed)
    home = tmp_path / "home"
    (home / "project").mkdir(parents=True)
    monkeypatch.setattr(module.Path, "home", classmethod(lambda _cls: home))

    def approval(cwd: str) -> dict[str, object]:
        return {
            "status": "pending",
            "workspace": str(tmp_path),
            "raw_command_text": "git fetch origin main",
            "action_envelope_json": {
                "action_type": "shell_command",
                "command": "git fetch origin main",
                "raw_payload_redacted": {
                    "cwd": cwd,
                    "tool_name": "Shell",
                    "tool_input": {"command": "git fetch origin main", "working_directory": cwd},
                },
            },
        }

    assert (
        module.live_approval_extension_hint(approval(".../project"), guard_home=tmp_path, snapshot=fixture.snapshot)
        is None
    )
    assert (
        module.live_approval_extension_allow_hint(
            approval(".../project"), guard_home=tmp_path, snapshot=fixture.snapshot
        )
        is None
    )

    recovered = module.live_approval_extension_hint(
        approval("~/project"), guard_home=tmp_path, snapshot=fixture.snapshot
    )
    assert recovered is not None
    assert validated_extension_coverage_hint(recovered) is not None


_STORED_COVERAGE: dict[str, object] = {
    "schema": "guard.extension-coverage-hint.v1",
    "catalog_digest": "a" * 64,
    "segments": [
        {
            "index": 0,
            "executable": "git",
            "extension_ids": ["command.git"],
            "rule_ids": ["command.git.unverified-fetch"],
            "permission_ids": [],
        }
    ],
}
_LIVE_ALLOW: dict[str, object] = {
    "schema": "guard.extension-allow-hint.v1",
    "permission_ids": ["command.git.permission.fetch"],
    "rule_ids": ["command.git.unverified-fetch"],
    "extension_ids": ["command.git"],
    "relied_permission_ids": [],
    "catalog_digest": "b" * 64,
}


def test_a_stored_coverage_only_hint_still_re_reviews_for_the_settlement(monkeypatch, tmp_path: Path) -> None:
    """Coverage in the stored column must not read as "the settlement was decided".

    A queue-time review that ran out of budget, missed the digest or found no
    all-or-nothing settlement still stores the coverage it read out of evidence
    it already had. Before coverage existed, that row stored nothing and the
    read path re-reviewed it; a row that now carries coverage has to be
    re-reviewed the same way or it silently loses its Always allow offer.
    """

    from codex_plugin_scanner.guard.daemon import native_review_allow_hint as module

    live_coverage = {**_STORED_COVERAGE, "catalog_digest": "c" * 64}
    monkeypatch.setattr(
        module,
        "live_approval_extension_hint",
        lambda *_args, **_kwargs: {**_LIVE_ALLOW, "coverage": live_coverage},
    )

    merged = module.recovered_approval_extension_hint(
        _STORED_COVERAGE, {"status": "pending"}, guard_home=tmp_path, snapshot=object()
    )

    assert validated_extension_allow_hint(merged) == validated_extension_allow_hint(_LIVE_ALLOW)
    # The queue-time coverage saw the directory the command really ran in.
    assert validated_extension_coverage_hint(merged) == validated_extension_coverage_hint(_STORED_COVERAGE)


def test_a_stored_settlement_and_a_connector_hint_are_left_alone(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon import native_review_allow_hint as module

    def refuse(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("a stored hint that answered the settlement must not be re-reviewed")

    monkeypatch.setattr(module, "live_approval_extension_hint", refuse)
    stored = {**_LIVE_ALLOW, "coverage": _STORED_COVERAGE}
    connector = {"schema": "guard.connector-setup-hint.v1", "cli_id": "local-cli.gh"}

    for hint in (stored, _LIVE_ALLOW, connector):
        assert (
            module.recovered_approval_extension_hint(
                hint, {"status": "pending"}, guard_home=tmp_path, snapshot=object()
            )
            is hint
        )


def test_a_row_with_nothing_stored_keeps_the_read_time_recovery(monkeypatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon import native_review_allow_hint as module

    monkeypatch.setattr(module, "live_approval_extension_hint", lambda *_args, **_kwargs: dict(_LIVE_ALLOW))
    assert (
        module.recovered_approval_extension_hint(None, {"status": "pending"}, guard_home=tmp_path, snapshot=object())
        == _LIVE_ALLOW
    )

    monkeypatch.setattr(module, "live_approval_extension_hint", lambda *_args, **_kwargs: None)
    assert (
        module.recovered_approval_extension_hint(None, {"status": "pending"}, guard_home=tmp_path, snapshot=object())
        is None
    )


def test_python_and_resident_command_only_keys_stay_identical() -> None:
    import re

    from codex_plugin_scanner.guard.daemon import native_review_allow_hint as module

    source = (
        Path(__file__).resolve().parents[1]
        / "rust"
        / "crates"
        / "guard-runtime"
        / "src"
        / "hook_direct_review_request.rs"
    ).read_text(encoding="utf-8")
    block = re.search(r"const COMMAND_ONLY_INPUT_KEYS: \[&str; \d+\] = \[(.*?)\];", source, re.DOTALL)
    assert block is not None
    assert set(re.findall(r'"([^"]+)"', block.group(1))) == set(module._COMMAND_ONLY_INPUT_KEYS)
