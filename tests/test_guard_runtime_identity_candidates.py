"""Launch-executable candidates for configured MCP servers.

Resolution happens in the native ``runtime-identity-probe`` command (its Rust
unit tests cover the lookup, placeholder and shebang rules). These tests drive
the real native binary through the Python glue: the launch request Python
builds and the mapping of the reply back to servers, unresolved kinds and the
candidate cap.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import runtime_identity_candidates
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime_identity_assessment import RuntimeIdentityError
from codex_plugin_scanner.guard.runtime_identity_candidates import RuntimeCandidates, collect_runtime_candidates
from codex_plugin_scanner.guard.runtime_identity_probe import RuntimeProbe

# Server discovery projects each entry's identity through the compiled runtime.
pytestmark = pytest.mark.usefixtures("native_hook_force")


def _executable(path: Path, body: str = "binary-not-a-script\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


def _collect(
    detections: list[HarnessDetection],
    *,
    environment: dict[str, str],
    workspace_dir: Path | None = None,
    limit: int = 64,
) -> RuntimeCandidates:
    return collect_runtime_candidates(detections, environment=environment, workspace_dir=workspace_dir, limit=limit)[0]


def _server(
    name: str,
    command: str | None,
    *,
    env: dict[str, str] | None = None,
    enabled: bool = True,
    harness: str = "claude-code",
) -> GuardArtifact:
    metadata: dict[str, object] = {"env": env or {}}
    if not enabled:
        metadata["enabled"] = False
    return GuardArtifact(
        artifact_id=f"{harness}:{name}",
        name=name,
        harness=harness,
        artifact_type="mcp_server",
        source_scope="project",
        config_path="config.json",
        command=command,
        args=("--serve",),
        transport="stdio",
        metadata=metadata,
    )


def _detection(*artifacts: GuardArtifact, harness: str = "claude-code") -> HarnessDetection:
    return HarnessDetection(
        harness=harness,
        installed=True,
        command_available=True,
        config_paths=("config.json",),
        artifacts=tuple(artifacts),
    )


def test_bare_command_resolves_through_the_given_path_to_the_real_file(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    node = _executable(bin_dir / "node")
    decoy = _executable(tmp_path / "other" / "node")

    found = _collect(
        [_detection(_server("files", "node"))],
        environment={"PATH": str(bin_dir)},
    )

    assert [candidate.path for candidate in found.candidates] == [str(node)]
    assert str(decoy) not in {candidate.path for candidate in found.candidates}
    assert found.candidates[0].sources == (("claude-code", "files", "launch"),)
    assert found.unresolved == ()
    assert not found.truncated


def test_server_configured_path_wins_over_the_process_path(tmp_path: Path) -> None:
    process_node = _executable(tmp_path / "process" / "node")
    server_node = _executable(tmp_path / "server" / "node")

    found = _collect(
        [_detection(_server("files", "node", env={"PATH": str(tmp_path / "server")}))],
        environment={"PATH": str(tmp_path / "process")},
    )

    assert [candidate.path for candidate in found.candidates] == [str(server_node)]
    assert str(process_node) not in {candidate.path for candidate in found.candidates}


def test_path_placeholder_expands_and_keeps_the_servers_own_directories_first(tmp_path: Path) -> None:
    process_node = _executable(tmp_path / "process" / "node")
    server_node = _executable(tmp_path / "opt" / "node22" / "node")
    process = {"PATH": str(tmp_path / "process")}

    shadowed = _collect(
        [_detection(_server("files", "node", env={"PATH": f"{tmp_path / 'opt' / 'node22'}:${{PATH}}"}))],
        environment=process,
    )
    appended = _collect([_detection(_server("files", "node", env={"PATH": "$PATH:/opt/extra"}))], environment=process)

    assert [candidate.path for candidate in shadowed.candidates] == [str(server_node)]
    assert [candidate.path for candidate in appended.candidates] == [str(process_node)]


def test_path_with_a_variable_this_process_lacks_is_unresolved_not_guessed(tmp_path: Path) -> None:
    _executable(tmp_path / "process" / "node")

    found = _collect(
        [_detection(_server("files", "node", env={"PATH": "${NO_SUCH_VARIABLE_FOR_GUARD}/bin:${PATH}"}))],
        environment={"PATH": str(tmp_path / "process")},
    )

    assert found.candidates == ()
    assert [(item.server, item.lookup) for item in found.unresolved] == [("files", "search_path")]


def test_relative_path_entries_resolve_against_the_launch_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    local = _executable(workspace / "node_modules" / ".bin" / "node")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    found = _collect(
        [_detection(_server("files", "node"))],
        environment={"PATH": "node_modules/.bin"},
        workspace_dir=workspace,
    )

    assert [candidate.path for candidate in found.candidates] == [str(local)]
    assert all(os.path.isabs(candidate.path) for candidate in found.candidates)


def test_without_a_workspace_relative_launches_use_the_process_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local = _executable(tmp_path / "tools" / "serve")
    monkeypatch.chdir(tmp_path)

    found = _collect([_detection(_server("files", "./tools/serve"))], environment={"PATH": ""})
    assert [candidate.path for candidate in found.candidates] == [str(local)]


def test_launcher_script_adds_its_shebang_interpreter(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    interpreter = _executable(bin_dir / "python3")
    launcher = _executable(bin_dir / "serve", "#!/usr/bin/env python3\nprint('x')\n")

    found = _collect(
        [_detection(_server("api", "serve"))],
        environment={"PATH": str(bin_dir)},
    )

    roles = {candidate.path: candidate.sources[0][2] for candidate in found.candidates}
    assert roles == {str(launcher): "launch", str(interpreter): "interpreter"}


def test_absolute_and_workspace_relative_commands(tmp_path: Path) -> None:
    absolute = _executable(tmp_path / "abs" / "runner")
    local = _executable(tmp_path / "workspace" / "tools" / "serve")

    found = _collect(
        [
            _detection(
                _server("abs", str(absolute)),
                _server("rel", "./tools/serve"),
                _server("missing", "./tools/missing"),
                _server("blank", "   "),
            )
        ],
        environment={"PATH": os.defpath},
        workspace_dir=tmp_path / "workspace",
    )

    assert sorted(candidate.path for candidate in found.candidates) == sorted([str(absolute), str(local)])
    assert [(item.server, item.lookup) for item in found.unresolved] == [
        ("missing", "configured_path"),
        ("blank", "search_path"),
    ]


def test_missing_commands_are_reported_without_a_path(tmp_path: Path) -> None:
    found = _collect(
        [_detection(_server("ghost", "no-such-tool"), _server("shared", None))],
        environment={"PATH": str(tmp_path)},
    )

    assert found.candidates == ()
    assert [(item.server, item.command) for item in found.unresolved] == [("ghost", "no-such-tool")]
    assert found.unresolved[0].lookup == "search_path"


def test_missing_explicit_path_keeps_the_configured_path_and_its_kind(tmp_path: Path) -> None:
    configured = str(tmp_path / "gone" / "serve")

    found = _collect([_detection(_server("ghost", configured))], environment={"PATH": str(tmp_path)})

    assert [(item.command, item.lookup) for item in found.unresolved] == [(configured, "configured_path")]


def test_disabled_servers_are_skipped(tmp_path: Path) -> None:
    _executable(tmp_path / "bin" / "node")

    found = _collect(
        [_detection(_server("off", "node", enabled=False))],
        environment={"PATH": str(tmp_path / "bin")},
    )

    assert found.candidates == ()
    assert found.unresolved == ()


def test_servers_sharing_an_executable_share_one_candidate(tmp_path: Path) -> None:
    node = _executable(tmp_path / "bin" / "node")

    found = _collect(
        [
            _detection(_server("one", "node"), _server("two", "node")),
            _detection(_server("three", "node", harness="cursor"), harness="cursor"),
        ],
        environment={"PATH": str(tmp_path / "bin")},
    )

    assert len(found.candidates) == 1
    assert found.candidates[0].path == str(node)
    assert {source[:2] for source in found.candidates[0].sources} == {
        ("claude-code", "one"),
        ("claude-code", "two"),
        ("cursor", "three"),
    }


def test_candidate_count_is_capped_and_reported(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    artifacts = []
    for index in range(5):
        _executable(bin_dir / f"tool{index}")
        artifacts.append(_server(f"s{index}", f"tool{index}"))

    found = _collect([_detection(*artifacts)], environment={"PATH": str(bin_dir)}, limit=3)

    assert len(found.candidates) == 3
    assert found.truncated


def test_collecting_candidates_never_runs_the_executable(tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    _executable(tmp_path / "bin" / "node", f"#!/bin/sh\ntouch {marker}\n")

    _collect(
        [_detection(_server("files", "node"))],
        environment={"PATH": str(tmp_path / "bin")},
    )

    assert not marker.exists()


def _fifo(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.mkfifo(path, 0o755)
    return path


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are POSIX only")
def test_executable_fifo_on_the_path_is_neither_opened_nor_a_candidate(tmp_path: Path) -> None:
    _fifo(tmp_path / "bin" / "node")

    found = _collect(
        [_detection(_server("files", "node", env={"PATH": str(tmp_path / "bin")}))],
        environment={"PATH": ""},
    )

    assert found.candidates == ()
    assert [item.server for item in found.unresolved] == ["files"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are POSIX only")
def test_fifo_launch_command_is_unresolved_and_never_opened(tmp_path: Path) -> None:
    fifo = _fifo(tmp_path / "serve")

    found = _collect([_detection(_server("api", str(fifo)))], environment={"PATH": ""})

    assert found.candidates == ()
    assert [(item.server, item.lookup) for item in found.unresolved] == [("api", "configured_path")]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes are POSIX only")
def test_fifo_named_by_a_shebang_is_not_read_or_admitted(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    fifo = _fifo(tmp_path / "interp")
    launcher = _executable(bin_dir / "serve", f"#!{fifo}\n")

    found = _collect([_detection(_server("api", "serve"))], environment={"PATH": str(bin_dir)})

    assert [candidate.path for candidate in found.candidates] == [str(launcher)]


@pytest.mark.parametrize(
    ("shebang", "expected"),
    [
        ("#!/usr/bin/env python3", "python3"),
        ("#!/usr/bin/env -u DEBUG python3", "python3"),
        ("#!/usr/bin/env --unset=DEBUG python3", "python3"),
        ("#!/usr/bin/env -uDEBUG python3", "python3"),
        ("#!/usr/bin/env -i FOO=1 python3", "python3"),
        ("#!/usr/bin/env -S python3 -u", "python3"),
        ("#!/usr/bin/env -- python3", "python3"),
        ("#!/usr/bin/env --no-such-option python3", None),
        ("#!/usr/bin/env -S 'python3 -u'", None),
        ("#!/usr/bin/env -u", None),
    ],
)
def test_env_shebang_options_do_not_hide_the_interpreter(tmp_path: Path, shebang: str, expected: str | None) -> None:
    bin_dir = tmp_path / "bin"
    interpreters = {name: _executable(bin_dir / name) for name in ("python3", "DEBUG")}
    launcher = _executable(bin_dir / "serve", f"{shebang}\nprint('x')\n")

    found = _collect(
        [_detection(_server("api", "serve"))],
        environment={"PATH": str(bin_dir)},
    )

    paths = {candidate.path for candidate in found.candidates}
    assert paths == {str(launcher)} | ({str(interpreters[expected])} if expected else set())


def test_no_servers_never_touch_the_native_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> RuntimeProbe:
        raise AssertionError("native probe must not run without servers")

    monkeypatch.setattr(runtime_identity_candidates, "probe_runtime_launches", refuse)

    found, probe = collect_runtime_candidates([_detection()], environment={"PATH": "/usr/bin"})

    assert found == RuntimeCandidates((), (), False)
    assert probe.launches == ()


def test_request_shares_only_variables_a_launch_could_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def capture(specs: list[dict[str, object]], *, environment: dict[str, str], candidate_limit: int) -> RuntimeProbe:
        seen.update(specs=specs, environment=environment, limit=candidate_limit)
        return RuntimeProbe(
            (), (), (), ({"index": 0, "state": "unresolved", "lookup": "search_path", "targets": []},), False
        )

    monkeypatch.setattr(runtime_identity_candidates, "probe_runtime_launches", capture)

    collect_runtime_candidates(
        [_detection(_server("api", " node ", env={"path": "${TOOLS}/bin:$PATH"}))],
        environment={"PATH": "/p", "TOOLS": "/t", "API_KEY": "secret", "HOME": "/h"},
        workspace_dir=tmp_path,
        limit=5,
    )

    assert seen["specs"] == [{"command": "node", "launch_dir": str(tmp_path), "configured_path": "${TOOLS}/bin:$PATH"}]
    assert seen["environment"] == {"PATH": "/p", "TOOLS": "/t", "HOME": "/h"}
    assert seen["limit"] == 5


def test_reply_for_a_different_number_of_launches_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runtime_identity_candidates,
        "probe_runtime_launches",
        lambda *_args, **_kwargs: RuntimeProbe((), (), (), (), False),
    )

    with pytest.raises(RuntimeIdentityError):
        collect_runtime_candidates([_detection(_server("api", "node"))], environment={"PATH": str(tmp_path)})
