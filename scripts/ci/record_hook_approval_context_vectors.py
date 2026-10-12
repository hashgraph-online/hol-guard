#!/usr/bin/env python3
"""Record hook approval-context vectors from the Python implementation.

Run at the commit that still carries the Python builders
(``_runtime_hook_approval_context_token`` in
``cli/commands_support_runtime_policy.py`` and
``_generic_hook_approval_context_token`` in
``cli/commands_hook_native_generic.py``) with a compiled runtime:

    HOL_GUARD_NATIVE_BINARY=... .venv/bin/python scripts/ci/record_hook_approval_context_vectors.py

Each vector records the native request inputs, the five components the old
builder produced and its token. Launch identity is replaced on both sides by
a deterministic digest of its transport fields, and reuse nonces by a
counter, so the Rust composition replays every vector exactly.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import itertools
import json
import os
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from codex_plugin_scanner.guard import native_context  # noqa: E402
from codex_plugin_scanner.guard import native_hook_approval_context as native  # noqa: E402
from codex_plugin_scanner.guard.cli import commands_hook_native_generic as generic  # noqa: E402
from codex_plugin_scanner.guard.cli import commands_support_runtime_policy as runtime  # noqa: E402
from codex_plugin_scanner.guard.config import GuardConfig  # noqa: E402
from codex_plugin_scanner.guard.models import GuardArtifact  # noqa: E402
from codex_plugin_scanner.guard.native_policy_snapshot import provision_native_policy_verifier_key  # noqa: E402
from codex_plugin_scanner.guard.proxy import _env as proxy_env  # noqa: E402
from codex_plugin_scanner.guard.runtime.approval_context import build_configured_environment_hash  # noqa: E402

OUTPUT = ROOT / "rust/crates/guard-runtime/tests/fixtures/hook_approval_context_vectors.json.gz"
HOME = "/hol-fixture-home/u"
AMBIENT = {
    "HERMES_GUARD_TOKEN": "fixture-token",
    "HOME": HOME,
    "LANG": "C",
    "PATH": "/hol-fixture/bin:/usr/bin",
    "PYTHONPATH": "/hol-fixture/py",
}


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def fake_launch(
    command: object,
    *,
    args: Any = (),
    structured_command: bool = False,
    direct_executable: bool = False,
    search_path: str | None = None,
    cwd: Path | None = None,
    home_dir: Path | None = None,
    launch_env: Any = None,
) -> dict[str, object]:
    request = {
        "args": list(args),
        "command": command,
        "cwd": str(cwd) if cwd is not None else None,
        "direct_executable": direct_executable,
        "home_dir": str(home_dir) if home_dir is not None else None,
        "launch_env": dict(launch_env) if launch_env is not None else None,
        "search_path": search_path,
        "structured_command": structured_command,
    }
    digest = hashlib.sha256(_canonical(request)).hexdigest()
    return {
        "argv_sha256": digest,
        "entrypoint": {"digest": digest[16:32], "status": "fixture"},
        "executable": f"exe:{digest[:16]}",
        "launch_cwd": request["cwd"],
    }


class _Recorder:
    def __init__(self) -> None:
        self.nonces = 0
        self.components: dict[str, object] | None = None

    def token_hex(self, _size: int) -> str:
        self.nonces += 1
        return f"{self.nonces:032x}"

    def wrap(self, real: Any) -> Any:
        def build(**components: object) -> str:
            self.components = json.loads(_canonical(components))
            return real(**components)

        return build


@contextmanager
def _patched(recorder: _Recorder) -> Iterator[None]:
    fake_os = SimpleNamespace(environ=AMBIENT)
    saved = (
        runtime.build_runtime_launch_identity,
        generic.build_runtime_launch_identity,
        runtime.build_approval_context_token,
        generic.build_approval_context_token,
        runtime.secrets,
        proxy_env.os,
        generic.os,
        native.os.environ.get("HOME"),
        native.os,
    )
    runtime.build_runtime_launch_identity = fake_launch
    generic.build_runtime_launch_identity = fake_launch
    runtime.build_approval_context_token = recorder.wrap(saved[2])
    generic.build_approval_context_token = recorder.wrap(saved[3])
    runtime.secrets = SimpleNamespace(token_hex=recorder.token_hex)
    proxy_env.os = fake_os
    generic.os = fake_os
    # The transport snapshots the ambient environment; only the fixture one may reach a vector.
    native.os = SimpleNamespace(environ=AMBIENT, path=os.path, getcwd=os.getcwd)
    os.environ["HOME"] = HOME
    try:
        yield
    finally:
        (
            runtime.build_runtime_launch_identity,
            generic.build_runtime_launch_identity,
            runtime.build_approval_context_token,
            generic.build_approval_context_token,
            runtime.secrets,
            proxy_env.os,
            generic.os,
        ) = saved[:7]
        native.os = saved[8]
        if saved[7] is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = saved[7]


def _envelope(variant: int) -> SimpleNamespace | None:
    if variant == 0:
        return None
    return SimpleNamespace(
        action_type="shell_command",
        command=(None, "git status", "  ", " npm test ")[variant],
        event_name="PreToolUse",
        mcp_server=None,
        mcp_tool=None,
        network_hosts=("example.test",),
        package_intent_kind=None,
        package_manager="npm" if variant == 3 else None,
        package_name=None,
        package_targets=(),
        raw_payload_redacted=(
            {},
            {"permission_mode": "ask"},
            {"permission_mode": "  ", "permissionMode": "bypassPermissions"},
            {"permissionMode": 7},
        )[variant],
        script_name=None,
        target_paths=("/hol-fixture/ws/file.txt",),
        tool_name="Bash",
        workspace=(None, "/hol-fixture/ws", "~/w", "rel/ws")[variant],
        workspace_hash=(None, "wh-1", None, "wh-3")[variant],
    )


RUNTIME_ARTIFACTS = (
    ("tool_action_request", "npm", ("test", "--", "x y")),
    ("mcp_server", "node", ("server.js",)),
    ("tool_action_request", None, ()),
)
RUNTIME_METADATA: tuple[dict[str, object], ...] = (
    {},
    {
        "shell_execution_context_hash": "h1",
        "shell_execution_context_reason_code": "",
        "shell_execution_context_reason_codes": ["a", "b"],
    },
    {
        "shell_execution_context_hash": "h2",
        "shell_execution_context_complete": True,
        "shell_execution_effective_cwds": [
            "/hol-fixture/ws/a",
            " ",
            3,
            "rel/dir",
            "~/proj",
            "/hol-fixture/ws/../x/./y/",
        ],
        "command_security_identity": {"kind": "fixture", "n": 1},
        "interpreter_executable_identities": [{"path": "/hol-fixture/bin/python3"}],
    },
    {
        "shell_execution_context_hash": "h3",
        "shell_execution_context_complete": True,
        "shell_execution_effective_cwds": [],
    },
    {
        "shell_execution_context_hashes": ["x"],
        "shell_execution_context_complete": True,
        "shell_execution_effective_cwds": ["/hol-fixture/c"],
        "shell_execution_context_reason_codes": ["c"],
    },
    {"shell_execution_context_hash": "h5", "shell_execution_context_complete": 1},
    {"shell_execution_context_hash": "", "shell_execution_context_complete": False, "tool_name": "Bash"},
)


def _runtime_env_variants() -> tuple[dict[str, object], ...]:
    matched = build_configured_environment_hash({"A": "1"}, configured_keys=("A",))
    return (
        {},
        {"env": {"A": "1", "PATH": "/hol-fixture/custom"}},
        {"env": {"A": "1"}, "env_keys": ["B", "A", ""]},
        {"env_keys": ["NODE_OPTIONS"], "env_values_hash": "sha:provided"},
        {"env": {"A": "1"}, "env_values_hash": "  ", "envValuesHash": "ignored"},
        {"env": {"A": "1"}, "envValuesHash": f" {matched} "},
        {"env": {"A": "1"}, "env_values_hash": "mismatch", "env_keys": "A"},
        {"env": {"A": "1"}, "env_values_hash": "guard-context-unbound:x"},
        {"env": {"A": 1, "B": "2"}, "env_keys": ["C"], "envValuesHash": "provided-c"},
    )


def _runtime_vectors() -> list[dict[str, object]]:
    vectors: list[dict[str, object]] = []
    workflow = {"capability": "fixture", "digest": "wf-1"}
    product = itertools.product(
        range(len(RUNTIME_ARTIFACTS)), range(len(RUNTIME_METADATA)), _runtime_env_variants(), (None, workflow)
    )
    for index, (artifact_index, metadata_index, env_variant, record) in enumerate(product):
        artifact_type, command, args = RUNTIME_ARTIFACTS[artifact_index]
        metadata = {**RUNTIME_METADATA[metadata_index], **env_variant}
        if index % 5 == 0:
            metadata["shell_execution_effective_cwds"] = ["~nobody-hol-fixture/x"]
            metadata["shell_execution_context_complete"] = True
            metadata["shell_execution_context_hash"] = "err"
        artifact = GuardArtifact(
            artifact_id=f"runtime:{index}",
            name=f"fixture {index}",
            harness="claude-code",
            artifact_type=artifact_type,
            source_scope="project",
            config_path="/hol-fixture/cfg/settings.json",
            command=command,
            args=args,
            transport="stdio" if artifact_type == "mcp_server" else None,
            publisher=None if index % 2 else "fixture-publisher",
            metadata=metadata,
        )
        config = GuardConfig(
            guard_home=Path("/hol-fixture/guard-home") if index % 4 else Path("~/guard-home"),
            workspace=(None, Path("/hol-fixture/cfg"), Path("~/cfg"))[index % 3],
            sandbox_analysis=("off", "on")[index % 2],
        )
        workspace = (None, Path("/hol-fixture/ws"), Path("rel"), Path("~/w"))[index % 4]
        envelope = _envelope(index % 4)
        current_action = ("review", "sandbox-required", "allow")[index % 3]
        composition = {
            "current_config_action": "review",
            "trusted_cli_action": None if index % 2 else "allow",
            "untrusted_payload_action": None,
            "package_action": "warn" if index % 3 == 0 else None,
            "data_flow_action": None,
            "scanner_action": "block" if index % 7 == 0 else None,
        }
        signals = ({"sink": "network", "n": index},) if index % 2 else ()
        evidence = ({"rule": "fixture"},) if index % 3 else ()
        workflow_record = SimpleNamespace(to_dict=lambda record=record: dict(record)) if record else None
        recorder = _Recorder()
        with _patched(recorder):
            inputs = native.runtime_hook_approval_context_inputs(
                artifact=artifact,
                content_hash=f"content-{index}",
                runtime_workspace=workspace,
                action_envelope=envelope,
                config=config,
                policy_config=runtime._runtime_hook_effective_policy_config(config),
                evaluator_policy_version=runtime._RUNTIME_HOOK_EVALUATOR_POLICY_VERSION,
                composition={"current_action": current_action, **composition},
                current_action=current_action,
                risk_classes=runtime._runtime_artifact_risk_classes(artifact),
                data_flow_signals=signals,
                scanner_evidence=evidence,
                workflow_approval_record=workflow_record,
            )
            try:
                token = runtime._runtime_hook_approval_context_token(
                    artifact=artifact,
                    content_hash=f"content-{index}",
                    runtime_workspace=workspace,
                    action_envelope=envelope,
                    config=config,
                    current_action=current_action,
                    data_flow_signals=signals,
                    scanner_evidence=evidence,
                    workflow_approval_record=workflow_record,
                    **composition,
                )
            except RuntimeError:
                vectors.append({"kind": "runtime", "name": f"runtime-{index}", "inputs": inputs, "error": True})
                continue
        vectors.append(_vector("runtime", index, inputs, recorder, token))
    return vectors


def _vector(kind: str, index: int, inputs: dict[str, object], recorder: _Recorder, token: str) -> dict[str, object]:
    assert recorder.components is not None
    assert not token.startswith("guard-context-unbound:"), token
    return {
        "kind": kind,
        "name": f"{kind}-{index}",
        "inputs": inputs,
        "components": recorder.components,
        "nonces": recorder.nonces,
        "token": token,
    }


GENERIC_PAYLOADS: tuple[dict[str, object], ...] = (
    {"tool_name": "Bash", "tool_input": {"command": "echo hi"}},
    {"tool_name": " BASH ", "tool_input": {"command": "  ls -la  "}, "command": "ignored"},
    {"tool_name": "sh", "tool_input": {}},
    {"tool_name": "Read", "tool_input": {"file_path": "/hol-fixture/ws/a"}},
    {"command": " make build ", "tool_name": 5},
    {"command": "  ", "tool_name": "Shell", "arguments": {"command": "pwd"}},
    {},
)
GENERIC_EXTRAS: tuple[dict[str, object], ...] = (
    {},
    {"source_scope": " user ", "artifact_hash": " h1 ", "changed_capabilities": ["a", " ", 3, " b "]},
    {"source_scope": "", "changed_capabilities": "x", "hookEventName": "pretooluse"},
    {"event": " PermissionRequestV2 ", "hook_event_name": "PostToolUse", "artifact_hash": 4},
    {"hook_name": "Custom", "event": "  "},
)


def _generic_vectors() -> list[dict[str, object]]:
    vectors: list[dict[str, object]] = []
    product = itertools.product(range(len(GENERIC_PAYLOADS)), range(len(GENERIC_EXTRAS)), range(4))
    for index, (payload_index, extra_index, envelope_variant) in enumerate(product):
        payload = {**GENERIC_PAYLOADS[payload_index], **GENERIC_EXTRAS[extra_index], "session_id": f"s{index}"}
        config = GuardConfig(
            guard_home=Path("/hol-fixture/guard-home"), workspace=None, sandbox_analysis=("off", "on")[index % 2]
        )
        workspace = (None, Path("/hol-fixture/ws"), Path("rel"))[index % 3]
        home_dir = None if index % 2 else Path("/hol-fixture-home/h")
        harness = ("claude-code", "codex", "cursor")[index % 3]
        current_action = ("review", "sandbox-required")[index % 2]
        decided = {
            "current_config_action": "review",
            "daemon_hint_disposition": None if index % 2 else "ignored",
            "daemon_hint_reason_code": None,
            "trusted_cli_action": None,
            "untrusted_payload_action": "review" if index % 3 == 0 else None,
            "untrusted_payload_action_disposition": None,
            "untrusted_payload_action_reason": None,
        }
        daemon_status = None if index % 2 else "reachable"
        fail_mode = None if index % 3 else "closed"
        envelope = _envelope(envelope_variant)
        recorder = _Recorder()
        with _patched(recorder):
            inputs = native.generic_hook_approval_context_inputs(
                action_envelope=envelope,
                artifact_id=f"generic:{index}",
                artifact_name=f"generic {index}",
                canonical_harness=generic._canonical_harness_name(harness),
                harness=harness,
                publisher=None if index % 2 else "fixture-publisher",
                home_dir=home_dir,
                runtime_workspace=workspace,
                payload=payload,
                payload_digest=generic._generic_hook_payload_digest(payload),
                tool_command=generic.command_text_from_tool_payload(
                    payload.get("tool_name"), payload.get("tool_input", payload.get("arguments"))
                ),
                config=config,
                policy_config=generic._runtime_hook_effective_policy_config(config),
                evaluator_policy_version=generic._GENERIC_HOOK_EVALUATOR_POLICY_VERSION,
                composition={
                    "current_action": current_action,
                    "daemon_status": daemon_status,
                    "fail_mode": fail_mode,
                    **decided,
                },
                current_action=current_action,
            )
            token = generic._generic_hook_approval_context_token(
                action_envelope=envelope,
                artifact_id=f"generic:{index}",
                artifact_name=f"generic {index}",
                config=config,
                current_action=current_action,
                daemon_status=daemon_status,
                fail_mode=fail_mode,
                harness=harness,
                home_dir=home_dir,
                payload=payload,
                publisher=None if index % 2 else "fixture-publisher",
                runtime_workspace=workspace,
                token=decided,
            )
        vectors.append(_vector("generic", index, inputs, recorder, token))
    return vectors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    options = parser.parse_args()
    if not os.environ.get("HOL_GUARD_NATIVE_BINARY"):
        parser.error("HOL_GUARD_NATIVE_BINARY must name the compiled runtime")
    os.environ.update({"HOL_GUARD_NATIVE": "force", "HOL_GUARD_TEST_MODE": "1", "HOL_GUARD_RESIDENT_TEST_SEAMS": "1"})
    real_home = str(Path.home())
    with tempfile.TemporaryDirectory(prefix="hol-actx-") as temp:
        guard_home = Path(temp) / "guard-home"
        (guard_home / "native-runtime").mkdir(mode=0o700, parents=True)
        provision_native_policy_verifier_key(guard_home, b"\x07" * 32)
        native_context.bind_context_digest_home(guard_home)
        previous = os.getcwd()
        os.chdir("/")
        try:
            vectors = _runtime_vectors() + _generic_vectors()
        finally:
            os.chdir(previous)
            from codex_plugin_scanner.guard.native_resident_client import close_native_residents

            close_native_residents(guard_home)
    assert all(temp not in json.dumps(vector) for vector in vectors), "host temp path leaked into a vector"
    assert all(vector["inputs"]["ambient_env"] == AMBIENT for vector in vectors), "host environment leaked"
    assert real_home not in json.dumps(vectors), "host home leaked into a vector"
    document = {"schema": "hook-approval-context-vectors.v1", "vectors": vectors}
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    with options.output.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as stream:
        stream.write(encoded)
    print(f"recorded {len(vectors)} vectors -> {options.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
