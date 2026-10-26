"""Opt-in paired source test driver; never an installed/runtime qualification.

Only authority, adapter preparation and daemon/native observations are fixtures.
Request decoding, CLI, store, journal publication and inverse are production code.
"""

from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path

from codex_plugin_scanner.cli import _build_parser
from codex_plugin_scanner.guard.adapters.base import HarnessContext, PreparedHarnessInstall
from codex_plugin_scanner.guard.cli import commands_lifecycle_gate
from codex_plugin_scanner.guard.cli import desktop_runtime_transition as cli
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity
from codex_plugin_scanner.guard.runtime_transition import RuntimeTransition, TransitionFile
from codex_plugin_scanner.guard.runtime_transition_admission import NativeProtectionAdmission, _seal_verified_admission
from codex_plugin_scanner.guard.runtime_transition_prepare import prepare_runtime_transition
from codex_plugin_scanner.guard.store import GuardStore


class FixtureAuthority:
    def _policy_integrity_secret_material(self, *, create):
        assert create is False
        return b"paired-source-fixture-only-key!!!", "paired-source-fixture"


def main() -> int:
    args = _build_parser("hol-guard", program_mode="hol-guard").parse_args(sys.argv[1:])
    home = Path(args.home).resolve(strict=True)
    guard = Path(args.guard_home).resolve(strict=True)
    context = HarnessContext(home, None, guard)
    store = GuardStore(guard)
    binding = home / "paired-binding.json"
    if not binding.exists():
        binding.write_bytes(b"previous binding generation")
        binding.chmod(0o600)
        store.set_managed_install(
            "codex", True, None, {"generation": "previous", "managed_hook_config_path": str(binding)}, "fixture"
        )
    commands_lifecycle_gate.canonical_lifecycle_home = lambda: guard
    cli.lifecycle_authority_home = lambda *_args, **_kwargs: guard
    cli.RuntimeTransition = lambda *_args, **_kwargs: RuntimeTransition(
        guard,
        FixtureAuthority(),
        install_store=store,
    )
    cli.require_high_risk = lambda *_args, **_kwargs: None  # Disabled generated fixture gate only.

    class Adapter:
        def prepare_install(self, _context):
            return PreparedHarnessInstall(
                (TransitionFile(binding, binding.read_bytes(), b"candidate binding generation"),),
                {"harness": "codex", "generation": "candidate", "managed_hook_config_path": str(binding)},
            )

    def prepare(request, **kwargs):
        from codex_plugin_scanner.guard import runtime_transition_prepare

        runtime_transition_prepare.get_adapter = lambda _harness: Adapter()
        return prepare_runtime_transition(request, **kwargs)

    cli.prepare_runtime_transition = prepare

    class Driver:
        def __init__(self, _runtime, plan, **_kwargs):
            self.plan = plan

        def stop(self, _artifact, *, deadline_monotonic):
            assert time.monotonic() < deadline_monotonic

        def start(self, _artifact, *, deadline_monotonic):
            assert time.monotonic() < deadline_monotonic

        def observe_protection(self, artifact, operation_id, *, deadline_monotonic):
            assert time.monotonic() < deadline_monotonic
            if artifact == self.plan.candidate:
                assert binding.read_bytes() == b"candidate binding generation"
                if (home / "pause-candidate").is_file():
                    (home / "candidate-ready").write_text("ready")
                    sys.stdin.buffer.read(1)  # Test-only crash boundary, no production hook.
                raise RuntimeError("paired candidate hook failure after publication")
            assert binding.read_bytes() == b"previous binding generation"
            assert store.list_managed_installs()[0]["manifest"]["generation"] == "previous"
            identity = self.plan.native_runtimes["predecessor"]
            native = NativeRuntimeIdentity(
                Path(identity["path"]), identity["size"], identity["mtime_ns"], identity["sha256"]
            )
            return _seal_verified_admission(
                NativeProtectionAdmission(
                    operation_id,
                    artifact["generation"],
                    native,
                    1,
                    "a" * 64,
                    {"paired_source_fixture": "allow"},
                    {"paired_source_fixture": "deny"},
                    guard,
                    time.monotonic(),
                    {
                        "schema": "hol-guard.installed-hook-evidence.v1",
                        "harness": "codex",
                        "paired_source_fixture": True,
                    },
                )
            )

    cli.TransitionDaemonDriver = Driver
    if args.desktop_command == "transition-activate":
        document = json.loads(Path(args.request).read_bytes())
        sys.frozen = True
        candidate = Path(document["managed_root"]) / document["candidate_pointer"]["relativePath"]
        sys.executable = str(candidate.resolve())
        cli.__version__ = document["candidate_pointer"]["version"]
    output = io.StringIO()
    result = cli.run_desktop_runtime_transition(args, context=context, store=store, output_stream=output)
    response = output.getvalue()
    (home / "paired-response.json").write_text(response)
    sys.stdout.write(response)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
