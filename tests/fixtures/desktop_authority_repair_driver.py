"""Opt-in real native/Core process fixture, never installed qualification.

Only the canonical OS-account home, test keyring storage and unrelated background
cloud workers are isolated. Installation, receipt signing, gate/password verification, request
loading, exact grant ownership, publication and native protection are real.
No admission or forward grant is fabricated.
"""

from __future__ import annotations

import io
import json
import os
import sys
from contextlib import redirect_stdout
from pathlib import Path


def fixture_home() -> Path:
    home = Path(os.environ["HOL_GUARD_AUTHORITY_REPAIR_TEST_HOME"]).resolve(strict=True)
    if home != Path.home().resolve(strict=True) or not (home / "isolated-authority-fixture").is_file():
        raise RuntimeError("Explicit isolated account fixture required")
    if (
        not os.environ.get("PYTEST_CURRENT_TEST")
        or Path(os.environ["HOL_GUARD_TEST_KEYRING_FILE"]).parent.resolve(strict=True) != home
    ):
        raise RuntimeError("Isolated test credential storage required")
    return home


def seed(home: Path, *, inverse: bool = False) -> int:
    from codex_plugin_scanner.guard.adapters.base import HarnessContext
    from codex_plugin_scanner.guard.adapters.codex import CodexHarnessAdapter
    from codex_plugin_scanner.guard.approval_gate import update_settings
    from codex_plugin_scanner.guard.codex_hook_integrity import hook_manifest_path
    from codex_plugin_scanner.guard.daemon import server
    from codex_plugin_scanner.guard.native_resident_client import close_native_residents
    from codex_plugin_scanner.guard.store import GuardStore

    config = home / ".codex/config.toml"
    config.parent.mkdir(mode=0o700)
    config.write_text("[features]\nhooks = true\n", encoding="utf-8")
    context = HarnessContext(home_dir=home, guard_home=home / ".hol-guard", workspace_dir=None)
    CodexHarnessAdapter().install(context)
    if inverse:
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from tests.test_codex_hook_recovery import crash

        crash(context, "manifest")
        (home / "isolated-publication-inverse").write_text("owned fixture lifecycle", encoding="utf-8")
    update_settings(
        context.guard_home,
        {
            "enabled": True,
            "new_password": "isolated-desktop-native-repair",
            "confirm_password": "isolated-desktop-native-repair",
        },
    )
    manifest = hook_manifest_path(context.guard_home, config)
    if not inverse:
        manifest.unlink()  # Generated incident fixture: receipt/config/key stay intact.
    store = GuardStore(context.guard_home)
    for name in ("_start_aibom_inventory_refresh", "_start_supply_chain_bundle_refresh", "_start_headless_cloud_sync"):
        setattr(server.GuardDaemonServer, name, lambda _self: None)
    server.start_command_queue_worker = lambda _store, existing: existing
    server.start_cloud_sync_sync_worker = lambda _store, existing, **_kwargs: existing
    server._queue_headless_cloud_sync = lambda **_kwargs: {"status": "not_configured"}
    daemon = server.GuardDaemonServer(store, host="127.0.0.1", port=0, home_dir=home)
    try:
        if not inverse:
            daemon.start()
        ready = home / "authority-fixture-ready.json"
        with ready.open("x", encoding="utf-8") as stream:
            json.dump({"manifest_path": str(manifest), "config_path": str(config)}, stream)
        ready.chmod(0o600)
        if sys.stdin.readline().strip() != "stop":
            raise RuntimeError("Owned fixture stop required")
        return 0
    finally:
        if not inverse:
            daemon.stop()
        close_native_residents()


def main() -> int:
    home = fixture_home()
    from codex_plugin_scanner.guard.cli import commands_lifecycle_gate

    # Production intentionally resolves the OS account without HOME. This
    # generated fixture maps that one boundary to its isolated account root;
    # real approval verification and exact action/subject/nonce checks remain.
    commands_lifecycle_gate.trusted_user_home = lambda: home
    if sys.argv[1:] in (["--seed"], ["--seed-inverse"]):
        return seed(home, inverse=sys.argv[1:] == ["--seed-inverse"])
    if (home / "isolated-publication-inverse").is_file():
        from codex_plugin_scanner.guard.adapters.base import HarnessContext
        from codex_plugin_scanner.guard.adapters.codex import codex_native_hook_state
        from codex_plugin_scanner.guard.cli import codex_authority_repair
        from codex_plugin_scanner.guard.store import GuardStore

        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from tests.test_runtime_transition_configured_inverse import OwnedDaemonLifecycle

        verify = codex_authority_repair.verify_and_retire_codex_publication_inverse

        def verify_with_owned_fixture_daemon(pending, **kwargs):
            # Qualification uses the existing real source daemon fixture after
            # restoration. Production daemon-generation integration is separate.
            plan = pending.authorization.plan
            assert plan.native_runtime is not None
            store = GuardStore(plan.guard_home)
            context = HarnessContext(home_dir=home, guard_home=plan.guard_home, workspace_dir=None)
            store.set_managed_install("codex", True, None, codex_native_hook_state(context), "isolated-desktop-inverse")
            daemon = OwnedDaemonLifecycle(home, plan.guard_home, plan.native_runtime.path)
            try:
                daemon.start(pending.authorization.deadline_monotonic)
                proof = verify(pending, **kwargs)
                daemon.stop(pending.authorization.deadline_monotonic)
                assert daemon.pids == daemon.retired and len(daemon.pids) == 1
                return proof
            finally:
                daemon.cleanup()

        codex_authority_repair.verify_and_retire_codex_publication_inverse = verify_with_owned_fixture_daemon
    from codex_plugin_scanner.cli import main as core_main

    sys.argv[0] = "hol-guard"
    output = io.StringIO()
    with redirect_stdout(output):
        code = core_main(sys.argv[1:])
    observed = output.getvalue()
    response = home / "last-source-response.json"
    response.write_text(observed, encoding="utf-8")
    response.chmod(0o600)
    sys.stdout.write(observed)
    sys.stdout.flush()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
