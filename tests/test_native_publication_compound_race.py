"""A verified publication promotion races a real native compound hook.

Publisher/credential I/O uses the existing disposable fixture. The compiler,
snapshot publisher, captured hook context, resident and decisions are real.
"""

from __future__ import annotations

import contextlib
import io
import json
import threading

from codex_plugin_scanner.guard import native_hook_edge
from codex_plugin_scanner.guard import store as store_module
from codex_plugin_scanner.guard.catalog_delivery import (
    activation_store,
    active_security,
    current_refresh,
    discovery,
    lifecycle_store,
)
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from tests.test_current_publication_refresh import (
    commit_initial,
    periodic,
    read,
    workers,
)
from tests.test_current_publication_refresh import (
    publication as publication,
)


def test_publication_promotion_races_captured_native_compound_decision(publication, monkeypatch):
    state = publication
    monkeypatch.setattr(
        store_module,
        "_build_policy_integrity_secret_store",
        lambda *args, **kwargs: state.store._policy_integrity_secret_store,
    )
    (state.home / "config.toml").write_text(
        'protection_posture = "protected"\ndefault_action = "allow"\n'
        'subprocess_action = "allow"\nsandbox_analysis = "off"\n'
    )
    state.offline = True
    try:
        discovery.installed_discovery(state.home)
    except ValueError as error:
        assert "preparing" in str(error)
    workers()
    initial = discovery.installed_discovery(state.home)
    commit_initial(state)
    publisher = NativePolicySnapshotPublisher(store=state.store)
    event_file = state.home / "compound-event.json"

    def hook(command):
        from codex_plugin_scanner.cli import main

        event_file.write_text(
            json.dumps(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                    "cwd": str(state.home),
                }
            )
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(
                [
                    "guard",
                    "hook",
                    "--guard-home",
                    str(state.home),
                    "--home",
                    str(state.home),
                    "--harness",
                    "claude-code",
                    "--event-file",
                    str(event_file),
                    "--json",
                ]
            )
        return json.loads(output.getvalue())["hookSpecificOutput"]["permissionDecision"]

    def active_identity():
        active = activation_store.read(state.store)
        return (
            active.record_digest,
            active.metadata.program_digest,
            active.metadata.catalog_digest,
            active.metadata.trust_digest,
            lifecycle_store.read(state.store),
            active_security.scope_identity(state.store),
        )

    prepared = threading.Event()
    captured = threading.Event()
    promotion_released = threading.Event()
    failures = []
    hook_generations = []
    worker = None
    real_prepare = current_refresh.prepare_discovery
    real_request = native_hook_edge.native_resident_client_request

    def pause_promotion(*args, **kwargs):
        handle = real_prepare(*args, **kwargs)
        prepared.set()
        assert captured.wait(30), "compound hook never captured its native context"
        promotion_released.set()
        return handle

    def race_request(**kwargs):
        envelope = json.loads(kwargs["payload"])
        generation = envelope["policy_snapshot"]["generation"]
        assert isinstance(generation, int) and generation > 0
        hook_generations.append(generation)
        captured.set()
        assert promotion_released.wait(2), "publication did not resume at the captured hook boundary"
        return real_request(**kwargs)

    def promote():
        try:
            periodic(state)
        except BaseException as error:
            failures.append(error)

    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        assert hook("pwd && pwd") == "allow"
        assert hook("pwd && rm -rf /") == "deny"
        before = active_identity()
        monkeypatch.setattr(current_refresh, "prepare_discovery", pause_promotion)
        state.offline = False
        worker = threading.Thread(target=promote)
        worker.start()
        assert prepared.wait(60), (failures, getattr(state, "last_error", None))
        # Publication bytes are fully verified before the hook starts. Promotion
        # resumes only after that hook has captured its signed native snapshot.
        monkeypatch.setattr(native_hook_edge, "native_resident_client_request", race_request)
        assert hook("pwd && rm -rf /") == "deny"
        monkeypatch.setattr(native_hook_edge, "native_resident_client_request", real_request)
        worker.join(60)
        assert not worker.is_alive()
        assert not failures, failures
        assert hook_generations, "the race must reach the actual native hook transport"
        current = discovery.installed_discovery(state.home)
        assert current.authority != initial.authority, getattr(state, "last_error", None)
        assert read(state)["total_count"] == state.initial_count + 1
        assert active_identity() == before
        assert hook("pwd && pwd") == "allow"
        assert hook("pwd && rm -rf /") == "deny"
    finally:
        captured.set()
        if worker is not None:
            worker.join(60)
            assert not worker.is_alive()
        assert publisher.close()
