"""Prioritize a due complete retry while retaining the following observer."""

from __future__ import annotations

import threading
import time
from contextlib import closing

import pytest

from codex_plugin_scanner.guard.native_policy_publication_lock import hold_policy_publication_mutation
from codex_plugin_scanner.guard.native_policy_snapshot_constants import _PUBLISH_TIMEOUT_SECONDS
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_context import CapturedV3PublicationInputs
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import _policy_fingerprint
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_policy_snapshot_capture_retry import _write_startup_status
from tests.test_native_policy_snapshot_reservation_capture import _make_publisher
from tests.test_native_policy_source_selection import _insert_untrusted_row


@pytest.mark.parametrize("change", ["steady", "configuration", "unsigned-source", "new-request"])
def test_due_retry_preserves_fresh_authority_and_following_observation(tmp_path, monkeypatch, change):
    store = GuardStore(tmp_path / "guard-home")
    calls = []
    with closing(_make_publisher(store, calls, scoped=False)) as publisher:
        original_run = publisher._run
        original_publish = publisher._publish_once
        original_context = publisher._publication_context
        original_fingerprint = publisher._current_input_fingerprint
        original_observe = publisher._policy_input_changed
        original_request = publisher.request_publish
        bootstrap_done = threading.Event()
        setup_paused = threading.Event()
        setup_resume = threading.Event()
        retry_done = threading.Event()
        observation_done = threading.Event()
        request_done = threading.Event()
        refusal_paused = threading.Event()
        refusal_resume = threading.Event()
        failures = []
        inputs = []
        writes = []
        order = []
        observations = []
        requests = []
        request_errors = []
        worker_errors = []
        measuring = False
        in_publication = False
        setup_gate_used = False
        attempt_number = 0
        context_number = 0

        def checked_run():
            try:
                original_run()
            except BaseException as error:
                worker_errors.append(error)
                publisher.close()

        def fingerprint():
            nonlocal setup_gate_used
            if bootstrap_done.is_set() and not in_publication and not setup_gate_used:
                setup_gate_used = True
                setup_paused.set()
                assert setup_resume.wait(_PUBLISH_TIMEOUT_SECONDS)
            return original_fingerprint()

        def request(*, require_source_authority=False):
            original_request(require_source_authority=require_source_authority)
            if measuring and failures:
                requests.append(publisher._epoch)
                request_errors.append(publisher.last_error)
                request_done.set()

        def observe(changed_paths=None):
            tracked = measuring and bool(failures)
            if tracked:
                order.append("observation")
            result = original_observe(changed_paths)
            if tracked:
                observations.append(result)
                observation_done.set()
            return result

        def capture(*, publish_epoch=None, prepared_command_extensions=None):
            nonlocal context_number
            context = original_context(
                publish_epoch=publish_epoch, prepared_command_extensions=prepared_command_extensions
            )
            if not measuring or context is None or publisher.closed:
                return context
            context_number += 1
            captured = context[5]
            assert isinstance(captured, CapturedV3PublicationInputs)
            inputs.append(captured)
            if attempt_number == 1 and context_number >= 2 and len(writes) < 2:
                before_epoch = publisher._epoch
                writes.append(_write_startup_status(store, len(writes) + 1, now=publisher._wall_clock()))
                assert publisher._epoch == before_epoch
            return context

        def publish(*, renew_after_generation=None):
            nonlocal in_publication, attempt_number, context_number
            observed = measuring
            if observed:
                attempt_number += 1
                context_number = 0
                if attempt_number > 1:
                    order.append("publication")
            in_publication = True
            try:
                return original_publish(renew_after_generation=renew_after_generation)
            finally:
                in_publication = False
                if not observed:
                    bootstrap_done.set()
                elif attempt_number == 1:
                    failures.append(
                        (
                            publisher.last_error,
                            publisher.is_ready(),
                            context_number,
                            len(calls),
                            publisher._epoch,
                            publisher._retry_not_before_monotonic is not None
                            and publisher._retry_not_before_monotonic <= publisher._monotonic_clock(),
                            publisher._publish_event.is_set(),
                        )
                    )
                    if change == "configuration":
                        with hold_policy_publication_mutation(store.guard_home):
                            (store.guard_home / "config.toml").write_text(
                                'mode = "enforce"\ndefault_action = "block"\n'
                            )
                    elif change == "unsigned-source":
                        _insert_untrusted_row(store)
                    elif change == "new-request":
                        publisher.request_publish()
                else:
                    retry_done.set()
                    if change == "unsigned-source" and request_done.is_set():
                        # The following observer invalidates the earlier refusal
                        # before scheduling this complete attempt. Inspect its
                        # finished result, not the interval with last_error reset.
                        refusal_paused.set()
                        assert refusal_resume.wait(_PUBLISH_TIMEOUT_SECONDS)

        monkeypatch.setattr(publisher, "_run", checked_run)
        monkeypatch.setattr(publisher, "_current_input_fingerprint", fingerprint)
        monkeypatch.setattr(publisher, "request_publish", request)
        monkeypatch.setattr(publisher, "_policy_input_changed", observe)
        monkeypatch.setattr(publisher, "_publication_context", capture)
        monkeypatch.setattr(publisher, "_publish_once", publish)
        try:
            publisher.start()
            assert publisher.wait_until_ready(time.monotonic() + _PUBLISH_TIMEOUT_SECONDS), publisher.last_error
            assert bootstrap_done.wait(_PUBLISH_TIMEOUT_SECONDS)
            assert setup_paused.wait(_PUBLISH_TIMEOUT_SECONDS)
            assert not worker_errors
            bootstrap_snapshot = publisher.current_snapshot()
            assert bootstrap_snapshot is not None and len(calls) == 1
            initial_epoch = publisher._epoch
            bootstrap_inputs = publisher._published_cloud_inputs
            assert isinstance(bootstrap_inputs, CapturedV3PublicationInputs)
            bootstrap_input_digest = bootstrap_inputs.input_digest
            workspace = tmp_path / "workspace"
            workspace.mkdir()
            measuring = True
            assert publisher.register_workspace(workspace)
            setup_resume.set()
            assert retry_done.wait(_PUBLISH_TIMEOUT_SECONDS), publisher.last_error
            assert observation_done.wait(_PUBLISH_TIMEOUT_SECONDS), publisher.last_error
            if change != "steady":
                assert request_done.wait(_PUBLISH_TIMEOUT_SECONDS), publisher.last_error
            if change == "unsigned-source":
                assert refusal_paused.wait(_PUBLISH_TIMEOUT_SECONDS), publisher.last_error
            observed_snapshot = publisher.current_snapshot()
            observed_binding = publisher.current_snapshot_binding()
            observed_epoch = publisher._epoch
            observed_error = publisher.last_error
            observed_ready = publisher.is_ready()
            current_policy = None if change == "unsigned-source" else publisher._compiled_effective_policy()
        finally:
            setup_resume.set()
            refusal_resume.set()
            publisher.close()
        assert publisher._thread is not None and not publisher._thread.is_alive()
        assert not worker_errors, [type(error).__name__ for error in worker_errors]
        assert failures == [("native_policy_authority_capture_changed", False, 3, 1, initial_epoch + 1, True, True)]
        assert inputs[0].input_digest == bootstrap_input_digest
        assert len(writes) == 2 and all(before != after for before, after in writes)
        assert order.count("publication") >= 1 and observations
        if change == "unsigned-source":
            assert not observed_ready and observed_snapshot is None and observed_binding is None
            assert len(calls) == 1
            assert request_errors and all(error is None for error in request_errors)
            assert observed_error == "native_policy_authority_local_unavailable"
            assert observed_epoch >= initial_epoch + 2 and requests
        else:
            assert observed_ready and observed_snapshot == calls[-1] and observed_binding is not None
            assert observed_snapshot is not None
            assert observed_error is None and len(calls) == 2
            assert current_policy is not None
            assert _policy_fingerprint(current_policy) == (
                observed_snapshot["config_digest"],
                observed_snapshot["mode"],
            )
            published_inputs = publisher._published_cloud_inputs
            assert isinstance(published_inputs, CapturedV3PublicationInputs)
            assert published_inputs.input_digest == inputs[-1].input_digest
            if change == "steady":
                assert observed_epoch == initial_epoch + 1 and requests == []
                assert not any(observations)
                assert order[0] == "publication", "due retry performed duplicate observation before fresh publication"
                assert all(event == "observation" for event in order[1:])
            else:
                assert observed_epoch == initial_epoch + 2 and requests
                assert order[0] == "observation"
                if change == "configuration":
                    assert observed_snapshot["config_digest"] != bootstrap_snapshot["config_digest"]
