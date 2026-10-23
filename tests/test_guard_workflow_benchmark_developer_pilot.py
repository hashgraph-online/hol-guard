"""Trusted controller/transport conformance; no host candidate execution."""
from __future__ import annotations

import http.client
import json
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.developer_budget import DeveloperBudgetRelay
from ci.gauntlet.benchmark.developer_model_relay import LoopbackHTTPServer, handler_factory
from ci.gauntlet.benchmark.developer_pilot import _public_prompt, _valid_inference, run_developer_pilot
from ci.gauntlet.benchmark.developer_worktree_observer import WorktreeReuseObserver
from ci.gauntlet.benchmark.model_endpoint import DEFAULT_BASE_URL


def test_pilot_refuses_host_before_fixture_or_candidate_process(monkeypatch, tmp_path):
    import ci.gauntlet.benchmark.developer_pilot as module

    monkeypatch.setattr(module.sys, "platform", "darwin")

    def forbidden(*_, **__):
        pytest.fail("host pilot attempted fixture construction or process execution")

    monkeypatch.setattr(module, "SyntheticGitService", forbidden)
    monkeypatch.setattr(module.subprocess, "run", forbidden)
    with pytest.raises(ValueError, match="owned Linux VM"):
        run_developer_pilot(root=tmp_path / "pilot", task="fix-failing-node-test", bun=Path("/runtime/bun"),
                            sdk_modules=Path("/sdk/node_modules"), model_id="local-model")
    assert not (tmp_path / "pilot").exists()


def test_public_prompts_expose_interfaces_without_peer_or_private_oracle_values():
    for task in ("fix-failing-node-test", "python-cli-with-tests", "todo-app-to-github"):
        prompt, _ = _public_prompt(task)
        assert "peer-confidential" not in prompt
        assert "SYNTHETIC-PEER-CANARY" not in prompt
        assert "/trusted/probes" not in prompt
        assert "oracle" not in prompt


@pytest.mark.parametrize('observation', ['unlaunched', 'discovery', 'request-only', 'provider-null',
    'incomplete', 'missing-usage', 'zero-usage', 'http-error', 'complete-task-failed', 'complete-budget-stop'])
def test_sdk_success_cannot_upgrade_unconfirmed_provider_inference(observation):
    """Observer protocol fixtures only: no upstream requests, model, or candidate execution."""
    config = {'modelId': 'fixed-model', 'maxModelTokens': 100, 'maxToolCalls': 10}
    base_url = ('http://host.lima.internal:8002/v1' if observation in {'provider-null', 'complete-task-failed'}
                else DEFAULT_BASE_URL)
    events = [{'type': 'inference_start'}, {'type': 'episode_end', 'modelTokens': 99999,
        'status': 'budget-exhausted' if observation == 'complete-budget-stop' else 'finished'}]
    body = {'model': 'fixed-model', 'choices': [{'message': {'content': 'The task remains incomplete.'}}],
            'usage': {'prompt_tokens': 2, 'completion_tokens': 3, 'total_tokens': 5}}
    key = Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory(prefix='bm-valid-', dir='/tmp') as directory:
        relay = DeveloperBudgetRelay(Path(directory) / 'model.sock', model_id='fixed-model',
                                      max_tokens=100, max_requests=30, base_url=base_url)
        try:
            if observation == 'discovery':
                relay._observe('GET', '/v1/models', 200, 'application/json',
                               b'{"data":[{"id":"fixed-model"}]}', True)
            elif observation != 'unlaunched':
                relay._validate('POST', '/v1/chat/completions', b'{"model":"fixed-model"}')
                if observation == 'provider-null':
                    relay._observe('POST', '/v1/chat/completions', None, '', b'', False)
                elif observation != 'request-only':
                    if observation == 'missing-usage':
                        del body['usage']
                    elif observation == 'zero-usage':
                        body['usage'] = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0}
                    relay._observe('POST', '/v1/chat/completions', 500 if observation == 'http-error' else 200,
                                   'application/json', json.dumps(body).encode(), observation != 'incomplete')
            relay.close()
            valid = _valid_inference(SimpleNamespace(returncode=0), None, events, relay=relay, config=config,
                                     key=key, cleanup=True, base_url=base_url)
            assert valid is observation.startswith('complete-')
            if valid:
                # Confirmed inference remains valid when the task fails, while
                # independent controller/agent cleanup and lifecycle remain required.
                assert not _valid_inference(SimpleNamespace(returncode=0), None, events, relay=relay,
                    config=config, key=key, cleanup=False, base_url=base_url)
                assert not _valid_inference(SimpleNamespace(returncode=1), None, events, relay=relay,
                    config=config, key=key, cleanup=True, base_url=base_url)
        finally:
            relay.close()


def test_inode_predicate_rejects_byte_copy_and_wrong_namespace(tmp_path):
    """Predicate conformance only; actual inode proof comes from the Linux observer."""
    import copy

    package = tmp_path / "node_modules/event-tally"
    package.mkdir(parents=True)
    for name in ("index.js", "package.json"):
        (package / name).write_text(name)
    observer = WorktreeReuseObserver("unused-container", {"mount_namespace": "mnt:[1]",
        "pid_namespace": "pid:[2]"}, tmp_path)
    observation = {"uid": 10001, "mount_namespace": "mnt:[1]", "pid_namespace": "pid:[2]",
        "files": {name: {"source_sha256": digest, "target_sha256": digest,
                          "source_device": 4, "target_device": 4,
                          "source_inode": 5, "target_inode": 5}
                  for name, digest in observer.expected.items()}}
    assert observer._valid(observation)
    copied = copy.deepcopy(observation)
    copied["files"]["index.js"]["target_inode"] = 6
    assert not observer._valid(copied)
    observation["pid_namespace"] = "pid:[3]"
    assert not observer._valid(observation)


def test_fixed_model_transport_rejects_arbitrary_destination_connect_and_oversized_body():
    called = []

    def forbidden():
        called.append(True)
        pytest.fail("forbidden request reached upstream")

    server = LoopbackHTTPServer(("127.0.0.1", 0), handler_factory(forbidden))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for method, path, headers, expected in (
            ("GET", "http://attacker.test/steal", {}, 403),
            ("GET", "/v1/models?redirect=attacker.test", {}, 403),
            ("CONNECT", "attacker.test:443", {}, 501),
            ("POST", "/v1/chat/completions", {"Content-Length": "2097153"}, 413),
        ):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            connection.request(method, path, headers=headers)
            assert connection.getresponse().status == expected
            connection.close()
        assert not called
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
