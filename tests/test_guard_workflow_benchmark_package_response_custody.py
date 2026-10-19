"""Real local HTTP body receipt cannot outrun durable observer acknowledgment."""
import json
import os
import threading
import urllib.request
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.pinned_dependency_mirror import PinnedZodMirror

CACHE = Path(os.environ.get('HOL_WORKFLOW_ZOD_CACHE',
             '/Users/construct/Documents/projects/hol-guard-refinement/workflow-benchmark-local-assets/zod-3.23.8'))


@pytest.fixture
def mirror(tmp_path):
    if not (CACHE / 'zod-3.23.8.tgz').is_file():
        pytest.skip('explicitly provisioned pinned official package cache unavailable')
    value = PinnedZodMirror(tmp_path / 'mirror', json.loads((CACHE / 'metadata.json').read_text()),
                           (CACHE / 'zod-3.23.8.tgz').read_bytes()).start()
    try:
        yield value
    finally:
        value.close()


def test_client_can_read_real_body_before_observer_but_wait_never_forges_completion(mirror):
    entered, released = threading.Event(), threading.Event()
    journal = []

    def durable_observer(event):
        entered.set()
        assert released.wait(3)
        journal.append(dict(event))

    mirror.observer = durable_observer
    try:
        with urllib.request.urlopen(mirror.url + '/zod', timeout=3) as response:
            raw = response.read()
        assert raw and entered.wait(2)
        assert not journal and not mirror.completed_responses
        with pytest.raises(TimeoutError):
            mirror.wait_for_responses(1, timeout=0.01)
        assert not journal and not mirror.completed_responses
        released.set()
        completed = mirror.wait_for_responses(1, timeout=3)
        assert len(completed) == len(journal) == 1
        assert completed[0] == journal[0]
        assert completed[0]['delivery_stage'] == 'socket-write-complete'
        assert completed[0]['bytes'] == len(raw)
    finally:
        released.set()


def test_observer_failure_after_real_body_read_never_becomes_success_receipt(mirror):
    def failed_observer(_event):
        raise RuntimeError('deliberate unit custody write failure')

    mirror.observer = failed_observer
    with urllib.request.urlopen(mirror.url + '/zod', timeout=3) as response:
        assert response.read()
    with pytest.raises(ValueError, match='observer failed'):
        mirror.wait_for_responses(1, timeout=3)
    assert not mirror.completed_responses


@pytest.mark.parametrize('count,timeout', [(-1, 1), (10001, 1), (1, 0), (1, 31)])
def test_wait_budget_is_bounded(mirror, count, timeout):
    with pytest.raises(ValueError, match='bounded count'):
        mirror.wait_for_responses(count, timeout=timeout)
