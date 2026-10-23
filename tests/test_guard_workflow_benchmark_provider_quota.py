"""Real durable accounting controls; no inference or provider charge is claimed."""
import json
import multiprocessing
import os
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.provider_quota import ProviderQuota, QuotaDeniedError


def make(tmp_path, *, cap=100, requests=10):
    return ProviderQuota.create((tmp_path/'quota').resolve(), authorization_id='test-authorization',
        total_tokens=cap, maximum_requests=requests, model_identity_digest='a'*64)


def reserve(quota, prompt=60, output=40):
    return quota.reserve(prompt_tokens=prompt, output_limit=output, request_digest='b'*64)


def test_contract_facade_reexports_the_same_bounded_json_primitives():
    from ci.gauntlet.benchmark import contracts, json_data
    for name in ('ContractError','canonical_json','strict_json_loads','digest','MAX_RECORD_BYTES'):
        assert getattr(contracts,name) is getattr(json_data,name)


def test_exact_reservation_refund_and_boundary(tmp_path):
    quota = make(tmp_path)
    with pytest.raises(QuotaDeniedError, match='remaining'):
        reserve(quota, 80, 21)
    assert quota.snapshot()['requests'] == 0
    lease = reserve(quota)
    assert quota.snapshot()['remaining_tokens'] == 0
    quota.settle(lease, prompt_tokens=60, output_tokens=4)
    assert quota.snapshot()['known_tokens'] == 64
    lease = reserve(quota, 30, 6)
    quota.settle(lease, prompt_tokens=30, output_tokens=6)
    snapshot = quota.snapshot()
    assert snapshot['charged_tokens'] == snapshot['known_tokens'] == 100
    assert snapshot['reserved_tokens'] == 0
    with pytest.raises(QuotaDeniedError):
        reserve(quota, 1, 1)


def test_milestone_ceiling_counts_existing_spend_and_exact_output_reservation(tmp_path):
    quota = make(tmp_path)
    key = reserve(quota, 60, 10)
    quota.settle(key, prompt_tokens=60, output_tokens=4)
    before = quota.snapshot()
    with pytest.raises(QuotaDeniedError, match='remaining'):
        quota.reserve(prompt_tokens=6, output_limit=6, request_digest='b'*64,
                      maximum_accounted_tokens=75)
    assert quota.snapshot() == before
    key = quota.reserve(prompt_tokens=6, output_limit=5, request_digest='b'*64,
                        maximum_accounted_tokens=75)
    quota.settle(key, prompt_tokens=6, output_tokens=5)
    assert quota.snapshot()['known_tokens']==75
    assert quota.snapshot()['token_cap']==100  # Lifetime authorization is unchanged.
    with pytest.raises(QuotaDeniedError):
        quota.reserve(prompt_tokens=1, output_limit=1, request_digest='b'*64,
                      maximum_accounted_tokens=75)


@pytest.mark.parametrize('ceiling', [True, 0, -1, 1.0, '75'])
def test_milestone_ceiling_is_not_coerced(tmp_path, ceiling):
    quota = make(tmp_path)
    with pytest.raises(QuotaDeniedError):
        quota.reserve(prompt_tokens=1, output_limit=1, request_digest='b'*64,
                      maximum_accounted_tokens=ceiling)
    assert quota.snapshot()['requests']==0


def test_milestone_cannot_increase_lifetime_authorization(tmp_path):
    quota = make(tmp_path)
    with pytest.raises(QuotaDeniedError):
        quota.reserve(prompt_tokens=80, output_limit=21, request_digest='b'*64,
                      maximum_accounted_tokens=1000)
    assert quota.snapshot()['requests']==0


def test_restart_preserves_spend_and_does_not_reset_unknown_request(tmp_path):
    quota = make(tmp_path)
    lease = reserve(quota, 20, 10)
    quota.settle(lease, prompt_tokens=20, output_tokens=2)
    quota = ProviderQuota(quota.root, expected_config_digest=quota.expected_config_digest)
    assert quota.snapshot()['known_tokens'] == 22
    lease = reserve(quota, 50, 20)
    restarted = ProviderQuota(quota.root, expected_config_digest=quota.expected_config_digest)
    assert restarted.snapshot()['charged_tokens'] == 92
    assert restarted.snapshot()['pending_requests'] == 1
    with pytest.raises(QuotaDeniedError, match='unsettled'):
        reserve(restarted, 1, 1)
    restarted.uncertain(lease, reason='provider-lost-before-terminal-accounting')
    assert restarted.snapshot()['halted'] is True
    with pytest.raises(QuotaDeniedError):
        restarted.settle(lease, prompt_tokens=50, output_tokens=0)
    assert restarted.snapshot()['charged_tokens'] == 92


@pytest.mark.parametrize(('prompt','output'), [(True,1),(1,False),(0,2),(1,-1),(1,1.0)])
def test_quota_types_are_not_coerced(tmp_path, prompt, output):
    with pytest.raises(QuotaDeniedError):
        reserve(make(tmp_path), prompt, output)


def test_settlement_is_single_use_exact_prompt_and_output_bounded(tmp_path):
    quota = make(tmp_path)
    key = reserve(quota, 60, 40)
    for prompt, output in ((59,4),(60,41),(60,True)):
        with pytest.raises(QuotaDeniedError):
            quota.settle(key, prompt_tokens=prompt, output_tokens=output)
    assert quota.snapshot()['reserved_tokens'] == 100
    quota.settle(key, prompt_tokens=60, output_tokens=0)
    with pytest.raises(QuotaDeniedError):
        quota.settle(key, prompt_tokens=60, output_tokens=0)
    assert quota.snapshot()['charged_tokens'] == 60


def test_request_limit_is_separate_from_token_cap(tmp_path):
    quota = make(tmp_path, requests=1)
    key = reserve(quota, 1, 1)
    quota.settle(key, prompt_tokens=1, output_tokens=0)
    with pytest.raises(QuotaDeniedError, match='remaining'):
        reserve(quota, 1, 1)
    assert quota.snapshot()['remaining_tokens'] == 99


@pytest.mark.parametrize('filename', ['events.jsonl','quota.lock','config.json'])
def test_missing_durable_state_is_never_recreated(tmp_path, filename):
    quota = make(tmp_path)
    reserve(quota)
    (quota.root/filename).unlink()
    with pytest.raises(QuotaDeniedError, match='missing'):
        ProviderQuota(quota.root, expected_config_digest=quota.expected_config_digest)
    assert not (quota.root/filename).exists()


def test_interrupted_or_modified_journal_is_not_repaired_implicitly(tmp_path):
    quota = make(tmp_path)
    reserve(quota)
    journal = quota.root/'events.jsonl'
    original = journal.read_bytes()
    journal.write_bytes(original+b'{')
    with pytest.raises(QuotaDeniedError, match='interrupted'):
        reserve(quota, 1, 1)
    row = json.loads(original)
    row['previous_hash'] = 'c'*64
    journal.write_text(json.dumps(row)+'\n')
    with pytest.raises(QuotaDeniedError, match='chain'):
        quota.snapshot()


def test_changed_configuration_and_another_counter_cannot_reuse_pin(tmp_path):
    quota = make(tmp_path)
    other = ProviderQuota.create((tmp_path/'other').resolve(), authorization_id='test-authorization',
        total_tokens=100, maximum_requests=10, model_identity_digest='a'*64)
    assert quota.expected_config_digest != other.expected_config_digest
    with pytest.raises(QuotaDeniedError, match='external pin'):
        ProviderQuota(other.root, expected_config_digest=quota.expected_config_digest)
    config = quota.root/'config.json'
    data = json.loads(config.read_bytes())
    data['total_tokens'] = 1000
    config.write_text(json.dumps(data))
    with pytest.raises(QuotaDeniedError, match='external pin'):
        quota.snapshot()


def test_private_ordinary_single_link_files_required(tmp_path):
    quota = make(tmp_path)
    quota.root.chmod(0o750)
    with pytest.raises(QuotaDeniedError, match='private'):
        quota.snapshot()
    quota.root.chmod(0o700)
    os.link(quota.root/'events.jsonl', tmp_path/'journal-link')
    with pytest.raises(QuotaDeniedError, match='regular files'):
        quota.snapshot()


def test_symlink_journal_is_not_followed(tmp_path):
    quota = make(tmp_path)
    target = tmp_path/'synthetic-canary'
    target.write_text('must not read this test canary as accounting')
    (quota.root/'events.jsonl').unlink()
    (quota.root/'events.jsonl').symlink_to(target)
    with pytest.raises(QuotaDeniedError):
        quota.snapshot()


def _admit_child(path, pin, start, output):
    quota = ProviderQuota(path, expected_config_digest=pin)
    start.wait(5)
    try:
        output.put(('admitted', reserve(quota, 50, 10)))
    except QuotaDeniedError:
        output.put(('denied', None))


def test_two_real_processes_cannot_double_admit(tmp_path, monkeypatch):
    quota = make(tmp_path)
    # Spawn starts a fresh interpreter before it receives the parent's
    # sys.path. Put this checkout on its initial import path as well.
    checkout = str(Path(__file__).resolve().parents[1])
    monkeypatch.syspath_prepend(checkout)
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join((checkout, os.environ.get("PYTHONPATH", ""))))
    context = multiprocessing.get_context('spawn')
    start, output = context.Event(), context.Queue()
    children = [context.Process(target=_admit_child,
                args=(quota.root,quota.expected_config_digest,start,output)) for _ in range(2)]
    try:
        for child in children:
            child.start()
        start.set()
        rows = [output.get(timeout=15) for _ in children]
        for child in children:
            child.join(timeout=5)
            assert child.exitcode == 0
        assert sorted(row[0] for row in rows) == ['admitted','denied']
        assert quota.snapshot()['requests'] == 1
        assert quota.snapshot()['reserved_tokens'] == 60
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
                child.join(timeout=5)
        output.close()
        output.join_thread()
