"""Lifetime allowance increases retain usage and require explicit external pins."""
import pytest

from ci.gauntlet.benchmark.provider_quota import ProviderQuota, QuotaDeniedError


def make(tmp_path):
    quota = ProviderQuota.create((tmp_path/'quota').resolve(), authorization_id='original',
        total_tokens=100, maximum_requests=10, model_identity_digest='a'*64)
    key = quota.reserve(prompt_tokens=60, output_limit=40, request_digest='b'*64)
    quota.settle(key, prompt_tokens=60, output_tokens=30)
    return quota


def extend(quota, **overrides):
    arguments = dict(total_tokens=300, authorization_digest='c'*64,
                     expected_journal_hash=quota.snapshot()['journal_hash'])
    arguments.update(overrides)
    return quota.extend_allowance(**arguments)


def test_extension_preserves_original_bytes_cost_requests_and_model(tmp_path):
    old = make(tmp_path)
    config = (old.root/'config.json').read_bytes()
    journal = (old.root/'events.jsonl').read_bytes()
    new = extend(old)
    state = new.snapshot()
    assert state['token_cap'] == 300
    assert state['charged_tokens'] == state['known_tokens'] == 90
    assert state['remaining_tokens'] == 210
    assert state['requests'] == 1 and state['maximum_requests'] == 10
    assert state['model_identity_digest'] == 'a'*64
    assert state['allowance_digest'] == 'c'*64
    assert (old.root/'config.json').read_bytes() == config
    assert (old.root/'events.jsonl').read_bytes().startswith(journal)
    for pin in (None, 'd'*64):
        with pytest.raises(QuotaDeniedError, match='authorization pin'):
            ProviderQuota(old.root, expected_config_digest=old.expected_config_digest,
                          expected_allowance_digest=pin)
    with pytest.raises(QuotaDeniedError, match='authorization pin'):
        old.reserve(prompt_tokens=1, output_limit=1, request_digest='b'*64)
    key = new.reserve(prompt_tokens=200, output_limit=10, request_digest='b'*64)
    new.settle(key, prompt_tokens=200, output_tokens=10)
    restarted = ProviderQuota(new.root, expected_config_digest=new.expected_config_digest,
                             expected_allowance_digest='c'*64)
    assert restarted.snapshot()['charged_tokens'] == 300
    with pytest.raises(QuotaDeniedError, match='remaining'):
        restarted.reserve(prompt_tokens=1, output_limit=1, request_digest='b'*64)


@pytest.mark.parametrize('cap', [True, 0, 99, 100, 300.0, 1_000_000_001])
def test_invalid_or_nonincreasing_ceiling_cannot_mutate_journal(tmp_path, cap):
    quota = make(tmp_path)
    before = (quota.root/'events.jsonl').read_bytes()
    with pytest.raises(QuotaDeniedError):
        extend(quota, total_tokens=cap)
    assert (quota.root/'events.jsonl').read_bytes() == before


@pytest.mark.parametrize('halt', [False, True])
def test_pending_or_uncertain_usage_cannot_be_bypassed(tmp_path, halt):
    quota = make(tmp_path)
    key = quota.reserve(prompt_tokens=5, output_limit=5, request_digest='b'*64)
    if halt:
        quota.uncertain(key, reason='lost producer')
    before = (quota.root/'events.jsonl').read_bytes()
    with pytest.raises(QuotaDeniedError, match='settled journal'):
        extend(quota)
    assert (quota.root/'events.jsonl').read_bytes() == before


def test_stale_observation_and_replayed_authorization_are_rejected(tmp_path):
    quota = make(tmp_path)
    with pytest.raises(QuotaDeniedError, match='exact settled journal'):
        extend(quota, expected_journal_hash='d'*64)
    extended = extend(quota)
    with pytest.raises(QuotaDeniedError):
        extend(extended, total_tokens=400)
    final = extend(extended, total_tokens=400, authorization_digest='e'*64)
    assert final.snapshot()['charged_tokens'] == 90
    assert final.snapshot()['remaining_tokens'] == 310
    with pytest.raises(QuotaDeniedError):
        extend(final, total_tokens=500, authorization_digest='c'*64)


def test_truncated_extension_cannot_reuse_new_deployment_pin(tmp_path):
    quota = make(tmp_path)
    journal = (quota.root/'events.jsonl').read_bytes()
    extended = extend(quota)
    (quota.root/'events.jsonl').write_bytes(journal)
    with pytest.raises(QuotaDeniedError, match='authorization pin'):
        extended.snapshot()
