"""Provider admission requires the exact extended-allowance pin in both planes."""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from ci.gauntlet.benchmark.ci_runner_preflight import verify_provider_status
from ci.gauntlet.benchmark.provider_quota import ProviderQuota


@pytest.fixture
def extended(tmp_path):
    quota = ProviderQuota.create((tmp_path/'quota').resolve(), authorization_id='original',
        total_tokens=100, maximum_requests=10, model_identity_digest='a'*64)
    key = quota.reserve(prompt_tokens=20, output_limit=10, request_digest='b'*64)
    quota.settle(key, prompt_tokens=20, output_tokens=5)
    quota = quota.extend_allowance(total_tokens=300, authorization_digest='c'*64,
                                  expected_journal_hash=quota.snapshot()['journal_hash'])
    pins = dict(profile='owned-mlx-serial.v1', quota_config_digest=quota.expected_config_digest,
        quota_allowance_digest='c'*64, model_identity_digest='a'*64, binding_sha256='d'*64,
        adapter_sha256='e'*64, server_sha256='f'*64, token_cap=300, maximum_requests=10)
    adapter = dict(schema='gauntlet-mlx-quota-adapter.v1', server_sha256='f'*64,
        adapter_sha256='e'*64, quota_config_digest=quota.expected_config_digest,
        quota_allowance_digest='c'*64, producer_mode='serial-original-tokenization-and-generation',
        counting='full prompt including cached input plus every producer-emitted response token',
        batching=False, draft=False, qualification_eligible=False)
    return pins, dict(adapter=adapter, binding_sha256='d'*64, qualification=False, quota=quota.snapshot())


def test_real_extended_counter_status_preserves_charges_at_admission(extended):
    pins, status = extended
    verified = verify_provider_status(status, pins)
    assert verified['charged_tokens'] == 25 and verified['remaining_tokens'] == 275


@pytest.mark.parametrize('plane,key', [('adapter','quota_allowance_digest'), ('quota','allowance_digest')])
@pytest.mark.parametrize('value', [None, 'a'*64, True, 'C'*64])
def test_changed_or_missing_status_allowance_rejected(extended, plane, key, value):
    pins, status = extended
    if value is None:
        status[plane].pop(key)
    else:
        status[plane][key] = value
    with pytest.raises(ValueError):
        verify_provider_status(status, pins)


def test_old_frozen_pin_cannot_admit_extended_status(extended):
    pins, status = extended
    pins.pop('quota_allowance_digest')
    with pytest.raises(ValueError):
        verify_provider_status(status, pins)


@pytest.mark.parametrize('name', ['ci-runner-config', 'ci-runner-private-cell-config',
                                 'ci-runner-conformance-config', 'ci-runner-compact-config'])
def test_all_config_versions_validate_optional_allowance_digest(extended, name):
    pins, _ = extended
    path = Path(__file__).parents[1]/'ci/gauntlet/benchmark/schemas'/(name+'.v1.json')
    schema = json.loads(path.read_bytes())
    provider = {**schema['properties']['provider'], '$defs':schema['$defs']}
    validator = Draft202012Validator(provider)
    validator.validate(pins)
    original = copy.deepcopy(pins)
    original.pop('quota_allowance_digest')
    validator.validate(original)
    for bad in [None, True, '', 'A'*64, 'c'*63]:
        assert list(validator.iter_errors({**pins, 'quota_allowance_digest':bad}))
