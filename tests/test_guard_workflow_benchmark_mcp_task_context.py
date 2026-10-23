"""Synthetic namespace/signature contracts, never evidence of live hook execution."""
import base64
import json
from copy import deepcopy

import pytest
from cryptography.exceptions import InvalidSignature

from ci.gauntlet.benchmark.contracts import canonical_json, digest
from ci.gauntlet.benchmark.mcp_task_context import verify_task_contexts
from tests.test_guard_workflow_benchmark_product_custody import fixture


def packet(tmp_path, *, decision='allow'):
    key, audit = fixture()
    controller = audit['product_plane']['controller_identity']
    product = audit['product_plane']['observations'][0]['identity']
    prompt = 'Actual public task fixture, without source contents or expected answers.'
    (tmp_path / 'public-episode.json').write_text(json.dumps({'prompt': prompt}))
    payload = {'hook_event_name': 'UserPromptSubmit', 'prompt': prompt,
        'config_path': '/product/public/mcp.json', 'session_id': 'root-assigned-session'}
    response = {'decision': decision}
    record = {'schema_version': '1.0', 'kind': 'isolated-normal-prompt-hook-observation',
        'controller_session_id': payload['session_id'], 'public_prompt_digest': digest(prompt),
        'public_prompt': prompt, 'phase': 'episode', 'product_claims_authenticated': False,
        'qualification_eligible': False, 'hooks': [{'sequence': 1, 'identity': product,
            'product_pid': 44, 'host_exec_pid': 55, 'payload_digest': digest(payload),
            'response': response, 'response_digest': digest(response),
            'raw_response': response, 'raw_response_digest': digest(response),
            'returncode': 0 if decision == 'allow' else 2}]}
    report = {'execution_valid': True, 'native_task_contexts': []}
    args = {'attempt_path': tmp_path, 'trusted_public_key': key.public_key().public_bytes_raw(),
            'controller': controller, 'product': product, 'agents': []}
    return key, record, report, args


def bind(key, record, report, args):
    report['native_task_contexts'] = [{'record': record, 'signature': base64.b64encode(
        key.sign(canonical_json(record).encode())).decode()}]
    return verify_task_contexts(report, **args)


def test_exact_signed_context_matches_public_prompt_without_authenticating_policy(tmp_path):
    key, record, report, args = packet(tmp_path)
    bind(key, record, report, args)
    assert not record['product_claims_authenticated'] and not record['qualification_eligible']


@pytest.mark.parametrize('mutation', ['prompt', 'payload', 'namespace', 'pid', 'returncode', 'raw'])
def test_signed_wrong_context_or_actual_boundary_cannot_enable_execution(tmp_path, mutation):
    key, record, report, args = packet(tmp_path)
    record = deepcopy(record)
    if mutation == 'prompt':
        (tmp_path / 'public-episode.json').write_text('{"prompt":"another task"}')
    elif mutation == 'payload':
        record['hooks'][0]['payload_digest'] = '0' * 64
    elif mutation == 'namespace':
        record['hooks'][0]['identity']['mount_namespace'] = 'different-product'
    elif mutation == 'pid':
        record['hooks'][0]['product_pid'] = 0
    elif mutation == 'returncode':
        record['hooks'][0]['returncode'] = 2
    else:
        record['hooks'][0]['raw_response'] = {'decision': 'deny'}
    with pytest.raises(ValueError):
        bind(key, record, report, args)


def test_native_task_denial_is_retained_but_cannot_have_valid_model_execution(tmp_path):
    key, record, report, args = packet(tmp_path, decision='deny')
    with pytest.raises(ValueError, match='execution followed'):
        bind(key, record, report, args)
    report['execution_valid'] = False
    bind(key, record, report, args)


def test_missing_and_duplicate_context_cannot_claim_valid_execution(tmp_path):
    key, record, report, args = packet(tmp_path)
    with pytest.raises(ValueError, match='lacks'):
        verify_task_contexts(report, **args)
    bind(key, record, report, args)
    report['native_task_contexts'] *= 2
    with pytest.raises(ValueError, match=r'lacks|duplicate'):
        verify_task_contexts(report, **args)


def test_context_signature_is_pinned_outside_product_reply(tmp_path):
    key, record, report, args = packet(tmp_path)
    bind(key, record, report, args)
    report['native_task_contexts'][0]['record']['public_prompt'] += ' tampered'
    with pytest.raises(InvalidSignature):
        verify_task_contexts(report, **args)
