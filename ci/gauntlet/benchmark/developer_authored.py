"""Bind actual isolated observations and trusted Git capture to authored grading."""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .authored_challenges import authored_fixture_digest, load_authored_challenges
from .contracts import canonical_json, digest
from .developer_oracles import verify_worker


def _payload(challenge_id, final, declaration, receipt, plan, public_key):
    worker = verify_worker(declaration, public_key)
    actual = receipt['payload']
    Ed25519PublicKey.from_public_bytes(public_key).verify(base64.b64decode(receipt['signature'], validate=True),
                                                        canonical_json(actual).encode())
    if (actual['plan_digest'] != plan.digest or actual['candidate_tree_digest'] != plan.candidate_tree_digest
            or actual['worker_id'] != worker['worker_id'] or actual['cleanup_complete'] is not True
            or actual.get('runtime_identity') != worker['runtime_identity'] or actual.get('source_measured') is not True
            or actual.get('timed_out') is not False or actual.get('exit_code') != 0):
        raise ValueError('authored result differs from actual bound isolated worker')
    workflow = next(row for row in load_authored_challenges() if row['id'] == challenge_id)
    tests = actual.get('agent_test_execution', [])
    artifacts = {**final, 'documentation_files': [name for name in final['committed_files']
        if name.lower().endswith(('.md', '.rst'))], 'local_remote': final['remote'],
        'agent_test_execution': tests, 'agent_tests_run': len(tests),
        'test_measurement_scope': 'actual bounded selected unittest child invocations; no assertion-coverage claim'}
    payload = {'schema': 'authored-developer-observations.v1', 'challenge_id': challenge_id,
        'fixture_digest': authored_fixture_digest(challenge_id), 'workflow_digest': digest(workflow),
        'worker_id': worker['worker_id'], 'plan_digest': plan.digest,
        'candidate_tree_digest': plan.candidate_tree_digest,
        'cleanup_complete': actual['cleanup_complete'], 'timed_out': actual['timed_out'], 'artifacts': artifacts,
        'observations': [{'case_id': name, **row} for name, row in actual['observations'].items()],
        'original_worker_receipt_digest': digest(receipt)}
    context = {'worker_id': worker['worker_id'], 'candidate_tree_digest': plan.candidate_tree_digest,
        'plan_digest': plan.digest, 'assets': dict(plan.assets), 'repository_id': final['repository_id']}
    return payload, context


def bind_authored(challenge_id, final, declaration, receipt, plan, key):
    payload, context = _payload(challenge_id, final, declaration, receipt, plan, key.public_key().public_bytes_raw())
    result = {'payload': payload, 'signature': base64.b64encode(key.sign(canonical_json(payload).encode())).decode()}
    return {'worker': declaration, 'result': result}, context


def verify_authored(challenge_id, final, declaration, receipt, plan, evidence, context, public_key):
    expected, expected_context = _payload(challenge_id, final, declaration, receipt, plan, public_key)
    if evidence['worker'] != declaration or evidence['result']['payload'] != expected or context != expected_context:
        raise ValueError('authored grade differs from original actual worker/Git collection')
    Ed25519PublicKey.from_public_bytes(public_key).verify(
        base64.b64decode(evidence['result']['signature'], validate=True), canonical_json(expected).encode())
