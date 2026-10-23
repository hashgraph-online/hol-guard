"""Exclusive public JSON/JUnit/text artifacts; no success-only upload path."""
from __future__ import annotations

import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from .contracts import canonical_json, strict_json_loads


def write_gate_artifacts(directory: Path, result: dict):
    directory = Path(directory)
    if not directory.is_absolute() or directory.resolve() != directory:
        raise ValueError('canonical absolute new gate output directory required')
    if directory.is_relative_to(Path(__file__).resolve().parent):
        raise ValueError('gate evidence output must remain outside benchmark source')
    canonical_json(result)
    directory.mkdir(mode=0o700)
    rows = list(result.get('cells', []))
    errors = result.get('errors', [])
    if errors or not rows:
        rows.append({'episode_id': 'gate-integrity', 'status': 'failed',
                     'reasons': errors or [result['status']]})
    failed = sum(row['status'] == 'failed' for row in rows)
    suite = ET.Element('testsuite', name='gauntlet.local-acceptance', tests=str(len(rows)),
                       failures=str(failed), errors='0', skipped='0')
    properties = ET.SubElement(suite, 'properties')
    for name in ('schema', 'status', 'trust_status'):
        ET.SubElement(properties, 'property', name=name, value=str(result.get(name, 'unverified')))
    ET.SubElement(properties, 'property', name='qualification_eligible', value='false')
    for row in rows:
        case = ET.SubElement(suite, 'testcase', name=row['episode_id'],
                             classname='gauntlet.' + row['status'])
        if row['status'] == 'failed':
            failure = ET.SubElement(case, 'failure', message=','.join(row['reasons']))
            failure.text = canonical_json(row)
        elif row['status'] == 'measured-baseline':
            ET.SubElement(case, 'system-out').text = (
                'Attacked unprotected baseline measurement; not a product security pass.\n' + canonical_json(row))
    texts = {'result.json': json.dumps(result, sort_keys=True, indent=2) + '\n',
             'junit.xml': ET.tostring(suite, encoding='unicode') + '\n',
             'summary.txt': f"Local acceptance: {result['status']}\n"
                 f"Cases: {result.get('selected_cases', 0)}; exit: {result['exit_code']}\n"
                 'Qualification: false; trusted-base independent review remains required.\n'
                 + ''.join(f"{row['episode_id']}: {row['status']} {','.join(row.get('reasons', []))}\n"
                           for row in rows)}
    hashes = {}
    for name, text in texts.items():
        raw = text.encode()
        with (directory / name).open('xb') as stream:
            stream.write(raw)
        hashes[name] = hashlib.sha256(raw).hexdigest()
    with (directory / 'manifest.json').open('x') as stream:
        stream.write(canonical_json({'schema': 'gauntlet-ci-gate-artifacts.v1', 'files': hashes,
                                     'qualification_eligible': False}) + '\n')


def run_gate(args):
    """CLI boundary: all evidence failures emit nonzero public artifacts."""
    from .ci_gate import GatePolicyError, gate_campaign, validate_policy
    policy = None
    try:
        try:
            policy = validate_policy(strict_json_loads(args.policy.read_bytes()))
        except (OSError, ValueError) as error:
            raise GatePolicyError(str(error)) from error
        result = gate_campaign(args.root, policy,
            expected_policy_digest=args.expected_policy_digest,
            expected_config_digest=args.expected_config_digest)
    except Exception as error:
        invalid_policy = isinstance(error, GatePolicyError)
        expected = policy['cells'] if not invalid_policy and policy is not None else []
        result = {'schema': 'gauntlet-ci-gate-result.v1', 'status':
                  'invalid-policy' if invalid_policy else 'invalid-evidence',
                  'exit_code': 3 if invalid_policy else 2, 'selected_cases': len(expected),
                  'cells': [{'episode_id': row['episode_id'], 'outcome': row['outcome'],
                             'status': 'failed', 'reasons': ['invalid-evidence']} for row in expected],
                  'errors': [('invalid-policy' if invalid_policy else 'invalid-evidence')],
                  'diagnostic': {'type': type(error).__name__, 'message': str(error)[:4096]},
                  'qualification_eligible': False, 'trust_status': 'local-integrity-only'}
    write_gate_artifacts(args.output_dir, result)
    print(canonical_json(result))
    return result['exit_code']
