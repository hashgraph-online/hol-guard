"""Actual SDK scheduler regression; synthetic unit stream, no model or Native claims."""
import json
import os
import subprocess
from pathlib import Path

import pytest


def test_locked_sdk_budget_stop_preserves_admitted_read_review_and_host_gate(tmp_path):
    sdk_root = os.environ.get('HOL_WORKFLOW_OMP_SDK_ROOT')
    bun = os.environ.get('HOL_WORKFLOW_BUN')
    if not sdk_root or not bun:
        pytest.skip('actual locked SDK lifecycle needs explicit HOL_WORKFLOW_OMP_SDK_ROOT and HOL_WORKFLOW_BUN')
    if not Path(sdk_root).is_absolute() or not Path(bun).is_absolute():
        pytest.fail('SDK/Bun conformance paths must be explicit absolute public artifacts')
    source = Path(__file__).parents[1] / 'ci/gauntlet/benchmark/developer_budget_lifecycle_conformance.ts'
    completed = subprocess.run([bun, str(source), sdk_root], capture_output=True, text=True, timeout=45,
        env={'PATH': '/usr/bin:/bin', 'HOME': str(tmp_path), 'TMPDIR': str(tmp_path)}, cwd=tmp_path)
    assert completed.returncode == 0, completed.stderr + completed.stdout
    report = json.loads(completed.stdout)
    assert report['version'] == '18.4.12'
    assert report['actualModelEpisode'] is report['qualificationEligible'] is report['nativePolicyConformance'] is False
    cases = {case['kind']: case for case in report['cases']}
    assert set(cases) == {'tool-limit', 'token-in-flight', 'hard-deadline'}
    for case in cases.values():
        assert case['syntheticStreamCalls'] == case['apiKeyRequests'] == case['toolCalls'] == 1
        assert case['hostGateCalls'] >= 1
        assert case['observations'][0] == 'admitted:first'
        assert 'admitted:second' not in case['observations']
    for kind, reason in [('tool-limit', 'tool-budget'), ('token-in-flight', 'token-budget')]:
        case = cases[kind]
        assert case['observations'] == ['admitted:first', 'post-start:first', 'post-complete:first']
        assert case['budgetStopReason'] == reason and case['hardCancellation'] is False
        assert case['usageKnown'] is True and case['modelTokens'] >= 1
    hard = cases['hard-deadline']
    assert hard['budgetStopReason'] == 'hard-deadline' and hard['hardCancellation'] is True
    assert 'pre-returned-after-cancellation' in hard['observations']
    assert 'post-complete:first' not in hard['observations']
