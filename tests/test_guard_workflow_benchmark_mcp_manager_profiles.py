"""Actual locked OMP manager observations, distinct from model ingestion/efficacy."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from ci.gauntlet.benchmark.adapters import omp_mcp_configs
from ci.gauntlet.benchmark.contracts import canonical_json, digest
from ci.gauntlet.benchmark.mcp_protocol_profiles import INSTRUCTION, PROFILES, SCHEMA
from ci.gauntlet.benchmark.service_supervisor import ServiceSupervisor
from tests.test_guard_workflow_benchmark_supervisor import custody, wait_until


@pytest.mark.parametrize('profile', sorted(PROFILES))
def test_actual_locked_manager_protocol_projection(custody, profile):
    bun, sdk = os.environ.get('HOL_WORKFLOW_BUN'), os.environ.get('HOL_WORKFLOW_SDK_ROOT')
    if not bun or not sdk:
        pytest.skip('explicit pinned Bun and SDK required for real manager controls')
    assert Path(bun).is_absolute() and Path(sdk).is_absolute()
    world, directory = custody
    before = world.snapshot()
    with ServiceSupervisor(world, directory, families=('docs', 'mail'),
            protocol_profile={'schema': SCHEMA, 'id': profile}) as supervisor:
        config = directory.parent / 'manager-control.json'
        config.write_text(canonical_json({'schema': 'mcp-protocol-manager-control.v1',
            'sdkRoot': sdk, 'workspace': str(directory.parent),
            'endpoints': omp_mcp_configs(tuple(supervisor.endpoint(f) for f in ('docs', 'mail')),
                                         workspace=directory.parent)}))
        helper = Path(__file__).parents[1] / 'ci/gauntlet/benchmark/mcp_protocol_manager_conformance.ts'
        execution = subprocess.run([bun, str(helper), str(config)], capture_output=True,
            text=True, timeout=40, cwd=directory.parent,
            env={'PATH': '/usr/bin:/bin', 'HOME': str(directory.parent)})
        assert execution.returncode == 0, execution.stdout + execution.stderr
        report = json.loads(execution.stdout)
        assert report['schema'] == 'mcp-protocol-manager-control-result.v1'
        assert report['modelExercised'] is report['guardExercised'] is False
        assert report['qualificationEligible'] is False and report['providerRequests'] == 0
        assert report['connected'] == ['docs', 'mail']
        read = lambda stage: next(t for t in report[stage] if t['rawTool'] == 'docs.read')
        if profile == 'tool-description':
            assert INSTRUCTION in read('before')['description']
        if profile == 'schema-change':
            assert INSTRUCTION not in canonical_json(read('before')['parameters'])
            assert INSTRUCTION in canonical_json(read('after')['parameters'])
        if profile == 'tool-list-change':
            assert 'docs.delete' not in {t['rawTool'] for t in report['before']}
            added = next(t for t in report['after'] if t['rawTool'] == 'docs.delete')
            assert INSTRUCTION in added['description']
        if profile in {'schema-change', 'tool-list-change'}:
            assert {'server': 'docs', 'method': 'notifications/tools/list_changed'} in report['notifications']
        if profile == 'reconnect-schema':
            assert INSTRUCTION not in canonical_json(read('before')['parameters'])
            assert INSTRUCTION in canonical_json(read('afterReconnect')['parameters'])
        if profile == 'structured-content':
            assert INSTRUCTION in canonical_json(report['result']['content'])
            assert report['result']['details']['structuredContent']['untrusted_protocol_instruction'] == INSTRUCTION
        if profile == 'resource-link':
            assert INSTRUCTION in canonical_json(report['result']['details']['rawContent'])
            assert INSTRUCTION not in canonical_json(report['result']['content'])
            assert 'peer-confidential' in canonical_json(report['linkedResource'])
        if profile == 'error-content':
            assert report['result']['isError'] and INSTRUCTION in canonical_json(report['result']['content'])
            assert not report['recovered'].get('isError', False)
        assert (INSTRUCTION in canonical_json(report['resource'])) is (profile == 'resource-read')
        assert (INSTRUCTION in canonical_json(report['prompt'])) is (profile == 'prompt-get')
        if profile == 'misleading-annotations':
            delete = next(t for t in report['before'] if t['rawTool'] == 'docs.delete')
            assert delete['approval'] == 'write'
            assert INSTRUCTION not in canonical_json(delete)
        wait_until(lambda: supervisor.active_sessions == supervisor.active_workers == 0)
        assert world.snapshot() == before
    assert not directory.exists()
    evidence_root = os.environ.get('HOL_WORKFLOW_PROTOCOL_EVIDENCE_DIR')
    if evidence_root:
        target = Path(evidence_root)
        assert target.is_absolute() and target.is_dir() and not target.is_symlink()
        with (target / (profile + '.json')).open('x') as stream:
            stream.write(canonical_json({'schema': 'mcp-protocol-manager-observation.v1',
                'profile': {'schema': SCHEMA, 'id': profile}, 'manager': report,
                'transport_events': supervisor.events,
                'initial_state_digest': digest(before), 'final_state_digest': digest(world.snapshot()),
                'active_sessions': supervisor.active_sessions, 'active_workers': supervisor.active_workers,
                'socket_directory_removed': not directory.exists(), 'model_ingestion_proven': False,
                'qualification_eligible': False}) + '\n')
