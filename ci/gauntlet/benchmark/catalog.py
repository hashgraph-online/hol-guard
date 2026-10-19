"""Public workflow contracts and isolated synthetic seed snapshots.

Expected answers are loaded only by ``load_oracle_fixture`` in the trusted scorer.
The runtime must mount the returned snapshot, never the backing fixture files.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

CATALOG_PATH = Path(__file__).with_name('workflows.json')
FIXTURE_ROOT = Path(__file__).with_name('fixtures')
DEVELOPER_IDS = frozenset({
    'todo-app-to-github', 'fix-failing-node-test', 'add-validation-dependency',
    'contributing-pull-request', 'worktree-report-branch', 'python-cli-with-tests',
})
BUSINESS_IDS = frozenset({
    'business-sales-lead-qualification', 'business-sales-renewal-outreach',
    'business-bd-partner-assessment', 'business-bd-pilot-planning',
    'business-marketing-campaign-package', 'business-marketing-consented-outreach',
    'business-support-ticket-resolution', 'business-support-escalation-triage',
    'business-finance-invoice-reconciliation', 'business-finance-purchase-comparison',
    'business-hr-applicant-shortlist', 'business-hr-interview-coordination',
    'business-operations-status-report', 'business-operations-access-review',
})
SERVICE_FAMILIES = frozenset({'mail', 'crm', 'calendar', 'docs', 'tables', 'chat', 'tickets'})
ATTACK_KINDS = frozenset({'text-injection', 'target-poisoning', 'forged-authorization'})


def load_catalog_document() -> dict[str, Any]:
    """Load public declarations. This contains neither hidden answers nor holdouts."""
    document = json.loads(CATALOG_PATH.read_text(encoding='utf-8'))
    validate_catalog(document)
    return document


def validate_catalog(document: dict[str, Any]) -> None:
    """Reject incomplete inventories, ambiguous attack IDs and broken fixtures."""
    rows = document.get('workflows', [])
    ids = [row.get('id') for row in rows]
    if len(ids) != 20 or set(ids) != DEVELOPER_IDS | BUSINESS_IDS:
        raise ValueError('catalog must contain exactly the six developer and fourteen business IDs')
    for row in rows:
        if row.get('schema_version') != '1.0':
            raise ValueError('unrecognized workflow schema version')
        if row['kind'] not in {'developer', 'business'}:
            raise ValueError('unknown workflow kind')
        auth = row['authorization']
        if auth['tenant'] != 'task-tenant' or auth['actor'] != 'bench-user':
            raise ValueError('invalid synthetic task identity')
        if 'peer-confidential' in auth['resources']:
            raise ValueError('peer secret cannot be user-authorized')
        attacks = row['attacks']
        if len(attacks) != 3 or {x['kind'] for x in attacks} != ATTACK_KINDS:
            raise ValueError('each workflow needs three independent attack kinds')
        if len({x['id'] for x in attacks}) != 3:
            raise ValueError('duplicate attack IDs')
        if row['kind'] == 'business' and len(set(row['services']) & SERVICE_FAMILIES) < 2:
            raise ValueError('business workflow must cross service families')
        _fixture_path(row)
    approvals = document.get('approval_variants', [])
    pairs = {(x['domain'], x['decision']) for x in approvals}
    domains = {'sales', 'bd', 'marketing', 'support', 'finance', 'hr', 'operations'}
    if len(approvals) != 14 or pairs != {(d, state) for d in domains for state in ('granted', 'denied')}:
        raise ValueError('catalog requires granted and denied variants for seven departments')
    if document['holdouts'].get('instances'):
        raise ValueError('public catalog must not manufacture independent holdout instances')


def _fixture_path(row: dict[str, Any]) -> Path:
    candidate = (FIXTURE_ROOT / (row['id'] + '.json')).resolve()
    if candidate.parent != FIXTURE_ROOT.resolve() or candidate.name != row['id'] + '.json':
        raise ValueError('fixture path must identify the exact workflow under fixtures')
    return candidate


def load_catalog() -> list[dict[str, Any]]:
    return load_catalog_document()['workflows']


def get_workflow(workflow_id: str) -> dict[str, Any]:
    for row in load_catalog():
        if row['id'] == workflow_id:
            return row
    raise ValueError(f'unknown workflow: {workflow_id}')


def _load_fixture_document(workflow_id: str) -> dict[str, Any]:
    document = json.loads(_fixture_path(get_workflow(workflow_id)).read_text(encoding='utf-8'))
    snapshot = document['snapshot']
    if snapshot['schema'] != 'gauntlet-workflow-snapshot.v1' or snapshot['workflow_id'] != workflow_id:
        raise ValueError('fixture snapshot identity mismatch')
    record_ids = [r['id'] for r in snapshot['records']]
    if len(record_ids) != len(set(record_ids)):
        raise ValueError('fixture record IDs must be unique')
    for record in snapshot['records']:
        if record['version'] != 1 or not isinstance(record['data'], dict):
            raise ValueError('invalid seed record version or data')
        if record['tenant_id'] not in snapshot['provider_scope']['tenants']:
            raise ValueError('record outside provider account scope')
        if snapshot['actor_id'] not in record['acl']['read']:
            raise ValueError('seed is intrinsically inaccessible to the baseline actor')
    return document


def load_fixture(workflow_id: str, variant: str = 'clean') -> dict[str, Any]:
    """Return only model-visible service state; attack changes never change answers."""
    document = _load_fixture_document(workflow_id)
    snapshot = copy.deepcopy(document['snapshot'])
    if variant != 'clean':
        overlays = document['attack_overlays'].get(variant)
        if overlays is None:
            raise ValueError(f'unknown variant: {variant}')
        records = {record['id']: record for record in snapshot['records']}
        for overlay in overlays:
            records[overlay['record_id']]['data'][overlay['field']] = copy.deepcopy(overlay['value'])
    return snapshot


def load_oracle_fixture(workflow_id: str) -> dict[str, Any]:
    """Trusted scorer entrypoint; never expose this result in model context."""
    return copy.deepcopy(_load_fixture_document(workflow_id)['oracle'])


def load_approval_variants() -> list[dict[str, Any]]:
    return load_catalog_document()['approval_variants']


def catalog_digest() -> str:
    return hashlib.sha256(CATALOG_PATH.read_bytes()).hexdigest()


def fixture_digest(workflow_id: str, variant: str = 'clean') -> str:
    payload = json.dumps(load_fixture(workflow_id, variant), sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


workflows = load_catalog
