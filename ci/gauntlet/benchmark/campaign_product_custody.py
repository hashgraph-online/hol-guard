"""Bind isolated product observations to the exact frozen campaign and attempt."""
from __future__ import annotations

import base64
from pathlib import Path

from .contracts import strict_json_loads
from .mcp_task_context import verify_task_contexts
from .product_custody import verify_product_audit


def bind_product_report(config, report, *, attempt_path):
    if report.get('product_isolated') is not True:
        raise ValueError('attempt did not declare the frozen product isolation lane')
    audit = report.get('native_audit')
    if audit is None:
        if report['execution_valid']:
            raise ValueError('valid execution lacks actual product custody evidence')
        return {'custody_verified': False, 'qualification_eligible': False}
    runtime, frozen = config['runtime'], config['isolation_tuple']
    arguments = dict(trusted_public_key=base64.b64decode(report['producer_public_key'], validate=True),
        expected_prefix_digest=config['identities']['isolated-product-prefix-digest'],
        expected_source_sha=runtime['guard_source_sha'], expected_image_id=frozen['image_id'])
    if 'guard_package_version' in runtime:
        arguments['expected_package_version'] = runtime['guard_package_version']
    verify_product_audit(audit, **arguments)
    events = strict_json_loads((attempt_path / 'transport-events.json').read_bytes())
    if audit['record']['transport_observations'] != events or not events:
        raise ValueError('product observation differs from retained frontdoor transport')
    plane = audit['record']['product_plane']
    if report.get('guard_identity') != {'product_self_report': plane['product_identity_claim'],
                                        'authenticated': False}:
        raise ValueError('product identity claim differs from observed namespace probe')
    if any(plane['controller_identity'].get(key) != value for key, value in frozen['controller'].items()):
        raise ValueError('product controller differs from frozen controller namespaces')
    prefix = str(Path(runtime['guard_python']).parent.parent)
    root = attempt_path / 'product-runtime'
    expected = {(prefix, prefix, 'ro'),
                (str(root / 'public'), '/product/public', 'ro'),
                (str(root / 'home'), '/product/home', 'rw'),
                (str(root / 'guard'), '/product/guard', 'rw'),
                (str(attempt_path / 'sockets'), '/upstream', 'ro')}
    containers = [row for row in plane['observations'] if row.get('kind') == 'container-boundary']
    if len(containers) != 1 or {(row['source'], row['destination'], row['mode']) for row in
                               containers[0]['mounts']} != expected:
        raise ValueError('product mounts differ from exact private/public attempt inventory')
    phases = report.get('approval_phase_isolations', [report.get('isolation')])
    agents = [(phase or {}).get('record', {}).get('agent') for phase in phases] or [None]
    verify_task_contexts(report, attempt_path=attempt_path,
        trusted_public_key=arguments['trusted_public_key'], controller=frozen['controller'],
        product=containers[0]['identity'], agents=agents)
    summaries = [verify_product_audit(audit, **arguments,
        expected_frontdoor_run_id=events[0]['run_id'], agent_identity=agent,
        require_exercised=False) for agent in agents]
    return summaries[0]
