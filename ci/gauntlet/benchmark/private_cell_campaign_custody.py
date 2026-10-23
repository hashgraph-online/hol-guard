"""Bind genuine v2 developer observations to pre-inference campaign authority."""
from __future__ import annotations

import base64
from pathlib import Path

from .contracts import canonical_json
from .developer_campaign_product import verify_builtin_review_history
from .private_cell_runtime_custody import verify_private_cell_runtime


def bind_private_cell_product(config, raw, *, attempt_path):
    runtime = config['runtime']
    cfg = runtime['guard_private_cell']
    frozen = config['isolation_tuple']['developer_product']['private_cell']
    if 'guard_package_version' in runtime and (frozen.get('schema') != 'private-cell-campaign-inputs.v2'
            or frozen.get('package_version') != runtime['guard_package_version']):
        raise ValueError('private-cell package version differs from frozen inputs')
    if (canonical_json(frozen['config']) != canonical_json(cfg)
            or frozen['artifacts']['manifest_sha256'] != cfg['artifact_manifest_sha256']
            or frozen['runtime_tree_digest'] != cfg['runtime_tree_digest']
            or frozen['mcp_identity_profile'] != 'private-cell-mcp-v2'
            or frozen.get('contained_output_binding') != 'controller-contained-output.v1'
            or frozen.get('contained_completion_profile') != 'guard-contained-completion.v1'):
        raise ValueError('private-cell runtime differs from pre-inference frozen inputs')
    envelope = raw['developer_product_evidence']
    sdk = raw['execution_measurements']['sdk_binding']
    observation = sdk['observation']
    if (sdk['error'] or sdk['cleanup_complete'] is not True or observation is None
            or observation['kernel_peer_authenticated'] is not True
            or observation['bound_before_sdk_import'] is not True):
        raise ValueError('private-cell SDK lacks actual pre-inference kernel binding')
    expected = {'source_sha':runtime['guard_source_sha'],'prefix_digest':runtime['guard_prefix_digest'],
        'bwrap_sha256':runtime['guard_bwrap_sha256'],'executor_image_id':runtime['guard_executor_image_id'],
        'mcp_image_id':config['isolation_tuple']['image_id'],
        'deadline_seconds':raw['resource_profile']['deadline_seconds'],
        'max_tool_calls':raw['resource_profile']['max_tool_calls'],
        'private_cell':cfg,'mcp_identity_profile':'private-cell-mcp-v2',
        'contained_output_binding':'controller-contained-output.v1',
        'contained_completion_profile':'guard-contained-completion.v1'}
    if 'guard_package_version' in runtime:
        expected['package_version'] = runtime['guard_package_version']
    summary = verify_private_cell_runtime(envelope,
        trusted_public_key=base64.b64decode(raw['public_key'],validate=True),expected_settings=expected,
        expected_session_id=attempt_path.name,expected_prompt_digest=raw['public_prompt_digest'],
        workspace_source=raw['baseline']['checkout_path'],
        provider_mounts=(raw['baseline']['remote_path'],str(attempt_path/'runtime/home')),
        agent_identity=raw['execution_measurements']['agent'],sdk_pid=observation['pid'],
        sdk_identity=observation['identity'],require_mcp=False)
    builtin = envelope['record']['native_builtin_audit']['record']
    plane = builtin['product_plane']
    controller = config['isolation_tuple']['controller']
    if (plane['runtime_prefix'] != str(Path(runtime['guard_python']).parent.parent)
            or not {'boot_id','mount_namespace','pid_namespace','network_namespace'} <= controller.keys()
            or any(plane['controller_identity'].get(name) != value
                   for name,value in controller.items())):
        raise ValueError('private-cell runtime/controller differs from frozen campaign authority')
    counts = verify_builtin_review_history(builtin)
    return {**summary,**counts}
