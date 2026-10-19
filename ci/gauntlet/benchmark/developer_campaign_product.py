"""Bind retained native developer custody to externally frozen controller pins."""
from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import canonical_json
from .developer_product_custody import verify_developer_product_runtime
from .native_product_container import verify_product_boundary


def verify_builtin_review_history(record):
    """Check review coverage, without interpreting Native decisions as safety credit."""
    consumed = {row['payload_digest'] for row in record['contained_transport_observations']
                if row['kind'] == 'contained-route-consumed'}
    pre, post = {}, {}
    for event in record['transport_observations']:
        if event['kind'] != 'actual-hook-response':
            continue
        call = event['tool_call_id']
        if event['tool_name'] not in {'read', 'write', 'edit', 'bash'}:
            raise ValueError('custom MCP call incorrectly passed through builtin hook plane')
        target = pre if event['hook_event_name'] == 'PreToolUse' else post
        if event['hook_event_name'] not in {'PreToolUse', 'PostToolUse'} or call in target:
            raise ValueError('builtin native review phase repeated or malformed')
        target[call] = event
        if target is post:
            original = pre.get(call)
            if (original is None or original['tool_name'] != event['tool_name']
                    or original['original_input_digest'] != event['original_input_digest']
                    or not isinstance(event['actual_output_sha256'], str)
                    or len(event['actual_output_sha256']) != 64):
                raise ValueError('actual builtin output lacks its bound original native input review')
    for call, event in pre.items():
        response = event['product_response']
        executed = ((response['decision'] == 'allow' and 'required_execution_profile' not in response
                     and response.get('policy_action') != 'sandbox-required') or event['payload_digest'] in consumed)
        if executed and call not in post:
            raise ValueError('native-admitted builtin lacks mandatory actual output review')
    return {'builtin_pre_count': len(pre), 'builtin_post_count': len(post)}


def bind_developer_product(config, raw, *, attempt_path):
    if 'guard_private_cell' in config['runtime']:
        from .private_cell_campaign_custody import bind_private_cell_product
        return bind_private_cell_product(config, raw, attempt_path=attempt_path)
    envelope = raw['developer_product_evidence']
    evidence = envelope['record']
    runtime, controller = config['runtime'], config['isolation_tuple']['controller']
    key_bytes = base64.b64decode(raw['public_key'], validate=True)
    key = Ed25519PublicKey.from_public_bytes(key_bytes)
    settings = evidence['settings']
    expected_settings = {'source_sha': runtime['guard_source_sha'], 'prefix_digest': runtime['guard_prefix_digest'],
        'bwrap_sha256': runtime['guard_bwrap_sha256'], 'executor_image_id': runtime['guard_executor_image_id'],
        'mcp_image_id': config['isolation_tuple']['image_id'],
        'deadline_seconds': raw['resource_profile']['deadline_seconds'],
        'max_tool_calls': raw['resource_profile']['max_tool_calls']}
    if 'guard_package_version' in runtime:
        expected_settings['package_version'] = runtime['guard_package_version']
    if (settings != expected_settings or evidence['errors'] or not evidence['prompt_allowed']
            or evidence['public_prompt_digest'] != raw['public_prompt_digest']
            or any(type(value) is not int or value != 0 for value in evidence['upstream_counts'].values())):
        raise ValueError('developer product settings/context/cleanup differ from frozen controller')
    sdk = raw['execution_measurements']['sdk_binding']
    if (sdk['error'] or sdk['cleanup_complete'] is not True or sdk['observation'] is None
            or sdk['observation']['kernel_peer_authenticated'] is not True
            or sdk['observation']['bound_before_sdk_import'] is not True):
        raise ValueError('developer SDK lacks actual pre-inference kernel binding')
    native = evidence['native_builtin_audit']
    key.verify(base64.b64decode(native['signature'], validate=True), canonical_json(native['record']).encode())
    record, plane = native['record'], native['record']['product_plane']
    if (record['kind'] != 'isolated-native-builtin-observation'
            or record['sdk_pid'] != sdk['observation']['pid']
            or record['sdk_identity'] != sdk['observation']['identity']
            or plane['kind'] != 'isolated-contained-builtin-product-plane'
            or plane['source_sha_expected'] != runtime['guard_source_sha']
            or plane['prefix_digest'] != runtime['guard_prefix_digest']
            or plane['image_id'] != runtime['guard_executor_image_id']
            or plane['prefix_unchanged'] is not True or plane['cleanup_complete'] is not True
            or plane['cleanup_errors'] or plane['backend_observation']['sha256'] != runtime['guard_bwrap_sha256']):
        raise ValueError('developer builtin plane differs from frozen native custody')
    for name, expected in controller.items():
        if plane['controller_identity'].get(name) != expected:
            raise ValueError('developer builtin controller namespace differs from frozen authority')
    containers = [row for row in plane['observations'] if row.get('kind') == 'container-boundary']
    if len(containers) != 1:
        raise ValueError('one actual builtin product namespace required')
    verify_product_boundary(containers[0]['identity'], plane['controller_identity'])
    if any(containers[0]['identity'][field] == record['sdk_identity'][field]
           for field in ('mount_namespace', 'pid_namespace', 'network_namespace')):
        raise ValueError('developer SDK shares private product namespace')
    prefix, root = Path(runtime['guard_python']).parent.parent, attempt_path / 'product' / 'builtin-product'
    baseline = raw['baseline']
    expected = [{'source': str(prefix), 'destination': str(prefix), 'mode': 'ro'},
        {'source': str(root / 'public'), 'destination': '/product/public', 'mode': 'ro'},
        {'source': str(root / 'home'), 'destination': '/runtime/home', 'mode': 'rw'},
        {'source': str(root / 'guard'), 'destination': '/product/guard', 'mode': 'rw'},
        {'source': baseline['checkout_path'], 'destination': '/runtime/home/project', 'mode': 'rw',
         'idmap': 'uids=10001-10004-1;gids=10001-10004-1'},
        {'source': str(root / 'tmp'), 'destination': '/tmp', 'mode': 'rw'}]
    expected += [{'source': str(path), 'destination': str(path), 'mode': 'rw',
                  'idmap': 'uids=10001-10004-1;gids=10001-10004-1'}
                 for path in (baseline['remote_path'], attempt_path / 'runtime' / 'home')]
    if containers[0]['mounts'] != expected:
        raise ValueError('developer builtin mounts differ from exact declared task/provider custody')
    counts = verify_builtin_review_history(record)
    summary = verify_developer_product_runtime(envelope, trusted_public_key=key_bytes,
        expected_settings=expected_settings, expected_session_id=attempt_path.name,
        expected_prompt_digest=raw['public_prompt_digest'], workspace_source=baseline['checkout_path'],
        provider_mounts=(baseline['remote_path'], str(attempt_path / 'runtime' / 'home')),
        agent_identity=raw['execution_measurements']['agent'], sdk_pid=sdk['observation']['pid'],
        sdk_identity=sdk['observation']['identity'])
    if summary['mcp_proxy_count'] < 1:
        raise ValueError('developer SDK did not exercise its native MCP frontdoor')
    return {**summary, **counts}


def private_runtime_custody(raw, *, attempt_path):
    """Recompute diagnostic support; frozen campaign binding remains mandatory."""
    envelope=raw.get('developer_product_evidence')
    if not envelope or envelope['record'].get('kind')!='developer-private-cell-runtime-observation':
        return None
    from .private_cell_runtime_custody import verify_private_cell_runtime
    record=envelope['record']
    observation=raw['execution_measurements']['sdk_binding']['observation']
    root=Path(attempt_path)
    return verify_private_cell_runtime(envelope,
        trusted_public_key=base64.b64decode(raw['public_key'],validate=True),
        expected_settings=record['settings'],expected_session_id=root.name,
        expected_prompt_digest=raw['public_prompt_digest'],workspace_source=raw['baseline']['checkout_path'],
        provider_mounts=(raw['baseline']['remote_path'],str(root/'runtime/home')),
        agent_identity=raw['execution_measurements']['agent'],sdk_pid=observation['pid'],
        sdk_identity=observation['identity'],require_mcp=False)
