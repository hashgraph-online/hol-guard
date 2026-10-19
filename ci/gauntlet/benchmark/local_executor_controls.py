"""Inert interpretation of externally pinned SDK/native conformance controls.

These observations authorize only a local diagnostic lane. They neither make
product claims authentic nor establish independent review or trust eligibility.
"""
from __future__ import annotations

import hashlib
from pathlib import PurePosixPath

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .builtin_hook_supervisor import review_summary
from .contained_output_binding import captured_output
from .developer_product_custody import _reviews, _signed
from .private_cell_custody import verify_private_cell_plane
from .private_cell_runtime_custody import verify_private_cell_runtime
from .product_custody import _kernel, _require, verify_product_audit

ROLES={'success','timeout','cancel','input-binding','boundary'}
NEGATIVES={'wrong-sha','foreign-workspace','foreign-cwd','wrong-event','wrong-tool',
           'nonstring-command','duplicate-field','wrong-schema','missing-payload'}


def request_rejection(stderr):
    """The two public names for the installed sink's request-binding refusal."""
    if type(stderr) is not str:
        return False
    code, separator, _ = stderr.partition(':')
    return separator == ':' and code in {
        'contained_test_authorization_failed', 'contained_run_authorization_failed'}


def verify_control(role, value, *, public_key, expected):
    """The package digest pins the outside key, observations and entire record."""
    _require(role in ROLES,'unknown conformance role')
    _require(value['control_completed'] is True and value['sdk_exercised'] is True
        and value['model_exercised'] is False and value['root_imported_product'] is False
        and all(value.get(name) is None for name in ('error','cleanup_error','gate_cleanup_error')),
        'control failed, imported product into Root or exercised inference')
    _require(value['image_released'] is True and value['agent_cgroup_absent'] is True
        and value['agent_profile_removed'] is True and value['agent_remove_returncode']==0,
        'control resources survived')
    _require(value['controller_public_key_hex']==public_key,'control key differs from outside pin')
    key_bytes=bytes.fromhex(public_key)
    key=Ed25519PublicKey.from_public_bytes(key_bytes)
    record=_signed(value['developer_runtime'],key)
    settings=record['settings']
    for name in ('source_sha','prefix_digest','bwrap_sha256','executor_image_id','mcp_image_id'):
        _require(settings[name]==expected[name],'control runtime differs from conformance tuple')
    if 'package_version' in expected:
        _require(settings.get('package_version')==expected['package_version'],
                 'control package version differs from conformance tuple')
    _require(record['schema_version']==('5.0' if 'package_version' in expected else '4.0')
        and settings['contained_output_binding']=='controller-contained-output.v1'
        and settings['contained_completion_profile']=='guard-contained-completion.v1',
        'current completion/output profiles required')
    cfg=settings['private_cell']
    for name in ('artifact_manifest_sha256','initializer_sha256','native_sha256',
                 'runtime_tree_digest','idmap_runtime','cpu_profile'):
        _require(cfg[name]==expected['private_cell'][name],'control backend differs from tuple')
    builtin=_signed(record['native_builtin_audit'],key)
    plane=builtin['product_plane']
    _require(value['plane']==plane,'detached control plane differs from signed observation')
    session=record['controller_session_id']
    # Paths are taken from the measured mounts, never used for filesystem I/O.
    mounts=plane['task_mounts']
    workspace=next(row['source'] for row in mounts if row['destination']==plane['workspace_path'])
    root=str(PurePosixPath(workspace).parent.parent)
    _require(PurePosixPath(root).name==session and '..' not in PurePosixPath(root).parts,
             'control allocation differs from session')
    providers=tuple(row['source'] for row in mounts if row['destination']!=plane['workspace_path'])
    _require(workspace==root+'/tasks/checkout' and set(providers)=={root+'/tasks/remote',root+'/tasks/home'},
        'control task paths differ from declared allocation')
    sdk=value['sdk_gate']
    observation=sdk['observation']
    _require(sdk['cleanup_complete'] is True and sdk['error'] is None
        and observation['kernel_peer_authenticated'] is True and observation['bound_before_sdk_import'] is True,
        'control lacks outside pre-import SDK binding')
    options=dict(trusted_public_key=key_bytes,expected_settings=settings,
        expected_session_id=session,expected_prompt_digest=record['public_prompt_digest'],
        workspace_source=workspace,provider_mounts=providers,agent_identity=value['agent_identity'],
        sdk_pid=observation['pid'],sdk_identity=observation['identity'],require_mcp=True)
    if role=='success':
        projection=value['sdk_result'].get('modelContextProjection')
        expected_projection={
            'schema':'contained-command-context-control.v1','originalCommandVisible':True,
            'executionTransportRetained':True,
            'scope':'actual SDK synthetic-stream control; no model inference'}
        _require(type(projection) is dict and set(projection)==set(expected_projection)
            and all(type(projection[key]) is type(expected_value) and projection[key]==expected_value
                    for key,expected_value in expected_projection.items()),
            'SDK provider context projection control missing or execution transcript changed')
    if role=='cancel':
        _cancel(value,record,builtin,plane,key_bytes,options)
    else:
        result=verify_private_cell_runtime(value['developer_runtime'],**options)
        _require(result['custody_verified'] is True,'control custody not established')
        _require(len(plane['executions'])==1,'one actual Native contained sink required')
        _require(builtin['review_summary']['post_review_counts']=={'sdk-contained-control':1},
                 'exactly one actual required Post required')
    sdk_result=value['sdk_result']
    _require(sdk_result['modelExercised'] is False and sdk_result['providerRequests']==0
        and sdk_result['syntheticStreamCalls']==3 and sdk_result['mcpExercised'] is True,
        'synthetic conformance cannot become model evidence')
    if role in {'success','boundary'}:
        execution=plane['executions'][0]
        _require(execution['exit_code']==0 and value['actual_sdk_bash_success'] is True
            and sdk_result['results'][1]['isError'] is False
            and sdk_result['results'][1]['content']==captured_output(execution)['tool_response'],
            'actual SDK did not receive successful exact captured output')
    if role=='timeout':
        _require(value['native_timeout_seconds']==5 and plane['executions'][0]['exit_code']==124
            and value['detached_child_samples'] and value['detached_child_alive_before_cell_teardown'] is False
            and value['cell_closed_before_explicit_teardown'] is False and value['late_effect_present'] is False,
            'timeout requires Native descendant cleanup before cell backstop')
    if role in {'success','input-binding','boundary'}:
        _require(all(value[name] is True for name in ('real_sdk_pre_replay_refused',
            'real_sdk_route_replay_refused','real_sdk_post_replay_refused'))
            and value['same_uid_peer_negative']['denied'] is True,
            'actual SDK replay or same-UID peer refusal missing')
        rows=value['kernel_boundary_negatives']['rows']
        _require(len(rows)==21 and all(row['denied'] is True for row in rows),
                 'kernel path/mount floor negatives missing')
    if role=='input-binding':
        rows=value['request_binding_negatives']
        _require(len(rows)==len(NEGATIVES) and {row['case'] for row in rows}==NEGATIVES
            and all(type(row['exit_code']) is int and row['exit_code']==126
                and row['trap_effect_present'] is False and row['kernel_process_samples']
                and request_rejection(row['stderr']) for row in rows),
            'required installed request negatives did not refuse without effects')
    if role=='boundary':
        _boundary(value,root)
    return {'role':role,'session_id':session,'synthetic':True,'model_tokens':0}


def _cancel(value,record,builtin,plane,key,options):
    _require(record['errors']==[] and record['prompt_allowed'] is True,'cancel setup failed')
    from .product_version import version_options
    verify_product_audit(record['native_mcp_audit'],trusted_public_key=key,
        expected_prefix_digest=options['expected_settings']['prefix_digest'],
        expected_source_sha=options['expected_settings']['source_sha'],
        expected_image_id=options['expected_settings']['mcp_image_id'],
        agent_identity=options['agent_identity'],require_exercised=True,
        expected_identity_profile='private-cell-mcp-v2',
        **version_options(options['expected_settings'].get('package_version')))
    failed=[row for row in plane['observations'] if row['kind']=='actual-native-capture-failure']
    _require(len(failed)==1 and failed[0]['exception_type']=='InterruptedError',
             'one real interrupted capture required')
    samples=failed[0]['kernel_process_samples']
    _require(type(samples) is list and 1<=len(samples)<=1000,
             'interrupted sink requires bounded nonempty outside samples')
    identities={(row['pid'],row['identity']['start_time'],row['command_sha256']) for row in samples}
    _require(len(identities)==len(samples),'interrupted sink repeats outside process samples')
    command=failed[0]['command']
    _require(command[:7]==[plane['runtime_prefix']+'/bin/python','-I','-B','-m',
        'codex_plugin_scanner.cli','guard','execute-contained-test'],
        'interrupted capture must be the actual installed Native contained sink')
    command_hash=hashlib.sha256(b'\0'.join(part.encode() for part in command)+b'\0').hexdigest()
    _require(any(row['command_sha256']==command_hash for row in failed[0]['kernel_process_samples']),
             'interrupted sink lacks outside command sampling')
    for row in failed[0]['kernel_process_samples']:
        _kernel(row['identity'],plane['controller_identity'],options['agent_identity'])
    verify_private_cell_plane(plane,settings=options['expected_settings'],
        workspace_source=options['workspace_source'],provider_mounts=options['provider_mounts'],
        agent_identity=options['agent_identity'],expected_interrupted_command=failed[0]['command'])
    _reviews(builtin,plane,sdk_pid=options['sdk_pid'],sdk_identity=options['sdk_identity'],require_sdk=True)
    summary=review_summary(builtin['transport_observations'],builtin['contained_transport_observations'])
    _require(summary==builtin['review_summary']
        and summary['missing_required_post_call_ids']==['sdk-contained-control']
        and plane['executions']==[],'cancelled sink became complete or lost missing Post')
    failures=[row for row in plane['observations'] if row['kind']=='actual-native-capture-failure']
    _require(len(failures)==1 and failures[0]['exception_type']=='InterruptedError'
        and failures[0]['cell_closed'] is True and failures[0]['kernel_process_samples']==samples
        and value['cell_closed_before_explicit_teardown'] is True
        and value['detached_child_alive_before_cell_teardown'] is False
        and value['late_effect_present'] is False and value['detached_child_samples'],
        'active cancellation/descendant/partial evidence incomplete')


def _boundary(value,root):
    rows=value['native_contained_boundary_negatives']['rows']
    paths={root+'/controller-canary.txt',root+'/agent/agent-canary.txt',
           '/product/guard/native-boundary-canary.txt'}
    _require(len(rows)==8 and all(row['denied'] is True for row in rows),
             'actual Native path/network negative failed')
    _require({(row['path'],row['operation']) for row in rows if row['surface']=='path'}
        =={(path,operation) for path in paths for operation in ('read','write')}
        and {row['family'] for row in rows if row['surface']=='network'}=={2,10},
        'actual Native negative surfaces missing')
    before=value['canary_initial_sha256']
    after=value['canary_terminal_sha256']
    _require(len(before)==3 and before==after,'synthetic private canary was altered')
