"""Externally signed versioned runtime custody; no captured execution or anchors."""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import PurePosixPath

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .builtin_hook_supervisor import review_summary
from .contracts import canonical_json, digest, strict_json_loads
from .developer_product_custody import (
    _BUILTIN,
    _RUNTIME,
    _hook,
    _operations,
    _reviews,
    _signed,
    _validation_errors,
)
from .private_cell_custody import verify_private_cell_plane
from .product_custody import _require, verify_product_audit


@_validation_errors
def verify_private_cell_runtime(evidence,*,trusted_public_key,expected_settings,expected_session_id,
                                expected_prompt_digest,workspace_source,provider_mounts,agent_identity,
                                sdk_pid,sdk_identity,require_mcp=False):
    _require(type(trusted_public_key) is bytes and len(trusted_public_key)==32,
             'external controller public key required')
    raw=evidence if isinstance(evidence,(str,bytes)) else canonical_json(evidence)
    _require(len(raw if isinstance(raw,bytes) else raw.encode())<=24*1024**2,
             'bounded signed runtime evidence required')
    value=strict_json_loads(raw)
    key=Ed25519PublicKey.from_public_bytes(trusted_public_key)
    record=_signed(value,key)
    binding = expected_settings.get('contained_output_binding')
    _require(binding in {None,'controller-contained-output.v1'},'unknown contained output binding profile')
    version = '2.0' if binding is None else '3.0'
    completion = expected_settings.get('contained_completion_profile')
    if completion is not None:
        _require(binding is not None and completion=='guard-contained-completion.v1',
                 'unknown contained completion profile')
        version = '4.0'
    if 'package_version' in expected_settings:
        _require(completion is not None, 'version-pinned private runtime requires completion proof')
        version = '5.0'
    _require(type(record) is dict and set(record)==_RUNTIME and record['schema_version']==version
        and record['kind']=='developer-private-cell-runtime-observation',
        'explicit matching-version runtime envelope required')
    _require(record['settings']==expected_settings and record['controller_session_id']==expected_session_id
        and record['public_prompt_digest']==expected_prompt_digest,'runtime differs from externally frozen context')
    _require(expected_settings['mcp_identity_profile']=='private-cell-mcp-v2',
             'private-cell runtime requires the separate explicit MCP identity')
    _require(record['errors']==[] and record['prompt_allowed'] is True
        and record['product_claims_authenticated'] is False and record['qualification_eligible'] is False
        and record['upstream_counts']=={'active_children':0,'active_workers':0,'active_sessions':0}
        and all(type(value) is int for value in record['upstream_counts'].values()),
        'runtime context/cleanup or product claim boundary invalid')
    from .product_version import version_options
    mcp=verify_product_audit(record['native_mcp_audit'],trusted_public_key=trusted_public_key,
        expected_prefix_digest=expected_settings['prefix_digest'],expected_source_sha=expected_settings['source_sha'],
        expected_image_id=expected_settings['mcp_image_id'],agent_identity=agent_identity,require_exercised=require_mcp,
        expected_identity_profile=expected_settings['mcp_identity_profile'],
        **version_options(expected_settings.get('package_version')))
    ingress=[row for row in record['native_mcp_audit']['record']['transport_observations']
        if row.get('kind')=='forwarded' and row.get('message',{}).get('method')=='tools/call']
    _require(type(require_mcp) is bool and (not require_mcp or bool(ingress)),
             'required MCP tools/call was not exercised')
    builtin=_signed(record['native_builtin_audit'],key)
    _require(set(builtin)==_BUILTIN and builtin['schema_version']=='1.0'
        and builtin['kind']=='isolated-native-builtin-observation'
        and builtin['controller_session_id']==expected_session_id,'invalid signed builtin transport')
    _require(type(sdk_pid) is int and sdk_pid>1 and builtin['sdk_pid']==sdk_pid
        and canonical_json(builtin['sdk_identity'])==canonical_json(sdk_identity) and type(sdk_identity) is dict
        and sdk_identity['effective_uid']==sdk_identity['effective_gid']==10001
        and sdk_identity['effective_capabilities']=='0000000000000000'
        and type(sdk_identity['no_new_privileges']) is int and sdk_identity['no_new_privileges']==1
        and sdk_identity.get('uid_slots')==[10001]*4 and sdk_identity.get('gid_slots')==[10001]*4
        and sdk_identity.get('supplementary_groups') in ([],[10001]) and sdk_identity.get('capability_sets')==
            dict.fromkeys(('CapEff','CapPrm','CapInh','CapBnd','CapAmb'),'0000000000000000')
        and agent_identity is not None,'missing exact outside SDK binding')
    plane=builtin['product_plane']
    boundary=verify_private_cell_plane(plane,settings=expected_settings,workspace_source=workspace_source,
                                      provider_mounts=provider_mounts,agent_identity=agent_identity)
    _require(record['native_mcp_audit']['record']['product_plane']['controller_identity']==plane['controller_identity'],
             'MCP and builtin observations have different outside collectors')
    actual=_reviews(builtin,plane,sdk_pid=sdk_pid,sdk_identity=sdk_identity,require_sdk=True)
    _require(all(canonical_json(row['identity'])==canonical_json(sdk_identity) for row in
        builtin['transport_observations'] if row.get('kind')=='peer-authenticated'),
        'SDK peer field types differ from outside kernel observation')
    phases=[(row['hook_event_name'],row['tool_call_id']) for row in actual]
    _require(len(phases)==len(set(phases)) and len(plane['hooks'])==len(actual)+1,
             'duplicate or unmatched actual native hook review')
    _operations(record,actual)
    summary=review_summary(builtin['transport_observations'],builtin['contained_transport_observations'])
    _require(summary==builtin['review_summary'] and not summary['missing_required_post_call_ids']
        and not summary['unreviewable_hook_call_ids'],'native output review incomplete or unavailable')
    _require(len(record['native_task_contexts'])==1,'exact normal MCP task context required')
    context=_signed(record['native_task_contexts'][0],key)
    _require(context['phase']=='developer' and context['public_prompt_digest']==expected_prompt_digest
        and digest(context['public_prompt'])==expected_prompt_digest and len(context['hooks'])==1,
        'MCP normal public task context differs')
    response=_hook(context['hooks'][0],plane['controller_identity'],agent_identity,product_uid=10005)
    _require(response['decision']=='allow','MCP public task review did not admit this context')
    mcp_plane=record['native_mcp_audit']['record']['product_plane']
    mcp_actor=next(row['identity'] for row in mcp_plane['observations'] if row['kind']=='container-boundary')
    _require(all(context['hooks'][0]['identity'][field]==mcp_actor[field] for field in
        ('boot_id','mount_namespace','pid_namespace','network_namespace')),'MCP task hook escaped its product boundary')
    prompt={'hook_event_name':'UserPromptSubmit','prompt':context['public_prompt'],
            'config_path':'/product/home/omp.json','session_id':expected_session_id}
    prompts=[row for row in builtin['transport_observations'] if row.get('kind')=='actual-user-prompt-response']
    _require(len(prompts)==1 and prompts[0]['payload_digest']==digest(prompt)
        and prompts[0]['product_response']['decision']=='allow'
        and any(row['payload_digest']==digest(prompt) and row['response_digest']==prompts[0]['response_digest']
                for row in plane['hooks']),'builtin task prompt lacks matching actual native admission')
    events=builtin['contained_transport_observations']
    prepared={row['token_digest'] for row in events if row['kind']=='contained-route-prepared'}
    consumed=[row for row in events if row['kind']=='contained-route-consumed']
    finished=[row for row in events if row['kind']=='actual-contained-result']
    _require(len({row['token_digest'] for row in consumed})==len(consumed)
        and {row['token_digest'] for row in consumed}<=prepared
        and Counter(row['token_digest'] for row in consumed)==Counter(row['token_digest'] for row in finished)
        and Counter(row['payload_digest'] for row in consumed)
            ==Counter(row['payload_digest'] for row in plane['executions'])
        and Counter(row['result_digest'] for row in finished)==Counter(digest(row) for row in plane['executions']),
        'contained authorization/result is missing, duplicated or transplanted')
    for result in plane['executions']:
        command=result['native_command']
        _require(type(command) is list and len(command)==21 and command[:7]==[
            plane['runtime_prefix']+'/bin/python','-I','-B','-m','codex_plugin_scanner.cli','guard',
            'execute-contained-test'],'contained result lacks the normal installed CLI')
        _require(command[7::2]==['--harness','--guard-home','--home','--workspace','--request-file',
            '--request-sha256','--timeout-seconds'],'contained CLI argument inventory differs')
        options=dict(zip(command[7::2],command[8::2],strict=True))
        request=PurePosixPath(options['--request-file'])
        from .release_mcp_entry import LIBRARY_VERSIONS
        home='/runtime/home' if expected_settings.get('package_version') in LIBRARY_VERSIONS else '/product/home'
        _require(options['--harness']=='omp' and options['--guard-home']=='/product/guard'
            and options['--home']==home and options['--workspace']==plane['workspace_path']
            and str(request)==options['--request-file'] and request.parent.parent==PurePosixPath('/product/home')
            and request.name=='request.json' and '..' not in request.parts
            and options['--request-sha256']==result['request_sha256']
            and re.fullmatch('[0-9a-f]{64}',result['request_sha256'])
            and options['--timeout-seconds'].isdigit() and 1<=int(options['--timeout-seconds'])<=900,
            'contained workspace/request/deadline binding differs')
        _require(type(result['exit_code']) is int,'actual contained CLI exit status required')
        for name in ('stdout','stderr'):
            _require(hashlib.sha256(result[name].encode()).hexdigest()==result[name+'_sha256'],
                     'contained output digest differs')
        _require(result['product_claims_authenticated'] is False
            and result['containment_conformance_established'] is False and result['kernel_process_samples'],
            'contained result lacks outside samples or promotes claims')
        observed_command=hashlib.sha256(b'\0'.join(part.encode() for part in command)+b'\0').hexdigest()
        _require(any(row['command_sha256']==observed_command for row in result['kernel_process_samples']),
                 'actual contained CLI was not independently sampled')
        for sample in result['kernel_process_samples']:
            identity=sample['identity']
            _require(identity['effective_uid']==identity['effective_gid']==10004
                and type(identity['no_new_privileges']) is int and identity['no_new_privileges']==1
                and identity['boot_id']==plane['controller_identity']['boot_id']
                and re.fullmatch('[0-9a-f]{16}',identity['effective_capabilities'])
                and all(identity[field] not in {plane['controller_identity'][field],agent_identity[field]}
                    for field in ('mount_namespace','pid_namespace','network_namespace'))
                and (int(identity['effective_capabilities'],16)==0
                    or (sample['user_namespace']!=plane['product_user_namespace']
                        and re.fullmatch(r'user:\[[0-9]+\]',sample['user_namespace']))),
                'contained descendant escaped privilege/namespace boundary')
    if binding is not None:
        from .contained_output_custody import verify_contained_outputs
        verify_contained_outputs(builtin)
    return {'custody_verified':True,'native_hook_count':boundary['native_hook_count'],
        'native_denial_count':sum(row['response']['decision'] in {'deny','block'} for row in plane['hooks']),
        'mcp_proxy_count':mcp['product_proxy_count'],'mcp_tool_call_count':len(ingress),'sdk_bound':True,
        'product_claims_authenticated':False,'qualification_eligible':False}
