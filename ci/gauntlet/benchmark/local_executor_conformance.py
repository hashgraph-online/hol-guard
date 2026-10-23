"""Caller-pinned local executor admission, never qualification or trust promotion."""
from __future__ import annotations

import hashlib
import os
import platform
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from .business_agent_container import BASE_IMAGE
from .contracts import digest, strict_json_loads
from .developer_product_custody import _validation_errors
from .local_executor_controls import ROLES, verify_control
from .product_custody import _require

SOURCE=Path(__file__).resolve().parent
# Execution code exercised by controls. Admission/scoring code is independently
# pinned by the invoking review package, not credited as an executed model task.
EXECUTION_SOURCES=(*(name+'.py' for name in (
    'builtin_hook_supervisor','contained_exec_relay','contained_output_binding','contained_request_file',
    'developer_product_runtime','developer_sdk_gate','developer_pilot','developer_pilot_services',
    'developer_resources','private_cell_factory','private_cell_hook_plane','product_cell_actor',
    'product_cell_idmap','product_cell_image','product_cell_layout','product_cell_protocol',
    'product_cell_supervisor','product_cell_system','product_cell_task_mounts','product_exec_gate',
    'product_vm_network','product_vm_rootfs','product_vm_seccomp','native_product_container',
    'native_builtin_plane','native_mcp_supervisor','mcp_task_context','service_supervisor',
    'mcp_server','mcp_protocol_profiles','mcp_protocol_campaign',
    'developer_budget','developer_model_relay','mcp_agent_profile','runtime_bundle','vm_bridge_frames','vm_bridge_io',
    'vm_bridge_rpc','vm_product_operations','product_version','private_cell_readiness','release_mcp_entry','release_hook_entry')),'builtin_guard_bridge.ts','private_cell_sdk_conformance.ts',
    'developer_omp_episode.ts','mcp_agent_surfaces.ts','service_relay.py','product_vm.apparmor','product_vm_seccomp_oci_v1.json')
REQUIREMENTS={'identity','separation','task-custody','readonly-inputs','network','syscalls-devices',
    'proc-paths','resources','input-output-replay','timeout','cancellation','cleanup'}


def platform_identity():
    release=platform.freedesktop_os_release()
    return {'kernel_release':platform.release(),'machine':platform.machine(),
            'os_id':release['ID'],'os_version':release['VERSION_ID']}


def _read(pin):
    _require(type(pin) is dict and set(pin)=={'path','sha256'},'exact external conformance pin required')
    path=Path(pin['path'])
    _require(path.is_absolute() and not path.is_symlink() and path.is_file(),
             'conformance package must be an ordinary absolute public file')
    _require(type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}',pin['sha256']),
             'external conformance package SHA256 required')
    with path.open('rb') as stream:
        before=os.fstat(stream.fileno())
        raw=stream.read(8*1024**2+1)
        after=os.fstat(stream.fileno())
    _require(len(raw)<=8*1024**2 and len(raw)==before.st_size
        and (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)==
            (after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns)
        and hashlib.sha256(raw).hexdigest()==pin['sha256'],'conformance bytes differ from outside pin')
    return strict_json_loads(raw)


@_validation_errors
def verify_local_conformance(runtime, *, public_assets=None, observed_platform=None):
    """No flag, self-selected key or module presence grants supported execution.

    The caller must pin the whole package before inference. Its embedded keys
    are meaningful only as bytes covered by that external digest. This is an
    author-reviewed local diagnostic capability, not independent certification.
    """
    pin=runtime.get('guard_conformance')
    _require(pin is not None and 'guard_private_cell' in runtime,
             'fresh authenticated SDK/native containment conformance not established')
    value=_read(pin)
    _require(type(value) is dict and set(value)=={'schema','scope','qualification_eligible',
        'platform','runtime','public_assets','execution_sources','review','controls'}
        and value['schema']=='local-executor-conformance.v1'
        and value['scope']=='local-diagnostic-only' and value['qualification_eligible'] is False,
        'explicit local-only executor conformance required')
    observed=platform_identity() if observed_platform is None else observed_platform
    _require(value['platform']==observed,'executor platform differs from conformance')
    cfg=runtime['guard_private_cell']
    expected={'source_sha':runtime['guard_source_sha'],'prefix_digest':runtime['guard_prefix_digest'],
        'bwrap_sha256':runtime['guard_bwrap_sha256'],'executor_image_id':runtime['guard_executor_image_id'],
        'mcp_image_id':BASE_IMAGE,
        'private_cell':{name:cfg[name] for name in ('artifact_manifest_sha256','initializer_sha256',
            'native_sha256','runtime_tree_digest','idmap_runtime','cpu_profile')}}
    if 'guard_package_version' in runtime:
        from .product_version import validate_version
        expected['package_version'] = validate_version(runtime['guard_package_version'])
    _require(value['runtime']==expected,'frozen runtime differs from local conformance')
    sources=value['execution_sources']
    _require(type(sources) is dict and set(sources)==set(EXECUTION_SOURCES),
             'exact exercised execution-source inventory required')
    for name,pin in sources.items():
        _require(hashlib.sha256((SOURCE/name).read_bytes()).hexdigest()==pin,
                 'execution source changed since conformance: '+name)
    review=value['review']
    _require(set(review)=={'schema','reviewer_role','verdict','requirements','document','document_sha256'}
        and review['schema']=='local-executor-equivalence-review.v1'
        and review['reviewer_role']=='implementation-author'
        and review['verdict']=='scoped-local-conformance'
        and set(review['requirements'])==REQUIREMENTS
        and all(type(v) is str and 1<=len(v)<=4096 for v in review['requirements'].values())
        and type(review['document']) is str and len(review['document'])<=65536
        and hashlib.sha256(review['document'].encode()).hexdigest()==review['document_sha256'],
        'explicit written local security-equivalence review required')
    controls=value['controls']
    _require(type(controls) is dict and set(controls)==ROLES,'all conformance control roles required')
    summaries=[]
    for role,row in sorted(controls.items()):
        _require(type(row) is dict and set(row)=={'public_key','record','record_digest'}
            and type(row['public_key']) is str and re.fullmatch('[0-9a-f]{64}',row['public_key'])
            and digest(row['record'])==row['record_digest'],'control differs from package anchor')
        try:
            summaries.append(verify_control(role,row['record'],public_key=row['public_key'],expected=expected))
        except InvalidSignature as error:
            raise ValueError('conformance control signature differs from pinned controller key') from error
    _require(len({row['session_id'] for row in summaries})==len(ROLES),'conformance roles must be distinct runs')
    assets=value['public_assets']
    _require(set(assets)=={'sdk','bun'},'exact public execution inputs required')
    for row in controls.values():
        _require(row['record']['public_input_assets_before']==assets,
                 'control SDK/Bun inputs differ')
    if public_assets is not None:
        # File ownership may legitimately differ after portable clean bootstrap.
        _require(public_assets['sdk']==assets['sdk']
            and all(public_assets['bun'][key]==assets['bun'][key] for key in ('sha256','size','mode')),
            'actual SDK/Bun differs from conformance')
    return {'schema':'local-executor-admission.v1','package_sha256':runtime['guard_conformance']['sha256'],
        'backend':'private-cell-native-hooks-v1','local_execution_supported':True,
        'public_inputs_verified':public_assets is not None,'platform':observed,
        'review_scope':'implementation-author-local-only','controls':summaries,
        'product_claims_authenticated':False,'qualification_eligible':False,
        'trust_status':'local-integrity-only'}
