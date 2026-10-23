"""Inert verification of the declared private-cell boundary, never policy truth.

Expected pins and physical task paths come from the outside frozen controller.
This module reads captured data only; it cannot run a captured solution/Guard.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath

from .contracts import canonical_json, strict_json_loads
from .native_builtin_plane import decode_hook_response
from .native_product_container import validate_identity_claim
from .product_custody import _kernel, _require
from .product_vm_network import validate_topology

FIELDS={'schema','boundary_schema','kind','controller_identity','profile','workspace_path','runtime_prefix',
    'prefix_digest','prefix_unchanged','runtime_tree_digest','source_sha','native_sha256','bwrap_sha256','image_id',
    'system_digest','initializer_sha256','task_digest','task_mounts','network_profile','cpu_profile','idmap_runtime',
    'wall_seconds','identity_claim','backend_observation','observations','hooks','executions','cell_observations',
    'cleanup_complete','cleanup_errors','product_claims_authenticated','containment_execution_supported',
    'containment_conformance_established','qualification_eligible','artifact_manifest_digest','product_user_namespace'}


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None


def _one(rows,kind):
    found=[row for row in rows if row.get('kind')==kind]
    _require(len(found)==1,'exactly one private-cell '+kind+' observation required')
    return found[0]


def _actor(identity,*,label,namespaces,filtered):
    status=identity['status']
    _require(type(identity['pid']) is int and identity['pid']>0 and identity['start_time'].isdigit()
        and identity['lsm_label']==label and identity['namespaces']==namespaces
        and set(identity['fds'])=={'0','1','2'}
        and status['Uid'].split()==status['Gid'].split()==['10004']*4
        and not status['Groups'].strip() and status['NoNewPrivs'].strip()=='1'
        and all(int(status[key],16)==0 for key in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb')),
        'actual private actor/process privilege boundary differs')
    if filtered:
        _require(status['Seccomp'].strip()=='2' and int(status['Seccomp_filters'])>=2,
                 'private process lacks both syscall filters')


def _hook_samples(samples, *, controller, agent, product_user_namespace, command_hash):
    """Keep the CLI unprivileged; distinguish sampled nested sandbox children.

    Native Pre admission can launch Bubblewrap probes. Their new user namespace
    has local capabilities even though the product retains zero host capabilities.
    No captured executable or namespace path is opened by this inert reader.
    """
    primary = []
    for sample in samples:
        identity = sample['identity']
        user_ns = sample.get('user_namespace')
        _require(type(user_ns) is str and re.fullmatch(r'user:\[[0-9]+\]', user_ns),
                 'hook sample lacks a kernel user namespace')
        caps = identity.get('effective_capabilities')
        _require(type(caps) is str and re.fullmatch('[0-9a-f]{16}', caps),
                 'hook sample capability mask invalid')
        if int(caps, 16) == 0:
            _kernel(identity, controller, agent)
        else:
            _require(user_ns != product_user_namespace
                and identity['effective_uid'] == identity['effective_gid'] == 10004
                and identity.get('uid_slots') == identity.get('gid_slots') == [10004] * 4
                and identity.get('supplementary_groups') in ([], [10004])
                and type(identity['no_new_privileges']) is int and identity['no_new_privileges'] == 1
                and identity['boot_id'] == controller['boot_id']
                and type(identity['start_time']) is str and identity['start_time'].isdigit()
                and identity['capability_sets'] == dict(
                    CapEff=caps, CapPrm=caps, CapBnd='0000000000000000',
                    CapInh='0000000000000000', CapAmb='0000000000000000')
                and all(type(identity[field]) is str and identity[field]
                    and identity[field] != controller[field]
                    and (agent is None or identity[field] != agent[field])
                    for field in ('mount_namespace', 'pid_namespace', 'network_namespace')),
                'hook descendant escaped host privilege/namespace boundary')
        if sample['command_sha256'] == command_hash:
            _require(int(caps, 16) == 0 and user_ns == product_user_namespace,
                     'native hook CLI changed user namespace or gained capabilities')
            primary.append(sample)
    _require(bool(primary), 'native hook CLI was not independently sampled')


def _mountinfo(raw,*,prefix,tasks):
    _require(type(raw) is str and len(raw)<1024**2,'bounded kernel mount inventory required')
    mounts={}
    for line in raw.splitlines():
        fields,separator,tail=line.partition(' - ')
        left,right=fields.split(),tail.split()
        _require(bool(separator) and len(left)>=6 and len(right)>=3,'malformed kernel mount inventory')
        path=left[4]
        for escaped,literal in (('\\040',' '),('\\011','\t'),('\\012','\n'),('\\134','\\')):
            path=path.replace(escaped,literal)
        _require(path not in mounts and not path.startswith(('/oldroot','/sys'))
                 and right[0] not in {'sysfs','cgroup','cgroup2'},'unexpected kernel/control filesystem mount')
        mounts[path]=set(left[5].split(','))
    for path in ('/','/usr','/opt/node','/public','/etc/alternatives',prefix):
        _require({'ro','nosuid','nodev'}<=mounts.get(path,set()),'immutable private-cell mount became writable/unsafe')
    _require({'ro','nosuid'}<=mounts.get('/dev',set()),'device directory is not readonly')
    for path in ('/product','/tmp',*(row['destination'] for row in tasks)):
        _require({'rw','nosuid','nodev'}<=mounts.get(path,set()),'mutable private-cell mount lost its declared floor')


def _tasks(plane,rows,*,workspace_source,provider_mounts,pid):
    expected={plane['workspace_path']:workspace_source,**{path:path for path in provider_mounts}}
    tasks=plane['task_mounts']
    _require(type(tasks) is list and len(tasks)==len(expected)<=9,'exact frozen task/provider mount inventory required')
    seen=set()
    for row in tasks:
        _require(set(row)=={'source','destination','device','inode','mode'} and row['destination'] not in seen
            and expected.get(row['destination'])==row['source']
            and all(type(row[key]) is int and row[key]>=0 for key in ('device','inode','mode'))
            and row['inode']>0 and row['mode']&0o700==0o700 and not row['mode']&~0o755,
            'task/provider source, inode or unchanged mode differs from frozen custody')
        seen.add(row['destination'])
    observation=_one(rows,'idmapped-task-mounts')
    _require(_sha(plane['task_digest']) and observation['declaration_digest']==plane['task_digest']
             and len(observation['mounts'])==len(tasks),'task declaration/outside observation binding differs')
    measured={row['destination']:row for row in observation['mounts']}
    _require(len(measured)==len(tasks),'duplicate outside task mapping')
    for row in tasks:
        actual=measured[row['destination']]
        physical={key:row[key] for key in ('device','inode','mode')}
        _require(set(actual)=={'source','destination','physical','product_view','observer_pid'}
            and actual['source']==row['source'] and actual['observer_pid']==pid
            and actual['physical']=={**physical,'uid':10001,'gid':10001}
            and actual['product_view']=={**physical,'uid':10004,'gid':10004},
            'outside kernel idmapping lacks unchanged physical task custody')


def verify_private_cell_plane(value,*,settings,workspace_source,provider_mounts,agent_identity=None,
                              expected_interrupted_command=None):
    """Verify the boundary, separately from completed runtime custody.

    Only the negative conformance reader supplies an exact interrupted command.
    Normal runtime verification never accepts a failed capture or missing Post.
    """
    try:
        raw=canonical_json(value)
        _require(len(raw.encode())<=16*1024**2,'private-cell custody byte budget')
        plane=strict_json_loads(raw)
        _require(set(plane)==FIELDS and plane['schema']=='private-cell-hook-plane.v2'
            and plane['boundary_schema']=='private-cell-boundary.v1'
            and plane['kind']=='private-cell-native-hook-plane'
            and plane['profile']=='private-cell-native-hooks-v1','explicit versioned private-cell profile required')
        cfg=settings['private_cell']
        for name,expected in {'prefix_digest':settings['prefix_digest'],'source_sha':settings['source_sha'],
            'image_id':settings['executor_image_id'],'bwrap_sha256':settings['bwrap_sha256'],
            'runtime_tree_digest':cfg['runtime_tree_digest'],'native_sha256':cfg['native_sha256'],
            'initializer_sha256':cfg['initializer_sha256'],'artifact_manifest_digest':cfg['artifact_manifest_sha256'],
            'cpu_profile':cfg['cpu_profile'],'idmap_runtime':cfg['idmap_runtime'],
            'network_profile':'private-loopback-v1','workspace_path':'/runtime/home/project',
            'wall_seconds':settings['deadline_seconds']+90}.items():
            _require(plane[name]==expected,'private-cell '+name+' differs from external runtime pin')
        _require(plane['prefix_unchanged'] is True and plane['cleanup_complete'] is True
            and plane['cleanup_errors']==[] and all(plane[name] is False for name in
                ('product_claims_authenticated','containment_execution_supported',
                 'containment_conformance_established','qualification_eligible')),
            'private-cell cleanup/claim boundary incomplete')
        _require(_sha(plane['system_digest']) and re.fullmatch(r'user:\[[0-9]+\]',plane['product_user_namespace']),
                 'private-cell image/user-namespace provenance incomplete')
        controller=plane['controller_identity']
        _require(type(controller['effective_uid']) is int and controller['effective_uid']==0,
                 'outside Root collector required')
        boundary=_one(plane['observations'],'private-cell-boundary')
        _require(boundary['schema']==plane['boundary_schema'] and boundary['image_id']==plane['image_id']
            and boundary['system_digest']==plane['system_digest']
            and boundary['observer_boot']==controller['boot_id'],'private-cell boundary provenance differs')
        _kernel(boundary['identity'],controller,agent_identity)
        rows=plane['cell_observations']
        _require(type(rows) is list and len(rows)<=10000,'bounded cell observations required')
        allowed={'idmapped-task-mounts','before-cell-gate',
            'private-loopback-network','filtered-cell','resource-ceilings','gated-product-process',
            'retired-product-process','cell-stderr','terminal-cleanup'}
        if expected_interrupted_command is not None:
            allowed.add('capture-failure')
            failed=[row for row in rows if row.get('kind')=='capture-failure']
            _require(len(failed)==1 and set(failed[0])=={'kind','argv','exception_type','stdout','stderr'}
                and failed[0]['argv']==expected_interrupted_command
                and failed[0]['exception_type']=='InterruptedError'
                and type(failed[0]['stdout']) is type(failed[0]['stderr']) is str
                and plane['executions']==[],
                'negative-only interruption boundary differs from exact failed command')
        _require(all(type(row) is dict and row.get('kind') in allowed for row in rows),
            'unknown or partial failed cell observation')
        initial=_one(rows,'before-cell-gate')['identity']
        filtered=_one(rows,'filtered-cell')['identity']
        namespaces=filtered['namespaces']
        _require(set(namespaces)=={'mnt','net','pid','ipc','uts','cgroup'}
            and re.fullmatch('hol-product-cell-[0-9a-f]{32} \\(enforce\\)',filtered['lsm_label']),
            'actual enforcing cell profile/namespaces required')
        for key,field in (('mnt','mount_namespace'),('pid','pid_namespace'),('net','network_namespace')):
            _require(namespaces[key]==boundary['identity'][field],'actor and boundary namespace observations differ')
        for identity,argv,has_filters in ((initial,['/public/initializer','/usr/bin/python3','-I','-B',
            '/public/actor.py','/public'],False),(filtered,['/usr/bin/python3','-I','-B','/public/actor.py','/public'],True)):
            _actor(identity,label=filtered['lsm_label'],namespaces=namespaces,filtered=has_filters)
            _require(identity['argv']==argv and identity['pid']==filtered['pid']
                and identity['start_time']==filtered['start_time']
                and identity['status']['NSpid'].split()[-1]=='1','actor gate identity changed')
        _require(filtered['start_time']==boundary['identity']['start_time'],'actor boundary start time differs')
        _tasks(plane,rows,workspace_source=workspace_source,provider_mounts=provider_mounts,pid=filtered['pid'])
        _mountinfo(filtered['mountinfo'],prefix=plane['runtime_prefix'],tasks=plane['task_mounts'])
        topology=_one(rows,'private-loopback-network')['topology']
        checked=validate_topology('lo: 0\n',topology['ipv4_routes'],topology['ipv6_routes'],topology['ipv6_addresses'])
        _require(checked==topology,'private network topology changed')
        resources=_one(rows,'resource-ceilings')
        expected={'memory.max':'1073741824','pids.max':'128','cpu.max':'100000 100000'}
        if cfg['cpu_profile']=='single-core-v1':
            cpu=filtered['status']['Cpus_allowed_list'].strip()
            _require(cpu.isdigit(),'single-core resource profile lacks exact CPU affinity')
            expected['cpuset.cpus.effective']=cpu
        _require(resources['cpu_profile']==cfg['cpu_profile'] and resources['values']==expected,
                 'outside resource ceilings differ from fixed floor')
        handles=set()
        for row in rows:
            if row['kind']=='gated-product-process':
                _require(row['handle'] not in handles,'reused product process gate handle')
                handles.add(row['handle'])
                _actor(row['identity'],label=filtered['lsm_label'],namespaces=namespaces,filtered=True)
                _require(row['identity']['argv'][:4]==['/usr/bin/python3','-I','-B',
                    '/public/ci/gauntlet/benchmark/product_exec_gate.py'],'product process lacks measured exec gate')
            _require(row['kind']!='capture-failure' or expected_interrupted_command is not None,
                     'partial failed capture cannot establish valid execution')
        terminal=_one(rows,'terminal-cleanup')
        _require(terminal=={'kind':'terminal-cleanup','cgroup_absent':True,'rootfs_mount_absent':True},
                 'private-cell processes or mounts survived')
        from .product_version import LEGACY_VERSION, validate_version
        validate_identity_claim(plane['identity_claim'],source_sha=settings['source_sha'],
            package_version=validate_version(settings.get('package_version',LEGACY_VERSION)))
        prefix=plane['runtime_prefix']
        _require(type(prefix) is str and prefix.startswith('/') and str(PurePosixPath(prefix))==prefix
            and '..' not in PurePosixPath(prefix).parts and len(PurePosixPath(prefix).parts)>=3
            and plane['identity_claim']['prefix']==prefix,'runtime prefix path/installed claim differs')
        _require(plane['identity_claim']['runtime_sha256']==cfg['native_sha256']
            and plane['backend_observation']['sha256']==settings['bwrap_sha256'],
            'installed native/backend identity differs')
        for sequence,row in enumerate(plane['hooks'],1):
            _require(row['sequence']==sequence and row['hook_event_name'] in
                {'UserPromptSubmit','PreToolUse','PostToolUse'} and _sha(row['payload_digest']),
                'hook sequence/classification/input binding invalid')
            response=decode_hook_response(canonical_json(row['raw_response']).encode(),
                returncode=row['returncode'],event=row['hook_event_name'])
            _require(response==row['response'] and hashlib.sha256(canonical_json(response).encode()).hexdigest()
                ==row['response_digest'] and bool(row['kernel_process_samples']),
                'actual hook response/process binding invalid')
            from .release_mcp_entry import LIBRARY_VERSIONS
            home='/runtime/home' if settings.get('package_version') in LIBRARY_VERSIONS else '/product/home'
            command=[prefix+'/bin/python','-I','-B','-m','codex_plugin_scanner.cli','guard','hook','--json',
                '--harness','omp','--guard-home','/product/guard','--home',home,
                '--workspace',plane['workspace_path']]
            if settings.get('package_version') in LIBRARY_VERSIONS:
                from .release_hook_entry import hook_command
                command=hook_command(prefix+'/bin/python',version=settings['package_version'],
                    timeout=row.get('timeout_seconds'),home=home,workspace=plane['workspace_path'])
            command_hash=hashlib.sha256(b'\0'.join(part.encode() for part in command)+b'\0').hexdigest()
            _hook_samples(row['kernel_process_samples'], controller=controller, agent=agent_identity,
                          product_user_namespace=plane['product_user_namespace'], command_hash=command_hash)
        return {'boundary_consistent':True,'native_hook_count':len(plane['hooks']),
                'task_mount_count':len(plane['task_mounts']),'product_claims_authenticated':False,
                'qualification_eligible':False}
    except (KeyError,TypeError,IndexError,AttributeError) as error:
        raise ValueError('malformed private-cell custody evidence') from error
