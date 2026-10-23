"""Frozen local Linux isolation identities; no independent qualification claim."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import canonical_json
from .model_endpoint import model_endpoint


def image_bwrap_identity(root):
    """Read only the declared ordinary binary, never image code or symlinks."""
    descriptors = [os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)]
    try:
        metadata = os.fstat(descriptors[0])
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('executor filesystem root is not root-owned without group/world write')
        for component in ('usr','bin'):
            descriptors.append(os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=descriptors[-1]))
            metadata = os.fstat(descriptors[-1])
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError('executor binary ancestry is not root-owned without group/world write')
        descriptor = os.open('bwrap',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=descriptors[-1])
        with os.fdopen(descriptor,'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                    or not before.st_mode & 0o111 or not 0 < before.st_size <= 64*1024*1024):
                raise ValueError('executor bwrap is not a bounded root-owned ordinary executable')
            value,total = hashlib.sha256(),0
            for chunk in iter(lambda:stream.read(1024*1024),b''):
                total += len(chunk)
                if total > 64*1024*1024:
                    raise ValueError('executor binary exceeds inert hash bound')
                value.update(chunk)
            after = os.fstat(stream.fileno())
            if ((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns) !=
                    (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) or total != before.st_size):
                raise ValueError('executor binary changed while hashing')
        return {'path':'/usr/bin/bwrap','sha256':value.hexdigest(),'uid':before.st_uid,
                'mode':stat.S_IMODE(before.st_mode),'size':total}
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def freeze_developer_product(runtime, *, podman):
    from .campaign_identity import validate_product_pins
    pins = validate_product_pins(runtime)
    if pins is None:
        return None
    from .native_product_container import root_prefix_inventory
    prefix = root_prefix_inventory(Path(runtime['guard_python']).parent.parent)['digest']
    if prefix != pins['guard_prefix_digest']:
        raise ValueError('declared developer product prefix differs from inert installed bytes')
    image = pins['guard_executor_image_id']
    inspected = json.loads(podman('image','inspect',image).stdout)
    if (len(inspected) != 1 or inspected[0]['Id'].removeprefix('sha256:') != image.removeprefix('sha256:')
            or inspected[0].get('Os') != 'linux'):
        raise ValueError('actual local executor image differs from frozen Linux image')
    mounts=json.loads(podman('image','mount','--format','json').stdout)
    if (type(mounts) is not list or len(mounts)>4096
            or any(type(row) is not dict or type(row.get('id')) is not str for row in mounts)):
        raise ValueError('bounded executor image mount inventory required')
    if any(row['id'].removeprefix('sha256:')==image.removeprefix('sha256:') for row in mounts):
        raise ValueError('executor image already mounted; refusing to borrow or unmount another lease')
    try:
        # Reserve ownership after refusing existing mounts. A failed helper may
        # still have mounted the image; the finally path must release our lease.
        mounted = podman('image','mount',image).stdout.strip()
        if not mounted.startswith('/') or '\n' in mounted or Path(mounted).is_symlink():
            raise ValueError('executor image mount returned an invalid literal filesystem path')
        bwrap = image_bwrap_identity(Path(mounted))
        if bwrap['sha256'] != pins['guard_bwrap_sha256']:
            raise ValueError('actual executor bwrap bytes differ from declared digest')
        from .executor_node_runtime import image_node_runtime_identity
        node_runtime=image_node_runtime_identity(Path(mounted))
    finally:
        podman('image','unmount',image)
    result = {'executor_image_id':image,'prefix_digest':prefix,'bwrap':bwrap,
              'node_runtime':node_runtime,
              'sdk_conformance_verified':False,'qualification_eligible':False}
    if 'guard_private_cell' in runtime:
        from .private_cell_campaign_inputs import freeze_private_cell
        result['private_cell'] = freeze_private_cell(runtime)
    return result

CLEANUP_FIELDS = ('active_service_children_after_cleanup', 'active_service_workers_after_cleanup',
                  'active_service_sessions_after_cleanup', 'active_native_sessions_after_cleanup')


def freeze_isolation(runtime):
    from .campaign_identity import validate_product_pins
    validate_product_pins(runtime)
    if not runtime.get('isolated', False):
        return None
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('isolated campaign requires the owned Linux root controller')
    provider = model_endpoint(runtime['base_url'])
    from .business_agent_container import BASE_IMAGE, _file_identity, _podman, freeze_public_tree
    from .linux_executor import _identity
    inspected = json.loads(_podman('image', 'inspect', BASE_IMAGE).stdout)
    if len(inspected) != 1 or inspected[0]['Id'].removeprefix('sha256:') != BASE_IMAGE.removeprefix('sha256:'):
        raise ValueError('actual local image differs from pinned business image')
    sdk = Path(runtime['sdk_root'])
    if sdk.name != 'pi-coding-agent' or sdk.parent.name != '@oh-my-pi' or sdk.parents[1].name != 'node_modules':
        raise ValueError('isolated campaign requires exact public SDK subtree layout')
    result = {'image_id': BASE_IMAGE, 'controller': _identity(os.getpid()), 'model_endpoint': provider,
            'sdk': freeze_public_tree(sdk.parents[1]), 'bun': _file_identity(Path(runtime['bun'])),
            'podman_sha256': hashlib.sha256(Path('/usr/bin/podman').read_bytes()).hexdigest(),
            'apparmor_parser_sha256': hashlib.sha256(Path('/usr/sbin/apparmor_parser').read_bytes()).hexdigest(),
            'agent_uid': 10001, 'network_mode': 'none', 'readonly_root': True,
            'qualification_eligible': False}
    product = freeze_developer_product(runtime,podman=_podman)
    if product is not None:
        result['developer_product'] = product
    if 'guard_conformance' in runtime:
        from .local_executor_conformance import verify_local_conformance
        result['local_executor_admission']=verify_local_conformance(runtime,public_assets={
            'sdk':result['sdk'],'bun':result['bun']})
        if result['local_executor_admission']['public_inputs_verified'] is not True:
            raise ValueError('local admission lacks measured public inputs')
    return result


def cleanup_complete(report, *, isolated=False):
    for name in CLEANUP_FIELDS:
        if name not in report:
            if isolated or name == CLEANUP_FIELDS[0]:
                return False
            continue
        if type(report[name]) is not int or report[name] != 0:
            return False
    if isolated:
        record = (report.get('isolation') or {}).get('record', {})
        if record.get('cleanup_complete') is not True or record.get('cleanup_errors'):
            return False
    return True


def bind_isolation(config, report, *, attempt_path):
    """Verify genuine signed local measurement against pre-inference frozen tuple.

    The producer key is pinned by the trusted live pilot callback and retained
    in its ledger; it is not an independently reviewed certification anchor.
    Failed execution may retain partial isolation measurements, never upgrade.
    """
    isolated = config['runtime'].get('isolated', False)
    expected_lane = 'isolated-linux' if isolated else 'shared-uid-diagnostic'
    if report.get('execution_lane', 'shared-uid-diagnostic') != expected_lane:
        raise ValueError('pilot execution lane differs from frozen isolation request')
    if not isolated:
        return
    envelope = report.get('isolation')
    if not envelope:
        if report['execution_valid']:
            raise ValueError('valid isolated execution lacks signed measurements')
        return
    record = envelope['record']
    Ed25519PublicKey.from_public_bytes(base64.b64decode(report['producer_public_key'], validate=True)).verify(
        base64.b64decode(envelope['signature'], validate=True), canonical_json(record).encode())
    frozen = config['isolation_tuple']
    sdk_package = str(Path(config['runtime']['sdk_root']) / 'package.json')
    if (record['image_id'] != frozen['image_id'] or record['controller'] != frozen['controller']
            or record['bun_sha256'] != config['identities'][config['runtime']['bun']]
            or record['sdk_package_sha256'] != config['identities'][sdk_package]
            or record['frozen_assets']['sdk'] != frozen['sdk'] or record['frozen_assets']['bun'] != frozen['bun']):
        raise ValueError('observed isolated image/controller/public runtime differs from frozen tuple')
    from .business_agent_container import PUBLIC_HELPERS
    helpers = set(PUBLIC_HELPERS) | ({'mcp_agent_surfaces.ts'} if config['runtime'].get('mcp_agent_surfaces') else set())
    if set(record['public_assets']) != helpers:
        raise ValueError('isolated evidence omits required mounted public helpers')
    for name, sha in record['public_assets'].items():
        origin = Path(__file__).with_name(name).resolve()
        if str(origin) not in config['identities'] or config['identities'][str(origin)] != sha:
            raise ValueError('isolated mounted public helper differs from frozen source')
    # World databases, keys and controller-owned roots must not enter the agent.
    path = attempt_path / 'agent-runtime'
    services = attempt_path / ('frontdoor' if report['adapter'] == 'hol-guard' else 'sockets')
    expected = {(str(path / 'public'), '/runtime/public', 'ro'),
                (str(path / 'home'), '/runtime/home', 'rw'),
                (str(path / 'workspace'), '/runtime/home/project', 'rw'),
                (str(path / 'agent'), '/runtime/agent', 'rw'),
                (str(services), '/services', 'ro'),
                (config['runtime']['bun'], '/runtime/bun', 'ro'),
                (str(Path(config['runtime']['sdk_root']).parents[1]), '/sdk/node_modules', 'ro'),
                (str(path / 'model.sock'), '/runtime/model.sock', 'ro')}
    actual = {(entry['source'], entry['destination'], entry['mode']) for entry in record['mounts']}
    if actual != expected:
        raise ValueError('isolated mounts differ from exact public-only inventory')
    if report['execution_valid']:
        agent = record.get('agent') or {}
        observed_image = record.get('observed_image') or ''
        if (record.get('isolation_observed') is not True or record.get('assets_unchanged') is not True
                or record.get('schema_version') != '1.0' or record.get('kind') != 'isolated-business-agent'
                or record.get('post_assets') != record.get('frozen_assets')
                or observed_image.removeprefix('sha256:') != frozen['image_id'].removeprefix('sha256:')
                or record.get('network_mode') != 'none' or record.get('uid') != 10001
                or agent.get('effective_uid') != 10001 or agent.get('effective_gid') != 10001
                or agent.get('effective_capabilities') != '0000000000000000'
                or agent.get('no_new_privileges') != 1
                or agent.get('boot_id') != frozen['controller']['boot_id']
                or any(not isinstance(agent.get(field), str) or not agent[field]
                       or agent[field] == frozen['controller'][field]
                       for field in ('mount_namespace', 'pid_namespace', 'network_namespace'))):
            raise ValueError('isolated valid outcome lacks measured namespace/asset boundaries')
        if not cleanup_complete(report, isolated=True):
            raise ValueError('isolated execution cleanup remains unresolved')


def verify_isolation_freeze(config):
    if 'isolation_tuple' not in config:
        raise ValueError('frozen isolation declaration missing; retrospective upgrades forbidden')
    if config['isolation_tuple'] != freeze_isolation(config['runtime']):
        raise ValueError('frozen Linux image, namespaces or public assets changed')
