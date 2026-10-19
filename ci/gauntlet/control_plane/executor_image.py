"""Provision a pinned allocator image and matching trusted cell artifacts."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


VERIFY_BASELINE = '''import json,sys
from pathlib import Path
s=json.loads(sys.stdin.read());sys.path.insert(0,s['template_controller'])
from ci.gauntlet.benchmark.ci_runner_config import load_config,verify_assets
from ci.gauntlet.benchmark.ci_runner_preflight import controller_environment
from ci.gauntlet.benchmark.local_executor_conformance import verify_local_conformance
loaded=load_config(Path(s['template_config']),expected_digest=s['template_config_digest'],asset_root=Path(s['asset_root']))
verify_assets(loaded)
with controller_environment(loaded):verify_local_conformance(loaded['runtime'])
if any(n.startswith('codex_plugin_scanner') for n in sys.modules):raise ValueError('candidate imported as Root')
print(json.dumps({'status':'verified'}))
'''


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def run(argv, **kwargs):
    result = subprocess.run(argv, capture_output=True, timeout=75,
                            env={'PATH':'/usr/bin:/bin', 'HOME':'/root'}, **kwargs)
    if len(result.stdout)>1024**2 or len(result.stderr)>1024**2:
        raise ValueError('bounded trusted executor provisioning output required')
    if result.returncode:
        raise RuntimeError('Trusted executor provisioning failed: '+result.stderr.decode(errors='replace')[-4000:])
    return result.stdout


def image(controller, trusted):
    context=controller/'ci/gauntlet/control_plane/allocator-image'
    names=('Executor.Dockerfile','malloc_policy.c','malloc.preload')
    for name in names:
        trusted(context/name,directory=False)
    sources={name:hashlib.sha256((context/name).read_bytes()).hexdigest() for name in names}
    receipt=controller/'executor-image.json'
    if receipt.exists():
        trusted(receipt,directory=False)
        value=json.loads(receipt.read_text())
        if value.get('sources')!=sources:
            raise ValueError('retained allocator image sources differ')
        identifier=value['image_id']
    else:
        iid=controller/'executor-image.iid'
        run(['/usr/bin/podman','build','--pull=never','--network=none','--timestamp=0',
             '--file',str(context/'Executor.Dockerfile'),'--iidfile',str(iid),str(context)])
        trusted(iid,directory=False)
        identifier=iid.read_text().strip()
        if not identifier.startswith('sha256:'):
            identifier='sha256:'+identifier
    if not re.fullmatch('sha256:[0-9a-f]{64}',identifier):
        raise ValueError('exact allocator image identity required')
    if receipt.exists():
        present=subprocess.run(['/usr/bin/podman','image','exists',identifier],
                               capture_output=True,timeout=75,
                               env={'PATH':'/usr/bin:/bin','HOME':'/root'})
        if len(present.stdout)>1024**2 or len(present.stderr)>1024**2:
            raise ValueError('bounded trusted executor image probe required')
        if present.returncode==1:
            # Podman may evict an unused image while the immutable receipt is
            # retained. Rebuild only from the already verified, offline inputs.
            rebuilt=run(['/usr/bin/podman','build','--quiet','--pull=never',
                         '--network=none','--timestamp=0',
                         '--file',str(context/'Executor.Dockerfile'),str(context)]).decode().strip()
            if rebuilt.removeprefix('sha256:')!=identifier[7:]:
                raise ValueError('recreated allocator image differs from retained identity')
        elif present.returncode!=0:
            raise RuntimeError('Trusted executor image probe failed: '
                               +present.stderr.decode(errors='replace')[-4000:])
    observed=json.loads(run(['/usr/bin/podman','image','inspect',identifier]))
    if (len(observed)!=1 or observed[0]['Id'].removeprefix('sha256:')!=identifier[7:]
            or observed[0]['Os']!='linux' or observed[0]['Architecture']!='arm64'):
        raise ValueError('exact Linux ARM64 allocator image required')
    if not receipt.exists():
        receipt.write_bytes(canonical({'image_id':identifier,'sources':sources})+b'\n')
        receipt.chmod(0o444)
    return identifier


def write(path, data, mode=0o444):
    if path.exists():
        if path.is_symlink() or path.read_bytes()!=data:
            raise ValueError('retained executor provisioning bytes differ: '+str(path))
        return
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
    with path.open('xb') as stream:
        stream.write(data)
    path.chmod(mode)


def install(controller, settings, trusted):
    if os.geteuid()!=0:
        raise ValueError('idle trusted Linux Root bootstrap required')
    verified=json.loads(run([settings['controller_python'],'-I','-B','-c',VERIFY_BASELINE],
                            input=canonical(settings)))
    if verified!={'status':'verified'}:
        raise ValueError('original pinned baseline verification required')
    identifier=image(controller,trusted)
    from ci.gauntlet.benchmark.private_cell_campaign_inputs import _sources
    original=Path(settings['template_config'])
    trusted(original,directory=False)
    template=json.loads(original.read_text())
    if hashlib.sha256(canonical(template)).hexdigest()!=settings['template_config_digest']:
        raise ValueError('baseline configuration digest differs')
    asset_root=Path(settings['asset_root'])
    # Preserve the original, independently pinned conformance. A newer product
    # may need additional locked dependencies before its own fresh six controls
    # can be staged; bind that operator-provisioned prefix separately.
    dependency_prefix=settings.get('staging_dependency_prefix')
    if dependency_prefix is not None:
        from ci.gauntlet.benchmark.native_product_container import root_prefix_digest
        replacement=Path(dependency_prefix)
        trusted(replacement,directory=True)
        expected=settings['staging_dependency_prefix_digest']
        if (not replacement.is_relative_to(asset_root)
                or root_prefix_digest(replacement)!=expected):
            raise ValueError('pinned staging dependency prefix differs')
        template['assets']['guard_prefix'].update(
            path=replacement.relative_to(asset_root).as_posix(),sha256=expected)
    previous=asset_root/template['assets']['private_cell']['path']
    trusted(previous,directory=True)
    sources=_sources()
    for name in ('public/initializer','public/actor.py'):
        path=previous/name;trusted(path,directory=False)
        sources[name]=path.read_bytes()
    artifacts=controller/'cell-artifacts'
    for name,data in sources.items():
        write(artifacts/name,data,0o555 if name=='public/initializer' else 0o444)
    manifest=canonical({'schema':'product-cell-artifacts.v1',
                        'files':{name:hashlib.sha256(data).hexdigest() for name,data in sources.items()}})+b'\n'
    write(artifacts/'manifest.json',manifest)
    template['assets']['private_cell'].update(path=artifacts.relative_to(asset_root).as_posix(),
                                              sha256=hashlib.sha256(manifest).hexdigest())
    template['runtime']['guard_executor_image_id']=identifier
    target=controller/'staging-template.json';raw=canonical(template)+b'\n'
    write(target,raw)
    return {'executor_image_id':identifier,'staging_template_config':str(target),
            'staging_template_config_digest':hashlib.sha256(canonical(template)).hexdigest(),
            'allocator_profile':'glibc-two-arenas.v1'}
