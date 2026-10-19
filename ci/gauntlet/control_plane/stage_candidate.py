"""Trusted Linux staging adapter: inert wheel installation, fresh actual controls.

Installed separately from PR artifacts. No package hooks, candidate interpreter,
or candidate imports execute as Root. Failed staging is retained and never retried.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import sys
import zipfile
from email.parser import BytesParser

BASE = Path('/opt/hol-gauntlet')
SITE = 'lib/python3.12/site-packages/'


def wheel_entries(raw, declaration, sha):
    result, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if not 1 <= len(archive.infolist()) <= 20000:
            raise ValueError('wheel entry count limit')
        for info in archive.infolist():
            name = info.filename
            if (name in result or PurePosixPath(name).as_posix() != name or '\\' in name
                    or name.startswith('/') or '..' in PurePosixPath(name).parts
                    or any(ord(c) < 32 for c in name)
                    or not (name.startswith('codex_plugin_scanner/') or
                            re.match(r'hol_guard-[A-Za-z0-9_.]+\.dist-info/', name))
                    or stat.S_ISLNK(info.external_attr >> 16) or info.is_dir()
                    or info.file_size > 128*1024**2):
                raise ValueError('unsupported wheel path/object')
            total += info.file_size
            if total > 512*1024**2:
                raise ValueError('wheel uncompressed byte limit')
            result[name] = archive.read(info)
    native_name = 'codex_plugin_scanner/_native/hol-guard-runtime'
    metadata_dirs = {name.split('/')[0] for name in result if '.dist-info/' in name}
    if len(metadata_dirs) != 1:
        raise ValueError('single hol-guard distribution metadata required')
    metadata = BytesParser().parsebytes(result[next(iter(metadata_dirs)) + '/METADATA'])
    if (metadata.get_all('Name') != ['hol-guard']
            or metadata.get_all('Version') != [declaration['version']]):
        raise ValueError('wheel distribution identity mismatch')
    manifest = json.loads(result['codex_plugin_scanner/_native/runtime-manifest.json'])
    if (manifest.get('source_sha') != sha or manifest.get('package_version') != declaration['version']
            or manifest.get('runtime_sha256') != declaration['native_sha256']
            or hashlib.sha256(result[native_name]).hexdigest() != declaration['native_sha256']):
        raise ValueError('inert wheel/native provenance mismatch')
    return result


def clone_with_wheel(prefix, target, wheels, inventory):
    entries, objects, _tree, _total = inventory(prefix)
    target.mkdir(mode=0o700)
    def old_product(name):
        return name.startswith(SITE) and (name[len(SITE):].split('/')[0] == 'codex_plugin_scanner'
                or re.fullmatch(r'hol_guard-[A-Za-z0-9_.]+\.dist-info', name[len(SITE):].split('/')[0]))
    links, modes = [], []
    for name, row in sorted(entries.items(), key=lambda item: (len(Path(item[0]).parts), item[0])):
        if name == '.' or old_product(name):
            continue
        path = target/name
        if row['kind'] == 'directory':
            path.mkdir(mode=0o700)
            modes.append((path, row['mode']))
        elif row['kind'] == 'file':
            with path.open('xb') as stream:
                stream.write(objects[row['sha256']])
            path.chmod(row['mode'])
        else:
            links.append((path, row['link']))
    for name, data in wheels.items():
        path = target/SITE/name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        with path.open('xb') as stream:
            stream.write(data)
        path.chmod(0o755 if name == 'codex_plugin_scanner/_native/hol-guard-runtime' else 0o644)
    for path, link in links:
        path.symlink_to(link)
    for path, mode in reversed(modes):
        path.chmod(mode)
    # Expose only after the entire new tree is written. All bytes remain Root owned.
    target.chmod(0o755)
    inventory(target)


def stage(request):
    if os.geteuid() != 0 or not sys.flags.isolated or sys.platform != 'linux':
        raise ValueError('isolated trusted Linux Root staging required')
    helpers = runpy.run_path(str(BASE/'worker.py'), run_name='trusted_worker_helpers')
    trusted, read_json = helpers['trusted'], helpers['read_json']
    settings = read_json(BASE/'stage-settings.json')
    controller = trusted(settings['controller'], directory=True)
    # All controller bytes were installed by the reviewed bootstrap, never by PRs.
    sys.path.insert(0, str(controller))
    from ci.gauntlet.control_plane.artifacts import inspect_archive
    from ci.gauntlet.benchmark.ci_runner_config import load_config, verify_assets
    from ci.gauntlet.benchmark.contracts import digest, canonical_json
    from ci.gauntlet.benchmark.runtime_bundle import inventory
    from ci.gauntlet.benchmark.native_product_container import root_prefix_digest
    from ci.gauntlet.benchmark.deterministic_control import run_control
    from ci.gauntlet.benchmark.local_executor_controls import verify_control, ROLES
    from ci.gauntlet.benchmark.local_executor_conformance import (
        verify_local_conformance, EXECUTION_SOURCES, SOURCE, platform_identity)
    from ci.gauntlet.benchmark.ci_runner_preflight import controller_environment
    from ci.gauntlet.control_plane.stage_outcome import require_cleanup, failed_roles
    from ci.gauntlet.benchmark.deterministic import evaluate_control
    diagnostic_roles=ROLES|{'injection'}

    sha = request.get('source_sha', '')
    keys = set(request)
    refresh = request.get('live_refresh_id')
    if (keys not in ({'source_sha', 'archive_sha256'},
                     {'source_sha', 'archive_sha256', 'build_job_id'},
                     {'source_sha', 'archive_sha256', 'build_job_id', 'live_refresh_id'})
            or not re.fullmatch(r'[0-9a-f]{40}', sha)):
        raise ValueError('exact bounded staging request required')
    if refresh is not None:
        if not isinstance(refresh, str) or not re.fullmatch(r'[0-9a-f]{16}', refresh):
            raise ValueError('fixed live refresh identity required')
        previous, _ = helpers['deployment'](sha)
        if previous is None:
            raise ValueError('live refresh requires an already staged exact candidate')
        receipt = read_json(Path('/var/lib/hol-gauntlet/builds')/request['build_job_id']/'result.json')
        if (receipt.get('status') != 'built' or receipt.get('source_sha') != sha
                or receipt.get('job_id') != request['build_job_id']
                or receipt.get('archive_sha256') != request['archive_sha256']):
            raise ValueError('live refresh requires the original verified successful build')
    if 'build_job_id' in request:
        if not re.fullmatch(r'[0-9a-f]{16}', request['build_job_id']):
            raise ValueError('fixed local build identity required')
        archive = trusted(Path('/var/lib/hol-gauntlet/builds')/request['build_job_id']/'candidate.zip')
    else:
        archive = Path(settings['guest_inbox'])/('hol-gauntlet-' + sha + '.zip')
    # Read mutable guest inbox once, then authenticate and use only captured bytes.
    fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 256*1024**2:
            raise ValueError('bounded ordinary artifact required')
        raw = stream.read(256*1024**2 + 1)
    if hashlib.sha256(raw).hexdigest() != request['archive_sha256']:
        raise ValueError('archive differs from externally supplied GitHub digest')
    root = (BASE/'live-candidates'/sha/refresh if refresh is not None
            else BASE/'candidates'/sha)
    if refresh is not None:
        root.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    root.mkdir(mode=0o755)  # exclusive; retained failures cannot be silently repaired
    emit = lambda phase, completed=(), current=None: helpers['stage_progress'](root, sha, phase, completed, current,total=len(diagnostic_roles))
    emit('artifact-verification')
    captured = root/'candidate.zip'
    with captured.open('xb') as stream:
        stream.write(raw)
    captured.chmod(0o444)
    declaration = inspect_archive(captured, sha)
    with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
        whl = bundle.read(declaration['wheel'])
    files = wheel_entries(whl, declaration, sha)
    missing_capabilities=[] if 'codex_plugin_scanner/guard/runtime/contained_completion.py' in files else ['contained-output-completion.v1']
    template = trusted(settings.get('staging_template_config',settings['template_config']))
    asset_root = trusted(settings['asset_root'], directory=True)
    loaded = load_config(template, expected_digest=settings.get('staging_template_config_digest',settings['template_config_digest']), asset_root=asset_root)
    verify_assets(loaded)  # validate every approved baseline input before cloning
    config = loaded['config']
    prefix = root/'prefix'
    emit('prefix-clone')
    clone_with_wheel(loaded['paths']['guard_prefix'], prefix, files, inventory)
    wheel = root/declaration['wheel']
    wheel.write_bytes(whl)
    native = root/'hol-guard-runtime'
    native.write_bytes(files['codex_plugin_scanner/_native/hol-guard-runtime'])
    native.chmod(0o555)
    # New dependencies must be explicitly provisioned in the reviewed baseline;
    # never execute installers, hooks or candidate imports as Root.
    from importlib.metadata import distributions
    emit('dependency-validation')
    from packaging.requirements import Requirement
    installed = {d.metadata['Name'].lower().replace('_', '-'): d for d in
                 distributions(path=[str(prefix/SITE)])}
    product = installed['hol-guard']
    for spec in product.requires or []:
        requirement = Requirement(spec)
        if requirement.marker and not requirement.marker.evaluate({'extra': ''}):
            continue
        dependency = installed.get(requirement.name.lower().replace('_', '-'))
        if (requirement.url or dependency is None or
                not requirement.specifier.contains(dependency.version, prereleases=True)):
            raise ValueError('PR dependency requires a separately reviewed baseline update: ' + spec)
    def relative(path):
        return path.relative_to(asset_root).as_posix()
    config['id'] = ('live-'+sha+'-'+refresh if refresh is not None else 'pr-'+sha)
    config['runtime']['guard_source_sha'] = sha
    config['runtime']['guard_package_version'] = declaration['version']
    config['runtime']['private_cell'].update(native_sha256=declaration['native_sha256'],
                                             runtime_tree_digest=inventory(prefix)[2])
    config['assets']['guard_prefix'].update(path=relative(prefix), sha256=root_prefix_digest(prefix))
    config['assets']['wheel'].update(path=relative(wheel), sha256=declaration['wheel_sha256'])
    for name in ('native', 'compiler'):
        config['assets'][name].update(path=relative(native), sha256=declaration['native_sha256'])
    provisional = root/'provisional.json'
    provisional.write_text(canonical_json(config) + '\n')
    current = load_config(provisional, expected_digest=digest(config), asset_root=asset_root)
    verify_assets(current)
    controls_root = (Path('/home/hr-' + refresh) if refresh is not None
                     else Path('/home/hc-' + sha[:16]))
    controls_root.mkdir(mode=0o700)
    records = {}
    with controller_environment(current):
        for role in sorted(diagnostic_roles):
            emit('conformance-control', records, role)
            record = run_control(controls_root/role, current, role)
            # A product rejection with verified cleanup can complete the suite.
            # Any uncertain process/resource cleanup still stops immediately.
            require_cleanup(record)
            records[role] = record
            emit('conformance-control', records)
    failed=failed_roles(records)
    if failed:
        result={'status':'conformance-failed','source_sha':sha,
                'build_job_id':request.get('build_job_id'),'failed_roles':failed,
                'controls':len(records),'conformance_controls':len(ROLES),
                'suite_profile':'deterministic-six-control-diagnostic.v1',
                'benchmark_admitted':False,'missing_capabilities':missing_capabilities,
                'cleanup_verified':True,'model_tokens':0}
        with (root/'stage-result.json').open('x') as stream:
            json.dump(result,stream,sort_keys=True)
        emit('conformance-failed',records)
        print(json.dumps(result))
        return
    emit('conformance-verification', records)
    sample = records['success']
    settings_observed = sample['developer_runtime']['record']['settings']
    expected = {k: settings_observed[k] for k in
                ('package_version', 'source_sha', 'prefix_digest', 'bwrap_sha256', 'executor_image_id', 'mcp_image_id')}
    expected['private_cell'] = {k: settings_observed['private_cell'][k] for k in
        ('artifact_manifest_sha256', 'initializer_sha256', 'native_sha256', 'runtime_tree_digest', 'idmap_runtime', 'cpu_profile')}
    for role in sorted(ROLES):
        record=records[role]
        verify_control(role, record, public_key=record['controller_public_key_hex'], expected=expected)
    # Recompute all six diagnostic verdicts, including injection attribution.
    # A successful diagnostic cannot bypass the strict completion-proof floor.
    cells = [evaluate_control(role, records[role], expected) for role in sorted(diagnostic_roles)]
    if missing_capabilities:
        result={'status':'diagnostic-passed','source_sha':sha,
                'build_job_id':request.get('build_job_id'),'failed_roles':[],
                'controls':len(records),'conformance_controls':len(ROLES),
                'suite_profile':'deterministic-six-control-diagnostic.v1',
                'benchmark_admitted':False,'missing_capabilities':missing_capabilities,
                'cleanup_verified':True,'model_tokens':0,'cells':cells}
        with (root/'stage-result.json').open('x') as stream:
            json.dump(result,stream,sort_keys=True)
        emit('diagnostic-passed',records)
        print(json.dumps(result))
        return
    baseline_conformance = json.loads(loaded['paths']['conformance'].read_text())
    review = baseline_conformance['review']
    document = ('Automated local regression conformance for source ' + sha + '. Fresh signed controls '
                'exercise the unchanged reviewed executor/SDK and new candidate bytes. Requirements below '
                'retain the approved isolation design; this is not independent review or qualification.\n' +
                '\n'.join(k + ': ' + v for k, v in sorted(review['requirements'].items())))
    review = {**review, 'document': document, 'document_sha256': hashlib.sha256(document.encode()).hexdigest()}
    conformance = {**baseline_conformance, 'runtime': expected, 'platform': platform_identity(),
        'execution_sources': {name: hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in EXECUTION_SOURCES},
        'public_assets': sample['public_input_assets_before'], 'review': review,
        'controls': {role: {'public_key': rec['controller_public_key_hex'], 'record': rec, 'record_digest': digest(rec)}
                     for role, rec in records.items() if role in ROLES}}
    proof = root/'conformance.json'
    proof.write_text(canonical_json(conformance) + '\n')
    config['assets']['conformance'].update(path=relative(proof), sha256=hashlib.sha256(proof.read_bytes()).hexdigest())
    final = root/'config.json'
    final.write_text(canonical_json(config) + '\n')
    current = load_config(final, expected_digest=digest(config), asset_root=asset_root)
    verify_local_conformance(current['runtime'])
    manifest = {'schema': 'hol-gauntlet-deployment.v1', 'source_sha': sha, 'config': str(final),
                'config_digest': digest(config), 'asset_root': str(asset_root),
                'controller': str(controller), 'python': settings['controller_python']}
    with (root/'deployment.json').open('x') as stream:
        json.dump(manifest, stream, sort_keys=True)
    if any(name.startswith('codex_plugin_scanner') for name in sys.modules):
        raise ValueError('candidate imported into Root controller')
    emit('candidate-ready', records)
    print(json.dumps({'status': 'staged', 'source_sha': sha, 'controls': len(records), 'model_tokens': 0}))


if __name__ == '__main__':
    import fcntl
    os.umask(0o022)
    request = sys.stdin.buffer.read(8193)
    if len(request) > 8192:
        raise ValueError('staging request exceeds byte limit')
    with (BASE/'worker.lock').open('a+') as lease:
        lease_path = BASE/'worker.lock'
        if lease_path.is_symlink() or lease_path.stat().st_uid != 0 or lease_path.stat().st_mode & 0o022:
            raise ValueError('Root worker lease required')
        lease_path.chmod(0o600)
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        stage(json.loads(request))
