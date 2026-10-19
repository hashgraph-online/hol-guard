"""Bind signed developer process/runtime measurements to the frozen controller."""
from __future__ import annotations

from pathlib import Path

from .developer_campaign import _verified_raw
from .model_endpoint import DEFAULT_BASE_URL, verify_model_endpoint


def bind_developer_isolation(config, report, *, attempt_path):
    if config['runtime'].get('isolated') is not True or report['execution_lane'] != 'isolated-linux':
        raise ValueError('developer live binding requires the frozen isolated Linux lane')
    raw = _verified_raw(attempt_path)
    if raw['public_key'] != report['producer_public_key']:
        raise ValueError('developer process producer differs from retained authority')
    measured, frozen, runtime = raw['execution_measurements'], config['isolation_tuple'], config['runtime']
    if (str(Path(__file__).with_name('model_endpoint.py').resolve()) in config['identities']
            and raw['model_budget_evidence'].get('provider') is None):
        raise ValueError('new frozen developer observer lacks endpoint declaration')
    verify_model_endpoint(raw['model_budget_evidence'].get('provider'), runtime.get('base_url', DEFAULT_BASE_URL))
    if (measured['controller'] != frozen['controller'] or measured['frozen_assets']['sdk'] != frozen['sdk']
            or measured['frozen_assets']['bun'] != frozen['bun']):
        raise ValueError('developer public runtime differs from pre-inference frozen tuple')
    if not report['execution_valid']:
        return
    if (measured['frozen_assets'] != measured['post_assets']
            or measured['public_assets_unchanged'] is not True):
        raise ValueError('developer mounted public assets changed during actual execution')
    helpers = {'developer_omp_episode.ts', 'developer_model_relay.py',
               'developer_provider_relay.py', 'service_relay.py', 'episode.json'}
    protected = raw.get('adapter_id') == 'hol-guard'
    if protected:
        helpers |= {'builtin_guard_bridge.ts', 'contained_exec_relay.py'}
    if runtime.get('mcp_agent_surfaces'):
        helpers.add('mcp_agent_surfaces.ts')
    if set(measured['public_assets']) != helpers:
        raise ValueError('developer public helper inventory differs from actual approved launcher')
    if runtime.get('mcp_agent_surfaces'):
        from .ci_runner_config import read_public, file_digest
        from .mcp_agent_profile import config_profile
        episode = attempt_path / 'runtime/public/episode.json'
        if (file_digest(episode) != measured['public_assets']['episode.json']
                or config_profile(read_public(episode)) != runtime['mcp_agent_surfaces']):
            raise ValueError('actual mounted developer episode lost its frozen harness selection')
    for name in helpers - {'episode.json'}:
        origin = str(Path(__file__).with_name(name).resolve())
        if config['identities'].get(origin) != measured['public_assets'][name]:
            raise ValueError('developer helper differs from frozen controller source')
    container, agent = measured['container'], measured['agent']
    if (container['image'].removeprefix('sha256:') != frozen['image_id'].removeprefix('sha256:')
            or container['user'] != '10001:10001' or container['network'] != 'none'
            or container['readonly_root'] is not True or agent['effective_uid'] != 10001
            or agent['effective_gid'] != 10001 or agent['effective_capabilities'] != '0000000000000000'
            or agent['no_new_privileges'] != 1 or agent['boot_id'] != frozen['controller']['boot_id']
            or any(agent[field] == frozen['controller'][field] for field in (
                'mount_namespace', 'pid_namespace', 'network_namespace'))):
        raise ValueError('developer agent lacks the externally observed isolated process boundary')
    baseline = raw['baseline']
    root = attempt_path / 'runtime'
    expected = {(baseline['checkout_path'], '/runtime/home/project', True),
        (baseline['remote_path'], baseline['remote_path'], True),
        (str(Path(runtime['sdk_root']).parents[1]), '/sdk/node_modules', False),
        (runtime['bun'], '/runtime/bun', False), (str(root / 'public'), '/runtime/public', False),
        (str(root / 'home'), '/runtime/home', True), (str(root / 'agent'), '/runtime/agent', True),
        (str(root / 'model.sock'), '/runtime/model.sock', False)}
    if protected:
        expected |= {(str(attempt_path / 'front'), '/runtime/resources', False),
                     (str(attempt_path / 'hooks'), '/runtime/guard-hook', False),
                     (str(attempt_path / 'sdk-gate'), '/runtime/sdk-gate', False)}
    else:
        expected.add((str(attempt_path / 'rs'), '/runtime/resources', False))
    if raw['base_workflow_id'] in {'add-validation-dependency', 'contributing-pull-request'}:
        socket = 'packages.sock' if raw['base_workflow_id'] == 'add-validation-dependency' else 'pulls.sock'
        expected.add((str(root / socket), '/runtime/provider.sock', False))
    actual = {(row['Source'], row['Destination'], row['RW']) for row in container['mounts']
              if row['Type'] == 'bind'}
    if actual != expected:
        raise ValueError('developer agent mounted undeclared controller/oracle/product resources')
    if protected:
        from .developer_campaign_product import bind_developer_product
        bind_developer_product(config, raw, attempt_path=attempt_path)
