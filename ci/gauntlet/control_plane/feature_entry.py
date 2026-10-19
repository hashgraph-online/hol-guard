"""Installed-candidate contract audit inside the disposable ARM builder image.

This is diagnostic evidence. Product tests use the exact built wheel and native
binary, but mocks and fixtures cannot certify live SaaS or every agent version.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET
import zipfile


FEATURES = (
    ('native_runtime', 'Native runtime selection and verified reads', (
        'tests/test_guard_native_runtime.py', 'tests/test_guard_verified_reads.py')),
    ('contained_completion', 'Contained output completion and one-use proof',
     ('tests/test_contained_completion.py',)),
    ('decision_io_gate', 'Decision-critical Python I/O ownership gate',
     ('tests/test_rust_io_ownership_gate.py::test_gate_inventories_reachable_io_and_passes_current_sources',)),
    ('alpha_release', 'Alpha version stamping and harness coverage', (
        'tests/test_release_critical_path.py::test_precompilation_stamps_a_requested_version_above_the_source_version',
        'tests/test_guard_harness_version_daemon.py::test_untested_acknowledge_then_version_change_flow')),
    ('prompt_secret', 'Prompt, secret and self-protection boundaries', (
        'tests/test_guard_user_prompt_policy.py', 'tests/test_guard_secret_redaction.py',
        'tests/test_guard_self_protection_schemas.py')),
    ('approval', 'Approval decisions and receipts', (
        'tests/test_guard_approvals.py', 'tests/test_guard_store_receipts_vectors.py',
        'tests/test_native_receipt_persistence_gate.py')),
    ('mcp', 'MCP tool identity and authority', (
        'tests/test_guard_mcp_contract.py', 'tests/test_guard_mcp_provider_authority.py')),
    ('package_hooks', 'Package install and local runner hooks', (
        'tests/test_guard_package_hook.py', 'tests/test_guard_js_package_hook_phase11.py')),
    ('local_tool_trust', 'Local tool approval and grant lifecycle', (
        'tests/test_guard_trusted_local_tools.py',)),
    ('package_shims', 'Package-manager shim lifecycle', ('tests/test_guard_package_shims_cli.py',)),
    ('supply_evaluation', 'Supply-chain package evaluation',
     ('tests/test_guard_supply_chain_evaluator.py',)),
    ('supply_audit', 'Supply-chain workspace audit',
     ('tests/test_guard_local_supply_chain_audit_phase16.py',)),
    ('network', 'Network grants and policy', (
        'tests/test_guard_network_local_core.py', 'tests/test_guard_network_policy_contract.py')),
    ('managed_controls', 'Managed control activation and authority', (
        'tests/test_managed_controls_activation_integration.py',
        'tests/managed_controls/test_authority_composition.py')),
    ('settings', 'Settings persistence and CLI modes', (
        'tests/test_guard_settings_sync_preservation.py',
        'tests/test_guard_cli.py::test_guard_settings_show_and_update_security_level',
        'tests/test_guard_cli.py::test_guard_settings_set_security_level_gentle',
        'tests/test_guard_cli.py::test_guard_settings_set_security_level_paranoid')),
    ('codex_claude', 'Codex and Claude native hooks', (
        'tests/test_guard_codex_authoritative_hook_boundary.py',
        'tests/test_claude_daemon_hook_bridge.py',
        'tests/test_claude_hook_failure_floor.py')),
    ('copilot', 'Copilot native hooks', ('tests/test_guard_copilot_hook_command_corpus.py',)),
    ('cursor', 'Cursor native hooks', ('tests/test_cursor_hooks.py',)),
    ('cursor_installed', 'Cursor installed adapter and bridge', (
        'tests/test_cursor_adapter.py', 'tests/test_cursor_native_bridge.py',
        'tests/test_cursor_pretooluse_write_hook.py')),
    ('cline', 'Cline native hooks', ('tests/test_cline_hook_transports.py',)),
    ('gemini_hermes_openclaw_opencode', 'Gemini, Hermes, OpenClaw and OpenCode adapters', (
        'tests/test_gemini_adapter.py', 'tests/test_hermes_adapter.py',
        'tests/test_openclaw_adapter.py', 'tests/test_opencode_hook_python.py')),
    ('kimi', 'Kimi adapter', ('tests/test_kimi_adapter.py',)),
    ('kimi_installed', 'Kimi installed ecosystem contract', ('tests/test_kimi_ecosystem.py',)),
    ('grok_pi_zcode_devin', 'Grok, Pi, ZCode and Devin adapters', (
        'tests/test_grok_adapter.py', 'tests/test_pi_adapter.py',
        'tests/test_zcode_hooks.py', 'tests/test_devin_adapter.py')),
    ('fleet', 'Fleet posture', ('tests/test_fleet_posture_builder.py',)),
    ('harness_inventory', 'Harness detection and support contracts', (
        'tests/test_guard_harness_posture.py',
        'tests/test_guard_phase04_harness_contracts.py')),
    ('cloud_review', 'Cloud review retry and batching contract',
     ('tests/test_guard_cloud_review_event_batching.py',)),
    ('evaluation', 'Evaluation CLI contract', (
        'tests/test_guard_evaluation_cli_package.py',)),
)

# These tests assert checkout-specific import paths or exercise resident services
# with source-tree fixtures. Running them against site-packages produces false
# installation failures. The installed wheel/native binary is still verified
# before the suite, and installed-compatible groups remain wheel-backed.
SOURCE_MODE = frozenset({'native_runtime', 'contained_completion', 'decision_io_gate', 'alpha_release',
                         'package_hooks', 'local_tool_trust', 'package_shims',
                         'supply_evaluation', 'supply_audit', 'cursor', 'cline',
                         'kimi', 'cloud_review'})


def catalog():
    return [{'id': key, 'label': label, 'tests': list(tests),
             'evidence_kind': ('source-native-contract' if key in SOURCE_MODE
                               else 'installed-product-contract')}
            for key, label, tests in FEATURES]


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    target = Path(path)
    temporary = target.with_suffix('.next')
    with temporary.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.write('\n')
    temporary.replace(target)


def junit(path):
    if not path.is_file() or path.stat().st_size > 4*1024**2:
        raise ValueError('bounded JUnit evidence missing')
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == 'testsuite' else list(root.findall('testsuite'))
    if not suites:
        raise ValueError('JUnit suites missing')
    return {name: sum(int(row.attrib.get(name, '0')) for row in suites)
            for name in ('tests', 'failures', 'errors', 'skipped')}


def run():
    if (os.geteuid() != 65532 or os.uname().machine not in {'aarch64', 'arm64'}
            or os.environ.get('HOL_GUARD_FEATURE_AUDIT') != '1'):
        raise ValueError('feature audit requires isolated unprivileged ARM builder')
    source_sha = os.environ['HOL_GUARD_BUILD_SHA']
    audit_id = os.environ['HOL_GUARD_AUDIT_ID']
    if not re.fullmatch('[0-9a-f]{40}', source_sha) or not re.fullmatch('[0-9a-f]{16}', audit_id):
        raise ValueError('exact source and audit identities required')
    output = Path('/output')
    Path('/work/home').mkdir()
    with tarfile.open('/input/source.tar.gz') as archive:
        archive.extractall('/work', filter='data')
    subprocess.run(['git', 'clone', '--no-hardlinks', '--no-checkout',
                    '/work/repository.git', '/work/source'], check=True)
    source = Path('/work/source')
    subprocess.run(['git', '-C', str(source), 'checkout', '--detach', source_sha], check=True)
    os.chdir(source)
    actual = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if actual != source_sha:
        raise ValueError('audited source differs from exact built candidate')
    with zipfile.ZipFile('/input/candidate.zip') as archive:
        record = json.loads(archive.read('artifact.json'))
        name = record['wheel']
        if (record.get('schema') != 'hol-gauntlet-pr-artifact.v1'
                or record.get('source_sha') != source_sha
                or not re.fullmatch(r'[A-Za-z0-9_.+-]+\.whl', name)):
            raise ValueError('candidate artifact declaration differs')
        wheel = Path('/work')/name
        wheel.write_bytes(archive.read(name))
    if sha(wheel) != record['wheel_sha256']:
        raise ValueError('audited wheel bytes differ from build declaration')
    save(output/'progress.json', {'audit_id': audit_id, 'source_sha': source_sha,
         'phase': 'dependencies', 'completed_groups': 0, 'total_groups': len(FEATURES)})
    subprocess.run(['uv', 'sync', '--frozen', '--no-dev', '--group', 'ci-test',
                    '--no-install-project', '--python', '3.12'], check=True, timeout=600)
    subprocess.run(['uv', 'pip', 'install', '--python', '.venv/bin/python',
                    '--no-deps', str(wheel)], check=True, timeout=120)
    runtime = source/'.venv/lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime'
    if sha(runtime) != record['native_sha256']:
        raise ValueError('installed native runtime differs from built artifact')
    cap = json.loads(subprocess.check_output([str(runtime), 'capabilities', '--json'], text=True, timeout=20))
    if cap.get('build_sha') != source_sha or cap.get('runtime_version') != record['version']:
        raise ValueError('native runtime provenance mismatch')
    node_version = subprocess.check_output(['node', '--version'], text=True, timeout=10).strip()
    if node_version != 'v22.22.2':
        raise ValueError('pinned ARM Node runtime differs')
    # Source-tree imports require the generated command catalog that the exact
    # wheel packages at build time. Overlay only those wheel-bound inert data
    # files in this disposable checkout; production source remains unchanged.
    installed_data = source/'.venv/lib/python3.12/site-packages/codex_plugin_scanner/guard/contracts/data'
    source_data = source/'src/codex_plugin_scanner/guard/contracts/data'
    if source_data.exists() or not installed_data.is_dir():
        raise ValueError('source contract data overlay is not pristine and wheel-backed')
    shutil.copytree(installed_data, source_data)
    for relative in ('extensions/command-catalog.v1.json',
                     'extensions/native-command-program.v1.json'):
        if not (source_data/relative).is_file():
            raise ValueError('required generated command resource missing from exact wheel')
    source_runtime = Path('/work/verified-native-runtime')
    shutil.copy2(runtime, source_runtime)
    source_runtime.chmod(0o555)
    if sha(source_runtime) != record['native_sha256']:
        raise ValueError('source-contract native copy differs from built artifact')
    # A source import next to a wheel distribution fails Guard's correct CLI
    # attestation check. Use mutually exclusive contexts in the disposable
    # venv: source+verified native first, then reinstall that exact wheel.
    subprocess.run(['uv', 'pip', 'uninstall', '--python', '.venv/bin/python',
                    'hol-guard'], check=True, timeout=120)
    absent = ('import importlib.metadata as m; '
              'assert not any(d.metadata["Name"].lower().replace("_", "-") == "hol-guard" '
              'for d in m.distributions())')
    subprocess.run(['.venv/bin/python', '-I', '-B', '-c', absent], check=True, timeout=20)
    # Verified-read regressions need the real offline source compiler. Build it
    # from the same checked-out commit inside this disposable ARM container;
    # the wheel-bound runtime above remains the authoritative product binary.
    save(output/'progress.json', {'audit_id': audit_id, 'source_sha': source_sha,
         'phase': 'source-compiler', 'completed_groups': 0, 'total_groups': len(FEATURES)})
    source_compiler = source/'rust/target/release/guard-command-source'
    with (output/'source-compiler.log').open('x') as stream:
        subprocess.run(['cargo', 'build', '--locked', '--release', '--manifest-path',
                        'rust/Cargo.toml', '-p', 'guard-command', '--bin', 'guard-command-source'],
                       stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=1800)
    if not source_compiler.is_file() or not os.access(source_compiler, os.X_OK):
        raise ValueError('exact-source native test compiler missing after build')
    ordered = ([row for row in FEATURES if row[0] in SOURCE_MODE]
               + [row for row in FEATURES if row[0] not in SOURCE_MODE])
    groups_by_id = {}
    installed = False
    for key, label, tests in ordered:
        if key not in SOURCE_MODE and not installed:
            subprocess.run(['uv', 'pip', 'install', '--python', '.venv/bin/python',
                            '--no-deps', str(wheel)], check=True, timeout=120)
            if sha(runtime) != record['native_sha256']:
                raise ValueError('reinstalled exact wheel native runtime differs')
            installed = True
        if any(not (source/test.split('::', 1)[0]).is_file() for test in tests):
            groups_by_id[key] = {'id': key, 'label': label, 'status': 'invalid-evidence',
                                 'reason': 'declared source test is missing'}
            continue
        save(output/'progress.json', {'audit_id': audit_id, 'source_sha': source_sha,
             'phase': 'testing', 'current_group': key,
             'completed_groups': len(groups_by_id), 'total_groups': len(FEATURES)})
        report = output/(key+'.xml')
        log = output/(key+'.log')
        test_environment = dict(os.environ, HOL_GUARD_NATIVE='force',
                                HOL_GUARD_NATIVE_BINARY=str(source_runtime if key in SOURCE_MODE else runtime))
        test_environment.pop('HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER', None)
        if key in SOURCE_MODE:
            test_environment.pop('HOL_GUARD_TEST_USE_INSTALLED', None)
            test_environment['PYTHONPATH'] = str(source/'src')
            if key == 'native_runtime':
                test_environment['HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER'] = str(source_compiler)
        else:
            test_environment['HOL_GUARD_TEST_USE_INSTALLED'] = '1'
            test_environment.pop('PYTHONPATH', None)
        command = ['uv', 'run', '--no-sync', 'python', '-B', '-m', 'pytest',
                   '-q', '-o', 'addopts=', '--junitxml='+str(report), *tests]
        started = time.monotonic()
        with log.open('x') as stream:
            try:
                process = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                         check=False, timeout=600, env=test_environment)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                exit_code = 124
        try:
            counts = junit(report)
            status = ('invalid-evidence' if counts['tests'] == 0 else
                      'failed' if counts['failures'] or counts['errors'] or exit_code else
                      'incomplete' if counts['skipped'] else 'passed')
        except (OSError, ValueError, ET.ParseError):
            counts, status = None, 'invalid-evidence'
        groups_by_id[key] = {'id': key, 'label': label, 'status': status, 'tests': list(tests),
                             'evidence_kind': ('source-native-contract' if key in SOURCE_MODE
                                               else 'installed-product-contract'),
                             'counts': counts, 'exit_code': exit_code,
                             'elapsed_seconds': round(time.monotonic()-started, 3),
                             'junit_sha256': sha(report) if report.is_file() else None,
                             'log_sha256': sha(log)}
    groups = [groups_by_id[key] for key, _label, _tests in FEATURES]
    result = {'schema': 'hol-gauntlet-feature-contracts.v1', 'audit_id': audit_id,
              'source_sha': source_sha, 'version': record['version'],
              'wheel_sha256': record['wheel_sha256'], 'native_sha256': record['native_sha256'],
              'node_version': node_version,
              'evidence_kind': 'mixed-source-installed-contract',
              'status': 'passed' if all(row['status'] == 'passed' for row in groups) else 'failed',
              'groups': groups, 'model_requests': 0, 'model_tokens': 0,
              'qualification_eligible': False}
    save(output/'contracts.json', result)
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(run())
