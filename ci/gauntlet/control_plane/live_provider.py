"""Start a fresh, quota-bound local Qwen provider for one live Gauntlet job.

Run with the trusted host checkout and a pinned cryptography environment. The
existing model bytes and lifetime quota journal are reused without resetting them.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import urllib.request

from ci.gauntlet.benchmark.provider_quota import ProviderQuota

PROJECT = Path(__file__).resolve().parents[4]
CAPSULE = PROJECT/'local-model-capsule-20261013'
TEMPLATE = PROJECT/'local-model-provider-20261016-beta-003'
TEMPLATE_SHA = 'f95dde32317bb5a2c09a2295c51524126c8c81ee4c16618a1b2a27ccfa8c8244'
MODEL_ID = 'mlx-community/Qwen3.6-35B-A3B-8bit'
ALLOWANCE = PROJECT/'local-evidence-20261014/lifetime-quota-authorization-14468885-001.json'
ALLOWANCE_SHA = '269508fcb01074d6bb07ef20505e90bc863fc85fca65a3a930ab93a8c23e2b28'
ALLOWANCE_START = 9_468_885
CEILING = 14_468_885
RESERVATIONS = {'beta-e2e': 1_200_000, 'feature-ai': 200_000,
                'feature-ai-protocol': 200_000}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_new(path, value, *, mode=0o600):
    with Path(path).open('xb') as stream:
        stream.write(canonical(value) + b'\n')
    Path(path).chmod(mode)


def inventory(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if '__pycache__' in path.parts or path.suffix == '.pyc':
            continue
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[name] = {'symlink': os.readlink(path)}
        elif path.is_file():
            info = path.stat()
            result[name] = {'sha256': sha(path), 'bytes': info.st_size,
                            'mode': info.st_mode & 0o777}
    return result


def get_json(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=10) as response:
        if response.status != 200 or int(response.headers.get('Content-Length', '0')) > 65536:
            raise ValueError('owned model endpoint returned an invalid response')
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError('owned model endpoint response exceeds bound')
    return json.loads(raw)


def start(job_id, profile, candidate_source_sha):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if re.fullmatch(r'[0-9a-f]{16}', job_id) is None:
        raise ValueError('fixed live job identity required')
    if (not isinstance(candidate_source_sha, str)
            or re.fullmatch(r'[0-9a-f]{40}', candidate_source_sha) is None
            or candidate_source_sha != 'c1d18f931eaba02a37a2c9515db769fc2219bee8'):
        raise ValueError('candidate source identity differs from local model allowance')
    if profile not in RESERVATIONS:
        raise ValueError('reviewed live profile required')
    reservation = RESERVATIONS[profile]
    if sha(TEMPLATE/'binding.json') != TEMPLATE_SHA:
        raise ValueError('reviewed provider template changed')
    if sha(ALLOWANCE) != ALLOWANCE_SHA:
        raise ValueError('local model allowance authorization changed')
    allowance = json.loads(ALLOWANCE.read_bytes())
    if (allowance.get('schema') != 'gauntlet-local-allowance-authorization.v1'
            or allowance.get('previous_charged_tokens') != ALLOWANCE_START
            or allowance.get('additional_tokens') != 5_000_000
            or allowance.get('total_tokens') != CEILING
            or allowance.get('candidate_source_sha') !=
               'c1d18f931eaba02a37a2c9515db769fc2219bee8'):
        raise ValueError('local model allowance authorization differs from this candidate')
    previous = json.loads((TEMPLATE/'binding.json').read_bytes())
    quota = ProviderQuota(Path(previous['quota_root']),
        expected_config_digest=previous['quota_config_digest'],
        expected_allowance_digest=ALLOWANCE_SHA)
    before = quota.snapshot()
    if (before['known_tokens'] != before['charged_tokens'] or before['halted']
            or before['pending_requests'] or before['reserved_tokens']
            or before['token_cap'] != CEILING
            or before['known_tokens'] + reservation > CEILING
            or before['known_tokens'] < ALLOWANCE_START):
        raise ValueError('complete selected matrix reservation does not fit settled quota')
    # An existing listener might be an operator-owned service; never replace it.
    try:
        with socket.create_connection(('127.0.0.1', 8002), timeout=1):
            raise ValueError('port 8002 already has a service')
    except OSError:
        pass

    root = PROJECT/('local-model-provider-gauntlet-' + job_id)
    root.mkdir(mode=0o700)
    authorization = {
        'schema': 'gauntlet-live-inference-authorization.v1',
        'user_request': 'Use a local mounted model to do actual model inference and testing, GLM 5.3 or Qwen 3.6',
        'model_id': MODEL_ID, 'job_id': job_id, 'profile': profile,
        'candidate_source_sha': candidate_source_sha,
        'scope': ('One source-bound twelve-cell beta E2E run' if profile == 'beta-e2e'
                  else 'One source-bound two-cell MCP feature AI probe')
                 + '; retained failures; no automatic inference retry',
        'previous_maximum_accounted_tokens': 9_600_000,
        'maximum_accounted_tokens': CEILING, 'lifetime_token_cap': before['token_cap'],
        'allowance_authorization_sha256': ALLOWANCE_SHA,
        'known_tokens_before': before['known_tokens'], 'planned_tokens': reservation,
    }
    write_new(root/'authorization.json', authorization)
    for name, expected in previous['code_files'].items():
        source = TEMPLATE/'provider-code'/name
        if sha(source) != expected:
            raise ValueError('trusted provider source changed: ' + name)
        target = root/'provider-code'/name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(source.read_bytes())
        target.chmod(0o444)
    source = TEMPLATE/'serve_model_v9.py'
    if sha(source) != previous['launcher_sha256']:
        raise ValueError('reviewed model launcher changed')
    with (root/'serve_model_v9.py').open('xb') as stream:
        stream.write(source.read_bytes())
    (root/'serve_model_v9.py').chmod(0o444)
    binding = dict(previous)
    binding.update(previous_binding_sha256=TEMPLATE_SHA,
        candidate_source_sha=candidate_source_sha,
        job_id=job_id, profile=profile,
        lifetime_token_cap=CEILING,
        lifetime_authorization_record_sha256=ALLOWANCE_SHA,
        quota_allowance_digest=ALLOWANCE_SHA,
        maximum_accounted_tokens=CEILING,
        milestone_start_tokens=ALLOWANCE_START,
        milestone_additional_tokens=5_000_000,
        milestone_authorization_sha256=sha(root/'authorization.json'),
        milestone_extension_authorization_sha256=ALLOWANCE_SHA,
        preparer_sha256=sha(Path(__file__)))
    write_new(root/'binding.json', binding, mode=0o444)
    for name in ('state', 'pycache', 'startup'):
        (root/name).mkdir(mode=0o700)

    run = root/'startup'
    python = CAPSULE/'.venv/bin/python'
    base_python = python.resolve().parent.parent
    if not base_python.name.startswith('cpython-3.11.15-'):
        raise ValueError('pinned MLX Python distribution changed')
    runtime = {'venv': inventory(CAPSULE/'.venv'),
               'python_distribution': inventory(base_python)}
    write_new(run/'runtime-inputs.json', runtime)
    args = [str(python), '-I', '-B', '-X', 'pycache_prefix=' + str(root/'pycache'),
        str(root/'serve_model_v9.py'), '--model', str(CAPSULE/'model'),
        '--host', '127.0.0.1', '--port', '8002', '--temp', '0', '--top-p', '1',
        '--top-k', '0', '--min-p', '0', '--max-tokens', '4096',
        '--prompt-concurrency', '1', '--decode-concurrency', '1',
        '--prompt-cache-size', '1', '--prompt-cache-bytes', '2GB',
        '--prefill-step-size', '1024',
        '--chat-template-args', '{"enable_thinking":false,"preserve_thinking":true}']
    environment = {'HOME': str(root/'state'), 'PATH': '/usr/bin:/bin',
        'HF_HOME': str(root/'state/huggingface'), 'HF_HUB_OFFLINE': '1',
        'TRANSFORMERS_OFFLINE': '1', 'TOKENIZERS_PARALLELISM': 'false',
        'HOL_BENCHMARK_PROVIDER_BINDING_SHA': sha(root/'binding.json')}
    config = {'schema': 'owned-model-provider-config.v2', 'model_id': MODEL_ID,
        'command': args, 'environment': environment,
        'weights_manifest_sha256': sha(CAPSULE/'verified-clone.json'),
        'runtime_inputs_sha256': sha(run/'runtime-inputs.json'),
        'requirements_lock_sha256': sha(CAPSULE/'requirements.lock'),
        'launcher_sha256': sha(root/'serve_model_v9.py'),
        'controller_sha256': sha(Path(__file__)),
        'memory_limit_bytes': 64*1024**3, 'wired_limit_bytes': 48*1024**3,
        'cache_limit_bytes': 2*1024**3, 'initial_mlx_seed': 0,
        'bytecode_policy': 'disabled; private pycache prefix',
        'chat_template_defaults': {'enable_thinking': False, 'preserve_thinking': True},
        'request_template_policy': 'exact boolean subset; no rewriting',
        'binding_sha256': sha(root/'binding.json'),
        'quota_config_digest': binding['quota_config_digest'],
        'model_identity_digest': binding['model_identity_digest'],
        'goal_token_cap': before['token_cap'],
        'quota_allowance_digest': binding['quota_allowance_digest'],
        'tool_formatter_compat': binding['tool_formatter_compat'],
        'qualification': False}
    key = Ed25519PrivateKey.generate()
    anchor = {'schema': 'owned-model-provider-anchor.v1',
        'public_key': base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        'config_sha256': hashlib.sha256(canonical(config)).hexdigest(),
        'qualification': False}
    write_new(run/'config.json', config)
    write_new(run/'public-anchor-before.json', anchor)
    process = None
    record = {'config_sha256': anchor['config_sha256'],
              'binding_sha256': config['binding_sha256'],
              'candidate_source_sha': candidate_source_sha,
              'job_id': job_id, 'profile': profile,
              'started': False, 'qualification': False}
    try:
        with (run/'stdout.txt').open('xb') as output, (run/'stderr.txt').open('xb') as errors:
            process = subprocess.Popen(args, env=environment, cwd=root,
                stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                start_new_session=True)
        record['pid'] = process.pid
        deadline = time.monotonic() + 240
        loaded = None
        while time.monotonic() < deadline and process.poll() is None:
            for line in (run/'stdout.txt').read_text().splitlines():
                if not line.startswith('{'):
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if row.get('schema') == 'owned-model-loaded.v1':
                    loaded = row
            if loaded:
                break
            time.sleep(0.5)
        if not loaded or process.poll() is not None:
            raise RuntimeError('owned model did not complete verified startup')
        if (loaded['pid'] != process.pid
                or loaded['input_manifest_sha256'] != config['weights_manifest_sha256']
                or loaded['weights_verified_before_and_after_load'] is not True):
            raise ValueError('loaded model identity differs')
        models = get_json('http://127.0.0.1:8002/v1/models')
        status = get_json('http://127.0.0.1:8002/v1/benchmark-quota')
        if ([row['id'] for row in models['data']] != [MODEL_ID]
                or status['binding_sha256'] != config['binding_sha256']
                or status['quota'] != before
                or status['adapter']['quota_allowance_digest'] != binding['quota_allowance_digest']):
            raise ValueError('local provider identity or quota differs after startup')
        lines = [json.loads(line) for line in (run/'stdout.txt').read_text().splitlines()
                 if line.startswith('{')]
        formatter = [r for r in lines if r.get('schema') == 'owned-tool-formatter-compat-installed.v1']
        parser = [r for r in lines if r.get('schema') == 'owned-nullable-parser-ready.v1']
        if (len(formatter) != 1 or formatter[0]['compat'] != binding['tool_formatter_compat']
                or len(parser) != 1
                or parser[0]['parser_sha256'] != binding['tool_formatter_compat']['parser_sha256']):
            raise ValueError('reviewed tool parser/formatter was not installed')
        if (inventory(CAPSULE/'.venv') != runtime['venv']
                or inventory(base_python) != runtime['python_distribution']):
            raise ValueError('MLX runtime changed during startup')
        identity = subprocess.run(['ps', '-ww', '-p', str(process.pid), '-o', 'pid=,lstart=,args='],
            check=True, capture_output=True, text=True).stdout.strip()
        record.update(started=True, loaded=loaded, models=models,
            process_identity=identity, quota_before_any_control=status,
            nullable_parser_ready=parser[0], tool_formatter_compat=formatter[0],
            runtime_inputs_unchanged=True, operator_server_modified=False)
    except Exception as error:
        record['error'] = f'{type(error).__name__}: {error}'
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        raise
    finally:
        signed = {'record': record,
            'signature': base64.b64encode(key.sign(canonical(record))).decode()}
        write_new(run/'signed-result.json', signed)
    write_new(root/'provider-manifest.json',
        {'anchor': anchor, 'binding': binding, 'signed_result': signed}, mode=0o444)
    write_new(root/'model-manifest.json',
        {'loaded': loaded, 'model_identity': binding['model_identity'],
         'model_identity_digest': binding['model_identity_digest'],
         'qualification': False}, mode=0o444)
    return {'root': str(root), 'provider_manifest': str(root/'provider-manifest.json'),
        'provider_sha256': sha(root/'provider-manifest.json'),
        'model_manifest': str(root/'model-manifest.json'),
        'model_sha256': sha(root/'model-manifest.json'),
        'binding_sha256': config['binding_sha256'],
        'model_id': MODEL_ID, 'pid': process.pid,
        'known_tokens_before': before['known_tokens'], 'maximum_accounted_tokens': CEILING}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('job_id')
    parser.add_argument('profile', choices=tuple(RESERVATIONS))
    parser.add_argument('candidate_source_sha')
    args = parser.parse_args()
    print(json.dumps(start(args.job_id, args.profile, args.candidate_source_sha), sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
