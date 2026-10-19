"""Root supplies only the actual public task to the namespace-only normal hook."""
from __future__ import annotations

import base64
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import canonical_json, digest, strict_json_loads
from .native_builtin_plane import decode_hook_response
from .native_product_container import verify_product_boundary
from .normal_hook_invoker import NormalHookInvoker


def prepare_task_context(frontdoor, prompt, *, controller_key, phase):
    invoker = NormalHookInvoker(frontdoor.product_plane,
        controller_session_id='gauntlet-mcp-' + uuid.uuid4().hex)
    response = invoker.prepare_user_prompt(prompt)
    record = {**invoker.observation(), 'phase': phase, 'public_prompt': prompt}
    envelope = {'record': record, 'signature': base64.b64encode(
        controller_key.sign(canonical_json(record).encode())).decode()}
    return envelope, response['decision'] == 'allow'


def verify_task_contexts(report, *, attempt_path, trusted_public_key, controller, product, agents):
    rows = report.get('native_task_contexts', [])
    phases = ('preparation', 'continuation') if report.get('group') == 'approval' else ('episode',)
    if report['execution_valid'] and len(rows) != len(phases):
        raise ValueError('valid product workflow lacks its normal public task contexts')
    if len(rows) > len(phases):
        raise ValueError('duplicate product public task contexts')
    key = Ed25519PublicKey.from_public_bytes(trusted_public_key)
    for index, envelope in enumerate(rows):
        if set(envelope) != {'record', 'signature'}:
            raise ValueError('invalid public task context envelope')
        record = envelope['record']
        key.verify(base64.b64decode(envelope['signature'], validate=True), canonical_json(record).encode())
        phase = phases[index]
        if (record['kind'] != 'isolated-normal-prompt-hook-observation' or record['phase'] != phase
                or record['product_claims_authenticated'] is not False
                or record['qualification_eligible'] is not False or len(record['hooks']) != 1):
            raise ValueError('invalid product public task context observation')
        prompt = record['public_prompt']
        if not isinstance(prompt, str) or not prompt or len(prompt.encode()) > 1024 * 1024:
            raise ValueError('invalid bounded public task context prompt')
        if record['public_prompt_digest'] != digest(prompt):
            raise ValueError('public task context prompt digest mismatch')
        path = (attempt_path / 'public-episode.json' if phase == 'episode' else
                attempt_path / phase / 'public' / 'episode.json')
        if path.is_file():
            prompt = strict_json_loads(path.read_bytes())['prompt']
            if record['public_prompt_digest'] != digest(prompt):
                raise ValueError('product task context differs from actual public harness prompt')
        elif report['execution_valid']:
            raise ValueError('actual public task context configuration absent')
        hook = record['hooks'][0]
        payload = {'hook_event_name': 'UserPromptSubmit', 'prompt': prompt,
            'config_path': '/product/public/mcp.json', 'session_id': record['controller_session_id']}
        if (hook['sequence'] != 1 or hook['payload_digest'] != digest(payload)
                or type(hook['product_pid']) is not int or hook['product_pid'] <= 0
                or type(hook['host_exec_pid']) is not int or hook['host_exec_pid'] <= 0):
            raise ValueError('actual public task hook payload/process binding mismatch')
        verify_product_boundary(hook['identity'], controller)
        for field in ('boot_id', 'mount_namespace', 'pid_namespace', 'network_namespace'):
            if hook['identity'][field] != product[field] or any(
                    field != 'boot_id' and agent and agent.get(field) == hook['identity'][field] for agent in agents):
                raise ValueError('public task hook was outside the product namespace boundary')
        response = hook['response']
        raw = hook['raw_response']
        if (hook['raw_response_digest'] != digest(raw) or
                decode_hook_response(canonical_json(raw).encode(), returncode=hook['returncode'],
                                     event='UserPromptSubmit') != response):
            raise ValueError('actual normal prompt response normalization mismatch')
        if hook['response_digest'] != digest(response) or response['decision'] not in {'allow', 'deny', 'block'}:
            raise ValueError('invalid actual normal public task hook response')
        if response['decision'] == 'allow' and hook['returncode'] != 0:
            raise ValueError('nonzero native task hook cannot allow execution')
        if report['execution_valid'] and response['decision'] != 'allow':
            raise ValueError('model execution followed an actual native task denial')
