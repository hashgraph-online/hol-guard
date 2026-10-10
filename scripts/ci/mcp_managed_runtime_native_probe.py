"""Exercise managed inventory with an installed native package, in isolation."""

import hashlib

import json

import os

import shutil

import secrets

import select

import subprocess

import sys

import sysconfig

import time

import zipfile

from dataclasses import replace

from pathlib import Path



if '--fixture-server' in sys.argv:

    Path('/lab/home/fixture-started').touch()

    for line in sys.stdin:

        request = json.loads(line)

        if 'id' not in request:

            continue

        response = {'jsonrpc': '2.0', 'id': request['id']}

        if request['method'] == 'initialize':

            response['result'] = {'protocolVersion': '2025-11-25', 'capabilities': {'tools': {}}, 'serverInfo': {'name': 'managed-inventory-fixture', 'version': '1'}}

        elif request['method'] == 'tools/list':

            response['result'] = {'tools': [

                {'name': name, 'description': name, 'inputSchema': {'type': 'object'}, 'annotations': {'readOnlyHint': name == 'read_record', 'destructiveHint': name == 'delete_record'}}

                for name in ('read_record', 'delete_record')

            ]}

        elif request['method'] == 'tools/call':

            name = request.get('params', {}).get('name')

            assert name in ('read_record', 'delete_record')

            with Path('/lab/fixture-executed-tools.jsonl').open('a') as calls:

                calls.write(json.dumps({'name':name}) + '\n')

            response['result'] = {'content':[{'type':'text','text':'fixture:' + name}], 'isError':False}

        else:

            response['error'] = {'code': -32601, 'message': 'Method not found'}

        print(json.dumps(response), flush=True)

    raise SystemExit(0)



if '--exercise' in sys.argv:

    from codex_plugin_scanner.guard.adapters.mcp_servers import ManagedMcpServer, proxy_cli_args

    from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService

    from codex_plugin_scanner.guard.native_runtime import native_runtime_status

    from codex_plugin_scanner.guard.store import GuardStore

    import codex_plugin_scanner



    assert codex_plugin_scanner.__file__.startswith('/lab/venv/')

    status = native_runtime_status()

    if os.environ.get('ARM64_NATIVE') == '1':

        assert status.mode == 'force' and status.available and status.compatible and status.reason == 'native_ready', status

    else:
        # amd64 native run: prove the native runtime reports ready; record the
        # wheel's own build_sha rather than asserting a specific source SHA
        # (the wheel release commit is not pinned to this branch).
        assert status.mode == 'auto' and status.available and status.compatible and status.reason == 'native_ready', status
        record_expected = os.environ.get('EXPECTED_SOURCE_SHA')
        if record_expected:
            assert status.capabilities.build_sha == record_expected, status.capabilities.build_sha

    home, guard = Path('/lab/home'), Path('/lab/guard')

    config = home / '.cursor/mcp.json'

    config.parent.mkdir()

    server = ManagedMcpServer(

        harness='cursor', name='managed-inventory-fixture', source_scope='global',

        config_path=str(config), command=sys.executable, args=('/runner.py', '--fixture-server'),

        transport='stdio', env={'FIXTURE_ACCOUNT': 'one'}, enabled=True,

    )

    for _ in range(2):

        args = proxy_cli_args(proxy_command='cursor-mcp-proxy', guard_home=str(guard), server=server)

        server = replace(server, command=sys.executable, args=tuple(args))

    config.write_text(json.dumps({'mcpServers': {server.name: {'command': server.command, 'args': server.args, 'env': server.env}}}))

    record = {

        'native': {'mode': status.mode, 'reason': status.reason, 'version': status.capabilities.runtime_version, 'source_sha': status.capabilities.build_sha},

        'production_profile_mounted': False, 'native_overrides': False, 'network': 'none',

        'scope': 'Installed package and real catalog probe; configured host fixture, not an actual Cursor application session',

        'python_candidate_overlay': json.loads(os.environ.get('PYTHON_CANDIDATE_OVERLAY', '{}')),

    }

    service = LocalCliApiService(store=GuardStore(guard))



    def finish(job):

        started = time.monotonic()

        while time.monotonic() - started < 45:

            value = service.refresh_job({'job_id': job['job_id']})

            if value['state'] in ('complete', 'failed', 'cancelled'):

                return {key: value.get(key) for key in ('state', 'error')}

            time.sleep(0.1)

        raise TimeoutError('Owned discovery job did not finish')



    try:

        record['configured_job'] = finish(service.refresh_job({'operation': 'configured-connections'}))

        assert record['configured_job']['state'] == 'complete'

        assert not (home / 'fixture-started').exists(), 'Configuration-only discovery launched a process'

        items = [item for item in service.list_items()['items'] if item.get('surface') == 'mcp']

        assert len(items) == 1

        item = items[0]

        record['observed_connection_name'] = item['name']

        record['refresh_job'] = finish(service.refresh_job({'cli_id': item['cli_id'], 'confirm_process_start': True}))

        assert record['refresh_job']['state'] == 'complete', 'Actual tool discovery failed'

        item = next(value for value in service.list_items()['items'] if value['cli_id'] == item['cli_id'])

        catalog = item['mcp_catalog']

        record['catalog'] = {key: catalog.get(key) for key in ('complete', 'reason', 'known_count')}

        record['tool_names'] = sorted(command['usage'] for command in item['commands'])

        assert catalog['complete'] is True and catalog['known_count'] == 2

        assert {'read_record', 'delete_record'} <= set(record['tool_names'])

        assert (home / 'fixture-started').exists()

        if os.environ.get('VERIFY_MCP_PERMISSIONS') == '1':

            from codex_plugin_scanner.guard.native_policy_snapshot import get_native_policy_snapshot_publisher

            from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store

            from codex_plugin_scanner.guard.native_resident_client import close_native_residents



            lab_env = dict(os.environ, HOL_GUARD_HOME=str(guard), HOME=str(home))

            password = secrets.token_urlsafe(24)

            enrolled = subprocess.run(['/lab/venv/bin/hol-guard', 'settings',

                'approval-password', 'enable',

                '--new-password=' + password, '--confirm-password=' + password,

                '--cooldown-seconds', '0', '--guard-home', str(guard), '--json'], env=lab_env, capture_output=True, text=True, timeout=30)

            record['lab_gate_enrollment'] = {'exit_code':enrolled.returncode,

                'error':enrolled.stderr.replace(password, '[lab-password]')[-1200:],

                'response':enrolled.stdout.replace(password, '[lab-password]')[-1200:]}

            if enrolled.returncode:

                print(json.dumps(record['lab_gate_enrollment']))

            assert enrolled.returncode == 0, 'Lab-only approval gate enrollment failed'

            record['debug_guard_tree'] = sorted(str(p.relative_to(guard)) for p in guard.rglob('*'))

            record['debug_home_guard_tree'] = sorted(str(p) for p in home.rglob('*'))

            gate_file = guard / 'approval-gate.json'

            record['debug_gate_file'] = {'exists': gate_file.is_file(),

                'store_guard_home': str(service._store.guard_home)}

            states = {'read_record':'allow', 'delete_record':'block'}

            payload = {key:item.get(key) for key in ('cli_id','identity_hash','name','kind','example_label','interpreter_name')}

            payload.update(state='allowed', previous_revision=service.list_items()['revision'],

                session_nonce=secrets.token_urlsafe(24), approval_password=password,

                commands=[{'command_id':command['command_id'],

                           'state':states.get(command['usage'], 'review')}

                          for command in item['commands']])

            preview = service.preview(payload)

            saved = service.apply(payload)

            assert saved['revision'] == preview['next_revision']

            publisher = get_native_policy_snapshot_publisher(service._store)

            process = None

            try:

                publisher.start()

                deadline = time.monotonic() + 60.0

                while not publisher.is_ready() and time.monotonic() < deadline:

                    publisher._publish_event.wait(timeout=1.0)

                assert publisher.is_ready(), publisher.last_error

                publication = service.list_items()['native_publication']

                assert publication['state'] == 'acknowledged' and publication['revision'] == saved['revision']

                actions = publisher._snapshot['effective_policy'].get('mcp_tool_actions', {})

                record['permission_publication'] = {'revision':saved['revision'], 'receipt':publication,

                    'native_actions':actions, 'real_approval_gate':True, 'credential_generated_in_lab':True}

                with Path('/output/proxy-stderr.log').open('w') as error_log:

                    process = subprocess.Popen([server.command, *server.args], env=dict(lab_env, **server.env),

                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error_log)

                    buffer = bytearray()

                    def rpc(method, request_id=None, params=None):

                        message = {'jsonrpc':'2.0','method':method}

                        if request_id is not None:

                            message['id'] = request_id

                        if params is not None:

                            message['params'] = params

                        process.stdin.write(json.dumps(message).encode() + b'\n')

                        process.stdin.flush()

                        if request_id is None:

                            return None

                        deadline = time.monotonic() + 35

                        while time.monotonic() < deadline:

                            while b'\n' in buffer:

                                line, _, remaining = buffer.partition(b'\n')

                                buffer[:] = remaining

                                response = json.loads(line)

                                if response.get('id') == request_id:

                                    return response

                                assert 'id' not in response, 'Unexpected request during an explicitly saved tool choice'

                            readable, _, _ = select.select([process.stdout], [], [], max(0, deadline-time.monotonic()))

                            if not readable:

                                break

                            chunk = os.read(process.stdout.fileno(), 65536)

                            assert chunk, 'Owned proxy closed without responding'

                            buffer.extend(chunk)

                            assert len(buffer) < 1024 * 1024

                        raise TimeoutError('Owned MCP permission call did not respond')

                    initialized = rpc('initialize', 1, {'protocolVersion':'2025-11-25',

                        'capabilities':{}, 'clientInfo':{'name':'isolated-permission-client','version':'1'}})

                    assert 'result' in initialized

                    rpc('notifications/initialized')

                    listed = rpc('tools/list', 2, {})

                    assert {tool['name'] for tool in listed['result']['tools']} == {'read_record','delete_record'}

                    read = rpc('tools/call', 3, {'name':'read_record','arguments':{}})

                    assert read.get('result', {}).get('isError') is not True and 'result' in read

                    denied = rpc('tools/call', 4, {'name':'delete_record','arguments':{}})

                    assert 'error' in denied or denied.get('result', {}).get('isError') is True

                    executed = [json.loads(line)['name'] for line in Path('/lab/fixture-executed-tools.jsonl').read_text().splitlines()]

                    assert executed == ['read_record'], 'A denied tool reached the upstream server'

                    record['actual_tool_calls'] = {'read_result':read, 'delete_result':denied,

                        'executed_upstream':executed, 'managed_proxy_layers':2,

                        'scope':'Real stdio client/proxies and native ACK; not an actual Cursor application or direct native tool-decision proof'}



                if os.environ.get('EXTENDED_SLICE') == '1':
                    # (b) publication-failure recovery on the same store: kill
                    # the resident, republish, and record whether it surfaces a
                    # failure or recovers to a fresh ACK. Runs before the
                    # reconnect probe so the restart budget is not already spent.
                    publisher.close()
                    assert close_native_residents(guard)
                    pub2 = get_native_policy_snapshot_publisher(service._store)
                    pub2.start()
                    try:
                        t0 = time.monotonic()
                        baseline = False
                        while time.monotonic() - t0 < 30:
                            if pub2.is_ready() or pub2.last_error:
                                baseline = pub2.is_ready()
                                break
                            pub2._publish_event.wait(timeout=0.5)
                        record['republication_baseline_ready'] = baseline
                        record['republication_baseline_error'] = pub2.last_error
                        assert close_native_residents(guard)
                        pub2.request_publish()
                        t0 = time.monotonic()
                        recovered = False
                        while time.monotonic() - t0 < 30:
                            if pub2.is_ready():
                                publication = service.list_items()['native_publication']
                                recovered = publication['state'] == 'acknowledged'
                                record['republication_ack'] = publication
                                break
                            if pub2.last_error:
                                record['republication_error'] = pub2.last_error
                                break
                            pub2._publish_event.wait(timeout=0.5)
                        record['republication_recovered'] = recovered
                    finally:
                        pub2.close()

                    # (c) Ask semantics: re-apply the payload with delete_record
                    # command state 'review' (the Ask/Review option), republish,
                    # and expect a review outcome distinct from the hard-deny
                    # path. Same store; revision/nonce refreshed.
                    ask_payload = dict(payload)
                    ask_commands = [dict(command) for command in payload['commands']]
                    for command in ask_commands:
                        if 'delete_record' in command['command_id']:
                            command['state'] = 'review'
                    ask_payload['commands'] = ask_commands
                    ask_payload['previous_revision'] = service.list_items()['revision']
                    ask_payload['session_nonce'] = secrets.token_urlsafe(24)
                    applied_ask = service.apply(ask_payload)
                    record['ask_apply'] = applied_ask
                    pub3 = get_native_policy_snapshot_publisher(service._store)
                    pub3.start()
                    try:
                        t0 = time.monotonic()
                        while time.monotonic() - t0 < 30:
                            if pub3.is_ready() or pub3.last_error:
                                break
                            pub3._publish_event.wait(timeout=0.5)
                        record['ask_publication_ready'] = pub3.is_ready()
                        record['ask_publication_error'] = pub3.last_error
                    finally:
                        pub3.close()

                    ask_err = Path('/output/proxy-ask-stderr.log')
                    with ask_err.open('w') as e3:
                        p3 = subprocess.Popen([server.command, *server.args],
                            env=dict(lab_env, **server.env),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=e3)
                        buf3 = bytearray()
                        def rpc3(method, request_id=None, params=None):
                            message = {'jsonrpc':'2.0','method':method}
                            if request_id is not None:
                                message['id'] = request_id
                            if params is not None:
                                message['params'] = params
                            p3.stdin.write(json.dumps(message).encode() + b'\n'); p3.stdin.flush()
                            if request_id is None:
                                return None
                            dl = time.monotonic() + 35
                            while time.monotonic() < dl:
                                while b'\n' in buf3:
                                    line, _, rem = buf3.partition(b'\n'); buf3[:] = rem
                                    r = json.loads(line)
                                    if r.get('id') == request_id:
                                        return r
                                rd,_,_ = select.select([p3.stdout], [], [], max(0, dl-time.monotonic()))
                                if not rd:
                                    break
                                buf3.extend(os.read(p3.stdout.fileno(), 65536))
                            raise TimeoutError('ask rpc timeout')
                        try:
                            rpc3('initialize', 1, {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'ask','version':'1'}})
                            rpc3('notifications/initialized')
                            ask_call = rpc3('tools/call', 2, {'name':'delete_record','arguments':{}})
                            record['ask_semantics'] = {'delete_result': ask_call}
                        finally:
                            p3.stdin.close()
                            try: p3.wait(timeout=15)
                            except subprocess.TimeoutExpired:
                                p3.terminate(); p3.wait(timeout=15)

                    # (a) reconnect survival: a fresh proxy process must re-apply
                    # the published policy without republish. Runs last — each
                    # new session triggers a spawn attempt that can consume
                    # restart budget.
                    rec2_err = Path('/output/proxy-reconnect-stderr.log')
                    with rec2_err.open('w') as e2:
                        p2 = subprocess.Popen([server.command, *server.args], env=dict(lab_env, **server.env),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=e2)
                        buf2 = bytearray()
                        def rpc2(method, request_id=None, params=None):
                            message = {'jsonrpc':'2.0','method':method}
                            if request_id is not None:
                                message['id'] = request_id
                            if params is not None:
                                message['params'] = params
                            p2.stdin.write(json.dumps(message).encode() + b'\n'); p2.stdin.flush()
                            if request_id is None:
                                return None
                            dl = time.monotonic() + 35
                            while time.monotonic() < dl:
                                while b'\n' in buf2:
                                    line, _, rem = buf2.partition(b'\n'); buf2[:] = rem
                                    r = json.loads(line)
                                    if r.get('id') == request_id:
                                        return r
                                rd,_,_ = select.select([p2.stdout], [], [], max(0, dl-time.monotonic()))
                                if not rd:
                                    break
                                buf2.extend(os.read(p2.stdout.fileno(), 65536))
                            raise TimeoutError('reconnect rpc timeout')
                        try:
                            rpc2('initialize', 1, {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'reconnect','version':'1'}})
                            rpc2('notifications/initialized')
                            reread = rpc2('tools/call', 2, {'name':'read_record','arguments':{}})
                            redeny = rpc2('tools/call', 3, {'name':'delete_record','arguments':{}})
                            record['reconnect_survival'] = {'read_result': reread, 'delete_result': redeny}
                        finally:
                            p2.stdin.close()
                            try: p2.wait(timeout=15)
                            except subprocess.TimeoutExpired:
                                p2.terminate(); p2.wait(timeout=15)


                if os.environ.get('EXTENDED_SLICE_2') == '1':
                    # Restart-decay recovery + approve/retry + revision
                    # invalidation + scope rejection + native latency. One proxy
                    # session; the resident is kept alive after recovery ACK so
                    # subsequent sessions reuse it without burning budget.
                    publisher.close()
                    assert close_native_residents(guard)

                    pub4 = get_native_policy_snapshot_publisher(service._store)
                    pub4.start()
                    t0 = time.monotonic()
                    while time.monotonic() - t0 < 15:
                        if pub4.is_ready() or pub4.last_error:
                            break
                        pub4._publish_event.wait(timeout=0.5)
                    record['ext2_baseline_ready'] = pub4.is_ready()
                    record['ext2_baseline_error'] = pub4.last_error

                    # Recovery: the restart budget re-opens the circuit when you
                    # republish while attempts are spent inside the 60s window
                    # (each failed consume re-sets circuit_until_ms). The correct
                    # recipe is to wait >60s from window_start with NO publish
                    # attempts so the window rolls + attempts reset, then publish
                    # exactly once. Baseline confirm, 65s silent wait, one publish.
                    record['ext2_recovery_wait_s'] = 65
                    time.sleep(65)
                    pub4.request_publish()
                    recovered = False
                    record['ext2_recovery_error'] = None
                    record['ext2_recovery_saw_transient_error'] = False
                    t0 = time.monotonic()
                    # Poll the full window even through a transient last_error:
                    # the publisher's own bounded retry (_PUBLISH_RETRY_MAX_SECONDS)
                    # is a legitimate recovery path, but the direct-attempt error
                    # is still recorded so transient-vs-persistent is visible.
                    while time.monotonic() - t0 < 45:
                        if pub4.is_ready():
                            publication = service.list_items()['native_publication']
                            recovered = publication['state'] == 'acknowledged'
                            record['ext2_recovery_ack'] = publication
                            break
                        if pub4.last_error:
                            record['ext2_recovery_saw_transient_error'] = True
                            record['ext2_recovery_error'] = pub4.last_error
                        pub4._publish_event.wait(timeout=0.5)
                    record['ext2_republication_recovered'] = recovered
                    # Gate the probe on recovery: a healthy amd64 native host must
                    # re-acknowledge after teardown + restart-budget window. The
                    # outer finally still writes managed-runtime.json on failure.
                    assert recovered, f"managed resident did not recover: {record.get('ext2_recovery_error')}"

                    # Introspect the recovery attempt: did a serve-managed spawn and
                    # did it reach publish_state (resident-state*.json), or did the
                    # Python stream client just time out on a live-but-stalled
                    # resident? arm64 native -> strace/comm are reliable.
                    intro = {}
                    try:
                        comms = subprocess.run(
                            ['sh','-c','for f in /proc/[0-9]*/comm; do echo "$f=$(cat $f)"; done'],
                            capture_output=True, text=True, timeout=10).stdout
                        intro['resident_comm'] = [l for l in comms.splitlines()
                            if 'serve' in l or 'resident' in l or 'managed' in l or 'guard' in l]
                    except Exception as e:
                        intro['resident_comm_error'] = repr(e)
                    try:
                        scope_dirs = sorted(Path(guard).glob('native-runtime/resident-v3-*'))
                        intro['scope_dirs'] = [d.name for d in scope_dirs]
                        intro['state_files'] = [str(p.relative_to(guard))
                            for d in scope_dirs for p in d.glob('**/resident-state*.json')]
                        intro['budget_file'] = None
                        for d in scope_dirs:
                            bf = d / 'restart-budget.json'
                            if bf.exists():
                                intro['budget_file'] = bf.read_text()[:400]
                    except Exception as e:
                        intro['scope_error'] = repr(e)
                    record['ext2_recovery_introspect'] = intro

                    import re as _re
                    import shutil as _sh
                    if not _sh.which('strace'):
                        intro['strace_error'] = 'strace not on PATH'
                    # Capture wchan (kernel wait reason — instant stall site) +
                    # the resident's open fds + a short strace window.
                    try:
                        intro['wchan'] = {}
                        for entry in intro.get('resident_comm', []):
                            mm = _re.match(r'/proc/(\d+)/comm', entry)
                            if mm:
                                pid = mm.group(1)
                                intro['wchan'][pid] = {
                                    'wchan': Path(f'/proc/{pid}/wchan').read_text().strip() if Path(f'/proc/{pid}/wchan').exists() else None,
                                    'status': [l for l in Path(f'/proc/{pid}/status').read_text().splitlines() if l.startswith(('State','Name'))] if Path(f'/proc/{pid}/status').exists() else None,
                                }
                    except Exception as e:
                        intro['wchan_error'] = repr(e)
                    try:
                        pids = []
                        for entry in intro.get('resident_comm', []):
                            m = _re.match(r'/proc/(\d+)/comm', entry)
                            if m:
                                pids.append(int(m.group(1)))
                        if pids:
                            target_pid = min(pids)
                            st = subprocess.run(
                                ['strace','-f','-tt','-e','trace=%all','-s','128','-p',str(target_pid),'-o','/tmp/recovery.strace'],
                                capture_output=True, text=True, timeout=5)
                            intro['strace_rc'] = st.returncode
                            intro['strace_stderr'] = st.stderr[-400:]
                            try:
                                intro['strace_tail'] = Path('/tmp/recovery.strace').read_text().splitlines()[-40:]
                            except Exception as e:
                                intro['strace_read_error'] = repr(e)
                    except Exception as e:
                        intro['strace_error'] = repr(e)
                    record['ext2_recovery_introspect'] = intro

                    # Re-apply delete_record -> review (Ask) on the same store so
                    # the live resident serves a review action, not block.
                    ask2_payload = dict(payload)
                    ask2_commands = [dict(command) for command in payload['commands']]
                    for command in ask2_commands:
                        if 'delete_record' in command['command_id']:
                            command['state'] = 'review'
                    ask2_payload['commands'] = ask2_commands
                    ask2_payload['previous_revision'] = service.list_items()['revision']
                    ask2_payload['session_nonce'] = secrets.token_urlsafe(24)
                    applied2 = service.apply(ask2_payload)
                    record['ext2_ask_apply'] = {'revision': applied2.get('revision')}
                    pub4.request_publish()
                    t0 = time.monotonic()
                    while time.monotonic() - t0 < 30:
                        if pub4.is_ready() or pub4.last_error:
                            break
                        pub4._publish_event.wait(timeout=0.5)
                    record['ext2_ask_publication_ready'] = pub4.is_ready()
                    record['ext2_ask_publication_error'] = pub4.last_error

                    ext2_err = Path('/output/proxy-ext2-stderr.log')
                    with ext2_err.open('w') as e4:
                        p4 = subprocess.Popen([server.command, *server.args],
                            env=dict(lab_env, **server.env),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=e4)
                        buf4 = bytearray()
                        def rpc4(method, request_id=None, params=None):
                            message = {'jsonrpc':'2.0','method':method}
                            if request_id is not None:
                                message['id'] = request_id
                            if params is not None:
                                message['params'] = params
                            p4.stdin.write(json.dumps(message).encode() + b'\n'); p4.stdin.flush()
                            if request_id is None:
                                return None
                            dl = time.monotonic() + 35
                            while time.monotonic() < dl:
                                while b'\n' in buf4:
                                    line, _, rem = buf4.partition(b'\n'); buf4[:] = rem
                                    r = json.loads(line)
                                    if r.get('id') == request_id:
                                        return r
                                rd,_,_ = select.select([p4.stdout], [], [], max(0, dl-time.monotonic()))
                                if not rd:
                                    break
                                buf4.extend(os.read(p4.stdout.fileno(), 65536))
                            raise TimeoutError('ext2 rpc timeout')
                        def approve(request_id, *extra):
                            # approvals approve is TTY-gated by design (only
                            # prompt_for_approval_gate; no env credential). Drive
                            # the real interactive prompt via a pseudo-terminal.
                            import pty
                            cmd = ['/lab/venv/bin/hol-guard', 'approvals', 'approve',
                                   request_id, '--guard-home', str(guard), '--home', str(home),
                                   '--json'] + list(extra)
                            output = bytearray()
                            # pty.spawn gives no stdin write hook; fork/exec so we
                            # can feed the password to the prompt on the PTY.
                            pid, mfd = pty.fork()
                            if pid == 0:
                                os.execvpe(cmd[0], cmd, lab_env)
                                os._exit(127)
                            output = bytearray()
                            deadline = time.monotonic() + 40
                            sent = False
                            rc = None
                            while time.monotonic() < deadline:
                                rd,_,_ = select.select([mfd], [], [], 0.3)
                                if rd:
                                    try:
                                        chunk = os.read(mfd, 65536)
                                    except OSError:
                                        chunk = b''
                                    if not chunk:
                                        # PTY EOF does not guarantee the child exited;
                                        # reap with a bounded WNOHANG poll so a stalled
                                        # child cannot hang the probe. If it is still
                                        # alive, rc stays None and the deadline path
                                        # below terminates it.
                                        eof_deadline = time.monotonic() + 5
                                        while time.monotonic() < eof_deadline:
                                            wpid, status = os.waitpid(pid, os.WNOHANG)
                                            if wpid == pid:
                                                rc = os.waitstatus_to_exitcode(status)
                                                break
                                            time.sleep(0.05)
                                        break
                                    output += chunk
                                    low = bytes(output).lower()
                                    if not sent and (b'password' in low or b'passphrase' in low):
                                        os.write(mfd, password.encode() + b'\n')
                                        sent = True
                                wpid, status = os.waitpid(pid, os.WNOHANG)
                                if wpid == pid:
                                    rc = os.waitstatus_to_exitcode(status)
                                    break
                            if rc is None:
                                # Deadline hit: don't block on a stalled PTY child.
                                # SIGTERM first so the child flushes logs; escalate to
                                # SIGKILL only if it ignores the term within 2s.
                                try:
                                    os.kill(pid, 15)
                                    term_deadline = time.monotonic() + 2
                                    while time.monotonic() < term_deadline:
                                        wpid, status = os.waitpid(pid, os.WNOHANG)
                                        if wpid == pid:
                                            rc = os.waitstatus_to_exitcode(status)
                                            break
                                        time.sleep(0.05)
                                    if rc is None:
                                        os.kill(pid, 9)
                                        _, status = os.waitpid(pid, 0)
                                        rc = os.waitstatus_to_exitcode(status)
                                except Exception:
                                    rc = -1
                                output += b'[approve-timeout-killed]'
                            try:
                                os.close(mfd)
                            except OSError:
                                pass
                            text = bytes(output).decode('utf-8','replace').replace(password,'[lab-password]')
                            return {'exit_code': rc, 'stdout': text[:1200], 'stderr': ''}
                        def cli(args):
                            env = dict(lab_env, HOL_GUARD_DESKTOP='1',
                                       HOL_GUARD_APPROVAL_PASSWORD=password)
                            out = subprocess.run(['/lab/venv/bin/hol-guard'] + list(args) +
                                ['--guard-home', str(guard), '--home', str(home), '--json'],
                                env=env, capture_output=True, text=True, timeout=30)
                            return {'exit_code': out.returncode, 'stdout': out.stdout[:1200],
                                'stderr': out.stderr.replace(password,'[lab-password]')[:800]}
                        try:
                            rpc4('initialize', 1, {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'ext2','version':'1'}})
                            rpc4('notifications/initialized')

                            # Latency: timed allowed calls on the live native path.
                            lat = []
                            for _ in range(15):
                                ts = time.monotonic()
                                rpc4('tools/call', 50+len(lat), {'name':'read_record','arguments':{}})
                                lat.append(round((time.monotonic()-ts)*1000, 3))
                            lat_sorted = sorted(lat)
                            record['ext2_latency_ms'] = {'samples': lat,
                                'p50': lat_sorted[len(lat_sorted)//2],
                                'p95': lat_sorted[int(len(lat_sorted)*0.95)-1],
                                'min': lat_sorted[0], 'max': lat_sorted[-1]}

                            # Ask: review action -> -32001 approval request R1.
                            d1 = rpc4('tools/call', 100, {'name':'delete_record','arguments':{}})
                            req1 = None
                            try:
                                req1 = d1['error']['data']['approvalRequests'][0]['request_id']
                            except Exception:
                                pass
                            record['ext2_review_first'] = {'delete_result': d1, 'request_id': req1}

                            if req1:
                                record['ext2_approve_artifact'] = approve(req1, '--scope', 'artifact')
                                assert record['ext2_approve_artifact']['exit_code'] == 0, \
                                    f"approve failed: {record['ext2_approve_artifact']}"
                                retry = rpc4('tools/call', 101, {'name':'delete_record','arguments':{}})
                                retry2 = rpc4('tools/call', 102, {'name':'delete_record','arguments':{}})
                                record['ext2_retry_after_approve'] = {'retry': retry, 'retry2': retry2}

                            # Revision invalidation: bump revision, republish,
                            # then a new call must mint a fresh bound request.

                            # List pending requests before the revision bump so
                            # we can prove the stale request is invalidated.
                            record['ext2_pending_before_bump'] = cli(['approvals'])
                            bump = dict(ask2_payload)
                            bump['previous_revision'] = service.list_items()['revision']
                            bump['session_nonce'] = secrets.token_urlsafe(24)
                            applied3 = service.apply(bump)
                            pub4.request_publish()
                            t0 = time.monotonic()
                            while time.monotonic() - t0 < 30:
                                if pub4.is_ready() or pub4.last_error:
                                    break
                                pub4._publish_event.wait(timeout=0.5)
                            d3 = rpc4('tools/call', 103, {'name':'delete_record','arguments':{}})
                            req3 = None; reqs = []
                            try:
                                reqs = d3['error']['data']['approvalRequests']
                                req3 = reqs[0]['request_id']
                            except Exception:
                                pass
                            record['ext2_revision_invalidation'] = {
                                'new_revision': applied3.get('revision'),
                                'publication_ready': pub4.is_ready(),
                                'publication_error': pub4.last_error,
                                'delete_result': d3, 'fresh_request_id': req3,
                                'request_statuses': [r.get('display_status') for r in reqs],
                                'prior_request_retry_hint': (cli(['approvals','retry-hint',req1]) if req1 else None),
                                'pending_after_bump': cli(['approvals'])}

                            # D31: workspace scope is not in allowed_scopes -> the
                            # approve resolves req3 but flags it require-reapproval
                            # (recommended_scope artifact). It CONSUMES req3, so a
                            # fresh request is needed for the remember test.
                            if req3:
                                record['ext2_workspace_scope_reject'] = approve(req3, '--scope', 'workspace')
                            # The workspace call already resolved req3; mint a fresh
                            # request for the --remember artifact approve so the
                            # reconnect-remembered rule below is really exercised.
                            d4 = rpc4('tools/call', 104, {'name':'delete_record','arguments':{}})
                            req4 = None
                            try:
                                req4 = d4['error']['data']['approvalRequests'][0]['request_id']
                            except Exception:
                                pass
                            record['ext2_remember_request'] = {'delete_result': d4, 'request_id': req4}
                            assert req4, f"no fresh approval request for remember test: {d4}"
                            record['ext2_remember_artifact'] = approve(req4, '--scope', 'artifact', '--remember')
                            assert record['ext2_remember_artifact']['exit_code'] == 0, \
                                f"remember approve failed: {record['ext2_remember_artifact']}"
                        finally:
                            p4.stdin.close()
                            try: p4.wait(timeout=15)
                            except subprocess.TimeoutExpired:
                                p4.terminate(); p4.wait(timeout=15)

                    # Reconnect with a remembered artifact rule: a fresh session
                    # should auto-allow the granted action (legitimate carry).
                    rec3_err = Path('/output/proxy-ext2-reconnect-stderr.log')
                    with rec3_err.open('w') as e5:
                        p5 = subprocess.Popen([server.command, *server.args],
                            env=dict(lab_env, **server.env),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=e5)
                        buf5 = bytearray()
                        def rpc5(method, request_id=None, params=None):
                            message = {'jsonrpc':'2.0','method':method}
                            if request_id is not None:
                                message['id'] = request_id
                            if params is not None:
                                message['params'] = params
                            p5.stdin.write(json.dumps(message).encode() + b'\n'); p5.stdin.flush()
                            if request_id is None:
                                return None
                            dl = time.monotonic() + 35
                            while time.monotonic() < dl:
                                while b'\n' in buf5:
                                    line, _, rem = buf5.partition(b'\n'); buf5[:] = rem
                                    r = json.loads(line)
                                    if r.get('id') == request_id:
                                        return r
                                rd,_,_ = select.select([p5.stdout], [], [], max(0, dl-time.monotonic()))
                                if not rd:
                                    break
                                buf5.extend(os.read(p5.stdout.fileno(), 65536))
                            raise TimeoutError('ext2 reconnect rpc timeout')
                        try:
                            rpc5('initialize', 1, {'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'ext2-reconnect','version':'1'}})
                            rpc5('notifications/initialized')
                            regrant = rpc5('tools/call', 1, {'name':'delete_record','arguments':{}})
                            record['ext2_reconnect_after_remember'] = regrant
                        finally:
                            p5.stdin.close()
                            try: p5.wait(timeout=15)
                            except subprocess.TimeoutExpired:
                                p5.terminate(); p5.wait(timeout=15)
                    pub4.close()

            finally:

                if process is not None:

                    process.stdin.close()

                    try:

                        process.wait(timeout=15)

                    except subprocess.TimeoutExpired:

                        process.terminate()

                        process.wait(timeout=15)

                stopped = subprocess.run(['/lab/venv/bin/hol-guard','daemon','stop','--json',

                    '--guard-home',str(guard),'--home',str(home)], env=lab_env,

                    capture_output=True, text=True, timeout=30)

                record['owned_daemon_stop_exit_code'] = stopped.returncode

                publisher.close()

                assert close_native_residents(guard), 'Owned native residents did not close'

                record['owned_native_residents_closed'] = True

    finally:

        assert service.close_discovery(), 'Owned discovery service did not close'

        record['owned_discovery_closed'] = True

        Path('/output/managed-runtime.json').write_text(json.dumps(record, indent=2) + '\n')

    print(json.dumps(record))

    raise SystemExit(0)



assert Path('/.dockerenv').is_file()

wheel, = Path('/wheel').glob('hol_guard-*.whl')

Path('/lab/home').mkdir(mode=0o700)

subprocess.run([sys.executable, '-m', 'venv', '--copies', '/lab/venv'], check=True)

site = Path('/lab/venv/lib/python3.12/site-packages')

shutil.copytree(sysconfig.get_paths()['purelib'], site, dirs_exist_ok=True,

    ignore=lambda _directory, names: [name for name in names if name.startswith(('_editable', '__editable', 'hol_guard', 'codex_plugin_scanner')) or name.endswith('.pth')])

python = '/lab/venv/bin/python'

arm64 = os.environ.get('ARM64_NATIVE') == '1'

if arm64:

    # x86_64 manylinux wheel can't pip-install on aarch64; extract the pure-Python

    # package onto the venv site-packages directly.

    with zipfile.ZipFile(wheel) as archive:

        archive.extractall(site)

    for name, target in (('hol-guard', 'codex_plugin_scanner.cli:main'),

                         ('hol-guard-eval', 'codex_plugin_scanner.guard.evaluation_cli:main'),

                         ('plugin-guard', 'codex_plugin_scanner.cli:main')):

        script = Path('/lab/venv/bin') / name

        module, func = target.split(':')

        script.write_text(f'#!{python}\nimport sys\nfrom {module} import {func}\nsys.exit({func}())\n')

        script.chmod(0o755)

else:

    subprocess.run([python, '-m', 'pip', 'install', str(wheel)], check=True, capture_output=True, text=True)

env = dict(os.environ, PATH='/lab/venv/bin:' + os.environ['PATH'])

if Path('/candidate-wheel').is_dir():

    candidate, = Path('/candidate-wheel').glob('hol_guard-*.whl')

    overlay = {'wheel_sha256': hashlib.sha256(candidate.read_bytes()).hexdigest(), 'modules': {}}

    with zipfile.ZipFile(candidate) as archive:

        relatives = ['codex_plugin_scanner/guard/adapters/' + name + '.py'

                     for name in ('managed_mcp_upstream', 'mcp_servers', 'cursor', 'cline_mcp')]

        if os.environ.get('VERIFY_NATIVE_VALUES') == '1':

            relatives += ['codex_plugin_scanner/guard/native_runtime.py',

                          'codex_plugin_scanner/guard/native_runtime_values.py']

        for relative in relatives:

            content = archive.read(relative)

            (site / relative).write_bytes(content)

            overlay['modules'][relative] = hashlib.sha256(content).hexdigest()

    env['PYTHON_CANDIDATE_OVERLAY'] = json.dumps(overlay)

for key in tuple(env):

    if key.startswith('HOL_GUARD_NATIVE') or key in ('PYTHONPATH', 'PYTHONHOME'):

        if arm64 and key in ('HOL_GUARD_NATIVE', 'HOL_GUARD_NATIVE_BINARY'):

            continue

        del env[key]

result = subprocess.run([python, '/runner.py', '--exercise'], cwd='/lab', env=env, capture_output=True, text=True, timeout=600)

Path('/output/managed-runtime.log').write_text(result.stdout + result.stderr)

Path('/output/package.json').write_text(json.dumps({'wheel_sha256': hashlib.sha256(wheel.read_bytes()).hexdigest(), 'exit_code': result.returncode}, indent=2) + '\n')

print('\n'.join((result.stdout + result.stderr).splitlines()[-12:]))

raise SystemExit(result.returncode)
