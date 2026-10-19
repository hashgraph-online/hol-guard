"""Cell IPC cannot borrow collector authority; RPC admission stays bounded."""
from __future__ import annotations

import base64
import os
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark.product_cell_protocol import CellCodec, read_bootstrap
from ci.gauntlet.benchmark.vm_bridge_frames import BridgeProtocolError, FrameCodec
from ci.gauntlet.benchmark.vm_bridge_rpc import BridgeClient

KEY = b'c' * 32
SESSION = '00000000-0000-4000-8000-000000000001'
BOOT = '00000000-0000-4000-8000-000000000002'


def codec(cls, role):
    return cls(KEY, session=SESSION, local_role=role, local_boot=BOOT, peer_boot=BOOT)


def test_cell_frames_roundtrip_but_cannot_authenticate_as_collector():
    actor = codec(CellCodec, 'cell-actor')
    supervisor = codec(CellCodec, 'cell-supervisor')
    raw = actor.encode('response', {'uid': 10004})[4:]
    assert supervisor.decode(raw, expected_kind='response') == {'uid': 10004}
    collector = codec(FrameCodec, 'controller')
    with pytest.raises(BridgeProtocolError, match='authentication'):
        collector.decode(raw, expected_kind='response')
    assert collector.poisoned and collector.received == 0


@pytest.mark.parametrize('role', ['controller', 'product-collector'])
def test_cell_codec_rejects_collector_roles(role):
    with pytest.raises(BridgeProtocolError, match='role'):
        codec(CellCodec, role)


@pytest.mark.parametrize('length', [0, 4097, 2**32 - 1])
def test_bootstrap_rejects_length_before_body_read(length):
    reader, writer = os.pipe()
    try:
        os.write(writer, struct.pack('!I', length))
        with pytest.raises(ValueError, match='budget'):
            read_bootstrap(reader, timeout=0.2)
    finally:
        os.close(reader)
        os.close(writer)


def test_bootstrap_eof_and_stalled_body_are_terminal():
    reader, writer = os.pipe()
    try:
        os.write(writer, struct.pack('!I', 3) + b'a')
        with pytest.raises(TimeoutError, match='deadline'):
            read_bootstrap(reader, timeout=0.02)
        os.close(writer)
        writer = None
        with pytest.raises(EOFError, match='ended'):
            read_bootstrap(reader, timeout=0.2)
    finally:
        os.close(reader)
        if writer is not None:
            os.close(writer)


@pytest.mark.parametrize('timeout', [True, False, 0, -1, float('inf'), float('nan'), 4001])
def test_rpc_invalid_time_budget_has_no_channel_effects(timeout):
    client = BridgeClient(object())
    with pytest.raises(BridgeProtocolError, match='finite'):
        client.call('hello', {}, timeout=timeout)


def test_rpc_queue_wait_is_part_of_deadline_without_poisoning_active_call():
    client = BridgeClient(object())
    entered, release = threading.Event(), threading.Event()

    def admitted(operation, payload, deadline):
        entered.set()
        assert release.wait(2)
        return {'completed': True}

    client._call = admitted
    results = []
    worker = threading.Thread(target=lambda: results.append(client.call('hello', {}, timeout=2)))
    worker.start()
    try:
        assert entered.wait(1)
        start = time.monotonic()
        with pytest.raises(TimeoutError, match='admission'):
            client.call('hello', {}, timeout=0.02)
        assert time.monotonic() - start < 0.5
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive() and results == [{'completed': True}]


@pytest.mark.parametrize('admission', [b'\x01', b'', b'\x00'])
def test_exec_gate_requires_admission_and_preserves_bounded_clean_allocator(monkeypatch, admission):
    from ci.gauntlet.benchmark import product_exec_gate as gate

    effects = []
    monkeypatch.setattr(gate, 'sys', SimpleNamespace(argv=['gate', '/usr/bin/python3', '-V']))
    monkeypatch.setattr(gate.ctypes, 'CDLL', lambda *args, **kwargs: SimpleNamespace(prctl=lambda *args: 0))
    monkeypatch.setattr(gate, 'os', SimpleNamespace(
        getuid=lambda: 10004, getgid=lambda: 10004,
        write=lambda fd, data: effects.append(('ready', fd, data)),
        read=lambda fd, size: admission,
        chdir=lambda path: effects.append(('cwd', path)),
        execve=lambda path, argv, env: effects.append(('exec', path, argv, env)),
    ))
    if admission != b'\x01':
        with pytest.raises(SystemExit) as error:
            gate.main()
        assert error.value.code == 126
        assert [effect[0] for effect in effects] == ['ready']
    else:
        gate.main()
        assert [effect[0] for effect in effects] == ['ready', 'cwd', 'exec']
        assert effects[-1][3] == {
            'PATH': '/usr/bin:/bin', 'HOME': '/product/home',
            'LANG': 'C.UTF-8', 'MALLOC_ARENA_MAX': '2',
        }


def test_terminal_child_must_drain_before_retirement_and_cannot_replay():
    from ci.gauntlet.benchmark.product_cell_actor import CellActor

    actor=CellActor()
    process=subprocess.Popen([sys.executable,'-I','-c',"print('actual pipe output')"],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        for stream in (process.stdin,process.stdout,process.stderr):
            os.set_blocking(stream.fileno(),False)
        actor.children['owned']={'process':process,'released':True,'input_bytes':0,'output_bytes':0,
                                 'stdout_eof':False,'stderr_eof':False}
        process.wait(timeout=3)
        with pytest.raises(ValueError,match='terminal drained'):
            actor.retire({'handle':'owned'})
        output=bytearray()
        for _ in range(4):
            chunk=actor.read({'handle':'owned','wait_ms':100})
            output.extend(base64.b64decode(chunk['stdout']))
            if chunk['stdout_eof'] and chunk['stderr_eof']:
                break
        assert output==b'actual pipe output\n'
        assert actor.retire({'handle':'owned'})=={'retired':True}
        assert not actor.children and all(stream.closed for stream in (process.stdin,process.stdout,process.stderr))
        with pytest.raises(ValueError,match='owned'):
            actor.retire({'handle':'owned'})
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        for stream in (process.stdin,process.stdout,process.stderr):
            stream.close()


@pytest.mark.parametrize('wait',[True,-1,101,0.5,float('nan')])
def test_actor_read_wait_rejects_invalid_budget_before_touching_process(wait):
    from ci.gauntlet.benchmark.product_cell_actor import CellActor

    with pytest.raises(ValueError,match='bounded'):
        CellActor().read({'handle':'not-owned','wait_ms':wait})


@pytest.mark.parametrize('full_active',[False,True])
def test_actor_reserves_finite_lifetime_and_active_process_budgets(monkeypatch,full_active):
    from ci.gauntlet.benchmark import product_cell_actor as module

    actor=module.CellActor()
    if full_active:
        actor.children={str(index):{} for index in range(64)}
    else:
        actor.spawn_count=1024
    monkeypatch.setattr(module.subprocess,'Popen',lambda *args,**kwargs:pytest.fail('budget must precede spawn'))
    with pytest.raises(ValueError,match='bounded'):
        actor.spawn({'argv':['/usr/bin/python3']})
