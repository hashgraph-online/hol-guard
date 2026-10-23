"""Real bounded pipes, authenticated custody and hostile transport records."""
from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
import threading
import time
from contextlib import suppress

import pytest

from ci.gauntlet.benchmark.json_data import canonical_json, strict_json_loads
from ci.gauntlet.benchmark.vm_bridge_frames import DOMAIN, MAX_FRAME_BYTES, BridgeProtocolError, FrameCodec
from ci.gauntlet.benchmark.vm_bridge_io import BridgeIO
from ci.gauntlet.benchmark.vm_bridge_rpc import BridgeClient, BridgeRemoteError, serve_one

KEY=b'k'*32
SESSION='00000000-0000-4000-8000-000000000001'
CONTROLLER='00000000-0000-4000-8000-000000000002'
PRODUCT='00000000-0000-4000-8000-000000000003'


def codecs(**limits):
    client=FrameCodec(KEY,session=SESSION,local_role='controller',local_boot=CONTROLLER,peer_boot=PRODUCT,**limits)
    server=FrameCodec(KEY,session=SESSION,local_role='product-collector',local_boot=PRODUCT,peer_boot=CONTROLLER,**limits)
    return client,server


def signed(message):
    mac=hmac.new(KEY,DOMAIN+canonical_json(message).encode(),hashlib.sha256).hexdigest()
    return canonical_json({'message':message,'mac':mac}).encode()


@pytest.fixture
def pipes():
    read_a,write_a=os.pipe()
    read_b,write_b=os.pipe()
    client,server=codecs()
    yield BridgeIO(read_b,write_a,client),BridgeIO(read_a,write_b,server)
    for fd in (read_a,write_a,read_b,write_b):
        with suppress(OSError):
            os.close(fd)


def test_real_authenticated_pipe_rpc_opaque_injection_and_unknown_operation(pipes,tmp_path):
    client,server=pipes
    marker=tmp_path/'must-not-execute'
    payload={'text':f'$(touch {marker})','frame':{'operation':'exec','payload':{'module':'os'}}}
    called=[]
    errors=[]
    def echo(value):
        called.append(value)
        return {'opaque':value}
    def dispatch():
        try:
            for _ in range(3):
                serve_one(server,{'echo':echo},deadline=time.monotonic()+2)
        except BaseException as error:
            errors.append(error)
    worker=threading.Thread(target=dispatch)
    worker.start()
    try:
        rpc=BridgeClient(client)
        assert rpc.call('echo',payload,timeout=2)=={'opaque':payload}
        with pytest.raises(BridgeRemoteError,match='unknown-operation'):
            rpc.call('exec',{'command':f'touch {marker}'},timeout=2)
        assert rpc.call('echo',{'after':'denial'},timeout=2)=={'opaque':{'after':'denial'}}
    finally:
        worker.join(timeout=3)
    assert not worker.is_alive() and not errors
    assert called==[payload,{'after':'denial'}] and not marker.exists()


def test_replay_poisoned_connection_cannot_be_reused():
    client,server=codecs()
    raw=client.encode('request',{'operation':'observe'})[4:]
    assert server.decode(raw,expected_kind='request')=={'operation':'observe'}
    with pytest.raises(BridgeProtocolError,match='order'):
        server.decode(raw,expected_kind='request')
    assert server.poisoned
    with pytest.raises(BridgeProtocolError,match='invalid'):
        server.decode(client.encode('request',{})[4:],expected_kind='request')


@pytest.mark.parametrize('field,value',[
    ('schema','old-schema'),('session',PRODUCT),('source_role','product-collector'),
    ('destination_role','controller'),('source_boot',PRODUCT),('destination_boot',CONTROLLER),
    ('sequence',True),('sequence',1),('sequence',-1),('kind','response'),('body',[])])
def test_even_authenticated_wrong_context_is_not_admitted(field,value):
    client,server=codecs()
    message=strict_json_loads(client.encode('request',{})[4:])['message']
    message[field]=value
    with pytest.raises(BridgeProtocolError,match='mismatch'):
        server.decode(signed(message),expected_kind='request')
    assert server.received==0 and server.poisoned


def test_corrupted_mac_and_duplicate_or_nonfinite_json_rejected():
    for raw in (b'{"message":{},"message":{},"mac":"x"}',b'{"message":NaN,"mac":"x"}'):
        _,server=codecs()
        with pytest.raises(ValueError):
            server.decode(raw,expected_kind='request')
        assert server.poisoned
    client,server=codecs()
    envelope=strict_json_loads(client.encode('request',{})[4:])
    envelope['mac']='0'*64
    with pytest.raises(BridgeProtocolError,match='authentication'):
        server.decode(canonical_json(envelope).encode(),expected_kind='request')


def test_key_never_in_diagnostic_representation():
    client,_=codecs()
    assert KEY.decode() not in repr(client) and KEY.hex() not in repr(client)


def test_management_io_rejects_regular_files_and_datagrams(tmp_path):
    codec,_=codecs()
    with (tmp_path/'not-a-management-pipe').open('w+b') as stream:
        duplicate=os.dup(stream.fileno())
        try:
            with pytest.raises(BridgeProtocolError,match='pipes or stream sockets'):
                BridgeIO(stream.fileno(),duplicate,codec)
        finally:
            os.close(duplicate)
    left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM)
    try:
        with pytest.raises(BridgeProtocolError,match='Unix stream'):
            BridgeIO(left.fileno(),right.fileno(),codec)
    finally:
        left.close()
        right.close()


def test_frame_and_aggregate_budgets_before_body_allocation(pipes):
    client,server=pipes
    os.write(client.writer_fd,struct.pack('!I',MAX_FRAME_BYTES+1))
    started=time.monotonic()
    with pytest.raises(BridgeProtocolError,match='budget'):
        server.receive('request',deadline=time.monotonic()+1)
    assert time.monotonic()-started<0.5 and server.codec.poisoned
    sender,receiver=codecs(maximum_frames=1)
    receiver.decode(sender.encode('request',{})[4:],expected_kind='request')
    with pytest.raises(BridgeProtocolError,match='budget'):
        sender.encode('request',{})
    _,receiver=codecs(maximum_bytes=1024)
    with pytest.raises(BridgeProtocolError,match='budget'):
        receiver.validate_length(1021)


def test_partial_header_eof_is_not_terminal_success(pipes):
    client,server=pipes
    os.write(client.writer_fd,b'\x00\x00')
    os.close(client.writer_fd)
    with pytest.raises(EOFError):
        server.receive('request',deadline=time.monotonic()+1)
    assert server.codec.poisoned


def test_read_timeout_and_write_backpressure_are_bounded(pipes):
    client,server=pipes
    with pytest.raises(TimeoutError):
        server.receive('request',deadline=time.monotonic()+0.03)
    assert server.codec.poisoned
    started=time.monotonic()
    with pytest.raises(TimeoutError):
        client.send('request',{'opaque':'x'*1024**2},deadline=time.monotonic()+0.05)
    assert time.monotonic()-started<0.5 and client.codec.poisoned


def test_callback_failure_is_authenticated_error_not_success(pipes):
    client,server=pipes
    captured=[]
    def fail(payload):
        raise RuntimeError('private diagnostics retained by collector')
    worker=threading.Thread(target=lambda:serve_one(server,{'observe':fail},deadline=time.monotonic()+2,
                                                  on_error=lambda error:captured.append(type(error).__name__)))
    worker.start()
    try:
        with pytest.raises(BridgeRemoteError,match='operation-failed'):
            BridgeClient(client).call('observe',{},timeout=2)
    finally:
        worker.join(timeout=3)
    assert not worker.is_alive() and captured==['RuntimeError']


def test_authenticated_response_must_bind_request(pipes):
    client,server=pipes
    def corrupt():
        body=server.receive('request',deadline=time.monotonic()+2)
        server.send('response',{'request_id':PRODUCT,'operation':body['operation'],'result':{},'error':None},
                    deadline=time.monotonic()+2)
    worker=threading.Thread(target=corrupt)
    worker.start()
    try:
        with pytest.raises(BridgeProtocolError,match='bind exact request'):
            BridgeClient(client).call('observe',{},timeout=2)
    finally:
        worker.join(timeout=3)
    assert not worker.is_alive() and client.codec.poisoned
