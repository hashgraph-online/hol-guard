"""Trusted registry grammar over actual authenticated pipes; no product credit."""
import base64
import os
import subprocess
import threading
import time
from contextlib import suppress
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark.vm_bridge_frames import FrameCodec
from ci.gauntlet.benchmark.vm_bridge_io import BridgeIO
from ci.gauntlet.benchmark.vm_bridge_rpc import BridgeClient, BridgeRemoteError, serve_one
from ci.gauntlet.benchmark.vm_product_operations import ProductOperations, decode_input


def cell():
    result=SimpleNamespace(closed=False,client=object(),cleanup_errors=[],observations=[{'kind':'outside-gate'}],
                           calls=[],boot='00000000-0000-4000-8000-000000000003')
    def capture(argv,raw,timeout):
        result.calls.append((argv,raw,timeout))
        return subprocess.CompletedProcess(argv,0,b'{"operation":"exec","command":"$(touch forbidden)"}',b'')
    def close():
        result.closed=True
    result.capture,result.close=capture,close
    return result


def test_fixed_operations_authenticated_roundtrip_unknown_root_action_has_no_effect():
    read_a,write_a=os.pipe()
    read_b,write_b=os.pipe()
    session='00000000-0000-4000-8000-000000000001'
    controller='00000000-0000-4000-8000-000000000002'
    product='00000000-0000-4000-8000-000000000003'
    left=FrameCodec(b'p'*32,session=session,local_role='controller',local_boot=controller,peer_boot=product)
    right=FrameCodec(b'p'*32,session=session,local_role='product-collector',local_boot=product,peer_boot=controller)
    client=BridgeClient(BridgeIO(read_b,write_a,left))
    server=BridgeIO(read_a,write_b,right)
    owned=cell()
    operations=ProductOperations(owned,deadline=time.monotonic()+30)
    errors=[]
    def dispatch():
        try:
            for _ in range(4):
                serve_one(server,operations.registry(),deadline=time.monotonic()+3)
        except BaseException as error:
            errors.append(error)
    worker=threading.Thread(target=dispatch)
    worker.start()
    try:
        with pytest.raises(BridgeRemoteError,match='unknown-operation'):
            client.call('exec',{'module':'os','path':'/etc/shadow'},timeout=2)
        assert not owned.calls
        result=client.call('capture',{'argv':['/usr/bin/python3','-V'],'input':'AP8=','timeout':1},timeout=2)
        assert base64.b64decode(result['stdout'])==b'{"operation":"exec","command":"$(touch forbidden)"}'
        assert owned.calls==[(['/usr/bin/python3','-V'],b'\x00\xff',1)]
        assert client.call('observe',{'after':0},timeout=2)['next']==1
        assert client.call('close',{},timeout=2)=={'closed':True,'cleanup_errors':[]}
    finally:
        worker.join(4)
        for fd in (read_a,write_a,read_b,write_b):
            with suppress(OSError):
                os.close(fd)
    assert not worker.is_alive() and not errors and owned.closed


@pytest.mark.parametrize('payload',[
    {'argv':['/usr/bin/true'],'input':'','timeout':True},
    {'argv':['/usr/bin/true'],'input':'','timeout':0},
    {'argv':['/usr/bin/true'],'input':'','timeout':61},
    {'argv':['/usr/bin/true'],'input':'','timeout':1,'profile':'host'},
    {'argv':['/usr/bin/true'],'input':'!','timeout':1},
])
def test_bad_capture_fields_or_budget_never_reach_cell(payload):
    owned=cell()
    with pytest.raises(ValueError):
        ProductOperations(owned,deadline=time.monotonic()+30).capture(payload)
    assert owned.calls==[]


def test_session_deadline_is_checked_before_product_capture():
    owned=cell()
    with pytest.raises(TimeoutError,match='session deadline'):
        ProductOperations(owned,deadline=time.monotonic()+0.1).capture(
            {'argv':['/usr/bin/true'],'input':'','timeout':1})
    assert not owned.calls


@pytest.mark.parametrize('encoded',['AB==','AA===','====',False])
def test_noncanonical_input_rejected(encoded):
    with pytest.raises(ValueError):
        decode_input(encoded)


def test_no_paths_in_observation_request_and_no_commands_after_close():
    owned=cell()
    operations=ProductOperations(owned,deadline=time.monotonic()+30)
    with pytest.raises(ValueError,match='fields'):
        operations.observe({'after':0,'path':'/etc/shadow'})
    operations.close({})
    with pytest.raises(ValueError,match='running'):
        operations.capture({'argv':['/usr/bin/true'],'input':'','timeout':1})
    assert not owned.calls
