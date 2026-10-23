"""Loopback utility must never admit external interfaces or forwarding routes."""
from __future__ import annotations

import pytest

from ci.gauntlet.benchmark import product_vm_network as module

DEV='Inter-| Receive | Transmit\n face |bytes packets|bytes packets\n lo: 0 0 0 0\n'
ROUTE4='Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n'
ZERO='0'*32
ONE='0'*31+'1'
REJECT=f'{ZERO} 00 {ZERO} 00 {ZERO} ffffffff 00000001 00000000 00200200 lo\n'
LOCAL6=f'{ONE} 80 {ZERO} 00 {ZERO} 00000000 00000000 00000000 80200001 lo\n'
ADDRESS6=f'{ONE} 01 80 10 80 lo\n'


def test_kernel_loopback_and_unreachable_ipv6_stubs_are_valid():
    assert module.validate_topology(DEV,ROUTE4,REJECT+LOCAL6,ADDRESS6)['interfaces']==['lo']
    assert module.validate_topology(DEV,ROUTE4,'','')['interfaces']==['lo']


@pytest.mark.parametrize('field,value',[
    (0,DEV+' eth0: 0 0 0 0\n'),(0,DEV.replace('lo:','eth0:')),
    (1,ROUTE4+'lo 00000000 00000000 0001 0 0 0 00000000 0 0 0\n'),
    (1,ROUTE4+'lo 0100007F 0100007F 0001 0 0 0 FFFFFFFF 0 0 0\n'),
    (1,ROUTE4+'lo 0000050A 00000000 0001 0 0 0 00FFFFFF 0 0 0\n'),
    (2,REJECT.replace('00200200','00000001')),
    (2,LOCAL6.replace(ONE,'20010db8000000000000000000000001',1)),
    (2,LOCAL6.replace(' lo',' eth0')),
    (3,ADDRESS6.replace(ONE,'fe800000000000000000000000000001')),
    (3,ADDRESS6.replace(' lo',' eth0')),
])
def test_external_network_topology_is_rejected(field,value):
    arguments=[DEV,ROUTE4,REJECT+LOCAL6,ADDRESS6]
    arguments[field]=value
    with pytest.raises(ValueError):
        module.validate_topology(*arguments)


def test_never_raise_loopback_from_host_or_unprivileged_process(monkeypatch):
    monkeypatch.setattr(module.os,'getuid',lambda:0)
    monkeypatch.setattr(module.os,'getgid',lambda:0)
    monkeypatch.setattr(module.os,'getpid',lambda:1)
    monkeypatch.setattr(module.os,'readlink',lambda path:'net:[123]')
    monkeypatch.setattr(module,'observe',lambda:pytest.fail('no topology mutation in host network'))
    with pytest.raises(ValueError,match='fresh'):
        module.raise_private_loopback('net:[123]')
    with pytest.raises(ValueError,match='fresh'):
        module.raise_private_loopback('net:[456]')


def test_kernel_reads_are_bounded(tmp_path):
    path=tmp_path/'oversized'
    path.write_bytes(b'x'*65537)
    with pytest.raises(ValueError,match='budget'):
        module._read(path)
