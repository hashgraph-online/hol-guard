"""Loopback-only topology for a separately declared private product cell.

No veth, bridge, route, forwarding, sysctl or host interface is created. Root
may raise only the pre-existing lo interface in a verified fresh net namespace,
before dropping privilege. Outside collectors recheck the actual kernel view.
"""
from __future__ import annotations

import fcntl
import ipaddress
import os
import socket
import struct
from pathlib import Path


def _read(path):
    with path.open('rb') as stream:
        raw=stream.read(65537)
    if len(raw)>65536:
        raise ValueError('private network kernel observation byte budget')
    return raw.decode('ascii')


def validate_topology(devices, routes4, routes6, addresses6):
    """Reject external interfaces/addresses/routes, including IPv6 defaults."""
    interfaces=[line.split(':',1)[0].strip() for line in devices.splitlines() if ':' in line]
    if interfaces!=['lo']:
        raise ValueError('private network must contain exactly loopback')
    for line in routes4.splitlines()[1:]:
        fields=line.split()
        if (len(fields)!=11 or fields[0]!='lo'
                or not ipaddress.IPv4Address(int(fields[1],16).to_bytes(4,'little')).is_loopback
                or int(fields[2],16)!=0 or int(fields[7],16)==0):
            raise ValueError('non-loopback IPv4 route')
    for line in routes6.splitlines():
        fields=line.split()
        if len(fields)!=10 or fields[-1]!='lo' or int(fields[4],16)!=0:
            raise ValueError('non-loopback IPv6 route')
        destination=ipaddress.IPv6Address(int(fields[0],16))
        # A new namespace has kernel-created unreachable ::/0 reject stubs.
        # Those are not forwarding routes; accept only their explicit RTF_REJECT.
        reject_stub=int(fields[8],16)&0x200 and int(destination)==0 and fields[1]=='00'
        if not reject_stub and not (destination.is_loopback and fields[1]=='80'):
            raise ValueError('non-loopback IPv6 destination')
    for line in addresses6.splitlines():
        fields=line.split()
        if len(fields)!=6 or fields[-1]!='lo' or not ipaddress.IPv6Address(int(fields[0],16)).is_loopback:
            raise ValueError('non-loopback IPv6 address')
    return {'schema':'product-cell-network-topology.v1','interfaces':interfaces,
            'ipv4_routes':routes4,'ipv6_routes':routes6,'ipv6_addresses':addresses6}


def observe(pid='self'):
    if pid!='self' and (type(pid) is not int or pid<=0):
        raise ValueError('literal owned process ID required')
    net=Path(f'/proc/{pid}/net')
    return validate_topology(*(_read(net/name) for name in ('dev','route','ipv6_route','if_inet6')))


def raise_private_loopback(parent_namespace):
    if (os.getuid()!=0 or os.getgid()!=0 or os.getpid()!=1
            or not isinstance(parent_namespace,str) or not parent_namespace.startswith('net:[')
            or parent_namespace!=os.readlink('/proc/1/ns/net')
            or os.readlink('/proc/self/ns/net')==parent_namespace):
        raise ValueError('Root PID1 in a fresh network namespace required')
    observe()
    # SIOCSIFFLAGS changes this namespace's pre-existing lo only. No helper,
    # candidate code, global setting, capability grant or route is involved.
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as channel:
        request=struct.pack('16sH22x',b'lo',0)
        current=fcntl.ioctl(channel.fileno(),0x8913,request)  # SIOCGIFFLAGS
        flags=struct.unpack_from('H',current,16)[0]
        fcntl.ioctl(channel.fileno(),0x8914,struct.pack('16sH22x',b'lo',flags|1))
    return observe()
