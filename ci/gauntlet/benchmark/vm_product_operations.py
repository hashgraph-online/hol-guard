"""Fixed Root-collector operations on one preconfigured unprivileged cell.

The caller supplies the already owned/frozen cell; wire messages cannot select
Root paths, profiles, modules or keys. Product argv executes only through its
measured UID10004 gate. This registry must never be exposed to agent/SUT sockets.
"""
from __future__ import annotations

import base64
import math
import os
import time

from .json_data import canonical_json
from .vm_bridge_rpc import serve_one


def fields(payload,expected):
    if type(payload) is not dict or set(payload)!=set(expected):
        raise ValueError('exact declared product operation fields required')


def decode_input(value):
    if type(value) is not str or len(value)>11184812:
        raise ValueError('bounded product input encoding required')
    raw=base64.b64decode(value,validate=True)
    if len(raw)>8*1024**2 or base64.b64encode(raw).decode('ascii')!=value:
        raise ValueError('canonical bounded product input required')
    return raw


class ProductOperations:
    def __init__(self,cell,*,deadline):
        self.cell,self.deadline=cell,deadline

    def _open(self):
        if self.cell.closed or self.cell.client is None:
            raise ValueError('running owned product cell required')

    def observe(self,payload):
        fields(payload,{'after'})
        after=payload['after']
        if type(after) is not int or not 0<=after<=len(self.cell.observations):
            raise ValueError('bounded owned observation cursor required')
        rows=[]
        for row in self.cell.observations[after:after+8]:
            if len(canonical_json([*rows,row]).encode())>1024**2:
                if not rows:
                    raise ValueError('single observation exceeds export budget')
                break
            rows.append(row)
        return {'schema':'vm-product-observations.v1','after':after,'next':after+len(rows),
                'observer_boot_id':self.cell.boot,'observer_scope':'outside-product-cell',
                'observations':rows,'closed':self.cell.closed,'cleanup_errors':list(self.cell.cleanup_errors)}

    def capture(self,payload):
        fields(payload,{'argv','input','timeout'})
        self._open()
        timeout=payload['timeout']
        if type(timeout) is not int or not 1<=timeout<=60:
            raise ValueError('bounded product capture time required')
        if time.monotonic()+timeout>=self.deadline:
            raise TimeoutError('product capture exceeds collector session deadline')
        raw=decode_input(payload['input'])
        result=self.cell.capture(payload['argv'],raw,timeout=payload['timeout'])
        return {'returncode':result.returncode,'stdout':base64.b64encode(result.stdout).decode('ascii'),
                'stderr':base64.b64encode(result.stderr).decode('ascii')}

    def spawn(self,payload):
        fields(payload,{'argv'})
        self._open()
        return {'handle':self.cell.spawn(payload['argv'],deadline=self.deadline)}

    def release(self,payload):
        fields(payload,{'handle'})
        self._open()
        return self.cell.release(payload['handle'],deadline=self.deadline)

    def retire(self,payload):
        fields(payload,{'handle'})
        self._open()
        return self.cell.retire(payload['handle'],deadline=self.deadline)

    def write(self,payload):
        fields(payload,{'handle','data'})
        self._open()
        raw=decode_input(payload['data'])
        if len(raw)>256*1024:
            raise ValueError('bounded process input chunk required')
        return self.cell._call('write',payload,self.deadline)

    def end_input(self,payload):
        fields(payload,{'handle'})
        self._open()
        return self.cell._call('end_input',payload,self.deadline)

    def read(self,payload):
        fields(payload,{'handle','wait_ms'})
        self._open()
        if type(payload['wait_ms']) is not int or not 0<=payload['wait_ms']<=100:
            raise ValueError('bounded process output wait required')
        return self.cell._call('read',payload,self.deadline)

    def close(self,payload):
        fields(payload,set())
        self.cell.close()
        return {'closed':self.cell.closed,'cleanup_errors':list(self.cell.cleanup_errors)}

    def registry(self):
        return {name:getattr(self,name) for name in
                ('observe','capture','spawn','release','write','end_input','read','retire','close')}


def serve_product(channel,cell,*,deadline):
    """Outside Root only; any EOF, malformed frame or error tears down the cell."""
    if os.getuid()!=0 or os.geteuid()!=0:
        raise ValueError('outside Root collector required')
    try:
        if (type(deadline) not in (int,float) or not math.isfinite(deadline)
                or not 0<deadline-time.monotonic()<=4000):
            raise ValueError('finite collector session deadline required')
        registry=ProductOperations(cell,deadline=deadline).registry()
        for _ in range(10000):
            operation=serve_one(channel,registry,deadline=min(deadline,time.monotonic()+65))
            if operation=='close':
                return
        raise ValueError('product collector operation budget exhausted')
    finally:
        cell.close()
