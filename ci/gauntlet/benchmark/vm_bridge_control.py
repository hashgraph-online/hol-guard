"""Root-only two-VM transport control, not a product-session executor.

Launch only over already authenticated private management stdio. The initial
bootstrap contains a fresh in-memory key; never log it or connect this entrypoint
to an agent/product/network listener. Only fixed metadata/opaque-echo/close actions
exist here. No Guard, task code or caller-selected command is imported/executed.
"""
from __future__ import annotations

import hashlib
import os
import re
import select
import struct
import sys
import time
from pathlib import Path

from .json_data import canonical_json, strict_json_loads
from .vm_bridge_frames import BridgeProtocolError, FrameCodec
from .vm_bridge_io import BridgeIO, validate_management_fd
from .vm_bridge_rpc import BridgeClient, BridgeRemoteError, serve_one

FILES = ('json_data.py','vm_bridge_frames.py','vm_bridge_io.py','vm_bridge_rpc.py','vm_bridge_control.py')


def source_hashes():
    return {name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in FILES}


def _bootstrap(role, *, expected_hashes=None, maximum_frames=64, maximum_bytes=1024**2):
    validate_management_fd(0)
    validate_management_fd(1)
    os.set_blocking(0,False)
    deadline=time.monotonic()+10
    def read(count):
        data=bytearray()
        while len(data)<count:
            left=deadline-time.monotonic()
            if left<=0 or not select.select([0],[],[],left)[0]:
                raise TimeoutError('private management bootstrap deadline exceeded')
            try:
                chunk=os.read(0,min(count-len(data),4096))
            except BlockingIOError:
                continue
            if not chunk:
                raise EOFError('private management bootstrap truncated')
            data.extend(chunk)
        return bytes(data)
    length=struct.unpack('!I',read(4))[0]
    if not 1<=length<=4096:
        raise BridgeProtocolError('private bootstrap byte budget')
    value=strict_json_loads(read(length))
    if (type(value) is not dict or set(value)!={'schema','session','key_hex','controller_boot','product_boot','hashes'}
            or value['schema']!='gauntlet-vm-bridge-private-bootstrap.v1'
            or type(value['key_hex']) is not str or not re.fullmatch('[0-9a-f]{64}',value['key_hex'])
            or value['hashes']!=(source_hashes() if expected_hashes is None else expected_hashes)):
        raise BridgeProtocolError('private bootstrap identity mismatch')
    local=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    local_expected=value['controller_boot'] if role=='controller' else value['product_boot']
    peer=value['product_boot'] if role=='controller' else value['controller_boot']
    if local!=local_expected:
        raise BridgeProtocolError('collector boot differs from private bootstrap')
    codec=FrameCodec(bytes.fromhex(value['key_hex']),session=value['session'],local_role=role,
                     local_boot=local,peer_boot=peer,maximum_frames=maximum_frames,maximum_bytes=maximum_bytes)
    # Only a one-way random-key fingerprint is public. The key stays in memory
    # outside actor namespaces; no persistent credential file is created/read.
    fingerprint=hashlib.sha256(b'vm-bridge-control-auth.v1\0'+bytes.fromhex(value['key_hex'])).hexdigest()
    return codec,fingerprint


def run(role: str, result: Path):
    if (os.getuid()!=0 or os.geteuid()!=0 or role not in {'controller','product-collector'}
            or not result.is_absolute() or '..' in result.parts or result.exists()):
        raise ValueError('Root collector role and fresh absolute result path required')
    for path in result.parents:
        metadata=path.lstat()
        if not path.is_dir() or path.is_symlink() or metadata.st_uid!=0 or metadata.st_mode&0o022:
            raise ValueError('result ancestry must be exclusively Root-owned')
    record={'schema':'vm-bridge-transport-control.v1','role':role,'pid':os.getpid(),
            'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'source_hashes':source_hashes(),'guard_exercised':False,'sdk_exercised':False,
            'model_exercised':False,'protected_execution_eligible':False,'qualification_eligible':False,
            'callbacks':[],'control_completed':False}
    codec=None
    try:
        codec,fingerprint=_bootstrap(role)
        record.update(session=codec.session,auth_fingerprint=fingerprint)
        channel=BridgeIO(0,1,codec)
        if role=='product-collector':
            def observe(payload):
                if payload:
                    raise ValueError('observe accepts no paths or other arguments')
                record['callbacks'].append('observe')
                return {'role':role,'boot_id':record['boot_id'],'uid':os.getuid(),'gid':os.getgid(),
                        'source_hashes':record['source_hashes'],
                        'sentinel_exists':Path('/opt/hol-vm-bridge-should-not-execute').exists()}
            def echo(payload):
                record['callbacks'].append('echo')
                return {'opaque':payload}
            def close(payload):
                if payload:
                    raise ValueError('close accepts no arguments')
                record['callbacks'].append('close')
                return {'closing':True}
            for _ in range(16):
                operation=serve_one(channel,{'observe':observe,'echo':echo,'close':close},
                                    deadline=time.monotonic()+5)
                if operation=='close':
                    record['control_completed']=True
                    break
        else:
            client=BridgeClient(channel)
            observed=client.call('observe',{},timeout=5)
            assert observed['boot_id']==codec.peer_boot and observed['uid']==observed['gid']==0
            assert observed['source_hashes']==record['source_hashes'] and not observed['sentinel_exists']
            payload={'text':'$(touch /opt/hol-vm-bridge-should-not-execute)',
                     'frame':{'operation':'exec','payload':{'module':'os'}}}
            assert client.call('echo',payload,timeout=5)=={'opaque':payload}
            try:
                client.call('exec',{'command':payload['text']},timeout=5)
            except BridgeRemoteError:
                record['unknown_operation_refused']=True
            else:
                raise AssertionError('unknown operation was admitted')
            assert not client.call('observe',{},timeout=5)['sentinel_exists']
            assert client.call('close',{},timeout=5)=={'closing':True}
            record['control_completed']=True
    except BaseException as error:
        # Never serialize bootstrap data, key material or raw input on failure.
        record['error_kind']=type(error).__name__
        public_error=isinstance(error,(BridgeProtocolError,TimeoutError,EOFError))
        record['error']=str(error) if public_error else 'control failed'
    finally:
        if codec is not None:
            record.update(sent=codec.sent,received=codec.received,bytes_sent=codec.bytes_sent,
                          bytes_received=codec.bytes_received,poisoned=codec.poisoned)
        with result.open('x') as stream:
            stream.write(canonical_json(record)+'\n')
        result.chmod(0o444)
    return 0 if record['control_completed'] else 1


if __name__=='__main__':
    if len(sys.argv)!=3:
        raise SystemExit('fixed collector role and exclusive result path required')
    raise SystemExit(run(sys.argv[1],Path(sys.argv[2])))
