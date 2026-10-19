"""Small trusted-operation registry over authenticated collector transport.

No shell, module, path or executable is selected by this protocol. Callbacks
must be trusted implementations with their own scope/resource/lifecycle checks.
Product stdout/stderr must be bounded independently and returned only as data.
"""
from __future__ import annotations

import math
import re
import threading
import time
import uuid

from .vm_bridge_frames import BridgeProtocolError

NAME = re.compile(r'[a-z][a-z0-9_]{0,31}')


class BridgeRemoteError(RuntimeError):
    pass


def _request(body):
    if (type(body) is not dict or set(body) != {'request_id','operation','payload'}
            or type(body['request_id']) is not str or str(uuid.UUID(body['request_id'])) != body['request_id']
            or type(body['operation']) is not str or not NAME.fullmatch(body['operation'])
            or type(body['payload']) is not dict):
        raise BridgeProtocolError('invalid bridge operation request')
    return body


def serve_one(channel, operations: dict, *, deadline, on_error=None):
    """Dispatch one authenticated request; unknown operations have zero effects."""
    if (type(operations) is not dict or not 1 <= len(operations) <= 32
            or any(type(name) is not str or not NAME.fullmatch(name) or not callable(callback)
                   for name,callback in operations.items())):
        raise BridgeProtocolError('fixed trusted operation registry required')
    try:
        body = _request(channel.receive('request', deadline=deadline))
    except BaseException:
        channel.codec.invalidate()
        raise
    response = {'request_id':body['request_id'],'operation':body['operation'],'result':None,'error':None}
    if body['operation'] not in operations:
        response['error'] = {'code':'unknown-operation'}
    else:
        try:
            result = operations[body['operation']](body['payload'])
            if type(result) is not dict:
                raise BridgeProtocolError('trusted operation must return bounded data object')
            response['result'] = result
        except Exception as error:
            if on_error is not None:
                on_error(error)
            response['error'] = {'code':'operation-failed','kind':type(error).__name__}
    channel.send('response', response, deadline=deadline)
    return body['operation']


class BridgeClient:
    def __init__(self, channel):
        self.channel = channel
        self._lock = threading.Lock()

    def call(self, operation, payload, *, timeout):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 4000:
            raise BridgeProtocolError('bounded finite RPC timeout required')
        deadline = time.monotonic()+timeout
        if not self._lock.acquire(timeout=timeout):
            raise TimeoutError('bridge single-flight admission deadline exceeded')
        try:
            return self._call(operation,payload,deadline)
        finally:
            self._lock.release()

    def _call(self,operation,payload,deadline):
        request = _request({'request_id':str(uuid.uuid4()),'operation':operation,'payload':payload})
        self.channel.send('request', request, deadline=deadline)
        try:
            response = self.channel.receive('response', deadline=deadline)
            if (type(response) is not dict or set(response) != {'request_id','operation','result','error'}
                    or response['request_id'] != request['request_id'] or response['operation'] != operation):
                raise BridgeProtocolError('bridge response does not bind exact request')
            if response['error'] is not None:
                if (response['result'] is not None or type(response['error']) is not dict
                        or set(response['error']) not in ({'code'},{'code','kind'})
                        or response['error'].get('code') not in {'unknown-operation','operation-failed'}):
                    raise BridgeProtocolError('invalid bridge operation error')
                error = response['error']
                if ((error['code'] == 'unknown-operation' and set(error) != {'code'})
                        or (error['code'] == 'operation-failed' and (
                            set(error) != {'code','kind'} or type(error['kind']) is not str
                            or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',error['kind'])))):
                    raise BridgeProtocolError('invalid bridge operation error fields')
                raise BridgeRemoteError('bridge operation failed: '+response['error']['code'])
            if type(response['result']) is not dict:
                raise BridgeProtocolError('invalid bridge operation result')
            return response['result']
        except BridgeRemoteError:
            raise
        except BaseException:
            self.channel.codec.invalidate()
            raise
