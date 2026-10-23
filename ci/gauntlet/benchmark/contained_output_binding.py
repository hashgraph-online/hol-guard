"""Deterministic delivery of captured sink output, independent of SDK formatting."""
from __future__ import annotations

import hashlib

from .contracts import digest

PROFILE = 'controller-contained-output.v1'


def captured_output(result):
    if (type(result) is not dict or type(result.get('exit_code')) is not int
            or not -255 <= result['exit_code'] <= 255
            or any(type(result.get(name)) is not str for name in ('stdout','stderr'))):
        raise ValueError('bounded actual contained result required for output binding')
    for name in ('stdout','stderr'):
        raw = result[name].encode()
        if len(raw)>8*1024**2 or hashlib.sha256(raw).hexdigest()!=result.get(name+'_sha256'):
            raise ValueError('captured contained output differs from its byte digest')
    text = f"Exit code: {result['exit_code']}\nSTDOUT:\n{result['stdout']}\nSTDERR:\n{result['stderr']}"
    if len(text.encode())>1024**2-16384:
        raise ValueError('captured contained output exceeds native review/delivery bound')
    return {'schema':PROFILE,'tool_response':[{'type':'text','text':text}],
            'is_error':result['exit_code']!=0,'result_digest':digest(result),
            'output_sha256':hashlib.sha256(text.encode()).hexdigest()}
