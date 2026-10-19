"""Trusted controller endpoint declarations; no agent-controlled egress or DNS."""
from __future__ import annotations

import math
import re

DEFAULT_BASE_URL = 'http://host.lima.internal:8001/v1'
SAMPLING_FIELDS = frozenset({'temperature', 'top_p', 'top_k', 'min_p', 'seed', 'max_tokens',
    'max_completion_tokens', 'repetition_penalty', 'presence_penalty', 'frequency_penalty'})


def generation_parameters(request):
    """Copy actual finite numeric/null sampling scalars; absent defaults stay absent."""
    result = {}
    for name in SAMPLING_FIELDS & request.keys():
        value = request[name]
        if value is not None and (type(value) not in {int, float}
                                  or (type(value) is float and not math.isfinite(value))):
            raise ValueError('model generation parameters require finite numeric or null scalars')
        result[name] = value
    return result


def model_endpoint(base_url=DEFAULT_BASE_URL):
    """Retain the exact frozen declaration and map local aliases to pinned Lima IP.

    Loopback names describe the existing local provider route, not arbitrary
    controller loopback services. The agent still uses its isolated 8001 bridge.
    """
    if type(base_url) is not str or re.fullmatch(
            r'http://(?:host\.lima\.internal|localhost|127\.0\.0\.1|192\.168\.5\.2):(8001|8002)/v1',
            base_url) is None:
        raise ValueError('local model endpoints require an explicit HTTP port 8001/8002 and exact /v1 path')
    return {'base_url': base_url, 'host': '192.168.5.2', 'port': int(base_url.rsplit(':', 1)[1].split('/')[0])}


def verify_model_endpoint(provider, base_url=DEFAULT_BASE_URL):
    """Legacy absent metadata means only the historical default, never port 8002."""
    expected = model_endpoint(base_url)
    if provider is None:
        if base_url != DEFAULT_BASE_URL:
            raise ValueError('legacy model evidence cannot establish the frozen endpoint')
    elif provider != expected:
        raise ValueError('observed model endpoint differs from exact frozen controller declaration')
    return expected
