"""Data-only v3 proof that native Post reviewed the controller's captured output."""
from __future__ import annotations

import re

from .contained_output_binding import PROFILE, captured_output
from .product_custody import _require


def verify_contained_outputs(builtin):
    events = builtin['transport_observations']
    reviews = [row for row in events if row.get('kind')=='actual-hook-response']
    pres = {row['payload_digest']:row for row in reviews if row['hook_event_name']=='PreToolUse'}
    posts = {row['tool_call_id']:row for row in reviews if row['hook_event_name']=='PostToolUse'}
    consumed = [row for row in builtin['contained_transport_observations'] if row['kind']=='contained-route-consumed']
    bindings = [row for row in events if row.get('kind')=='actual-contained-output-binding']
    results = builtin['product_plane']['executions']
    _require(len(bindings)==len(consumed)==len(results),'contained output binding coverage differs from sinks')
    seen = set()
    for row in bindings:
        _require(set(row)=={'sequence','kind','tool_call_id','pre_payload_digest','payload_digest',
            'result_digest','output_sha256','sdk_output_sha256','schema'} and row['schema']==PROFILE
            and type(row['sdk_output_sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sdk_output_sha256']),
            'invalid controller contained output binding record')
        pre = pres.get(row['pre_payload_digest'])
        post = posts.get(row['tool_call_id'])
        matching = [result for result in results if result['payload_digest']==row['pre_payload_digest']]
        _require(pre is not None and post is not None and len(matching)==1
            and pre['tool_call_id']==row['tool_call_id'] and row['tool_call_id'] not in seen,
            'contained result transplanted to another SDK call')
        seen.add(row['tool_call_id'])
        expected = captured_output(matching[0])
        _require(row['result_digest']==expected['result_digest']
            and row['output_sha256']==expected['output_sha256']==post['actual_output_sha256']
            and row['payload_digest']==post['payload_digest'],
            'native Post output differs from actual contained result')
    _require(seen=={pres[row['payload_digest']]['tool_call_id'] for row in consumed},
             'consumed contained execution lacks its exact output binding')
    return len(bindings)
