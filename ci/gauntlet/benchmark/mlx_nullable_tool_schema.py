"""Parser-only nullable type view; never change tool schemas or argument text.

The pinned Qwen XML parser handles literal null before type conversion, but
interprets JSON Schema type arrays as Python type names. Resolving a single
non-null type preserves that parser's null branch and the original MCP validator.
Ambiguous unions remain untouched; no answer or model output is reconstructed.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
from pathlib import Path

PARSER_SHA256 = '32de6d9f7472a1f00a2acfaacaf13e0e0864cfc19adebbff688ac5004b8ecc25'
PROFILE = 'qwen-xml-nullable-type-view.v2'
TYPES = {'string', 'integer', 'number', 'boolean', 'object', 'array'}


def verify_parser(parser, expected_sha256):
    if (expected_sha256 != PARSER_SHA256
            or getattr(parser, '__module__', None) != 'mlx_lm.tool_parsers.qwen3_coder'
            or getattr(parser, '__name__', None) != 'parse_tool_call'):
        raise ValueError('nullable schema view requires the pinned Qwen XML parser')
    filename = inspect.getsourcefile(parser)
    if filename is None:
        raise ValueError('nullable schema parser source is unavailable')
    path = Path(filename)
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha256:
        raise ValueError('nullable schema parser source differs from frozen pin')


def parser_schema_view(tools):
    """Detach schemas and select unambiguous parser conversion modes only."""
    result = copy.deepcopy(tools)
    if not isinstance(result, list):
        return result
    for tool in result:
        if not isinstance(tool, dict):
            continue
        function = tool.get('function')
        parameters = function.get('parameters') if isinstance(function, dict) else None
        properties = parameters.get('properties') if isinstance(parameters, dict) else None
        if not isinstance(properties, dict):
            continue
        for value in properties.values():
            if not isinstance(value, dict):
                continue
            types = value.get('type')
            if (type(types) is list and len(types) == 2
                    and all(type(name) is str for name in types) and 'null' in types):
                nonnull = [name for name in types if name != 'null']
                if len(nonnull) == 1 and nonnull[0] in TYPES:
                    # The upstream boolean converter maps any other text to
                    # False. Use its JSON/literal decoding branch instead, so
                    # malformed boolean text cannot become an invented value.
                    # Original schemas still validate the decoded value.
                    value['type'] = 'object' if nonnull[0] == 'boolean' else nonnull[0]
    return result
