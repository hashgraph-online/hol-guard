"""Owned-provider compatibility for malformed model-selected tool syntax.

Keep the pinned server's existing ValueError rejection path. Never repair model
arguments or turn invalid syntax into an executable call. The observer retains
the exact bounded text before rejection, independently of downstream HTTP usage.
This module imports neither MLX nor product/candidate code.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


def install_tool_formatter_compat(server, *, expected_server_sha256, observe,
                                  nullable_parser_sha256=None):
    path = Path(server.__file__)
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected_server_sha256:
        raise ValueError('tool formatter server differs from frozen source')
    original = server.ToolCallFormatter
    if getattr(original, '_hol_syntax_compat', False):
        raise ValueError('tool formatter compatibility must be installed once')
    if not callable(observe):
        raise ValueError('trusted malformed-output observer required')
    nullable = nullable_parser_sha256 is not None
    if nullable:
        from .mlx_nullable_tool_schema import PARSER_SHA256, PROFILE, parser_schema_view, verify_parser
        if nullable_parser_sha256 != PARSER_SHA256:
            raise ValueError('nullable schema view requires the pinned Qwen XML parser')

    class SyntaxBoundFormatter(original):
        _hol_syntax_compat = True

        def __init__(self, tool_parser, tools, streaming=False):
            if nullable:
                verify_parser(tool_parser, nullable_parser_sha256)
            def checked(text, actual_tools):
                try:
                    return tool_parser(text, parser_schema_view(actual_tools) if nullable else actual_tools)
                except (SyntaxError, ValueError) as rejection:
                    if isinstance(rejection, ValueError) and not nullable:
                        raise
                    if type(text) is not str or len(text.encode()) > 1024**2:
                        raise RuntimeError('malformed tool text exceeds retention bound') from None
                    event = {
                        'schema': 'mlx-malformed-tool-output.v1',
                        'raw_text': text,
                        'raw_text_sha256': hashlib.sha256(text.encode()).hexdigest(),
                        'error_class': type(rejection).__name__,
                        'action': 'reject-tool-call-without-repair',
                    }
                    try:
                        observe(event)
                    except Exception as error:
                        # The upstream ValueError handler must not swallow a
                        # retention fault and report ordinary malformed output.
                        raise RuntimeError('malformed tool evidence retention failed') from error
                    # The original formatter already rejects ValueError per
                    # call and preserves other valid calls and HTTP accounting.
                    if isinstance(rejection, ValueError):
                        raise
                    raise ValueError('model-selected tool syntax is invalid') from None

            super().__init__(checked, tools, streaming=streaming)

    server.ToolCallFormatter = SyntaxBoundFormatter
    return {
        'schema': 'mlx-tool-formatter-compat.v2' if nullable else 'mlx-tool-formatter-compat.v1',
        'server_sha256': expected_server_sha256,
        'adapter_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'policy': 'retain-exact-invalid-text-and-reject-without-repair',
        **({'parser_schema_profile': PROFILE, 'parser_sha256': nullable_parser_sha256,
            'retained_error_classes': ['SyntaxError', 'ValueError']} if nullable else {}),
    }
