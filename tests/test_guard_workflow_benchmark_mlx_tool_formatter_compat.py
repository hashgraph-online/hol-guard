"""Compatibility boundary contracts; installed MLX proof is a separate control."""
import hashlib
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark.mlx_tool_formatter_compat import install_tool_formatter_compat


@pytest.fixture
def case(tmp_path):
    source=tmp_path/'server.py';source.write_text('inert dependency identity')
    # This dependency stand-in captures the parser supplied to its constructor.
    # It does not impersonate MLX's formatter or supply installed-runtime proof.
    class Consumer:
        def __init__(self, parser, tools, streaming=False):
            self.parser,self.tools,self.streaming=parser,tools,streaming
    server=SimpleNamespace(__file__=str(source),ToolCallFormatter=Consumer)
    return server,hashlib.sha256(source.read_bytes()).hexdigest(),[]


def test_valid_arguments_and_schema_identity_are_untouched(case):
    server,pin,events=case;tools=[{'name':'synthetic-tool'}];value={'nested':{'answer':42}}
    def parser(text, actual_tools):
        assert text=='original text' and actual_tools is tools
        return value
    metadata=install_tool_formatter_compat(server,expected_server_sha256=pin,observe=events.append)
    formatter=server.ToolCallFormatter(parser,tools,streaming=True)
    assert formatter.parser('original text',tools) is value
    assert formatter.streaming is True and events==[]
    assert metadata['policy']=='retain-exact-invalid-text-and-reject-without-repair'


def test_syntax_failure_retains_exact_original_without_producing_a_call(case):
    server,pin,events=case;tools=[];raw='{"incomplete": invalid model syntax'
    def parser(text, actual_tools):
        assert text is raw and actual_tools is tools
        raise SyntaxError('invalid model syntax')
    install_tool_formatter_compat(server,expected_server_sha256=pin,observe=events.append)
    formatter=server.ToolCallFormatter(parser,tools)
    with pytest.raises(ValueError,match='model-selected tool syntax is invalid'):
        formatter.parser(raw,tools)
    assert events==[{'schema':'mlx-malformed-tool-output.v1','raw_text':raw,
        'raw_text_sha256':hashlib.sha256(raw.encode()).hexdigest(),
        'error_class':'SyntaxError','action':'reject-tool-call-without-repair'}]


@pytest.mark.parametrize('error',[ValueError('original rejection'),RuntimeError('engine fault'),OSError('storage fault')])
def test_other_failures_are_not_reclassified_or_hidden(case,error):
    server,pin,events=case
    def parser(*_):raise error
    install_tool_formatter_compat(server,expected_server_sha256=pin,observe=events.append)
    with pytest.raises(type(error)) as caught:server.ToolCallFormatter(parser,[]).parser('input',[])
    assert caught.value is error and events==[]


@pytest.mark.parametrize('fault',[OSError('storage fault'),ValueError('serialization fault')])
def test_observer_failure_cannot_be_claimed_as_retained_output(case,fault):
    server,pin,_=case
    def parser(*_):raise SyntaxError('invalid')
    def observe(_):raise fault
    install_tool_formatter_compat(server,expected_server_sha256=pin,observe=observe)
    with pytest.raises(RuntimeError,match='retention failed') as caught:
        server.ToolCallFormatter(parser,[]).parser('raw',[])
    assert caught.value.__cause__ is fault


def test_unbounded_malformed_output_never_reaches_observer(case):
    server,pin,events=case
    def parser(*_):raise SyntaxError('invalid')
    install_tool_formatter_compat(server,expected_server_sha256=pin,observe=events.append)
    with pytest.raises(RuntimeError,match='retention bound'):
        server.ToolCallFormatter(parser,[]).parser('x'*(1024**2+1),[])
    assert events==[]


def test_wrong_source_or_duplicate_installation_refused(case):
    server,pin,events=case;original=server.ToolCallFormatter
    with pytest.raises(ValueError,match='frozen source'):
        install_tool_formatter_compat(server,expected_server_sha256='0'*64,observe=events.append)
    assert server.ToolCallFormatter is original
    install_tool_formatter_compat(server,expected_server_sha256=pin,observe=events.append)
    with pytest.raises(ValueError,match='installed once'):
        install_tool_formatter_compat(server,expected_server_sha256=pin,observe=events.append)


def enable_nullable_standin(case, monkeypatch, observer=None):
    # Identity conformance uses the installed parser in a separate retained
    # control. These pure unit cases isolate callback/error behavior only.
    from ci.gauntlet.benchmark import mlx_nullable_tool_schema as nullable
    monkeypatch.setattr(nullable,'verify_parser',lambda *_:None)
    server,pin,events=case
    metadata=install_tool_formatter_compat(server,expected_server_sha256=pin,
        observe=observer or events.append,nullable_parser_sha256=nullable.PARSER_SHA256)
    return server,events,metadata


def test_v2_projects_only_schema_and_never_argument_text(case,monkeypatch):
    import copy
    tools=[{'function':{'name':'synthetic','parameters':{
        'properties':{'tenant':{'type':['string','null'],'enum':['synthetic-tenant',None]}}}}}]
    original=copy.deepcopy(tools)
    server,events,metadata=enable_nullable_standin(case,monkeypatch)
    raw='exact original model-selected text'
    result={'name':'synthetic','arguments':{'tenant':'synthetic-tenant'}}
    def parser(text,view):
        assert text is raw and view is not tools
        assert view[0]['function']['parameters']['properties']['tenant']=={
            'type':'string','enum':['synthetic-tenant',None]}
        return result
    assert server.ToolCallFormatter(parser,tools).parser(raw,tools) is result
    assert tools==original and events==[]
    assert metadata['schema']=='mlx-tool-formatter-compat.v2'
    assert metadata['retained_error_classes']==['SyntaxError','ValueError']


def test_v2_retains_valueerror_without_reclassifying_or_repairing(case,monkeypatch):
    server,events,_=enable_nullable_standin(case,monkeypatch)
    rejection=ValueError('original parser rejection')
    def parser(*_):raise rejection
    with pytest.raises(ValueError) as caught:
        server.ToolCallFormatter(parser,[]).parser('raw invalid argument',[])
    assert caught.value is rejection
    assert events[0]['error_class']=='ValueError'
    assert events[0]['raw_text']=='raw invalid argument'


@pytest.mark.parametrize('fault',[OSError('storage fault'),ValueError('observer fault')])
def test_v2_retention_failure_escapes_original_valueerror_path(case,monkeypatch,fault):
    def observer(_):raise fault
    server,_,_=enable_nullable_standin(case,monkeypatch,observer)
    def parser(*_):raise ValueError('invalid argument')
    with pytest.raises(RuntimeError,match='retention failed') as caught:
        server.ToolCallFormatter(parser,[]).parser('raw',[])
    assert caught.value.__cause__ is fault


def test_v2_does_not_hide_engine_errors(case,monkeypatch):
    server,events,_=enable_nullable_standin(case,monkeypatch)
    error=RuntimeError('engine fault')
    def parser(*_):raise error
    with pytest.raises(RuntimeError) as caught:
        server.ToolCallFormatter(parser,[]).parser('raw',[])
    assert caught.value is error and events==[]


def test_v2_wrong_parser_pin_is_rejected_before_formatter_install(case):
    server,pin,events=case
    original=server.ToolCallFormatter
    with pytest.raises(ValueError,match='pinned Qwen'):
        install_tool_formatter_compat(server,expected_server_sha256=pin,observe=events.append,
                                      nullable_parser_sha256='0'*64)
    assert server.ToolCallFormatter is original and events==[]
