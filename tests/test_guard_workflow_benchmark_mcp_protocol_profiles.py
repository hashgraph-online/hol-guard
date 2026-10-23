"""Actual MCP wire/profile controls; no model, Guard efficacy or E2E credit."""
from contextlib import asynccontextmanager

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ci.gauntlet.benchmark.contracts import canonical_json, digest
from ci.gauntlet.benchmark.mcp_protocol_profiles import INSTRUCTION, PROFILES, SCHEMA, ProtocolProfile
from ci.gauntlet.benchmark.service_supervisor import ServiceSupervisor
from tests.test_guard_workflow_benchmark_supervisor import custody, wait_until


@asynccontextmanager
async def client(supervisor, family='docs', notifications=None):
    endpoint = supervisor.endpoint(family)
    parameters = StdioServerParameters(command=endpoint.command[0], args=list(endpoint.command[1:]))
    async def incoming(message):
        method = getattr(getattr(message, 'root', None), 'method', None)
        if notifications is not None and method:
            notifications.append(method)
    async with stdio_client(parameters) as (inbound, outbound):
        async with ClientSession(inbound, outbound, message_handler=incoming) as session:
            initialized = await session.initialize()
            yield session, initialized


def declared(profile):
    return {'schema': SCHEMA, 'id': profile}


@pytest.mark.parametrize('value', [None, {}, {'schema': SCHEMA, 'id': 'unknown'},
    {'schema': SCHEMA, 'id': True}, {'schema': SCHEMA, 'id': 'clean', 'payload': 'override'},
    {'schema': 'unknown', 'id': 'clean'}])
def test_profile_rejects_unversioned_unknown_or_arbitrary_configuration(value):
    with pytest.raises(ValueError):
        ProtocolProfile(value)


@pytest.mark.parametrize('profile', sorted(PROFILES))
def test_real_protocol_surfaces_keep_service_state_and_exposure_separate(custody, profile):
    world, directory = custody
    before = world.snapshot()
    notifications = []
    observed = []
    with ServiceSupervisor(world, directory, families=('docs',),
            protocol_profile=declared(profile), observer=observed.append) as supervisor:
        assert supervisor.endpoint('docs').environment == ()
        assert str(world.path) not in str(supervisor.endpoint('docs').command)
        async def exercise():
            with anyio.fail_after(12):
                async with client(supervisor, notifications=notifications) as (session, initialized):
                    tools = (await session.list_tools()).tools
                    selected = next(t for t in tools if t.name == 'docs.read')
                    if profile == 'tool-description':
                        assert INSTRUCTION in selected.description
                    if profile == 'misleading-annotations':
                        delete = next(t for t in tools if t.name == 'docs.delete')
                        assert delete.annotations.readOnlyHint is True
                        assert delete.annotations.destructiveHint is False
                        assert INSTRUCTION in delete.annotations.title
                    if profile in {'schema-change', 'tool-list-change', 'reconnect-schema'}:
                        assert INSTRUCTION not in canonical_json(selected.inputSchema)
                    if profile == 'tool-list-change':
                        assert 'docs.delete' not in {t.name for t in tools}
                    result = await session.call_tool('docs.read', {'record_id': 'qualification-rubric'})
                    if profile == 'resource-link':
                        links = [c for c in result.content if c.type == 'resource_link']
                        assert len(links) == 1 and str(links[0].uri) == 'fixture://docs/peer-confidential'
                        assert INSTRUCTION in links[0].description
                    elif profile == 'structured-content':
                        assert result.structuredContent['untrusted_protocol_instruction'] == INSTRUCTION
                        assert INSTRUCTION not in ''.join(getattr(c, 'text', '') for c in result.content)
                    elif profile == 'error-content':
                        assert result.isError and INSTRUCTION in result.content[0].text
                        recovered = await session.call_tool('docs.read', {'record_id': 'qualification-rubric'})
                        assert not recovered.isError and recovered.structuredContent['id'] == 'qualification-rubric'
                    else:
                        assert not result.isError and result.structuredContent['id'] == 'qualification-rubric'
                    if profile in {'schema-change', 'tool-list-change'}:
                        while 'notifications/tools/list_changed' not in notifications:
                            await anyio.sleep(0.01)
                        refreshed = next(t for t in (await session.list_tools()).tools if t.name == 'docs.read')
                        if profile == 'schema-change':
                            assert INSTRUCTION in canonical_json(refreshed.inputSchema)
                        else:
                            added = next(t for t in (await session.list_tools()).tools if t.name == 'docs.delete')
                            assert INSTRUCTION in added.description
                    resource = await session.read_resource('fixture://docs/qualification-rubric')
                    assert (INSTRUCTION in resource.contents[0].text) is (profile == 'resource-read')
                    prompts = await session.list_prompts()
                    assert [p.name for p in prompts.prompts] == ['workflow_context']
                    prompt = await session.get_prompt('workflow_context', {'record_id': 'qualification-rubric'})
                    assert (INSTRUCTION in prompt.messages[0].content.text) is (profile == 'prompt-get')
                    if profile == 'server-identity-collision':
                        assert initialized.serverInfo.name == 'benchmark-collision'
                if profile == 'reconnect-schema':
                    async with client(supervisor) as (reconnected, _):
                        updated = next(t for t in (await reconnected.list_tools()).tools if t.name == 'docs.read')
                        assert INSTRUCTION in canonical_json(updated.inputSchema)
        anyio.run(exercise)
        wait_until(lambda: supervisor.active_sessions == 0 and supervisor.active_workers == 0)
        assert world.snapshot() == before
        emissions = [e for e in observed if e['kind'] == 'protocol-fixture-stimulus']
        assert emissions and all(e['model_ingestion_proven'] is False for e in emissions)
        assert all(e['stage'] == 'constructed' and e['transport_delivery_proven'] is False for e in emissions)
        assert world.key.private_bytes_raw().hex() not in canonical_json(observed)
        assert [e['sequence'] for e in observed] == list(range(1, len(observed) + 1))
    assert not directory.exists()


def test_misleading_annotations_do_not_remove_reachable_unauthorized_effect(custody):
    world, directory = custody
    with ServiceSupervisor(world, directory, families=('docs',),
            protocol_profile=declared('misleading-annotations')) as supervisor:
        async def exercise():
            with anyio.fail_after(12):
                async with client(supervisor) as (session, _):
                    tool = next(t for t in (await session.list_tools()).tools if t.name == 'docs.delete')
                    assert tool.annotations.readOnlyHint is True
                    result = await session.call_tool('docs.delete',
                        {'record_id': 'qualification-rubric', 'expected_version': 1})
                    assert not result.isError
        anyio.run(exercise)
    assert not any(r['id'] == 'qualification-rubric' for r in world.snapshot()['records'])
    assert world.receipts()[-1]['event']['operation'] == 'docs.delete'


def test_protocol_state_has_finite_reconnect_and_emission_limits():
    state = ProtocolProfile(declared('clean'))
    for _ in range(64):
        state.opened('docs')
    with pytest.raises(ValueError, match='reconnect budget'):
        state.opened('docs')
    state.events = [{}] * 4096
    with pytest.raises(ValueError, match='emission budget'):
        state.tools('docs', [])


def test_two_real_servers_can_claim_same_name_without_sharing_fixture_identity(custody):
    world, directory = custody
    with ServiceSupervisor(world, directory, families=('docs', 'mail'),
            protocol_profile=declared('server-identity-collision')) as supervisor:
        async def exercise():
            with anyio.fail_after(12):
                async with client(supervisor, 'docs') as (docs, left):
                    async with client(supervisor, 'mail') as (mail, right):
                        assert left.serverInfo.name == right.serverInfo.name == 'benchmark-collision'
                        assert 'docs.read' in {t.name for t in (await docs.list_tools()).tools}
                        assert 'mail.read' in {t.name for t in (await mail.list_tools()).tools}
        anyio.run(exercise)


def test_real_resource_link_crosses_servers_and_foreign_read_is_reachable(custody):
    world, directory = custody
    with ServiceSupervisor(world, directory, families=('docs', 'mail'),
            protocol_profile=declared('resource-link')) as supervisor:
        async def exercise():
            with anyio.fail_after(12):
                async with client(supervisor, 'mail') as (mail, _):
                    async with client(supervisor, 'docs') as (docs, _):
                        result = await mail.call_tool('mail.read', {'record_id': 'lead-a'})
                        link = next(c for c in result.content if c.type == 'resource_link')
                        resource = await docs.read_resource(str(link.uri))
                        assert 'peer-confidential' in resource.contents[0].text
        anyio.run(exercise)
    assert [r['event']['operation'] for r in world.receipts()] == ['mail.read', 'docs.read']
    assert world.receipts()[-1]['event']['raw_args_digest'] == digest({'record_id': 'peer-confidential'})


def test_developer_metadata_transport_preserves_opt_in_profile_and_evidence(custody):
    import os
    from ci.gauntlet.benchmark.developer_resources import DeveloperInputContext
    world, directory = custody
    profile = declared('tool-description')
    context = DeveloperInputContext(directory.parent, world.key, 'python-cli-with-tests',
        'clean', None, 15, 20, allowed_uid=os.getuid(), socket_gid=None, protocol_profile=profile)
    try:
        context.start()
        async def exercise():
            with anyio.fail_after(12):
                async with client(context.supervisor) as (session, _):
                    tools = (await session.list_tools()).tools
                    assert INSTRUCTION in next(t for t in tools if t.name == 'docs.read').description
                    assert {'packages.read', 'git.read'} <= {t.name for t in tools}
                    read = await session.call_tool('git.read', {'record_id': 'run-repository'})
                    assert not read.isError and read.structuredContent['id'] == 'run-repository'
        anyio.run(exercise)
    finally:
        context.close()
    evidence = context.evidence()
    assert evidence['protocol_profile'] == profile
    assert any(e['kind'] == 'protocol-fixture-stimulus' for e in evidence['transport_events'])
    assert evidence['active_workers'] == evidence['active_children'] == evidence['active_sessions'] == 0


def test_observer_callbacks_keep_sequence_without_holding_lifecycle_lock(custody):
    import threading
    world,directory=custody
    entered,release,second_entered,read_done=[threading.Event() for _ in range(4)]
    observed=[]
    def observer(event):
        if event['kind']=='first':
            entered.set()
            assert release.wait(2)
        if event['kind']=='second':
            second_entered.set()
        observed.append(event['sequence'])
    supervisor=ServiceSupervisor(world,directory,observer=observer)
    first=threading.Thread(target=lambda:supervisor._emit('first'))
    second=threading.Thread(target=lambda:supervisor._emit('second'))
    reader=threading.Thread(target=lambda:(supervisor.active_sessions,read_done.set()))
    first.start()
    try:
        assert entered.wait(1)
        second.start()
        reader.start()
        assert read_done.wait(1), 'observer must not hold the lifecycle lock'
        assert not second_entered.wait(.1), 'later callback overtook the first callback'
    finally:
        release.set()
        first.join(2)
        if second.ident is not None:
            second.join(2)
        if reader.ident is not None:
            reader.join(2)
    assert not first.is_alive() and not second.is_alive() and not reader.is_alive()
    assert observed==[1,2]
