"""Synthetic producer conformance, explicitly not a real model episode."""
import dataclasses
import hashlib
from queue import Queue
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark.mlx_quota_adapter import install_mlx_quota
from ci.gauntlet.benchmark.provider_quota import ProviderQuota, QuotaDeniedError


@dataclasses.dataclass
class Args:
    max_tokens: int = 4


@dataclasses.dataclass
class Context:
    prompt: list
    prompt_cache_count: int


@dataclasses.dataclass
class Response:
    token: int


def setup(tmp_path, *, cap=100, ceiling=None):
    source = tmp_path/'synthetic-server-source.py'
    source.write_text('# inert synthetic source identity, not a provider\n')
    quota = ProviderQuota.create((tmp_path/'quota').resolve(), authorization_id='synthetic-adapter-test',
        total_tokens=cap, maximum_requests=10, model_identity_digest='a'*64)

    class Generator:
        def __init__(self, provider, cache):
            self.model_provider, self.calls, self.tokenizations = provider, 0, 0
            self._is_distributed = False

        def _tokenize(self, tokenizer, request, args):
            self.tokenizations += 1
            return request['prompt'], [request['prompt']], ['assistant'], 'normal'

        def _serve_single(self, packet):
            output, request, args = packet
            self.calls += 1
            if request['mode'] == 'changed-input':
                args.max_tokens += 1
            prompt = self._tokenize(self.model_provider.tokenizer, request, args)[0]
            output.put(Context(prompt, len(prompt)-1))  # Most input is cached; still all charged.
            count = 5 if request['mode'] == 'overflow' else 2
            for token in range(count):
                output.put(Response(token))
            if request['mode'] == 'error':
                output.put(RuntimeError('synthetic failure after actual producer records'))
            else:
                output.put(None)

    server = SimpleNamespace(__file__=str(source),ResponseGenerator=Generator,
                             GenerationContext=Context,Response=Response)
    pin = hashlib.sha256(source.read_bytes()).hexdigest()
    record = install_mlx_quota(server,quota,expected_server_sha256=pin,
                               maximum_accounted_tokens=ceiling)
    provider = SimpleNamespace(cli_args=SimpleNamespace(prompt_concurrency=1,decode_concurrency=1),
                               tokenizer=object(),draft_model=None)
    generator = server.ResponseGenerator(provider,None)
    return quota,server,generator,record,pin


def emit(generator, *, mode='normal'):
    output = Queue()
    generator._serve_single((output,{'prompt':list(range(50)),'mode':mode},Args()))
    rows = []
    while not output.empty():
        rows.append(output.get_nowait())
    return rows


def test_cached_input_and_all_producer_output_charged_before_completion(tmp_path):
    quota,_,generator,record,_ = setup(tmp_path)
    assert generator._is_batchable(Args()) is False
    assert emit(generator)[-1] is None
    assert generator.tokenizations == 1  # Original producer receives the identical pre-counted tokens.
    assert quota.snapshot()['known_tokens'] == 52
    assert quota.snapshot()['pending_requests'] == 0
    assert record['batching'] is False and record['qualification_eligible'] is False


def test_over_budget_request_never_enters_generation(tmp_path):
    quota,_,generator,_,_ = setup(tmp_path,cap=53)  # Prompt50 + output bound4 cannot fit.
    assert isinstance(emit(generator)[-1],QuotaDeniedError)
    assert generator.calls == 0
    assert quota.snapshot()['requests'] == quota.snapshot()['charged_tokens'] == 0


def test_milestone_ceiling_reaches_real_reservation_before_generation(tmp_path):
    quota,_,generator,_,_ = setup(tmp_path, ceiling=53)
    assert isinstance(emit(generator)[-1], QuotaDeniedError)
    assert generator.calls == quota.snapshot()['requests'] == 0
    assert quota.snapshot()['token_cap']==100


def test_milestone_retains_full_cached_input_cost_across_requests(tmp_path):
    quota,_,generator,_,_ = setup(tmp_path, ceiling=90)
    assert emit(generator)[-1] is None
    assert quota.snapshot()['known_tokens']==52
    assert isinstance(emit(generator)[-1], QuotaDeniedError)
    assert generator.calls==1 and quota.snapshot()['known_tokens']==52


@pytest.mark.parametrize('mode', ['error','overflow','changed-input'])
def test_incomplete_or_changed_generation_retains_reservation_and_halts(tmp_path,mode):
    quota,_,generator,_,_ = setup(tmp_path)
    rows = emit(generator,mode=mode)
    assert isinstance(rows[-1],Exception) and rows[-1] is not None
    snapshot = quota.snapshot()
    assert snapshot['halted'] is True and snapshot['reserved_tokens'] == 54
    assert isinstance(emit(generator)[-1],QuotaDeniedError)
    assert generator.calls == 1


def test_source_substitution_or_double_installation_rejected(tmp_path):
    quota,server,_,_,pin = setup(tmp_path)
    with pytest.raises(QuotaDeniedError,match='exactly once'):
        install_mlx_quota(server,quota,expected_server_sha256=pin)
    with pytest.raises(QuotaDeniedError,match='source differs'):
        install_mlx_quota(server,quota,expected_server_sha256='0'*64)


def test_unsupported_concurrency_and_draft_refused(tmp_path):
    quota,server,generator,_,_ = setup(tmp_path)
    generator.model_provider.cli_args.prompt_concurrency = 2
    with pytest.raises(QuotaDeniedError,match='serial'):
        server.ResponseGenerator(generator.model_provider,None)
    generator.model_provider.cli_args.prompt_concurrency = 1
    generator.model_provider.draft_model = object()
    assert isinstance(emit(generator)[-1],QuotaDeniedError)
    assert generator.calls == quota.snapshot()['requests'] == 0


def test_final_http_queue_marker_waits_for_durable_settlement(tmp_path):
    quota,_,generator,_,_ = setup(tmp_path)
    class CheckingQueue(Queue):
        def put(self,value,*args,**kwargs):
            if value is None:
                snapshot = quota.snapshot()
                assert snapshot['pending_requests'] == 0 and snapshot['known_tokens'] == 52
            return super().put(value,*args,**kwargs)
    output = CheckingQueue()
    generator._serve_single((output,{'prompt':list(range(50)),'mode':'normal'},Args()))
    assert quota.snapshot()['charged_tokens'] == 52
