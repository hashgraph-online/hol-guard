"""Exact-token quota seam for the pinned MLX-LM single-request producer.

No MLX import occurs here. The owned launcher supplies its pinned server module.
The original tokenizer and generation implementation remain in use; batching is
explicitly disabled. Production consumers must review this version-specific seam.
"""
from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path

from .json_data import digest
from .provider_quota import ProviderQuota, QuotaDeniedError


def install_mlx_quota(server, quota: ProviderQuota, *, expected_server_sha256: str,
                      maximum_accounted_tokens: int | None = None):
    if maximum_accounted_tokens is not None and (
            type(maximum_accounted_tokens) is not int or not 1<=maximum_accounted_tokens<=1_000_000_000):
        raise QuotaDeniedError('positive bounded cumulative provider ceiling required')
    path = Path(server.__file__)
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected_server_sha256:
        raise QuotaDeniedError('actual provider server source differs from its frozen quota adapter pin')
    original = server.ResponseGenerator
    if getattr(original, '_hol_provider_quota_installed', False):
        raise QuotaDeniedError('provider quota adapter must be installed exactly once')

    class QuotaResponseGenerator(original):
        _hol_provider_quota_installed = True

        def __init__(self, model_provider, prompt_cache):
            self._quota_fault = None
            args = model_provider.cli_args
            if args.prompt_concurrency != 1 or args.decode_concurrency != 1:
                raise QuotaDeniedError('provider quota requires frozen serial prompt/decode concurrency')
            super().__init__(model_provider, prompt_cache)

        def _is_batchable(self, args):
            return False

        def _serve_single(self, packet):
            output, request, args = packet
            lease = None
            settled = False
            queue = None
            original_tokenize = self._tokenize
            try:
                if self._quota_fault is not None:
                    raise QuotaDeniedError('provider process stopped after an unresolved durable quota fault')
                if self.model_provider.draft_model is not None or self._is_distributed:
                    raise QuotaDeniedError('draft/distributed generation is outside this exact-token quota profile')
                tokenizer = self.model_provider.tokenizer
                tokenized = original_tokenize(tokenizer, request, args)
                prompt = tokenized[0]
                if (not isinstance(prompt, list) or not prompt
                        or any(type(token) is not int or token < 0 for token in prompt)):
                    raise QuotaDeniedError('exact original tokenizer token IDs are required before admission')
                input_digest = digest({'prompt_token_ids': prompt, 'generation_args': dataclasses.asdict(args)})
                bounds = ({} if maximum_accounted_tokens is None else
                          {'maximum_accounted_tokens': maximum_accounted_tokens})
                lease = quota.reserve(prompt_tokens=len(prompt), output_limit=args.max_tokens,
                                      request_digest=input_digest, **bounds)

                def frozen_tokenize(actual_tokenizer, actual_request, actual_args):
                    if (actual_tokenizer is not tokenizer or actual_request is not request or actual_args is not args
                            or digest({'prompt_token_ids': prompt,
                                       'generation_args': dataclasses.asdict(args)}) != input_digest):
                        raise QuotaDeniedError('generation inputs changed after their exact reservation')
                    return tokenized

                self._tokenize = frozen_tokenize
                queue = _QuotaQueue(output, server, prompt, args.max_tokens)
                super()._serve_single((queue, request, args))
                if queue.error is not None or not queue.ended or not queue.context_seen:
                    raise QuotaDeniedError('provider generation ended without complete producer-side usage')
                quota.settle(lease, prompt_tokens=len(prompt), output_tokens=queue.tokens)
                settled = True
                output.put(None)  # Complete only after durable accounting, including cancellation.
            except Exception as error:
                terminal = queue.error if queue is not None and queue.error is not None else error
                if lease is not None and not settled:
                    try:
                        quota.uncertain(lease, reason=type(error).__name__)
                    except Exception as quota_error:
                        self._quota_fault = type(quota_error).__name__
                        terminal = QuotaDeniedError('provider failure (' + type(terminal).__name__
                            + '); durable halt failed (' + self._quota_fault + ')')
                output.put(terminal)
            finally:
                self._tokenize = original_tokenize

    server.ResponseGenerator = QuotaResponseGenerator
    return {'schema': 'gauntlet-mlx-quota-adapter.v1', 'server_sha256': expected_server_sha256,
            'quota_config_digest': quota.expected_config_digest,
            **({'quota_allowance_digest': quota.expected_allowance_digest}
               if quota.expected_allowance_digest is not None else {}),
            'adapter_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'producer_mode': 'serial-original-tokenization-and-generation',
            'counting': 'full prompt including cached input plus every producer-emitted response token',
            'batching': False, 'draft': False, 'qualification_eligible': False}


class _QuotaQueue:
    """Observe the producer, not downstream HTTP consumption or client claims."""
    def __init__(self, output, server, prompt, limit):
        self.output, self.server, self.prompt, self.limit = output, server, tuple(prompt), limit
        self.tokens, self.ended, self.context_seen, self.error = 0, False, False, None

    def put(self, value):
        if isinstance(value, Exception):
            self.error = value
            return
        if value is None:
            if self.ended:
                raise QuotaDeniedError('provider producer completed twice')
            self.ended = True
            return
        if self.ended or self.error is not None:
            raise QuotaDeniedError('provider output followed terminal producer state')
        if isinstance(value, self.server.GenerationContext):
            if self.context_seen or tuple(value.prompt) != self.prompt:
                raise QuotaDeniedError('actual generation prompt differs from reserved exact token IDs')
            self.context_seen = True
        elif isinstance(value, self.server.Response):
            if not self.context_seen or self.tokens >= self.limit:
                raise QuotaDeniedError('provider response exceeds its admitted prompt/output bound')
            self.tokens += 1
        elif not (isinstance(value, tuple) and len(value) == 2
                  and all(type(number) is int and number >= 0 for number in value)):
            raise QuotaDeniedError('unknown provider-side output record')
        self.output.put(value)
