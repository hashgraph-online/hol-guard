"""Durable provider-side reservations before token generation, including cache input.

The trusted local provider supplies the exact tokenized prompt length and output
bound. Unknown/interrupted requests retain their full reservation and halt new
admissions. This journal is operational accounting, not verifier eligibility.
"""
from __future__ import annotations

import fcntl
import os
import re
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path

from .json_data import canonical_json, digest, strict_json_loads

MAX_LOG = 16 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{64}')


class QuotaDeniedError(ValueError):
    """No inference may start under the current durable budget state."""


def _integer(value, *, minimum=0, maximum=1_000_000_000):
    if type(value) is not int or not minimum <= value <= maximum:
        raise QuotaDeniedError('quota integer outside its explicit bound')
    return value


def _sha(value):
    if type(value) is not str or SHA.fullmatch(value) is None:
        raise QuotaDeniedError('quota requires a lowercase immutable input digest')
    return value


class ProviderQuota:
    def __init__(self, root: Path, *, expected_config_digest: str,
                 expected_allowance_digest: str | None = None):
        self.root = Path(root)
        self.expected_config_digest = _sha(expected_config_digest)
        self.expected_allowance_digest = (_sha(expected_allowance_digest)
                                          if expected_allowance_digest is not None else None)
        self._root_check()
        with self._locked():
            self._state()

    @classmethod
    def create(cls, root: Path, *, authorization_id: str, total_tokens: int,
               maximum_requests: int, model_identity_digest: str):
        if (type(authorization_id) is not str
                or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', authorization_id) is None):
            raise QuotaDeniedError('bounded external authorization identity required')
        config = {'schema': 'gauntlet-provider-quota.v1', 'authorization_id': authorization_id,
                  'quota_id': uuid.uuid4().hex,
                  'total_tokens': _integer(total_tokens, minimum=1),
                  'maximum_requests': _integer(maximum_requests, minimum=1, maximum=10000),
                  'model_identity_digest': _sha(model_identity_digest), 'maximum_inflight': 1}
        root = Path(root)
        if not root.is_absolute() or root.resolve() != root:
            raise QuotaDeniedError('new canonical absolute quota directory required')
        root.mkdir(mode=0o700)
        root.chmod(0o700)
        descriptor = os.open(root/'config.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write((canonical_json(config)+'\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
        for name in ('events.jsonl', 'quota.lock'):
            descriptor = os.open(root/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        cls._fsync_directory(root)
        return cls(root, expected_config_digest=digest(config))

    @staticmethod
    def _fsync_directory(path):
        descriptor = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _root_check(self):
        root = self.root
        if not root.is_absolute() or root.resolve() != root:
            raise QuotaDeniedError('canonical absolute quota directory required')
        info = root.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid in {10001, 10004}):
            raise QuotaDeniedError('quota storage must remain private to its trusted provider')
        for parent in root.parents:
            meta = parent.lstat()
            sticky = meta.st_uid == 0 and meta.st_mode & stat.S_ISVTX
            if meta.st_uid not in {0, os.geteuid()} or (meta.st_mode & 0o022 and not sticky):
                raise QuotaDeniedError('quota ancestry is writable outside trusted provider authority')

    def _open(self, name, flags):
        try:
            descriptor = os.open(self.root/name, flags|os.O_NOFOLLOW)
        except OSError as error:
            raise QuotaDeniedError('required durable quota state is missing or inaccessible') from error
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            os.close(descriptor)
            raise QuotaDeniedError('quota files must be exclusively owned private regular files')
        return descriptor

    @contextmanager
    def _locked(self):
        self._root_check()
        descriptor = self._open('quota.lock', os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read(self, name, *, limit=MAX_LOG):
        descriptor = self._open(name, os.O_RDONLY)
        with os.fdopen(descriptor, 'rb') as stream:
            if os.fstat(stream.fileno()).st_size > limit:
                raise QuotaDeniedError('quota journal exceeds its bound')
            raw = stream.read(limit+1)
        if len(raw) > limit:
            raise QuotaDeniedError('quota journal exceeds its bound')
        return raw

    def _state(self):
        config = strict_json_loads(self._read('config.json', limit=16384))
        if (set(config) != {'schema','authorization_id','quota_id','total_tokens','maximum_requests',
                           'model_identity_digest','maximum_inflight'}
                or config['schema'] != 'gauntlet-provider-quota.v1'
                or type(config['maximum_inflight']) is not int or config['maximum_inflight'] != 1
                or type(config['quota_id']) is not str or re.fullmatch(r'[0-9a-f]{32}',config['quota_id']) is None
                or digest(config) != self.expected_config_digest):
            raise QuotaDeniedError('provider quota configuration differs from external pin')
        _integer(config['total_tokens'], minimum=1)
        _integer(config['maximum_requests'], minimum=1, maximum=10000)
        _sha(config['model_identity_digest'])
        raw = self._read('events.jsonl')
        if raw and not raw.endswith(b'\n'):
            raise QuotaDeniedError('interrupted quota append requires explicit reconciliation')
        previous, pending, finished, charged, requests, halted = '0'*64, {}, set(), 0, 0, False
        token_cap, allowance_digest, authorizations = config['total_tokens'], None, set()
        rows = raw.splitlines()
        if len(rows) > 30000:
            raise QuotaDeniedError('provider quota journal row bound exceeded')
        for sequence, line in enumerate(rows):
            row = strict_json_loads(line)
            if (set(row) != {'sequence','previous_hash','config_digest','event'}
                    or type(row['sequence']) is not int or row['sequence'] != sequence
                    or row['previous_hash'] != previous or row['config_digest'] != self.expected_config_digest):
                raise QuotaDeniedError('provider quota journal chain or configuration changed')
            event = row['event']
            if type(event) is not dict or not {'type','reservation_id'} <= event.keys():
                raise QuotaDeniedError('malformed provider quota event')
            kind, key = event['type'], event['reservation_id']
            if type(key) is not str or re.fullmatch(r'[0-9a-f]{32}', key) is None:
                raise QuotaDeniedError('quota reservation identity malformed')
            if kind == 'extend_allowance':
                if (set(event) != {'type','reservation_id','total_tokens','authorization_digest'}
                        or pending or halted or key in finished):
                    raise QuotaDeniedError('allowance extension requires settled known usage')
                new_cap = _integer(event['total_tokens'], minimum=1)
                authorization = _sha(event['authorization_digest'])
                if new_cap <= token_cap or authorization in authorizations:
                    raise QuotaDeniedError('allowance extension must increase the lifetime ceiling')
                token_cap, allowance_digest = new_cap, authorization
                authorizations.add(authorization)
                finished.add(key)
            elif kind == 'reserve':
                if (set(event) != {'type','reservation_id','prompt_tokens','output_limit','request_digest'}
                        or pending or key in finished or halted):
                    raise QuotaDeniedError('overlapping, repeated or halted quota admission')
                prompt = _integer(event['prompt_tokens'], minimum=1)
                output = _integer(event['output_limit'], minimum=1)
                _sha(event['request_digest'])
                requests += 1
                if requests > config['maximum_requests'] or charged+prompt+output > token_cap:
                    raise QuotaDeniedError('quota journal exceeds the approved provider budget')
                pending[key] = event
                charged += prompt+output
            elif kind == 'settle':
                if (set(event) != {'type','reservation_id','prompt_tokens','output_tokens'}
                        or key not in pending or halted):
                    raise QuotaDeniedError('quota settlement lacks its exact reserved request')
                lease = pending.pop(key)
                output = _integer(event['output_tokens'])
                if type(event['prompt_tokens']) is not int or event['prompt_tokens'] != lease['prompt_tokens']:
                    raise QuotaDeniedError('actual prompt count differs from its pre-generation reservation')
                if output > lease['output_limit']:
                    raise QuotaDeniedError('provider emitted more tokens than its reserved generation limit')
                charged -= lease['output_limit']-output
                finished.add(key)
            elif kind == 'uncertain':
                if (set(event) != {'type','reservation_id','reason'} or key not in pending or halted
                        or type(event['reason']) is not str or not 1 <= len(event['reason']) <= 256):
                    raise QuotaDeniedError('unknown-usage witness lacks an active exact reservation')
                halted = True
            else:
                raise QuotaDeniedError('unknown provider quota journal event')
            previous = digest(row)
        if allowance_digest != self.expected_allowance_digest:
            raise QuotaDeniedError('provider allowance differs from external authorization pin')
        return {'config': config, 'last_hash': previous, 'rows': len(rows), 'charged_tokens': charged,
                'pending': pending, 'requests': requests, 'halted': halted,
                'token_cap': token_cap, 'allowance_digest': allowance_digest,
                'authorizations': authorizations}

    def extend_allowance(self, *, total_tokens: int, authorization_digest: str,
                         expected_journal_hash: str):
        """Append an externally authorized lifetime ceiling; never reset accounting.

        The trusted caller must retain the authorization document whose digest
        it supplies. This is an accounting operation, not proof of user consent.
        Existing instances fail closed after this append; callers must adopt the
        returned instance and pin the new authorization in deployment inputs.
        """
        total_tokens = _integer(total_tokens, minimum=1)
        authorization_digest = _sha(authorization_digest)
        expected_journal_hash = _sha(expected_journal_hash)
        with self._locked():
            state = self._state()
            if (state['pending'] or state['halted']
                    or state['last_hash'] != expected_journal_hash):
                raise QuotaDeniedError('allowance extension requires the exact settled journal')
            if (total_tokens <= state['token_cap']
                    or authorization_digest in state['authorizations']):
                raise QuotaDeniedError('allowance extension must increase the lifetime ceiling')
            self._append(state, {'type':'extend_allowance','reservation_id':uuid.uuid4().hex,
                                'total_tokens':total_tokens,
                                'authorization_digest':authorization_digest})
        return type(self)(self.root, expected_config_digest=self.expected_config_digest,
                          expected_allowance_digest=authorization_digest)

    def _append(self, state, event):
        row = {'sequence': state['rows'], 'previous_hash': state['last_hash'],
               'config_digest': self.expected_config_digest, 'event': event}
        data = (canonical_json(row)+'\n').encode()
        if state['rows'] >= 30000:
            raise QuotaDeniedError('quota journal row bound exceeded')
        descriptor = self._open('events.jsonl', os.O_WRONLY|os.O_APPEND)
        with os.fdopen(descriptor, 'ab') as stream:
            if os.fstat(stream.fileno()).st_size+len(data) > MAX_LOG:
                raise QuotaDeniedError('quota journal byte bound exceeded')
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def reserve(self, *, prompt_tokens: int, output_limit: int, request_digest: str,
                maximum_accounted_tokens: int | None = None):
        prompt_tokens = _integer(prompt_tokens, minimum=1)
        output_limit = _integer(output_limit, minimum=1)
        request_digest = _sha(request_digest)
        if maximum_accounted_tokens is not None:
            maximum_accounted_tokens = _integer(maximum_accounted_tokens, minimum=1)
        with self._locked():
            state = self._state()
            if state['halted'] or state['pending']:
                raise QuotaDeniedError('unsettled or unknown usage prevents new provider inference')
            ceiling = (state['token_cap'] if maximum_accounted_tokens is None else
                       min(state['token_cap'], maximum_accounted_tokens))
            if (state['requests'] >= state['config']['maximum_requests']
                    or state['charged_tokens']+prompt_tokens+output_limit > ceiling):
                raise QuotaDeniedError('request exceeds the remaining approved provider budget')
            key = uuid.uuid4().hex
            self._append(state, {'type':'reserve','reservation_id':key,'prompt_tokens':prompt_tokens,
                                'output_limit':output_limit,'request_digest':request_digest})
            return key

    def settle(self, key, *, prompt_tokens: int, output_tokens: int):
        _integer(prompt_tokens, minimum=1)
        _integer(output_tokens)
        with self._locked():
            state = self._state()
            lease = state['pending'].get(key)
            if (lease is None or state['halted'] or prompt_tokens != lease['prompt_tokens']
                    or output_tokens > lease['output_limit']):
                raise QuotaDeniedError('quota settlement does not match the active known-usage reservation')
            self._append(state, {'type':'settle','reservation_id':key,
                                'prompt_tokens':prompt_tokens,'output_tokens':output_tokens})

    def uncertain(self, key, *, reason: str):
        if type(reason) is not str or not 1 <= len(reason) <= 256:
            raise QuotaDeniedError('bounded unknown-usage reason required')
        with self._locked():
            state = self._state()
            if key not in state['pending'] or state['halted']:
                raise QuotaDeniedError('unknown usage must refer to the single active reservation')
            self._append(state, {'type':'uncertain','reservation_id':key,'reason':reason})

    def snapshot(self):
        with self._locked():
            state = self._state()
            reserved = sum(e['prompt_tokens']+e['output_limit'] for e in state['pending'].values())
            return {'schema':'gauntlet-provider-quota-status.v1','config_digest':self.expected_config_digest,
                    'model_identity_digest':state['config']['model_identity_digest'],
                    'token_cap':state['token_cap'],'charged_tokens':state['charged_tokens'],
                    'known_tokens':state['charged_tokens']-reserved,'reserved_tokens':reserved,
                    'requests':state['requests'],'maximum_requests':state['config']['maximum_requests'],
                    'pending_requests':len(state['pending']),'halted':state['halted'],
                    'remaining_tokens':state['token_cap']-state['charged_tokens'],
                    **({'allowance_digest':state['allowance_digest']}
                       if state['allowance_digest'] is not None else {}),
                    'journal_hash':state['last_hash'],'qualification_eligible':False}
