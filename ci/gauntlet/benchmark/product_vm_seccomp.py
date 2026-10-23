"""Pinned native-aarch64 syscall floor for the proposed product VM profile.

Trusted bootstrap code only. This neither establishes VM custody nor enables an
executor. The base is the captured zero-capability Podman OCI filter, followed by
a native-only socket filter. The default permits Unix/route-netlink only; the
separate private-loopback profile also admits IP in a checked empty net namespace.
No captured Python is evaluated. Route netlink supports Bubblewrap loopback setup.
"""
from __future__ import annotations

import ctypes as c
import hashlib
import json
import platform
from pathlib import Path

PROFILE_SHA256 = 'c904570e61ccaf7d03b9814796c625913650d08f97144e32e7030c19adbbfee5'
LIBRARY = Path('/usr/lib/aarch64-linux-gnu/libseccomp.so.2.5.5')
LIBRARY_SHA256 = '3d128123b494ca9e88f3c237b0912397145af1754e86ea99f460af6857441f19'
ALLOW, ERRNO = 0x7fff0000, 0x00050000
OPS = {'SCMP_CMP_NE': 1, 'SCMP_CMP_LT': 2, 'SCMP_CMP_EQ': 4, 'SCMP_CMP_GT': 6}
ARCHES = {'SCMP_ARCH_AARCH64': 0xc00000b7, 'SCMP_ARCH_ARM': 0x40000028}


class Comparison(c.Structure):
    _fields_ = [('arg', c.c_uint), ('op', c.c_int), ('datum_a', c.c_uint64), ('datum_b', c.c_uint64)]


def _uint(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('invalid bounded seccomp integer')
    return value


def validate_profile(raw: bytes) -> dict:
    """Require the externally selected exact floor, then validate its grammar."""
    if not isinstance(raw, bytes) or len(raw) > 128 * 1024:
        raise ValueError('seccomp profile byte budget')
    if hashlib.sha256(raw).hexdigest() != PROFILE_SHA256:
        raise ValueError('seccomp floor digest mismatch')

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate seccomp field')
            result[key] = value
        return result

    profile = json.loads(raw, object_pairs_hook=unique,
                         parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    if (set(profile) != {'architectures', 'defaultAction', 'defaultErrnoRet', 'syscalls'}
            or profile['architectures'] != list(ARCHES)
            or profile['defaultAction'] != 'SCMP_ACT_ERRNO'
            or profile['defaultErrnoRet'] != 38
            or type(profile['syscalls']) is not list or len(profile['syscalls']) != 21):
        raise ValueError('unsupported seccomp floor')
    for rule in profile['syscalls']:
        if (not {'names', 'action'} <= set(rule)
                or set(rule) - {'names', 'action', 'args', 'errnoRet'}
                or type(rule['names']) is not list or not 1 <= len(rule['names']) <= 512
                or any(type(name) is not str or not name.isascii()
                       or not name.replace('_', '').isalnum() for name in rule['names'])):
            raise ValueError('invalid seccomp rule')
        _action(rule)
        args = rule.get('args', [])
        if type(args) is not list or len(args) > 6:
            raise ValueError('invalid seccomp comparisons')
        for arg in args:
            if set(arg) != {'index', 'op', 'value'} or arg['op'] not in OPS:
                raise ValueError('unsupported seccomp comparison')
            _uint(arg['index'], 5)
            _uint(arg['value'], 2**64 - 1)
    return profile


def _action(rule):
    if rule['action'] == 'SCMP_ACT_ALLOW' and 'errnoRet' not in rule:
        return ALLOW
    if rule['action'] == 'SCMP_ACT_ERRNO':
        value = _uint(rule.get('errnoRet'), 4095)
        if value:
            return ERRNO | value
    raise ValueError('unsupported seccomp action')


def _checked(result, operation):
    if result != 0:
        raise RuntimeError(f'{operation} failed: {result}')


def _library():
    if platform.system() != 'Linux' or platform.machine() != 'aarch64':
        raise ValueError('product VM syscall profile requires native Linux aarch64')
    if LIBRARY.resolve() != LIBRARY or hashlib.sha256(LIBRARY.read_bytes()).hexdigest() != LIBRARY_SHA256:
        raise ValueError('libseccomp library differs from pinned runtime')
    lib = c.CDLL(str(LIBRARY), use_errno=True)
    declarations = {
        'seccomp_init': (c.c_void_p, [c.c_uint32]),
        'seccomp_release': (None, [c.c_void_p]),
        'seccomp_arch_add': (c.c_int, [c.c_void_p, c.c_uint32]),
        'seccomp_arch_native': (c.c_uint32, []),
        'seccomp_syscall_resolve_name': (c.c_int, [c.c_char_p]),
        'seccomp_rule_add_array': (c.c_int, [c.c_void_p, c.c_uint32, c.c_int, c.c_uint, c.POINTER(Comparison)]),
        'seccomp_load': (c.c_int, [c.c_void_p]),
    }
    for name, (restype, argtypes) in declarations.items():
        function = getattr(lib, name)
        function.restype, function.argtypes = restype, argtypes
    if lib.seccomp_arch_native() != ARCHES['SCMP_ARCH_AARCH64']:
        raise ValueError('libseccomp native architecture mismatch')
    return lib


def _rule(lib, context, action, name, args=()):
    syscall = lib.seccomp_syscall_resolve_name(name.encode('ascii'))
    # Negative pseudo-numbers other than -1 are valid libseccomp syscall tokens.
    if syscall == -1:
        raise ValueError(f'unresolved pinned syscall: {name}')
    comparisons = (Comparison * len(args))(*(
        Comparison(arg['index'], OPS[arg['op']], arg['value'], 0) for arg in args))
    _checked(lib.seccomp_rule_add_array(context, action, syscall, len(args), comparisons), name)


def install(raw: bytes, *, network_profile='unix-only-v1') -> dict:
    """Install both filters in this zero-capability actor before any imports.

    Call only in a disposable child. On *any* exception the launcher must exit;
    successfully installing one of two layers is not a supported environment.
    This function never clears existing filters and cannot be used as a waiver.
    """
    if network_profile not in {'unix-only-v1','private-loopback-v1'}:
        raise ValueError('separately declared cell network profile required')
    profile = validate_profile(raw)
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if (status['Uid'].split() != ['10004'] * 4 or status['Gid'].split() != ['10004'] * 4
            or status['Groups'].strip() or status['NoNewPrivs'].strip() != '1'
            or any(int(status[name], 16) for name in ('CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb'))):
        raise ValueError('seccomp installation requires measured zero-capability UID10004/NNP')
    if network_profile=='private-loopback-v1':
        from .product_vm_network import observe
        observe()
    lib = _library()
    contexts = []
    try:
        base = lib.seccomp_init(ERRNO | profile['defaultErrnoRet'])
        if not base:
            raise RuntimeError('seccomp initialization failed')
        contexts.append(base)
        _checked(lib.seccomp_arch_add(base, ARCHES['SCMP_ARCH_ARM']), 'compatibility architecture')
        for rule in profile['syscalls']:
            for name in rule['names']:
                _rule(lib, base, _action(rule), name, rule.get('args', []))
        sockets = lib.seccomp_init(ALLOW)
        if not sockets:
            raise RuntimeError('socket filter initialization failed')
        contexts.append(sockets)
        # Unix and NETLINK_ROUTE, plus IP only in the separate loopback profile.
        # Each rule uses at most one comparison per argument for libseccomp.
        denied_families={0,*range(2,16)}
        if network_profile=='private-loopback-v1':
            denied_families-={2,10}
        for family in sorted(denied_families):
            _rule(lib, sockets, ERRNO | 1, 'socket',
                  [{'index': 0, 'op': 'SCMP_CMP_EQ', 'value': family}])
        _rule(lib, sockets, ERRNO | 1, 'socket',
              [{'index': 0, 'op': 'SCMP_CMP_GT', 'value': 16}])
        _rule(lib, sockets, ERRNO | 1, 'socket',
              [{'index': 0, 'op': 'SCMP_CMP_EQ', 'value': 16},
               {'index': 2, 'op': 'SCMP_CMP_NE', 'value': 0}])
        _rule(lib, sockets, ERRNO | 1, 'socketpair',
              [{'index': 0, 'op': 'SCMP_CMP_NE', 'value': 1}])
        # This second filter is native-only: incompatible syscall ABIs are killed
        # by libseccomp's bad-architecture action, preventing socketcall bypass.
        for context in contexts:
            _checked(lib.seccomp_load(context), 'seccomp_load')
        families=['AF_UNIX','AF_NETLINK:NETLINK_ROUTE']
        if network_profile=='private-loopback-v1':
            families+=['AF_INET:private-loopback','AF_INET6:private-loopback']
        return {'schema': 'product-vm-seccomp.v1', 'profile_sha256': PROFILE_SHA256,
                'library_sha256': LIBRARY_SHA256, 'socket_families':families,
                'declared_network_profile':network_profile,
                'executable_abi': 'aarch64', 'installed_layers': 2}
    finally:
        for context in contexts:
            lib.seccomp_release(context)
