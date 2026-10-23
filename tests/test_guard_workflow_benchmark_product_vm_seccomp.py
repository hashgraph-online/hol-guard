"""Syscall contract tests; real-kernel controls are retained separately."""
from pathlib import Path

import pytest

from ci.gauntlet.benchmark import product_vm_seccomp as module

RAW = Path(module.__file__).with_name('product_vm_seccomp_oci_v1.json').read_bytes()


class Library:
    def __init__(self, fail_load=0):
        self.rules, self.arches, self.loaded, self.released = {}, [], [], []
        self.names, self.fail_load = {}, fail_load

    def seccomp_init(self, action):
        context = len(self.rules)+1
        self.rules[context] = {'default': action, 'rules': []}
        return context

    def seccomp_arch_add(self, context, architecture):
        self.arches.append((context, architecture))
        return 0

    def seccomp_syscall_resolve_name(self, name):
        self.names.setdefault(name, len(self.names)+1)
        return self.names[name]

    def seccomp_rule_add_array(self, context, action, syscall, count, comparisons):
        name = next(key.decode() for key, value in self.names.items() if value == syscall)
        self.rules[context]['rules'].append((name, action, [
            (item.arg, item.op, item.datum_a) for item in comparisons]))
        return 0

    def seccomp_load(self, context):
        self.loaded.append(context)
        return -1 if context == self.fail_load else 0

    def seccomp_release(self, context):
        self.released.append(context)


def install_environment(monkeypatch, **changes):
    status = {'Uid':'10004 10004 10004 10004', 'Gid':'10004 10004 10004 10004',
              'Groups':'', 'NoNewPrivs':'1', **{key:'0' for key in
              ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')}}
    status.update(changes)
    monkeypatch.setattr(module.Path, 'read_text', lambda self: '\n'.join(
        key+':'+value for key, value in status.items()))


def test_exact_captured_floor_and_reject_any_modified_bytes():
    floor = module.validate_profile(RAW)
    assert floor['defaultAction']=='SCMP_ACT_ERRNO' and floor['defaultErrnoRet']==38
    assert len(floor['syscalls'])==21
    for changed in (RAW+b' ', RAW.replace(b'SCMP_ACT_ERRNO', b'SCMP_ACT_ALLOW', 1), b'{}', b''):
        with pytest.raises(ValueError, match='digest'):
            module.validate_profile(changed)


@pytest.mark.parametrize('field,value', [('Uid','0 0 0 0'),('Gid','10001 '*4),('Groups','10004'),
    ('NoNewPrivs','0'), *[(name,'1') for name in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb')]])
def test_never_install_or_import_library_before_complete_privilege_drop(monkeypatch, field, value):
    install_environment(monkeypatch, **{field:value})
    monkeypatch.setattr(module, '_library', lambda: pytest.fail('library must not load'))
    with pytest.raises(ValueError, match='zero-capability'):
        module.install(RAW)


def test_base_rules_preserved_and_socket_layer_denies_host_channels(monkeypatch):
    install_environment(monkeypatch)
    library=Library()
    monkeypatch.setattr(module, '_library', lambda: library)
    result=module.install(RAW)
    assert result['installed_layers']==2 and library.loaded==library.released==[1,2]
    assert library.arches==[(1,module.ARCHES['SCMP_ARCH_ARM'])]
    base=module.validate_profile(RAW)
    expected=[(name,module._action(rule),[(arg['index'],module.OPS[arg['op']],arg['value'])
              for arg in rule.get('args',[])]) for rule in base['syscalls'] for name in rule['names']]
    assert library.rules[1]['default']==module.ERRNO|38
    assert library.rules[1]['rules']==expected
    sockets=library.rules[2]
    assert sockets['default']==module.ALLOW
    operators={1:lambda left,right:left!=right,4:lambda left,right:left==right,6:lambda left,right:left>right}

    def denied(name, family, protocol):
        args=[family % 2**64, 1, protocol]
        return any(rule_name==name and all(operators[op](args[index],value)
            for index,op,value in comparisons) for rule_name,action,comparisons in sockets['rules'])

    for family in (0,2,10,17,40,45,65535,-1):
        assert denied('socket',family,0), family
    assert not denied('socket',1,0) and not denied('socketpair',1,0)
    assert not denied('socket',16,0)
    assert all(denied('socket',16,protocol) for protocol in (1,9,15,2**32-1))
    assert all(denied('socketpair',family,0) for family in (0,2,16,40,-1))


@pytest.mark.parametrize('failed_layer', [1,2])
def test_partial_filter_installation_is_an_error_and_releases_contexts(monkeypatch, failed_layer):
    install_environment(monkeypatch)
    library=Library(fail_load=failed_layer)
    monkeypatch.setattr(module, '_library', lambda: library)
    with pytest.raises(RuntimeError,match='seccomp_load failed'):
        module.install(RAW)
    assert library.released==[1,2]
    assert library.loaded==list(range(1,failed_layer+1))


def test_loopback_profile_requires_topology_before_loading_library(monkeypatch):
    from ci.gauntlet.benchmark import product_vm_network as network
    install_environment(monkeypatch)
    def reject():
        raise ValueError('external topology')
    monkeypatch.setattr(network,'observe',reject)
    monkeypatch.setattr(module,'_library',lambda:pytest.fail('unsafe topology must not install'))
    with pytest.raises(ValueError,match='external topology'):
        module.install(RAW,network_profile='private-loopback-v1')


def test_loopback_profile_keeps_both_layers_and_non_ip_socket_denials(monkeypatch):
    from ci.gauntlet.benchmark import product_vm_network as network
    install_environment(monkeypatch)
    library=Library()
    monkeypatch.setattr(network,'observe',lambda:{'interfaces':['lo']})
    monkeypatch.setattr(module,'_library',lambda:library)
    result=module.install(RAW,network_profile='private-loopback-v1')
    assert library.loaded==[1,2] and result['declared_network_profile']=='private-loopback-v1'
    rules=library.rules[2]['rules']
    denied={args[0][2] for name,action,args in rules if name=='socket' and len(args)==1 and args[0][:2]==(0,4)}
    assert 2 not in denied and 10 not in denied and {0,3,15}<=denied
    assert ('socket',module.ERRNO|1,[(0,6,16)]) in rules
