import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys
import unittest
from unittest.mock import Mock, patch

from ci.gauntlet.benchmark.release_mcp_entry import ENTRY, FAMILIES, library_command


class EntryTests(unittest.TestCase):
    def test_only_declared_releases_and_families_are_adapted(self):
        for version in ('3.48.0','3.49.0','3.50.0a5'):
            for family in FAMILIES:
                with self.subTest(version=version,family=family):
                    command=library_command(Path('/prefix/bin/python'),version=version,family=family,server_id='bound-id')
                    self.assertEqual(command[:4],['/prefix/bin/python','-I','-B','-c'])
                    self.assertEqual(json.loads(command[-1]),{'family':family,'server_id':'bound-id'})
        for version,family in [('3.50.0','docs'),('3.48.0','other')]:
            with self.assertRaises(ValueError):
                library_command('/python',version=version,family=family,server_id='id')

    def test_entry_delegates_policy_and_session_to_installed_omp_native_proxy(self):
        context=SimpleNamespace(guard_home=Path('/product/guard'),workspace_dir=Path('/product/home/project'))
        store,policy=object(),object()
        proxy=Mock();proxy.return_value.serve.return_value=17
        current=Mock(return_value=policy)
        synced=Mock(return_value={'signed_policy':'retained'})
        exports={
            'codex_plugin_scanner.guard.adapters.base':{'HarnessContext':Mock(return_value=context)},
            'codex_plugin_scanner.guard.config':{'load_guard_config':Mock(return_value=policy),'overlay_synced_guard_policy':current},
            'codex_plugin_scanner.guard.synced_policy':{'synced_policy_payload':synced},
            'codex_plugin_scanner.guard.proxy.runtime_mcp':{'RuntimeMcpGuardProxy':proxy},
            'codex_plugin_scanner.guard.store':{'GuardStore':Mock(return_value=store)},
        }
        modules={}
        for name,fields in exports.items():
            module=ModuleType(name);module.__dict__.update(fields);modules[name]=module
        with patch.dict(sys.modules,modules),patch.object(sys,'argv',['entry',json.dumps({'family':'docs','server_id':'bound-id'})]):
            with self.assertRaises(SystemExit) as result:
                exec(compile(ENTRY,'<release-mcp-entry>','exec'),{})
        self.assertEqual(result.exception.code,17)
        options=proxy.call_args.kwargs
        self.assertEqual(options['harness'],'omp')
        self.assertEqual(options['server_id'],'bound-id')
        self.assertEqual(options['command'],['/usr/bin/python3','/product/public/service_relay.py','--socket','/upstream/docs.sock'])
        self.assertIs(options['config'],policy)
        self.assertIs(options['current_config_provider'](),policy)
        current.assert_called_with(policy,{'signed_policy':'retained'})
        synced.assert_called_with(store)
        proxy.reset_mock()
        with patch.dict(sys.modules,modules),patch.object(sys,'argv',['entry',json.dumps({'family':'crm','server_id':'crm-id'})]):
            with self.assertRaises(SystemExit) as result:
                exec(compile(ENTRY,'<release-mcp-entry>','exec'),{})
        self.assertEqual(result.exception.code,17)
        self.assertEqual(proxy.call_args.kwargs['server_name'],'crm')
        self.assertEqual(proxy.call_args.kwargs['command'][-1],'/upstream/crm.sock')
