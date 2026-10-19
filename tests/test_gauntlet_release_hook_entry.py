from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from ci.gauntlet.benchmark.release_hook_entry import ENTRY,hook_command


class HookEntryTests(unittest.TestCase):
    def test_native_omp_bridge_preserves_denial_receipt_and_normal_deadline(self):
        response={'decision':'deny','policy_action':'sandbox-required',
                  'required_execution_profile':'workspace-contained-v1'}
        adapter=ModuleType('codex_plugin_scanner.guard.adapters.pi_extension_native_hook')
        adapter.pi_native_hook_runtime=Mock(return_value=Path('/prefix/native'))
        result=SimpleNamespace(returncode=0,stdout=json.dumps({'status':200,'body':json.dumps(response)}).encode())
        raw=b'{"hook_event_name":"PreToolUse","tool_input":{"command":"python3 -m unittest"}}'
        output=io.StringIO()
        with patch.dict(sys.modules,{adapter.__name__:adapter}), \
             patch.object(sys,'argv',['entry','30','/runtime/home','/runtime/home/project']), \
             patch.object(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(raw))), \
             patch('subprocess.run',return_value=result) as run,redirect_stdout(output):
            with self.assertRaises(SystemExit) as exited:
                exec(compile(ENTRY,'<private-native-hook-client>','exec'),{})
        self.assertEqual(exited.exception.code,0)
        self.assertEqual(json.loads(output.getvalue()),response)
        argv=run.call_args.args[0]
        self.assertEqual(argv[:2],['/prefix/native','pi-hook-bridge'])
        config=json.loads(argv[2])
        self.assertEqual(config['harness'],'omp')
        self.assertEqual(config['guard_home'],'/product/guard')
        self.assertEqual(config['timeout_ms'],20300)
        self.assertEqual(json.loads(run.call_args.kwargs['input']),
                         {**json.loads(raw),'guard_remaining_ms':20300})
        self.assertEqual(run.call_args.kwargs['timeout'],29)
        adapter.pi_native_hook_runtime.assert_called_once_with(guard_home=Path('/product/guard'))

    def test_missing_native_bridge_refuses_without_http_or_cli_fallback(self):
        adapter=ModuleType('codex_plugin_scanner.guard.adapters.pi_extension_native_hook')
        adapter.pi_native_hook_runtime=Mock(return_value=None)
        with patch.dict(sys.modules,{adapter.__name__:adapter}), \
             patch.object(sys,'argv',['entry','30','/runtime/home','/runtime/home/project']), \
             patch.object(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(b'{}'))), \
             patch('subprocess.run') as run:
            with self.assertRaises(SystemExit) as exited:
                exec(compile(ENTRY,'<private-native-hook-client>','exec'),{})
        self.assertEqual(exited.exception.code,69)
        run.assert_not_called()

    def test_error_status_has_nonzero_exit_even_with_allow_body(self):
        adapter=ModuleType('codex_plugin_scanner.guard.adapters.pi_extension_native_hook')
        adapter.pi_native_hook_runtime=Mock(return_value=Path('/prefix/native'))
        result=SimpleNamespace(returncode=0,stdout=json.dumps({
            'status':503,'body':json.dumps({'decision':'allow'})}).encode())
        output=io.StringIO()
        with patch.dict(sys.modules,{adapter.__name__:adapter}), \
             patch.object(sys,'argv',['entry','30','/runtime/home','/runtime/home/project']), \
             patch.object(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(b'{}'))), \
             patch('subprocess.run',return_value=result),redirect_stdout(output):
            with self.assertRaises(SystemExit) as exited:
                exec(compile(ENTRY,'<private-native-hook-client>','exec'),{})
        self.assertEqual(exited.exception.code,69)

    def test_version_context_and_deadline_are_fixed(self):
        command=hook_command('/prefix/bin/python',version='3.48.0',timeout=30,
                             home='/runtime/home',workspace='/runtime/home/project')
        self.assertEqual(command[:4],['/prefix/bin/python','-I','-B','-c'])
        self.assertEqual(hook_command('/prefix/bin/python',version='3.50.0a5',timeout=30,
                             home='/runtime/home',workspace='/runtime/home/project')[:4],command[:4])
        for values in ({'version':'3.50.0'},{'timeout':True},{'home':'/root'},{'workspace':'/tmp'}):
            options={'version':'3.48.0','timeout':30,'home':'/runtime/home','workspace':'/runtime/home/project',**values}
            with self.assertRaises(ValueError):
                hook_command('/prefix/bin/python',**options)
