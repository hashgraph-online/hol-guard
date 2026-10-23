"""Version-scoped launch of the installed OMP native MCP proxy library.

These releases export RuntimeMcpGuardProxy but have no omp-mcp-proxy CLI.
The adapter supplies the missing entry point, without modifying installed bytes,
changing harness attribution, replacing policy, or emulating a response.
"""
from .json_data import canonical_json

LIBRARY_VERSIONS = frozenset({'3.48.0', '3.49.0', '3.50.0a5'})
FAMILIES = frozenset({'mail', 'crm', 'calendar', 'docs', 'tables', 'chat', 'tickets'})
ENTRY = '''import json,sys
from pathlib import Path
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import load_guard_config,overlay_synced_guard_policy
from codex_plugin_scanner.guard.synced_policy import synced_policy_payload
from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy
from codex_plugin_scanner.guard.store import GuardStore
r=json.loads(sys.argv[1])
if set(r)!={'family','server_id'} or r['family'] not in {'mail','crm','calendar','docs','tables','chat','tickets'}:raise ValueError('fixed declared proxy required')
context=HarnessContext(Path('/product/home'),Path('/product/home/project'),Path('/product/guard'))
store=GuardStore(context.guard_home,allow_system_keyring=False)
current=lambda:overlay_synced_guard_policy(load_guard_config(context.guard_home,workspace=context.workspace_dir),synced_policy_payload(store))
proxy=RuntimeMcpGuardProxy(harness='omp',server_name=r['family'],
 command=['/usr/bin/python3','/product/public/service_relay.py','--socket','/upstream/'+r['family']+'.sock'],
 context=context,store=store,config=current(),source_scope='project',
 config_path='/product/public/mcp.json',transport='stdio',server_id=r['server_id'],
 server_env_keys=(),current_config_provider=current)
raise SystemExit(proxy.serve())
'''


def library_command(python, *, version, family, server_id):
    if version not in LIBRARY_VERSIONS or family not in FAMILIES:
        raise ValueError('explicit supported release and MCP family required')
    return [str(python),'-I','-B','-c',ENTRY,
            canonical_json({'family':family,'server_id':server_id})]
