"""Apply final Paseo review changes to one verified parent commit."""
from pathlib import Path
import ast
import runpy

root = Path.cwd()
src = root / 'src/codex_plugin_scanner/guard'
staging = Path(__file__).parent

p = src/'cli/grok_hook_validation.py'
s = p.read_text().replace('from ..adapters.base import _shell_command','from ..adapters.base import HarnessContext, _shell_command')
s = s.replace('def _config(text: str, executable: str, *, frozen: bool)', 'def _config(text: str, executable: str, *, frozen: bool, context: HarnessContext | None)')
s = s.replace('    return config\n', '''    if context is not None and not _matches_context(parsed, context):
        return None
    return config
''', 1)
at = s.index('\n\ndef _desktop_proxy(')
s = s[:at] + '''


def _matches_context(options: dict[str, str], context: HarnessContext) -> bool:
    """Require the bridge's store, effective home, and workspace to match its owner."""
    expected = {"--guard-home": context.guard_home, "--home": context.home_dir}
    actual = {"--guard-home": options["--guard-home"], "--home": options.get("--home", str(Path.home()))}
    if any(Path(actual[key]).resolve() != path.resolve() for key, path in expected.items()):
        return False
    workspace = options.get("--workspace")
    if context.workspace_dir is None:
        return workspace is None
    return workspace is not None and Path(workspace).resolve() == context.workspace_dir.resolve()
''' + s[at:]
s = s.replace('def _desktop_proxy(args: tuple[str, ...])', 'def _desktop_proxy(args: tuple[str, ...], context: HarnessContext | None)')
s = s.replace('_config(config, core, frozen=True)', '_config(config, core, frozen=True, context=context)')
s = s.replace('def is_grok_hook_command(command: str)', 'def is_grok_hook_command(command: str, context: HarnessContext | None = None)')
s = s.replace('_desktop_proxy(args)', '_desktop_proxy(args, context)')
s = s.replace('_config(args[2], args[0], frozen=True)', '_config(args[2], args[0], frozen=True, context=context)')
s = s.replace('_config(args[4], args[0], frozen=False)', '_config(args[4], args[0], frozen=False, context=context)')
p.write_text(s)
p=src/'cli/native_install_checks.py';s=p.read_text()
for name,arg in [('_grok_pretool_is_catchall','pretool_hook: Path'),('_grok_prompt_hook_is_observe','prompt_hook: Path'),('_grok_event_has_command_hook','entries: object'),('_grok_hook_command_is_guard','command: str')]:
    old=f'def {name}({arg})'; assert old in s
    s=s.replace(old,f'def {name}({arg}, context: HarnessContext | None = None)')
s=s.replace('_grok_hook_command_is_guard(command)', '_grok_hook_command_is_guard(command, context)')
s=s.replace('is_grok_hook_command(command)', 'is_grok_hook_command(command, context)')
s=s.replace('_grok_event_has_command_hook(hooks.get(event_name))', '_grok_event_has_command_hook(hooks.get(event_name), context)')
s=s.replace('_grok_pretool_is_catchall(pretool_hook)', '_grok_pretool_is_catchall(pretool_hook, context)')
s=s.replace('_grok_prompt_hook_is_observe(prompt_hook)', '_grok_prompt_hook_is_observe(prompt_hook, context)')
p.write_text(s)
p=src/'adapters/grok.py';s=p.read_text().replace('_grok_pretool_is_catchall(hooks_dir / GUARD_HOOK_PRETOOL_FILE)', '_grok_pretool_is_catchall(hooks_dir / GUARD_HOOK_PRETOOL_FILE, context)').replace('        hooks_dir / GUARD_HOOK_PROMPT_FILE\n', '        hooks_dir / GUARD_HOOK_PROMPT_FILE, context\n');p.write_text(s)

p = src/'inventory_contract.py'; original=p.read_text(); tree=ast.parse(original); lines=original.splitlines(keepends=True)
groups = {
 'inventory_contract_redaction': set('redact_local_path redact_headers redact_url classify_endpoint_host _safe_source_detail _safe_finding_text _safe_artifact_metadata _sanitize_paths _redact_known_path _redact_command_value _sanitize_serializer_string _assert_serialized_inventory_payload_safe _safe_json'.split()),
 'inventory_contract_fingerprints': set('fingerprint_text fingerprint_mapping _inventory_snapshot_content_hash _stable_snapshot_value _stable_snapshot_sort_key inventory_item_id fingerprint_path_tree _fingerprint_file_bytes'.split()),
 'inventory_contract_metadata': set('_aibom_detection_module _aibom_symlink_module _aibom_trust_metadata_module _inventory_item_description_module _item_kind _resolve_item_content_hash _discard_unverified_skill_directory_hash _primary_artifact_content_hash _canonical_inventory_content_hash _safe_roots_for_inspection _apply_source_of_truth_metadata _apply_aibom_metadata_enrichment _capabilities_for_artifact _bind_skill_document_evidence _risk_level'.split()),
 'inventory_contract_items': {'_item_from_artifact', '_mcp_tool_items_from_artifact'},
 'inventory_contract_mcp': set('_apply_tool_trust_attestation_metadata _attestation_path_hash _attestation_repository_id _optional_context_string _string_value _first_present_value _mcp_tool_definitions _mcp_schema_signal_text _capabilities_for_mcp_tool _risk_level_for_capabilities'.split()),
 'inventory_contract_scans': set('_cisco_inventory_findings _cisco_inventory_sources _cisco_source _inventory_severity _score_delta_for_severity _artifact_id_for_cisco_finding _source_status_for_cisco_status _symlink_findings_from_items'.split()),
}
module_for = {name:module for module,names in groups.items() for name in names}
def names_for(node):
    if isinstance(node,(ast.ClassDef,ast.FunctionDef)):return [node.name]
    if isinstance(node,(ast.Assign,ast.AnnAssign)):
        targets=node.targets if isinstance(node,ast.Assign) else [node.target]
        return [target.id for target in targets if isinstance(target,ast.Name)]
    return []
for node in tree.body:
    names=names_for(node)
    if isinstance(node,ast.ClassDef) or isinstance(node,ast.Assign) and any(not name.startswith('_') for name in names):
        for name in names:module_for[name]='inventory_contract_models'
    elif isinstance(node,(ast.Assign,ast.AnnAssign)):
        for name in names:module_for[name]='inventory_contract_constants'
    elif isinstance(node,ast.FunctionDef) and node.name not in module_for:module_for[node.name]='inventory_contract'
import_map={}
for node in tree.body:
    if isinstance(node,ast.Import):
        for alias in node.names:import_map[alias.asname or alias.name.split('.')[0]]='import '+alias.name+(' as '+alias.asname if alias.asname else '')
    if isinstance(node,ast.ImportFrom) and node.module!='__future__':
        prefix='from '+'.'*node.level+(node.module or '')+' import '
        for alias in node.names:import_map[alias.asname or alias.name]=prefix+alias.name+(' as '+alias.asname if alias.asname else '')
module_nodes={}
for node in tree.body:
    names=names_for(node)
    if names:module_nodes.setdefault(module_for[names[0]],[]).append(node)
module_edges={}
for module,nodes in module_nodes.items():
    referenced={x.id for node in nodes for x in ast.walk(node) if isinstance(x,ast.Name) and isinstance(x.ctx,ast.Load)}
    imports=[]; edges=set()
    for name in sorted(referenced):
        owner=module_for.get(name)
        if owner and owner != module:
            imports.append(f'from .{owner} import {name}');edges.add(owner)
        elif name in import_map:imports.append(import_map[name])
    if module=='inventory_contract':
        imports=[]
        for name,statement in import_map.items():
            if ' as ' not in statement:statement += f' as {name}'
            imports.append(statement)
        for name,owner in sorted(module_for.items()):
            if owner!=module:imports.append(f'from .{owner} import {name} as {name}')
    chunks=[]
    for node in nodes:
        start=min([node.lineno]+[d.lineno for d in getattr(node,'decorator_list',[])])-1
        chunks.append(''.join(lines[start:node.end_lineno]).rstrip())
    label={
       'inventory_contract':'Public inventory API and snapshot assembly; legacy exports remain compatible.',
       'inventory_contract_models':'Inventory value types and immutable wire-contract models.',
       'inventory_contract_constants':'Shared inventory redaction, capability, and wire-format constants.',
       'inventory_contract_redaction':'Inventory redaction and safe serialization of untrusted strings.',
       'inventory_contract_fingerprints':'Stable content identities and bounded inventory fingerprints.',
       'inventory_contract_metadata':'Inventory evidence enrichment and safe source-of-truth inspection.',
       'inventory_contract_items':'Native artifact and MCP-tool inventory item assembly.',
       'inventory_contract_mcp':'MCP capability classification and tool attestation metadata.',
       'inventory_contract_scans':'Scanner results and symlink findings normalized into inventory evidence.'
    }[module]
    output=f'"""{label}"""\n\nfrom __future__ import annotations\n\n'+'\n'.join(sorted(set(imports)))+'\n\n\n'+'\n\n\n'.join(chunks)+'\n'
    (src/(module+'.py')).write_text(output)
    module_edges[module]=edges
assert all('inventory_contract' not in edges for module,edges in module_edges.items() if module!='inventory_contract'),module_edges
p=root/'tests/test_guard_protection_recovery.py';s=p.read_text();s=s.replace('def _ctx(tmp_path: Path) -> HarnessContext:\n    return HarnessContext(','''def _ctx(tmp_path: Path) -> HarnessContext:
    """Match the machine-wide installs registered with workspace=None in these tests."""
    return HarnessContext(''').replace('        workspace_dir=tmp_path / "workspace",','        workspace_dir=None,');p.write_text(s)
(root/'tests/test_grok_hook_context.py').write_text((staging/'context_test.py').read_text())
runpy.run_path(str(staging/'docs.py'))
