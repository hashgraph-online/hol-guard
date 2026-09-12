from pathlib import Path
import ast, json
root=Path.cwd()
originals={}
def write(rel,s):
 p=root/rel
 if rel not in originals: originals[rel]=p.read_text() if p.exists() else None
 p.parent.mkdir(parents=True,exist_ok=True);p.write_text(s)
def replace(rel,old,new):
 s=(root/rel).read_text();assert s.count(old)==1,(rel,old[:70],s.count(old));write(rel,s.replace(old,new,1))
def function(rel,name,replacement):
 s=(root/rel).read_text();tree=ast.parse(s);n=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
 lines=s.splitlines(keepends=True);write(rel,''.join(lines[:n.lineno-1])+replacement.rstrip()+'\n'+''.join(lines[n.end_lineno:]))
base='src/codex_plugin_scanner/guard/'
rel='docs/guard/contracts/hook-data-plane-ownership.v2.json'
s=(root/rel).read_text()
s=s.replace('    "opencode",\n    "pi",','    "opencode",\n    "paseo",\n    "pi",')
s=s.replace('    "pi": {"pre_tool_use":', '    "paseo": {"pre_tool_use": "unavailable", "post_tool_use": "unavailable"},\n    "pi": {"pre_tool_use":')
write(rel,s)
rel=base+'adapters/contracts.py';s=(root/rel).read_text();i=s.index('        harness="paseo",');part=s[i:];assert 'browser_fallback=True' in part;write(rel,s[:i]+part.replace('browser_fallback=True','browser_fallback=False',1))
replace('docs/guard/harness-support.md','| `paseo` | `paseo` | ❌ | ✅ | ❌ | — |','| `paseo` | `paseo` | ❌ | ❌ | ❌ | — |')
rel='docs/guard/paseo.md';s=(root/rel).read_text();write(rel,s+'\nPaseo itself has no Guard hook endpoint or browser approval fallback. The ownership\nmanifest therefore marks its own pre/post-tool routes unavailable; supported\nprovider sessions keep their native harness identities and native Rust routes.\n')
replace(base+'adapters/paseo.py','        # A failed repair must not leave a receipt claiming the new install succeeded.\n        path.unlink(missing_ok=True)\n','        # Keep the last verified receipt until atomic replacement succeeds.\n')
function(base+'adapters/paseo_config.py','require_local_path','''def require_local_path(root: Path, path: Path, *, home_dir: Path | None = None) -> None:
    """Reject redirected ancestors and non-regular files before managed writes.

    A supplied user home is an explicit trust anchor and may itself be symlinked.
    Links below that home, including above a not-yet-created Guard root, are not.
    """
    root = Path(os.path.abspath(root))
    path = Path(os.path.abspath(path))
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise ValueError("Paseo managed path escapes its declared root.") from error
    anchor = Path(root.anchor)
    if home_dir is not None:
        home = Path(os.path.abspath(home_dir))
        if root.is_relative_to(home):
            anchor = home.resolve()
            root = anchor / root.relative_to(home)
            path = root / relative
    candidate = anchor
    for part in ("", *path.relative_to(anchor).parts):
        candidate = candidate / part if part else candidate
        if candidate.is_symlink():
            raise ValueError(f"Paseo refuses a symlink in a managed path: {candidate}")
        if candidate.exists():
            metadata = candidate.stat()
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise ValueError(f"Paseo requires regular managed files: {candidate}")
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise ValueError(f"Paseo refuses a multiply-linked managed file: {candidate}")
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Paseo managed path escapes its declared root.")
''')
for rel in [base+'adapters/paseo.py',base+'adapters/paseo_install.py']:
 s=(root/rel).read_text();lines=[]
 for line in s.splitlines():
  if 'require_local_path(' in line:
   line=line[:-1]+', home_dir=context.home_dir)'
  lines.append(line)
 write(rel,'\n'.join(lines)+'\n')
replace(base+'adapters/paseo_install.py','    manifest = get_adapter(harness).install(native_context(context))','    preflight_native(harness, context)\n    manifest = get_adapter(harness).install(native_context(context))')
replace(base+'adapters/paseo.py','        shim_manifest = install_guard_shim(self.harness, native_context(context))','        for shim in self.guard_launcher_paths(native_context(context)):\n            require_local_path(context.guard_home, shim, home_dir=context.home_dir)\n        shim_manifest = install_guard_shim(self.harness, native_context(context))')
rel=base+'adapters/paseo_config.py'
replace(rel,'def _override_reason(harness: str, entry: dict[str, object]) -> str | None:', 'def _override_reason(harness: str, entry: dict[str, object], context: HarnessContext) -> str | None:')
replace(rel,'    provider_keys = {str(key).upper() for key in environment}','''    def redirects(key: str, value: str) -> bool:
        """Allow only the normal XDG home, never alternate native configuration roots."""
        if key.upper() == "XDG_CONFIG_HOME" and (
            not value or Path(value).is_absolute() and Path(os.path.abspath(value)) == context.home_dir / ".config"
        ):
            return False
        return key.upper().startswith(prefixes)

    provider_keys = {str(key).upper() for key in environment}''')
replace(rel,'    if provider_keys.intersection(_COMMON_OVERRIDES) or any(key.startswith(prefixes) for key in provider_keys):','    if provider_keys.intersection(_COMMON_OVERRIDES) or any(redirects(key, value) for key, value in environment.items()):')
replace(rel,'    if any(value and key.upper().startswith(_RUNTIME_OVERRIDES[harness]) for key, value in os.environ.items()):','''    if any(
        value and key.upper().startswith(_RUNTIME_OVERRIDES[harness]) and redirects(key, value)
        for key, value in os.environ.items()
    ):''')
replace(rel,'def _provider(provider_id: str, raw: object, entries: dict[str, object]) -> PaseoProvider:', 'def _provider(\n    provider_id: str, raw: object, entries: dict[str, object], context: HarnessContext\n) -> PaseoProvider:')
replace(rel,'            reason = _override_reason(native, effective)','            reason = _override_reason(native, effective, context)')
replace(rel,'return tuple(_provider(key, value, entries) for key, value in sorted(entries.items()))','return tuple(_provider(key, value, entries, context) for key, value in sorted(entries.items()))')
replace(base+'aibom_cli.py','    snapshots = cloud_syncable_snapshots(snapshots)\n','''    snapshots = cloud_syncable_snapshots(snapshots)
    cloud_snapshot_ids = {snapshot.snapshot_id for snapshot in snapshots}
    primary_content_sources = [source for source in primary_content_sources if source.snapshot_id in cloud_snapshot_ids]
''')
replace(base+'aibom_reporting.py','    return redacted\n\n\ndef _aibom_connection_status','''    launch_command = item.get("launch_command")
    if isinstance(launch_command, str):
        from .inventory_contract import _redact_command_value

        redacted["launch_command"] = _redact_command_value(launch_command, home_dir, None)
    return redacted


def _aibom_connection_status''')
function(base+'cli/native_install_checks.py','_grok_hook_command_is_guard','''def _grok_hook_command_is_guard(command: str) -> bool:
    """Validate a serialized native hook invocation, not arbitrary Guard marker text."""
    from .grok_hook_validation import is_grok_hook_command

    return is_grok_hook_command(command)
''')
function(base+'cli/native_install_checks.py','_grok_managed_config_is_active','''def _grok_managed_config_is_active(managed_text: str) -> bool:
    """Require the credential deny rule in the parsed managed permission table."""
    from ..adapters.grok_config import GUARD_MANAGED_BEGIN, GUARD_MANAGED_END
    from ..codex_config import tomllib

    start = managed_text.find(GUARD_MANAGED_BEGIN)
    stop = managed_text.find(GUARD_MANAGED_END)
    if start < 0 or stop <= start:
        return False
    try:
        payload = tomllib.loads(managed_text[start:stop])
    except (ValueError, TypeError):
        return False
    permission = payload.get("permission")
    denied = permission.get("deny") if isinstance(permission, dict) else None
    return isinstance(denied, list) and "Read(**/.grok/auth/**)" in denied
''')
replace(base+'cli/native_install_checks.py','''    managed_text = managed_config.read_text(encoding="utf-8") if managed_config.is_file() else ""
    if not managed_config.is_file() or not _grok_managed_config_is_active(managed_text):''','''    try:
        managed_text = managed_config.read_text(encoding="utf-8") if managed_config.is_file() else ""
        managed_read_error = False
    except (OSError, UnicodeError):
        managed_text = ""
        managed_read_error = True
    if managed_read_error:
        warnings.append("Grok managed config could not be read. Re-run `hol-guard apps repair grok`.")
    elif not managed_config.is_file() or not _grok_managed_config_is_active(managed_text):''')
function('tests/test_guard_daemon_runtime_repair.py','test_live_identity_rejects_authenticated_probe_redirects','''def test_live_identity_rejects_authenticated_probe_redirects() -> None:
    """The authenticated production client must not follow even a loopback redirect."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread

    paths: list[str] = []

    class Redirect(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            """Record requests and redirect the health probe to a token collection path."""
            paths.append(self.path)
            self.send_response(302 if self.path.endswith("details") else 200)
            self.send_header("Location", "/collect")
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            """Suppress loopback-test access logs."""

    with ThreadingHTTPServer(("127.0.0.1", 0), Redirect) as server:
        worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        worker.start()
        try:
            result = live_identity._proxy_disabled_health_details(f"http://127.0.0.1:{server.server_port}", "token")
            assert result is None
            assert paths == ["/v1/healthz/details"]
        finally:
            server.shutdown()
            worker.join(timeout=2)
''')
rel='tests/test_guard_protection_recovery.py';s=(root/rel).read_text();s=s.replace('GROK\\ndeny =','GROK\\n[permission]\\ndeny =');write(rel,s)
rel='tests/test_paseo_adapter.py';s=(root/rel).read_text();s=s.replace('test_install_failure_removes_old_receipt_but_does_not_uninstall_shared_hooks','test_install_failure_preserves_last_receipt_and_shared_hooks');s=s.replace('A failed repair invalidates composite success without rolling back shared protection.','An unchanged installation remains tracked when a repair fails before writing.');s=s.replace('    original = extension.read_bytes()\n\n    def fail','    original = extension.read_bytes()\n    original_receipt = receipt_path(context).read_bytes()\n\n    def fail');s=s.replace('    assert not receipt_path(context).exists()\n    assert extension.read_bytes() == original\n    assert adapter.diagnostics(context)["setup_status"] != "active"','    assert receipt_path(context).read_bytes() == original_receipt\n    assert extension.read_bytes() == original\n    assert adapter.diagnostics(context)["setup_status"] == "active"');write(rel,s)
import shutil
sources=Path(__file__).parent
for name, rel in {
 'grok_hook_validation.py':base+'cli/grok_hook_validation.py',
 'test_grok_hook_validation.py':'tests/test_grok_hook_validation.py',
 'test_paseo_review_boundaries.py':'tests/test_paseo_review_boundaries.py',
}.items():
 shutil.copyfile(sources/name,root/rel)
rel='tests/test_paseo_adapter.py';s=(root/rel).read_text()
s=s.replace('primary_content_sources.append(SimpleNamespace(snapshot_id=local.snapshot_id))','primary_content_sources.append(SimpleNamespace(snapshot_id=local.snapshot_id))\n        if include_native:\n            primary_content_sources.append(SimpleNamespace(snapshot_id=native.snapshot_id))')
s=s.replace('    assert all(not sources for sources in uploads)','    assert [source.snapshot_id for sources in uploads for source in sources] == (\n        [native.snapshot_id] if include_native else []\n    )');write(rel,s)
rel='tests/test_guard_aibom_export_safety.py';s=(root/rel).read_text()
s=s.replace('        "custom_field": "preserve-me",','        "custom_field": "preserve-me",\n        "launch_command": f"python {home}/server.py --token fake-secret",')
s=s.replace('    assert row["custom_field"] == "preserve-me"','    assert row["custom_field"] == "preserve-me"\n    assert row["launch_command"] == "python {home}/server.py --token redacted"\n    assert "fake-secret" not in json.dumps(payload)\n    assert original["launch_command"].endswith("--token fake-secret")');write(rel,s)
rel='tests/test_guard_protection_recovery.py';s=(root/rel).read_text()
s=s.replace("'# BEGIN HOL GUARD MANAGED GROK\\n[permission]\\ndeny = [\"Read(**/.grok/auth/**)\"]\\n# END HOL GUARD MANAGED GROK\\n'", "'# BEGIN HOL GUARD MANAGED GROK\\n[permission]\\n'\n            'deny = [\"Read(**/.grok/auth/**)\"]\\n# END HOL GUARD MANAGED GROK\\n'")
s=s.replace('"# BEGIN HOL GUARD MANAGED GROK\\n[permission]\\ndeny = [] # Read(**/.grok/auth/**)\\n# END HOL GUARD MANAGED GROK\\n"', '"# BEGIN HOL GUARD MANAGED GROK\\n[permission]\\n"\n            "deny = [] # Read(**/.grok/auth/**)\\n# END HOL GUARD MANAGED GROK\\n"');write(rel,s)
