"""Real isolated native mediation for developer SDK builtins and MCP tools.

Native refusals are measured outcomes. This runtime supplies transport and
custody, never approvals, policy replacements, or campaign qualification.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import threading
from pathlib import Path

from .adapters import McpEndpoint, omp_mcp_configs
from .builtin_hook_supervisor import BuiltinHookSupervisor
from .contracts import canonical_json, digest
from .mcp_task_context import prepare_task_context
from .native_contained_plane import NativeContainedHookPlane
from .native_mcp_supervisor import NativeMcpSupervisor, require_root_private
from .native_product_container import BASE_IMAGE, NativeProductContainer
from .service_supervisor import ServiceSupervisor

EXECUTOR_IMAGE = "sha256:830e10601acaaa774387277dec0f6c6f9b1c8f20ef970edab27bcf9028d5ca66"


class OperationBudget:
    """Actual controller ingress counts; no SDK stdout counter is authoritative."""
    def __init__(self, maximum):
        if type(maximum) is not int or not 1 <= maximum <= 200:
            raise ValueError("bounded controller operation limit required")
        self.maximum, self.events, self.lock = maximum, [], threading.Lock()
        self.admitted = 0

    def claim(self, source, request):
        with self.lock:
            allowed = self.admitted < self.maximum
            if len(self.events) >= self.maximum + 1:
                raise ValueError("controller operation observation budget exhausted")
            self.events.append({"sequence":len(self.events)+1,"source":source,
                "request_digest":digest(request),"admitted":allowed})
            if not allowed:
                raise ValueError("controller operation budget exhausted before product forwarding")
            self.admitted += 1

    def record(self):
        return {"maximum":self.maximum,"admitted":self.admitted,"events":self.events}


class _BudgetPlane(NativeContainedHookPlane):
    def __init__(self, *, operation_budget, **kwargs):
        self.operation_budget = operation_budget
        super().__init__(**kwargs)

    def invoke_hook(self, payload, **kwargs):
        if payload.get("hook_event_name") == "PreToolUse":
            self.operation_budget.claim("sdk-builtin",payload)
        return super().invoke_hook(payload,**kwargs)


class _BudgetFrontdoor(NativeMcpSupervisor):
    def __init__(self, *args, operation_budget, **kwargs):
        self.operation_budget = operation_budget
        super().__init__(*args,**kwargs)

    def _forward_message(self, family, session_id, process, ended, message):
        if message.get("method") == "tools/call":
            self.operation_budget.claim("native-mcp",{"family":family,"session_id":session_id,"message":message})
        return super()._forward_message(family,session_id,process,ended,message)


class DeveloperProductRuntime:
    def __init__(self, *, root: Path, upstream: ServiceSupervisor, public_mcp_directory: Path,
                 public_hook_directory: Path, python: Path, source_sha: str, prefix_digest: str,
                 bwrap_sha256: str, workspace_source: Path, workspace_custody_root: Path,
                 provider_mounts: tuple[Path,...] = (), provider_custody_root: Path | None = None,
                 public_prompt: str, controller_session_id: str, deadline_seconds: int,
                 max_tool_calls: int, mcp_image_id: str = BASE_IMAGE, executor_image_id: str = EXECUTOR_IMAGE,
                 private_cell: dict | None = None, package_version: str | None = None,
                 sdk_resource_directory: Path | None = None):
        require_root_private(root,existing=False)
        mcp_uid=10004 if private_cell is None else 10005
        if (os.geteuid() != 0 or root.exists() or not isinstance(upstream,ServiceSupervisor)
                or upstream.allowed_uid != mcp_uid or upstream.socket_gid != mcp_uid
                or upstream.sockets or upstream._stop.is_set() or tuple(upstream.families) != ("docs","mail")):
            raise ValueError(f"fresh root runtime with private unstarted UID{mcp_uid} docs/mail upstream required")
        if (type(max_tool_calls) is not int or not 1 <= max_tool_calls <= 200
                or type(deadline_seconds) is not int or not 1 <= deadline_seconds <= 900
                or not isinstance(public_prompt,str) or not public_prompt or len(public_prompt.encode()) > 1024*1024
                or not isinstance(controller_session_id,str) or not controller_session_id
                or len(controller_session_id) > 256
                or not re.fullmatch(r"[0-9a-f]{40}",source_sha)
                or not re.fullmatch(r"[0-9a-f]{64}",prefix_digest)
                or not re.fullmatch(r"[0-9a-f]{64}",bwrap_sha256)):
            raise ValueError("exact bounded public context, controller session, identities and budgets required")
        paths = (root,public_mcp_directory,public_hook_directory,upstream.directory)
        for path in paths:
            require_root_private(path,existing=False)
        if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
               for i,a in enumerate(paths) for b in paths[i+1:]):
            raise ValueError("public sockets and all private custody directories must be disjoint")
        if sdk_resource_directory is not None:
            if (not isinstance(sdk_resource_directory, Path) or not sdk_resource_directory.is_absolute()
                    or any(sdk_resource_directory == path or sdk_resource_directory.is_relative_to(path)
                           or path.is_relative_to(sdk_resource_directory) for path in paths)):
                raise ValueError("Rust SDK tap resource directory must be a distinct absolute mount")
        self.root,self.upstream,self.python = root,upstream,python
        self.public_mcp_directory,self.public_hook_directory = public_mcp_directory,public_hook_directory
        self.sdk_resource_directory = (public_mcp_directory if sdk_resource_directory is None
                                       else sdk_resource_directory)
        self.public_prompt,self.session_id = public_prompt,controller_session_id
        self.settings = dict(source_sha=source_sha,prefix_digest=prefix_digest,bwrap_sha256=bwrap_sha256,
            deadline_seconds=deadline_seconds,max_tool_calls=max_tool_calls,
            mcp_image_id=mcp_image_id,executor_image_id=executor_image_id)
        if package_version is not None:
            from .product_version import validate_version
            self.settings['package_version'] = validate_version(package_version)
        self.private_cell=None
        if private_cell is not None:
            from .private_cell_factory import PrivateCellConfig
            self.private_cell=PrivateCellConfig.parse(private_cell)
            self.settings['private_cell']=self.private_cell.declaration()
            self.settings['mcp_identity_profile']='private-cell-mcp-v2'
            self.settings['contained_output_binding']='controller-contained-output.v1'
            self.settings['contained_completion_profile']='guard-contained-completion.v1'
        self.workspace_source,self.workspace_custody_root = workspace_source,workspace_custody_root
        self.provider_mounts,self.provider_custody_root = provider_mounts,provider_custody_root
        self.operations = OperationBudget(max_tool_calls)
        self.frontdoor,self.builtin,self.hooks = None,None,None
        self.contexts,self.errors,self.public_assets = [],[],{}
        self.prompt_allowed,self.started,self.closed = False,False,False
        self._key = None
        self._evidence = None

    def stage_public_helpers(self, public: Path):
        if (public.resolve() != public or not public.is_dir() or public.stat().st_uid != 0
                or public.stat().st_mode & 0o022):
            raise ValueError("literal controller-owned public helper directory required")
        for name in ("builtin_guard_bridge.ts","contained_exec_relay.py"):
            target = public / name
            if target.exists() or target.is_symlink():
                raise ValueError("fresh helper assets required")
            shutil.copyfile(Path(__file__).with_name(name),target)
            target.chmod(0o644)
            self.public_assets[name] = hashlib.sha256(target.read_bytes()).hexdigest()
        return {"guardExtension":"/runtime/public/builtin_guard_bridge.ts",
                "assets":dict(self.public_assets)}

    def start(self, *, controller_key):
        if self.started or self.closed or self.root.exists():
            raise ValueError("fresh one-shot developer product runtime required")
        self._key = controller_key
        self.root.mkdir(mode=0o700)
        settings = self.settings
        try:
            self.upstream.start()
            mcp_options={} if self.private_cell is None else {'identity_profile':'private-cell-mcp-v2'}
            mcp_plane = NativeProductContainer(runtime_root=self.root/"mcp-product",python=self.python,
                expected_source_sha=settings["source_sha"],image_id=settings["mcp_image_id"],
                upstream_directory=self.upstream.directory,wall_seconds=settings["deadline_seconds"]+90,
                **self._version_options(),**mcp_options)
            self.frontdoor = _BudgetFrontdoor(self.public_mcp_directory,upstream=self.upstream,
                python=self.python,expected_source_sha=settings["source_sha"],
                private_root=self.root/"mcp-frontdoor",product_plane=mcp_plane,
                operation_budget=self.operations,idle_timeout=settings["deadline_seconds"]+60,
                session_timeout=settings["deadline_seconds"]+60)
            self.frontdoor.start()
            if mcp_plane.prefix_digest != settings["prefix_digest"]:
                raise ValueError("MCP native prefix differs from frozen product bytes")
            context,response_allowed = prepare_task_context(self.frontdoor,self.public_prompt,
                controller_key=controller_key,phase="developer")
            self.contexts.append(context)
            self.builtin = self._create_builtin()
            self.builtin.start()
            self.hooks = BuiltinHookSupervisor(self.public_hook_directory,plane=self.builtin,
                controller_session_id=self.session_id,max_calls=settings["max_tool_calls"])
            builtin_prompt = self.hooks.prepare_user_prompt(self.public_prompt)
            self.prompt_allowed = response_allowed and builtin_prompt["decision"] == "allow"
            self.hooks.start()
            self.started = True
            return self
        except BaseException as error:
            self.errors.append(f"{type(error).__name__}: {error}")
            self.close()
            raise

    def _version_options(self):
        from .product_version import version_options
        return version_options(self.settings.get('package_version'))

    def _create_builtin(self):
        settings=self.settings
        if self.private_cell is not None:
            from .private_cell_factory import build_private_cell
            return build_private_cell(root=self.root/'builtin-product',config=self.private_cell,
                python=self.python,source_sha=settings['source_sha'],prefix_digest=settings['prefix_digest'],
                bwrap_sha256=settings['bwrap_sha256'],image_id=settings['executor_image_id'],
                workspace_source=self.workspace_source,workspace_custody_root=self.workspace_custody_root,
                provider_mounts=self.provider_mounts,provider_custody_root=self.provider_custody_root,
                package_version=settings.get('package_version'),
                wall_seconds=settings['deadline_seconds']+90,operation_budget=self.operations)
        return _BudgetPlane(runtime_root=self.root/"builtin-product",python=self.python,
                expected_source_sha=settings["source_sha"],expected_prefix_digest=settings["prefix_digest"],
                expected_bwrap_sha256=settings["bwrap_sha256"],image_id=settings["executor_image_id"],
                workspace_source=self.workspace_source,workspace_custody_root=self.workspace_custody_root,
                provider_mounts=self.provider_mounts,provider_custody_root=self.provider_custody_root,
                wall_seconds=settings["deadline_seconds"]+90,operation_budget=self.operations,
                **self._version_options())

    def resource_endpoints(self, workspace="/runtime/home/project"):
        if self.closed or workspace != "/runtime/home/project":
            raise ValueError("exact open developer public frontdoor workspace declaration required")
        return omp_mcp_configs(tuple(McpEndpoint(family,('/usr/bin/python3','/runtime/public/service_relay.py',
            '--socket',f'/runtime/resources/{family}.sock')) for family in self.upstream.families),
            workspace=Path(workspace))

    def agent_mounts(self):
        return [{"source":str(self.sdk_resource_directory),"destination":"/runtime/resources","mode":"ro"},
                {"source":str(self.public_hook_directory),"destination":"/runtime/guard-hook","mode":"ro"}]

    def bind_sdk(self, pid, *, expected_identity):
        if not self.started or self.closed or not self.prompt_allowed:
            raise ValueError("prepared allowed public context required before actual SDK execution")
        self.hooks.bind_sdk(pid,expected_identity=expected_identity)

    def close(self):
        if self.closed:
            return
        resources = (("builtin-hook",self.hooks),("builtin-product",self.builtin if self.hooks is None else None),
                     ("native-mcp",self.frontdoor),("upstream",self.upstream))
        for label, resource in resources:
            if resource is not None:
                try:
                    resource.close()
                except Exception as error:
                    self.errors.append(f"{label}: {error}")
        self.closed = True

    def evidence_record(self):
        if not self.closed or self._key is None:
            raise ValueError("closed real runtime and externally held controller key required")
        if self._evidence is not None:
            return json.loads(canonical_json(self._evidence))
        version = ('5.0' if self.private_cell else '2.0') if 'package_version' in self.settings else (
            '4.0' if self.private_cell else '1.0')
        record = {"schema_version":version,
            "kind":("developer-private-cell-runtime-observation" if self.private_cell
                    else "developer-product-runtime-observation"),
            "settings":self.settings,"controller_session_id":self.session_id,
            "public_prompt_digest":digest(self.public_prompt),"public_assets":self.public_assets,
            "prompt_allowed":self.prompt_allowed,"operations":self.operations.record(),
            "agent_public_mounts":self.agent_mounts(),"errors":list(self.errors),
            "native_mcp_audit":None,"native_builtin_audit":None,"native_task_contexts":self.contexts,
            "upstream_counts":{name:getattr(self.upstream,name) for name in
                               ("active_children","active_workers","active_sessions")},
            "product_claims_authenticated":False,"qualification_eligible":False}
        for field, producer in (("native_mcp_audit",self.frontdoor),("native_builtin_audit",self.hooks)):
            if producer is not None:
                try:
                    record[field] = (producer.collect_audit(controller_key=self._key) if field=="native_mcp_audit"
                                     else producer.evidence(controller_key=self._key))
                except Exception as error:
                    record["errors"].append(f"{field}: {error}")
        self._evidence = record
        return json.loads(canonical_json(record))

    def evidence(self, *, controller_key):
        record = self.evidence_record()
        return {"record":record,
                "signature":base64.b64encode(controller_key.sign(canonical_json(record).encode())).decode()}
