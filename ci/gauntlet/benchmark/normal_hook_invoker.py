"""Normal prompt hook inside an already-owned product plane, never on root.

Its observations are separate from the immutable MCP mount-profile evidence.
An actual denial is returned unchanged; this helper supplies no approval.
"""
from __future__ import annotations

from .contracts import canonical_json, digest
from .native_builtin_plane import NativeBuiltinHookPlane


class NormalHookInvoker:
    def __init__(self, plane, *, controller_session_id: str):
        if (not isinstance(controller_session_id, str) or not controller_session_id
                or len(controller_session_id) > 256):
            raise ValueError("bounded externally assigned controller session required")
        self.plane, self.session_id = plane, controller_session_id
        self.hook_observations, self.prompt_digest = [], None

    def __getattr__(self, name):
        return getattr(self.plane, name)

    @property
    def started(self):
        return self.plane.started

    @started.setter
    def started(self, value):
        self.plane.started = value

    def prepare_user_prompt(self, prompt: str, *, timeout: float = 30) -> dict:
        if (not isinstance(prompt, str) or not prompt or len(prompt.encode()) > 1024 * 1024
                or not 0 < timeout <= 60 or not self.started):
            raise ValueError("bounded actual public task and running product plane required")
        payload = {"hook_event_name": "UserPromptSubmit", "prompt": prompt,
            "config_path": "/product/public/mcp.json", "session_id": self.session_id}
        command = [str(self.plane.python), "-I", "-m", "codex_plugin_scanner.cli", "guard", "hook", "--json",
            "--harness", "omp", "--guard-home", "/product/guard", "--home", "/product/home",
            "--workspace", "/product/home/project"]
        raw = (canonical_json(payload) + "\n").encode()
        if len(raw) > 1024 * 1024:
            raise ValueError("normal prompt packet exceeds native input budget")
        with self.plane._lock:
            if self.prompt_digest is not None:
                raise ValueError("public task context may only be prepared once per controller session")
            self.prompt_digest = digest(prompt)
            return NativeBuiltinHookPlane._invoke(self, command, raw, payload, timeout)

    def observation(self) -> dict:
        return {"schema_version": "1.0", "kind": "isolated-normal-prompt-hook-observation",
            "controller_session_id": self.session_id, "public_prompt_digest": self.prompt_digest,
            "hooks": self.hook_observations, "product_claims_authenticated": False,
            "qualification_eligible": False}
