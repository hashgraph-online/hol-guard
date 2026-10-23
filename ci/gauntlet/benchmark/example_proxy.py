"""Real transport mediation for the independent example argument policy.

Policy, trusted record resolver and write counter live in the supervisor. The
agent sees only a key-free stdio socket relay. This adapter does not inspect
inbound content or provide comprehensive injection/approval protection.
"""

from __future__ import annotations

import copy
import threading
from collections.abc import Callable

from .adapters import ExamplePolicyAdapter
from .contracts import canonical_json, digest
from .world import World

EXAMPLE_LIMITATIONS = (
    "Conformance-only argument policy; no qualification or general injection-protection claim.",
    "Search without explicit tenant/fields can exceed task delegation; inbound search results are unfiltered.",
    "Read without explicit fields can expose the full stored record rather than the delegated projection.",
    "New output IDs require an existing delegated record; legitimate create workflows may fail.",
    "Write budgets are shared across reconnects within each service family, not across all service families.",
    "Inbound content, resources, prompts, tool-list changes, and external approvals are unmediated.",
)


class ExampleProxyPolicy:
    def __init__(self, adapter: ExamplePolicyAdapter, *, observer: Callable[[dict], None] | None = None):
        self.adapter, self.observer = adapter, observer
        self._lock = threading.RLock()

    limitations = EXAMPLE_LIMITATIONS

    def _observe(self, message, action, reason):
        event = {
            "kind": "product-decision",
            "product": "example-policy",
            "family": self.adapter.family,
            "request_id": message.get("id"),
            "request_digest": digest(message),
            "action": action,
            "reason": reason,
        }
        if self.observer is not None:
            try:
                self.observer(copy.deepcopy(event))
            except Exception as error:
                raise ValueError("example policy decision collector unavailable") from error

    def mediate(self, message: dict, forward: Callable[[dict], dict]) -> dict:
        # This lock spans the real response, so two authenticated sessions cannot
        # both pass the same final write-budget slot before a commit is observed.
        with self._lock:
            forwarded = False

            def actual_forward(request):
                nonlocal forwarded
                action = "allow" if request.get("method") == "tools/call" else "unsupported"
                reason = "within-delegation" if action == "allow" else "surface-unmediated"
                self._observe(request, action, reason)
                forwarded = True
                return forward(request)

            response = self.adapter.mediate(message, actual_forward)
            if not forwarded:
                reason = response["result"]["content"][0]["text"]
                self._observe(message, "deny", reason)
            return response


def example_policy_factory(world: World, authorization: dict, *, observer=None) -> Callable[[str], ExampleProxyPolicy]:
    """Bind actor and metadata reader from trusted custody, never request params."""
    authorization = copy.deepcopy(authorization)

    def factory(family):
        return ExampleProxyPolicy(
            ExamplePolicyAdapter(authorization, family=family, actor=world.actor, resolve_record=world.inspect),
            observer=observer,
        )

    return factory


class PolicySessionBridge:
    """Route actual child responses back through policy before client delivery."""

    def __init__(self, policy, *, forward, deliver, ended, stopping):
        self.policy, self.forward, self.deliver = policy, forward, deliver
        self.ended, self.stopping = ended, stopping
        self._pending = {}
        self._lock = threading.Lock()

    @staticmethod
    def _identity(message):
        identity = message.get("id")
        if type(identity) not in (str, int):
            raise ValueError("mediated tools/call requires a string/integer request ID")
        return canonical_json(identity)

    def receive(self, message):
        if "method" in message or not ({"result", "error"} & message.keys()):
            return False
        identity = self._identity(message)
        with self._lock:
            waiter = self._pending.get(identity)
            if waiter is None:
                return False
            if waiter["response"] is not None:
                raise ValueError("duplicate actual service response")
            waiter["response"] = message
            waiter["ready"].set()
            return True

    def _forward_and_wait(self, message):
        identity = self._identity(message)
        waiter = {"ready": threading.Event(), "response": None}
        with self._lock:
            if identity in self._pending:
                raise ValueError("duplicate pending MCP request identity")
            self._pending[identity] = waiter
        try:
            self.forward(message)
            while not waiter["ready"].wait(0.1):
                if self.ended.is_set() or self.stopping.is_set():
                    raise OSError("actual service response interrupted")
            return waiter["response"]
        finally:
            with self._lock:
                self._pending.pop(identity, None)

    def mediate(self, message):
        self._identity(message)
        response = self.policy.mediate(message, self._forward_and_wait)
        if not isinstance(response, dict):
            raise ValueError("policy transport returned no actual MCP response")
        self.deliver(response)
