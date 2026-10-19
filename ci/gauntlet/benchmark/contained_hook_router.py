"""One-time routing to Native's actual contained sink, never an approval grant."""
from __future__ import annotations

import json
import secrets
import threading

from .contracts import canonical_json, digest


class ContainedHookRouter:
    def __init__(self, plane, *, max_executions: int = 500, timeout: int = 300):
        if (type(max_executions) is not int or not 1 <= max_executions <= 500
                or type(timeout) is not int or not 1 <= timeout <= 900):
            raise ValueError("bounded contained execution policy required")
        self.plane, self.maximum, self.timeout = plane, max_executions, timeout
        self.pending, self.events, self.lock = {}, [], threading.Lock()

    def prepare(self, payload: dict, native_response: dict, *, request_digest: str) -> str | None:
        if (not getattr(self.plane, "supports_contained_execution", False)
                or native_response.get("decision") != "deny"
                or native_response.get("policy_action") != "sandbox-required"
                or native_response.get("required_execution_profile") != "workspace-contained-v1"
                or native_response.get("observe_mode") is True
                or payload.get("tool_name") != "bash"
                or not isinstance(payload.get("tool_input", {}).get("command"), str)):
            return None
        detached = json.loads(canonical_json(payload))
        with self.lock:
            if len(self.pending) >= self.maximum:
                raise ValueError("contained execution ticket budget exhausted")
            token = secrets.token_hex(32)
            self.pending[token] = {"payload": detached, "payload_digest": digest(detached),
                "request_digest": request_digest, "native_response_digest": digest(native_response), "used": False}
            self.events.append({"kind": "contained-route-prepared", "token_digest": digest(token),
                "payload_digest": digest(detached), "native_response_digest": digest(native_response)})
            return token

    def execute(self, token: str, *, peer_pid: int, cancelled=None) -> dict:
        if not isinstance(token, str) or len(token) != 64 or type(peer_pid) is not int or peer_pid <= 0:
            raise ValueError("bound contained route token and actual caller PID required")
        with self.lock:
            ticket = self.pending.get(token)
            if ticket is None or ticket["used"]:
                raise ValueError("unknown or already consumed contained execution route")
            # Consume before invoking any native sink. Failure remains consumed;
            # retries must obtain a new real NativeHook authorization.
            ticket["used"] = True
        self.events.append({"kind": "contained-route-consumed", "token_digest": digest(token),
                            "peer_pid": peer_pid, "payload_digest": ticket["payload_digest"]})
        result = self.plane.execute_contained(ticket["payload"], timeout=self.timeout, cancelled=cancelled)
        if getattr(self.plane,'requires_contained_output_binding',False):
            with self.lock:
                ticket['result'] = json.loads(canonical_json(result))
        self.events.append({"kind": "actual-contained-result", "token_digest": digest(token),
                            "result_digest": digest(result), "exit_code": result["exit_code"]})
        return {"schema_version": "1.0", "kind": "actual-contained-result", "result": result,
                "request_digest": ticket["request_digest"], "product_claims_authenticated": False}

    def output_for_post(self, call_id, binding):
        """Only the completed, one-time sink corresponding to the original Pre."""
        from .contained_output_binding import captured_output
        with self.lock:
            tickets = [row for row in self.pending.values() if row['payload'].get('tool_call_id')==call_id]
            if not tickets:
                return None
            if len(tickets)!=1:
                raise ValueError('ambiguous contained output authorization')
            ticket = tickets[0]
            original = {name:ticket['payload'][name] for name in ('tool_name','tool_input')}
            if (canonical_json(binding)!=canonical_json(original) or ticket['used'] is not True
                    or 'result' not in ticket or ticket['result']['payload_digest']!=ticket['payload_digest']):
                raise ValueError('contained output lacks its completed original execution')
            return {**captured_output(ticket['result']),'pre_payload_digest':ticket['payload_digest']}
