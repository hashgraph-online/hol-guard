"""Authenticated workspace preparation for the generated Grok prompt client."""

GROK_HOOK_READINESS_TEMPLATE = """
def _prepare_grok_prompt(input_text, host, port, token, deadline):
    payload = _json_object(input_text)
    if payload is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    workspace = payload.get("cwd")
    if not isinstance(workspace, str) or not workspace.strip():
        payload.pop("guard_remaining_seconds", None)
        payload["guard_remaining_ms"] = max(1, int(remaining * 1000))
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    request = {"cwd": workspace} if isinstance(workspace, str) else {}
    ready = _http_json(
        _loopback_url(host, port, "/v1/hooks/grok/readiness"),
        token,
        data=json.dumps(request, separators=(",", ":")).encode("utf-8"),
        timeout=remaining,
    )
    if ready is None or ready.get("ready") is not True:
        return None
    if ready.get("native_required") is not False and (
        ready.get("workspace_acknowledged") is not True
        or ready.get("worker_ready") is not True
    ):
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    # Stamp only the remaining original transport budget. Workspace preparation
    # is not a native semantic decision and cannot authorize the prompt.
    payload.pop("guard_remaining_seconds", None)
    payload["guard_remaining_ms"] = max(1, int(remaining * 1000))
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
"""
