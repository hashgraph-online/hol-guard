"""Execution-environment stamp written into the generated bounded hook client."""

from __future__ import annotations

from ..hook_execution_environment import INERT_NODE_OPTIONS_PATTERN

HOOK_EXECUTION_STAMP_TEMPLATE = """def _loader_value_fits(value: str | None) -> bool:
    if not value:
        return False
    try:
        return len(value.encode()) <= 32 * 1024
    except UnicodeEncodeError:
        return False


def _stamp_hook_input(text: str) -> str:
    payload = _json_object(text)
    if payload is None:
        return text
    active = {key: value for key, value in os.environ.items() if value}
    # Git pages through `less` by default; flags taking a file argument are excluded.
    pager_ok = re.compile(r"(?:cat|less(?: -[ABCEFGIJKLMNQRSUVWXacdefgimnqrsuw~]+)*)?").fullmatch
    stamp: dict[str, object] = {
        "path": os.environ.get("PATH", ""),
        "environment_names": sorted(set(active) | {n for n in ("GIT_PAGER", "PAGER") if n in os.environ}),
        "environment_digest": hashlib.sha256(
            json.dumps(active, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "xdg_config_home": os.environ.get("XDG_CONFIG_HOME") or None,
        "git_config_no_system": _git_config_no_system_enabled(
            os.environ.get("GIT_CONFIG_NOSYSTEM")
        ),
        "home": os.environ.get("HOME"),
        "git_pager_disabled": pager_ok(os.environ.get("GIT_PAGER", "-")) is not None,
        "pager_disabled": pager_ok(os.environ.get("PAGER", "-")) is not None,
        "library_search_paths": {
            name: value
            for name in (
                "LD_LIBRARY_PATH",
                "DYLD_LIBRARY_PATH",
                "DYLD_FALLBACK_LIBRARY_PATH",
                "DYLD_FRAMEWORK_PATH",
                "DYLD_FALLBACK_FRAMEWORK_PATH",
            )
            if (value := os.environ.get(name)) and _loader_value_fits(value)
        },
    }
    # Heap and diagnostics flags only; the value itself is never stamped.
    if re.fullmatch(__INERT_NODE_OPTIONS__, os.environ.get("NODE_OPTIONS", "")):
        stamp["node_options_inert"] = True
    payload["guard_execution_environment"] = stamp
    stamped = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    return stamped if len(stamped) <= 1_000_000 else text


""".replace("__INERT_NODE_OPTIONS__", repr(INERT_NODE_OPTIONS_PATTERN))
