"""Send one prompt to the CIGAR prompt hook of an arm and return the note text (no model calls)."""

import json
import os
import subprocess
import uuid


def note(hook, project, prompt, session, timeout=90):
    payload = {
        "session_id": session,
        "turn_id": str(uuid.uuid4()),
        "transcript_path": None,
        "cwd": str(project),
        "hook_event_name": "UserPromptSubmit",
        "model": "gpt-6-luna",
        "permission_mode": "default",
        "prompt": prompt,
    }
    out = subprocess.run(
        hook["command"],
        shell=True,
        input=json.dumps(payload),
        cwd=project,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=dict(os.environ, **hook.get("env", {})),
    )
    # A failed or garbled hook run must not score as a silent note.
    if out.returncode != 0:
        raise RuntimeError(f"hook exited {out.returncode}: {out.stderr[-300:]!r}")
    try:
        o = json.loads(out.stdout)
    except ValueError as err:
        raise RuntimeError(f"hook output not JSON: {out.stdout[:200]!r} {out.stderr[-200:]!r}") from err
    return (o.get("hookSpecificOutput") or {}).get("additionalContext") or ""
