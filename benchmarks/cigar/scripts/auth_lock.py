#!/usr/bin/env python3
"""auth_lock.py <codex_home> take|give <marker>: share an arm's Codex login between batches.

take: under the arm's lock, add this batch's marker and put a copy of ~/.codex/auth.json in place.
give: under the same lock, remove the marker and delete the copy once no batch holds a marker.
The lock is a kernel flock, so the kernel releases it when its holder exits, however it exits.
"""

import fcntl
import os
import sys
from pathlib import Path


def main():
    home, action, marker = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    auth = home / "auth.json"
    with open(home / ".auth.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if action == "take":
            (home / f".{marker}").touch()
            data = (Path.home() / ".codex" / "auth.json").read_bytes()
            tmp = home / f".auth.json.{os.getpid()}"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(data)
            os.replace(tmp, auth)
        elif action == "give":
            (home / f".{marker}").unlink(missing_ok=True)
            if not any(home.glob(".auth-users.*")):
                auth.unlink(missing_ok=True)
        else:
            sys.exit(f"unknown action {action}")


if __name__ == "__main__":
    main()
