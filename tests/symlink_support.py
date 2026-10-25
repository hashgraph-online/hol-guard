"""Whether this account may create a directory symlink on this platform.

POSIX always may. Windows needs ``SeCreateSymbolicLinkPrivilege``, which an
elevated or developer-mode account holds and an ordinary CI account does not,
so the answer is measured rather than assumed from ``sys.platform``. A junction
(``mklink /J``) is deliberately not probed: ``Path.is_symlink`` is False for a
junction, so a junction never triggers the symlink rules under test.
"""

from __future__ import annotations

import os
import tempfile
from functools import lru_cache


@lru_cache(maxsize=1)
def directory_symlinks_available() -> bool:
    with tempfile.TemporaryDirectory() as root:
        target = os.path.join(root, "target")
        os.mkdir(target)
        try:
            os.symlink(target, os.path.join(root, "link"), target_is_directory=True)
        except (OSError, NotImplementedError, AttributeError):
            return False
        return True


SYMLINK_REASON = "creating a directory symlink needs a privilege this account does not hold"
