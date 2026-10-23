"""Public immutable unittest entrypoint; only runs as the isolated candidate UID."""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path


def main():
    if sys.platform != 'linux' or os.geteuid() != 10003 or len(sys.argv) != 4:
        raise RuntimeError('requires isolated Linux candidate UID and exact selected test')
    relative, class_name, method = sys.argv[1:]
    root = Path('/candidate/source')
    file = root / relative
    if (Path(relative).is_absolute() or '..' in Path(relative).parts or file.is_symlink()
            or not file.resolve().is_relative_to(root) or not class_name.isidentifier()
            or not method.isidentifier() or not method.startswith('test')):
        raise ValueError('test must bind an immutable source file and method')
    sys.path.insert(0, str(root))
    spec = importlib.util.spec_from_file_location('_candidate_test', file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    case = getattr(module, class_name)
    if not isinstance(case, type) or not issubclass(case, unittest.TestCase):
        raise ValueError('selected class is not a unittest TestCase')
    result = unittest.TextTestRunner(verbosity=0).run(unittest.TestSuite([case(method)]))
    return 0 if result.wasSuccessful() and result.testsRun == 1 and not result.skipped else 1


if __name__ == '__main__':
    raise SystemExit(main())
