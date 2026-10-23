"""Inert discovery and validation of independently collected test invocations."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path

RUNNER = '/trusted/public/developer_unittest_runner.py'


def discover_tests(source: Path):
    tests = []
    for path in sorted(source.rglob('test*.py')):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 262144:
            raise ValueError('candidate test source must be bounded regular Python')
        relative = path.relative_to(source).as_posix()
        if any(part in {'.git', 'node_modules', '__pycache__'} for part in path.relative_to(source).parts):
            continue
        data = path.read_bytes()
        tree = ast.parse(data, filename=relative)
        aliases = {'unittest.TestCase', 'TestCase'}
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module == 'unittest':
                aliases.update(alias.asname or alias.name for alias in node.names if alias.name == 'TestCase')
            if isinstance(node, ast.Import):
                aliases.update(f'{alias.asname}.TestCase' for alias in node.names
                               if alias.name == 'unittest' and alias.asname)
        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or not any(ast.unparse(base) in aliases for base in node.bases):
                continue
            for method in node.body:
                if isinstance(method, ast.FunctionDef) and method.name.startswith('test'):
                    tests.append({'file': relative, 'class': node.name, 'method': method.name,
                        'syntactic_assertion_nodes': sum(isinstance(item, ast.Assert) or (
                            isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute)
                            and item.func.attr.startswith('assert')) for item in ast.walk(method)),
                        'source_sha256': hashlib.sha256(data).hexdigest(),
                        'argv': ['/usr/bin/python3', '-I', RUNNER, relative, node.name, method.name]})
                    if len(tests) > 32:
                        raise ValueError('candidate unittest suite exceeds 32 bounded invocations')
    return tests


def test_execution_valid(rows, committed_files):
    if not isinstance(rows, list) or not 1 <= len(rows) <= 32:
        return False
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            return False
        identity = (row.get('file'), row.get('class'), row.get('method'))
        if not all(isinstance(value, str) and value for value in identity):
            return False
        if (identity in seen or Path(identity[0]).is_absolute() or '..' in Path(identity[0]).parts
                or row.get('source_sha256') != committed_files.get(identity[0])
                or type(row.get('syntactic_assertion_nodes')) is not int or row['syntactic_assertion_nodes'] < 1
                or row.get('argv') != ['/usr/bin/python3', '-I', RUNNER, *identity]
                or row.get('candidate_uid') != 10003 or type(row.get('pid')) is not int or row['pid'] < 1
                or type(row.get('exit_code')) is not int or row['exit_code'] != 0 or row.get('timed_out') is not False):
            return False
        seen.add(identity)
    return True
