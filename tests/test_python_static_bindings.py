from __future__ import annotations

import ast
from pathlib import Path

import pytest

from scripts.ci.python_hook_semantic_callgraph_gate import (
    _functions,
    _imports,
    _Module,
    _reachable_functions,
    _semantic_references,
)
from scripts.ci.python_static_bindings import StaticBindings, function_node


@pytest.fixture
def composed_server(tmp_path: Path) -> Path:
    folder = tmp_path / "src/codex_plugin_scanner/guard/daemon"
    folder.mkdir(parents=True)
    sources = {
        "server.py": (
            "from . import server_handler as _owner\n"
            "from . import server_dependencies as _dependencies\n"
            "_GuardDaemonHandler = _owner._GuardDaemonHandler\n"
            "_native_mode_requires_rust = _dependencies._native_mode_requires_rust\n"
        ),
        "server_dependencies.py": "from ..native_mode import native_mode_requires_rust as _native_mode_requires_rust\n",
        "server_handler.py": (
            "from . import server_execution as _methods\n"
            "class _GuardDaemonHandler:\n"
            "    _execute_runtime_hook = _methods._execute_runtime_hook\n"
            "    _next = _methods._next\n"
        ),
        "server_execution.py": (
            "from . import server as _server\n"
            "def _execute_runtime_hook(self):\n"
            "    if _server._native_mode_requires_rust():\n"
            "        return 'native'\n"
            "    return self._next()\n"
            "def _next(self):\n"
            "    return 'transport'\n"
        ),
    }
    for name, text in sources.items():
        (folder / name).write_text(text, encoding="utf-8")
    return folder / "server.py"


def _replace(path: Path, before: str, after: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert text.count(before) == 1
    path.write_text(text.replace(before, after), encoding="utf-8")


def _execute(path: Path) -> ast.FunctionDef:
    return function_node(path, "_execute_runtime_hook", "_GuardDaemonHandler")


def test_resolver_follows_actual_facade_and_method(composed_server: Path) -> None:
    node = _execute(composed_server)
    assert isinstance(node.body[0], ast.If)
    assert isinstance(node.body[0].test, ast.Call)
    assert isinstance(node.body[0].test.func, ast.Name)
    assert node.body[0].test.func.id == "_native_mode_requires_rust"


def test_relative_entrypoint_resolves_same_binding(composed_server: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    absolute = ast.dump(_execute(composed_server))
    monkeypatch.chdir(composed_server.parent)
    assert ast.dump(_execute(Path("server.py"))) == absolute


def test_method_retarget_inspects_replacement_body(composed_server: Path) -> None:
    helper = composed_server.with_name("server_execution.py")
    helper.write_text(helper.read_text() + "def replacement(self):\n    return evaluate_command()\n")
    _replace(
        composed_server.with_name("server_handler.py"), "= _methods._execute_runtime_hook", "= _methods.replacement"
    )
    node = ast.unparse(_execute(composed_server))
    assert "evaluate_command" in node
    assert "_native_mode_requires_rust" not in node


def test_facade_retarget_inspects_replacement_class(composed_server: Path) -> None:
    owner = composed_server.with_name("server_handler.py")
    owner.write_text(
        owner.read_text() + "class Replacement:\n    def _execute_runtime_hook(self):\n        return 'replacement'\n"
    )
    _replace(composed_server, "= _owner._GuardDaemonHandler", "= _owner.Replacement")
    assert "replacement" in ast.unparse(_execute(composed_server))


def test_moved_callee_remains_in_semantic_reachability(composed_server: Path) -> None:
    _replace(composed_server.with_name("server_execution.py"), "return 'transport'", "return evaluate_command()")
    tree = StaticBindings(composed_server).logical_tree()
    name = "codex_plugin_scanner.guard.daemon.server"
    module = _Module(name, composed_server, tree, _functions(tree), _imports(name, tree))
    entry = module.functions[("_GuardDaemonHandler", "_execute_runtime_hook")]
    failures = [f for n in _reachable_functions(module, entry) for f in _semantic_references(n, name, module.imports)]
    assert any("evaluate_command" in f for f in failures)


@pytest.mark.parametrize(
    "statement",
    [
        "_server = object()",
        "def _server():\n        return False",
        "async def _server():\n        return False",
        "class _server:\n        _native_mode_requires_rust = lambda: False",
        "try:\n        pass\n    except Exception as _server:\n        pass",
        "match {}:\n        case {'x': _server}:\n            pass",
        "match []:\n        case [*_server]:\n            pass",
        "match {}:\n        case {**_server}:\n            pass",
        "import other as _server",
        "from other import replacement as _server",
    ],
)
def test_facade_alias_shadowing_is_rejected(composed_server: Path, statement: str) -> None:
    _replace(
        composed_server.with_name("server_execution.py"),
        "def _execute_runtime_hook(self):\n",
        "def _execute_runtime_hook(self):\n    " + statement + "\n",
    )
    with pytest.raises(RuntimeError, match="facade alias"):
        _execute(composed_server)


@pytest.mark.parametrize(
    ("file", "before", "after", "reason"),
    [
        (
            "server_execution.py",
            "def _execute_runtime_hook(self):",
            "def _execute_runtime_hook(self, _server):",
            "facade alias",
        ),
        ("server_execution.py", "from . import server as _server", "import other as _server", "exact facade"),
        (
            "server.py",
            "_GuardDaemonHandler = _owner._GuardDaemonHandler",
            "_GuardDaemonHandler = cycle\ncycle = _GuardDaemonHandler",
            "cyclic",
        ),
        (
            "server_dependencies.py",
            "native_mode_requires_rust as",
            "python_oracle_enabled as",
            "native authority guard",
        ),
        ("server_handler.py", "class _GuardDaemonHandler:", "@replace_class\nclass _GuardDaemonHandler:", "decorated"),
    ],
)
def test_invalid_binding_is_rejected(composed_server: Path, file: str, before: str, after: str, reason: str) -> None:
    _replace(composed_server.with_name(file), before, after)
    with pytest.raises(RuntimeError, match=reason):
        _execute(composed_server)


def test_missing_helper_is_rejected(composed_server: Path) -> None:
    composed_server.with_name("server_execution.py").unlink()
    with pytest.raises(RuntimeError):
        _execute(composed_server)


def test_duplicate_facade_binding_is_rejected(composed_server: Path) -> None:
    composed_server.write_text(composed_server.read_text() + "_GuardDaemonHandler = _owner._GuardDaemonHandler\n")
    with pytest.raises(RuntimeError, match="exactly one"):
        _execute(composed_server)


def test_custom_base_cannot_replace_inspected_methods(composed_server: Path) -> None:
    owner = composed_server.with_name("server_handler.py")
    _replace(owner, "class _GuardDaemonHandler:", "class _GuardDaemonHandler(ReplacingBase):")
    owner.write_text(
        "class ReplacingBase:\n"
        "    def __init_subclass__(cls):\n"
        "        cls._execute_runtime_hook = replacement\n" + owner.read_text()
    )
    with pytest.raises(RuntimeError, match="unsupported base"):
        _execute(composed_server)


@pytest.mark.parametrize("wrapper", ["staticmethod", "classmethod"])
@pytest.mark.parametrize("direct", [True, False])
def test_rebound_descriptor_wrapper_is_rejected(composed_server: Path, wrapper: str, direct: bool) -> None:
    owner = composed_server.with_name("server_handler.py")
    replacement = (
        f"    @{wrapper}\n    def _execute_runtime_hook(self):\n        return 'native'\n"
        if direct
        else f"    _execute_runtime_hook = {wrapper}(_methods._execute_runtime_hook)\n"
    )
    _replace(owner, "    _execute_runtime_hook = _methods._execute_runtime_hook\n", replacement)
    owner.write_text(f"{wrapper} = application_decorator\n" + owner.read_text())
    with pytest.raises(RuntimeError, match="descriptor wrapper"):
        _execute(composed_server)


@pytest.mark.parametrize(
    "statement",
    [
        "locals().update({'_execute_runtime_hook': replacement})",
        "if True:\n        _execute_runtime_hook = replacement",
        "del _execute_runtime_hook",
        "_execute_runtime_hook = factory()",
        "effect: object = mutate_methods()",
        "_unused = (locals().update({'_execute_runtime_hook': replacement}), 1)",
    ],
)
def test_executable_class_bindings_are_rejected(composed_server: Path, statement: str) -> None:
    owner = composed_server.with_name("server_handler.py")
    owner.write_text(owner.read_text() + "    " + statement + "\n")
    with pytest.raises(RuntimeError):
        _execute(composed_server)


@pytest.mark.parametrize(
    "statement",
    [
        "setattr(_owner._GuardDaemonHandler, '_execute_runtime_hook', replacement)",
        "_owner._GuardDaemonHandler._execute_runtime_hook = replacement",
        "_unused = setattr(_owner._GuardDaemonHandler, '_execute_runtime_hook', replacement)",
        "_unused = (setattr(_owner._GuardDaemonHandler, '_execute_runtime_hook', replacement), 1)",
    ],
)
def test_indirect_module_mutation_is_rejected(composed_server: Path, statement: str) -> None:
    composed_server.write_text(composed_server.read_text() + statement + "\n")
    with pytest.raises(RuntimeError, match="module"):
        _execute(composed_server)
