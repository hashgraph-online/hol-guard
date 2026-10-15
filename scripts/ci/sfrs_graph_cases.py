"""Record compound developer effect graph cases for the filesystem fixture."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from codex_plugin_scanner.guard.runtime import github_shell_capabilities as gh_shell
from codex_plugin_scanner.guard.runtime.github_capability_contract import github_assessment
from codex_plugin_scanner.guard.runtime.secret_file_request_services import developer_inspection

PROJ = "{ROOT}/home/proj"
TEXTS = [
    "cd {P} && ls src",
    "cd {P} && ls",
    "cd {P} && cat src/a.txt | head -5",
    "cd {P} && cat src/a.txt | sort -n",
    "cd {P} && cat src/a.txt | sort -x",
    "cd {P} && grep -r alpha src",
    "cd {P} && rg alpha src",
    "cd {P} && rg alpha src --no-config",
    "RIPGREP_CONFIG_PATH=x rg alpha src",
    "cd {P} && find src -name '*.txt'",
    "cd {P} && find src -delete",
    "cd {P} && wc -l src/a.txt",
    "cd {P} && wc",
    "cd {P} && echo hi",
    "cd {P} && echo $HOME",
    "cd {P} && echo hi && cat src/b.txt",
    "cd {P} && ls ../../elsewhere",
    "cd {P} && cat ../bare/f.txt",
    "cd {P} && cat link.txt",
    "cd {P} && cat outside.txt",
    "cd {P} && cat dirlink/a.txt",
    "cd {P}; ls",
    "cd {P} && ls || echo no",
    "cd {P} && ls > out.txt",
    "cd {P} && ls 2>&1",
    "cd {P} && ls & ls",
    "cd {P} && rm src/a.txt",
    "cd {P} && cat src/a.txt | tee x",
    "cd {P}",
    "cd {P} && cd src && ls",
    "cd src && ls",
    "cd {ROOT}/elsewhere && ls",
    "cd {ROOT}/home && ls proj",
    "cd {P} && gh pr view 1",
    "cd {P} && gh pr merge 1",
    "cd {P} && gh pr view 1 | jq .title",
    "cd {P} && gh pr view 1 | jq 'env'",
    "cd {P} && jq .a src/a.txt",
    "cd {P} && git status",
    "cd {P} && python3 -c 'print(1)'",
    "cd {P} && python3 -c 'import os; os.remove(1)'",
    "cd {P} && bash -n x.sh",
    "cd {P} && sed -n 1,3p src/a.txt",
    "cd {P} && sed -i s/a/b/ src/a.txt",
    "cd {P} && head -3 src/a.txt | tail -1",
    "cd {P} && ls $(pwd)",
    "cd {P} && ls `pwd`",
    "ls",
    "echo hi",
    "ls src",
    "cat ../bare/f.txt",
    "cat src/a.txt | head -2",
    "grep alpha src/a.txt",
    "gh pr view 1",
    "git status",
]


def _stand_in(args):
    joined = " ".join(args)
    if joined.startswith("pr merge"):
        capability = "merge_remote"
    elif "delete" in joined:
        capability = "delete_remote"
    elif joined.startswith(("pr view", "repo view")):
        capability = "read_remote"
    else:
        capability = "unknown"
    return github_assessment(capability, f"stub.{joined}", "stub")


def _summary(graph: object, root: Path) -> object:
    if graph is None:
        return None
    context = graph.context
    return {
        "complete": context.complete,
        "segments": len(context.segments),
        "effects": [[item.index, item.command_name, item.effect.value] for item in graph.segments],
        "workspace_root": str(context.workspace_root) if context.workspace_root else None,
    }


def _provision_resident_home() -> None:
    """Seed the resident's verifier key; the context model needs the resident."""

    import os

    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
    from codex_plugin_scanner.guard.store import GuardStore

    provision_native_verifier_key_for_store(GuardStore(Path(os.environ["HOL_GUARD_HOME"])))


def graph_cases(root: Path, add: Callable[[str, list[object], object], None]) -> None:
    """Needs HOL_GUARD_NATIVE=force, HOL_GUARD_NATIVE_BINARY and HOL_GUARD_HOME set."""

    _provision_resident_home()
    home = root / "home"
    proj = home / "proj"
    original = gh_shell.classify_github_cli
    original_chain = developer_inspection.is_low_risk_compound_git_inspection
    original_segment = developer_inspection.is_low_risk_git_inspection_segment
    gh_shell.classify_github_cli = _stand_in
    # The Rust port injects git inspection through the resident host; the
    # vectors pin the no-git-host behaviour, so Python's git checks are off.
    developer_inspection.is_low_risk_compound_git_inspection = lambda *_a, **_k: False
    developer_inspection.is_low_risk_git_inspection_segment = lambda *_a, **_k: False
    try:
        for template in TEXTS:
            text = template.replace("{P}", str(proj)).replace("{ROOT}", str(root))
            for cwd in (None, proj, proj / "src"):
                graph = developer_inspection._compound_developer_effect_graph(text, cwd=cwd, home_dir=home)
                add(
                    "compound_developer_effect_graph",
                    [text, None if cwd is None else str(cwd), str(home)],
                    _summary(graph, root),
                )
    finally:
        developer_inspection.is_low_risk_compound_git_inspection = original_chain
        developer_inspection.is_low_risk_git_inspection_segment = original_segment
        gh_shell.classify_github_cli = original
