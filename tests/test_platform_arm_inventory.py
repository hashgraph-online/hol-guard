"""Keep every non-Unix behaviour arm in the Rust tree under standing review."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from scripts.ci import platform_arm_inventory as gate

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/platform-arm-inventory.yml"


def _crate(root: Path, body: str) -> Path:
    source = root / "rust" / "crates" / "guard-demo" / "src"
    source.mkdir(parents=True)
    (source / "lib.rs").write_text(body, encoding="utf-8")
    return root / "rust" / "crates"


def _rewrite(crates: Path, body: str) -> None:
    """Change the demo crate's source without recreating its directories."""
    (crates / "guard-demo" / "src" / "lib.rs").write_text(body, encoding="utf-8")


def _inventory(root: Path, arms: list[dict[str, str]]) -> Path:
    path = root / "platform_arms.json"
    path.write_text(
        json.dumps({"schema_version": gate.SCHEMA_VERSION, "arms": arms}),
        encoding="utf-8",
    )
    return path


def test_repository_arms_are_all_reviewed() -> None:
    """The gate the CI job runs, run here too so the required suite catches a new arm."""
    found = gate.arms(ROOT / gate.CRATES)
    assert found, "the extractor found no arms at all, which means it stopped matching"
    assert gate.problems(found, gate.load(ROOT / gate.INVENTORY)) == []


def test_a_declared_arm_is_named_by_its_signature(tmp_path: Path) -> None:
    """A function arm is keyed on its declaration, so a changed return type is re-reviewed."""
    crates = _crate(tmp_path, "#[cfg(not(unix))]\nfn probe(path: &Path) -> bool {\n    true\n}\n")

    [arm] = gate.arms(crates)

    assert arm["file"] == "rust/crates/guard-demo/src/lib.rs"
    assert arm["item"] == "fn probe(path: &Path) -> bool"
    assert arm["cfg"] == "not(unix)"
    assert len(arm["body"]) == 12


def test_a_block_arm_is_named_after_the_item_it_stands_in(tmp_path: Path) -> None:
    """`#[cfg(not(unix))] { .. }` has no declaration of its own to key on."""
    crates = _crate(
        tmp_path,
        "fn probe(path: &Path) -> bool {\n"
        "    #[cfg(unix)]\n"
        "    {\n"
        "        use std::os::unix::fs::PermissionsExt;\n"
        "        mode(path)\n"
        "    }\n"
        "    #[cfg(not(unix))]\n"
        "    {\n"
        "        true\n"
        "    }\n"
        "}\n",
    )

    assert [arm["item"] for arm in gate.arms(crates)] == ["fn probe -- non-Unix block"]


def test_two_block_arms_in_one_item_stay_distinct(tmp_path: Path) -> None:
    """Both have to be reviewable, so the second is numbered rather than folded into the first."""
    crates = _crate(
        tmp_path,
        "fn probe() {\n"
        "    #[cfg(not(unix))]\n"
        "    {\n"
        "        first();\n"
        "    }\n"
        "    #[cfg(not(unix))]\n"
        "    {\n"
        "        second();\n"
        "    }\n"
        "}\n",
    )

    assert [arm["item"] for arm in gate.arms(crates)] == [
        "fn probe -- non-Unix block",
        "fn probe -- non-Unix block #2",
    ]


def test_a_test_only_arm_is_not_behaviour(tmp_path: Path) -> None:
    """A test that only runs off Unix is proof, not an arm to review."""
    crates = _crate(tmp_path, "#[cfg(all(test, not(unix)))]\nmod windows_tests {}\n")

    assert gate.arms(crates) == []


def test_a_cfg_that_also_compiles_in_tests_is_behaviour(tmp_path: Path) -> None:
    """`all(test, ..)` is a test; `any(not(unix), test)` ships, so it stays under review."""
    crates = _crate(
        tmp_path,
        "#[cfg(all(test, not(unix)))]\nmod proof {}\n"
        "#[cfg(any(not(unix), test))]\nfn helper() -> bool {\n    true\n}\n",
    )

    assert [arm["item"] for arm in gate.arms(crates)] == ["fn helper() -> bool"]


def test_a_const_keeps_the_type_its_name_is_read_with(tmp_path: Path) -> None:
    """An array length is a `;` inside the type, not the end of the declaration."""
    crates = _crate(
        tmp_path,
        '#[cfg(not(unix))]\nconst NAMES: [&str; 2] = ["a", "b"];\n',
    )

    assert [arm["item"] for arm in gate.arms(crates)] == ["const NAMES: [&str; 2]"]


def test_a_predicate_is_evaluated_rather_than_matched(tmp_path: Path) -> None:
    """`not(any(unix, windows))` spells the same condition and a text match for `not(unix)` misses it."""
    crates = _crate(
        tmp_path,
        "#[cfg(not(any(unix, windows)))]\nfn fallback() -> bool {\n    true\n}\n"
        '#[cfg(all(not(unix), feature = "wide"))]\nfn gated() -> bool {\n    true\n}\n',
    )

    assert [arm["item"] for arm in gate.arms(crates)] == ["fn fallback() -> bool", "fn gated() -> bool"]


def test_a_windows_only_predicate_is_not_an_arm(tmp_path: Path) -> None:
    """The gate asks what compiles off Unix; a predicate that never names `unix` is not that."""
    crates = _crate(tmp_path, "#[cfg(windows)]\nfn probe() -> bool {\n    true\n}\n")

    assert gate.arms(crates) == []


def test_a_cfg_expression_is_an_arm(tmp_path: Path) -> None:
    """A runtime `cfg!` branch decides the same platform difference and has no second item to find."""
    crates = _crate(
        tmp_path,
        "fn probe() -> bool {\n    if cfg!(unix) {\n        mode()\n    } else {\n        true\n    }\n}\n",
    )

    [arm] = gate.arms(crates)
    assert arm["item"] == "fn probe -- cfg! expression"
    assert arm["cfg"] == "unix"


def test_a_cfg_expression_keeps_its_whole_predicate(tmp_path: Path) -> None:
    """Nested brackets end the predicate, not the first `)` after `cfg!(`."""
    crates = _crate(tmp_path, "fn probe() -> bool {\n    !cfg!(any(unix, windows))\n}\n")

    [arm] = gate.arms(crates)
    assert arm["cfg"] == "any(unix, windows)"


def test_a_cfg_expression_inside_a_test_module_is_not_behaviour(tmp_path: Path) -> None:
    """An inline `#[cfg(test)] mod` is proof; a platform branch in it is not an arm to review."""
    crates = _crate(
        tmp_path,
        "fn probe() -> bool {\n    true\n}\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    #[test]\n"
        "    fn probes() {\n"
        "        if cfg!(unix) {\n"
        "            assert!(super::probe());\n"
        "        }\n"
        "    }\n"
        "}\n",
    )

    assert gate.arms(crates) == []


def test_a_changed_block_is_reported(tmp_path: Path) -> None:
    """A block arm has no declaration to key on, so the verdict is bound to the block itself."""
    crates = _crate(
        tmp_path,
        "fn probe() -> bool {\n    #[cfg(not(unix))]\n    {\n        true\n    }\n}\n",
    )
    [arm] = gate.arms(crates)
    reviewed = [{**arm, "body": "0" * 12, "verdict": "windows-permissive", "note": "it used to return false"}]

    messages = gate.problems(gate.arms(crates), reviewed)

    assert len(messages) == 1
    assert "the block behind `fn probe -- non-Unix block` changed" in messages[0]


def test_a_rewritten_block_loses_its_verdict(tmp_path: Path) -> None:
    """`--write` must not carry a reason for behaviour that is no longer there."""
    crates = _crate(
        tmp_path,
        "fn probe() -> bool {\n    #[cfg(not(unix))]\n    {\n        true\n    }\n}\n",
    )
    [arm] = gate.arms(crates)
    reviewed = [{**arm, "body": "0" * 12, "verdict": "windows-equivalent", "note": "reads the extension"}]
    inventory = _inventory(tmp_path, reviewed)

    gate.write(inventory, gate.arms(crates), reviewed)

    [entry] = gate.load(inventory)
    assert entry["note"] == gate.UNREVIEWED
    assert entry["body"] == arm["body"]


def test_a_rewritten_declaration_body_is_reported(tmp_path: Path) -> None:
    """A stub that fails closed must not keep its reason once it returns true."""
    stub = "#[cfg(not(unix))]\nfn executable_file() -> bool {\n    false\n}\n"
    crates = _crate(tmp_path, stub)
    [arm] = gate.arms(crates)
    reviewed = [{**arm, "verdict": "windows-unsupported", "note": "fails closed"}]
    _rewrite(crates, stub.replace("false", "true"))

    messages = gate.problems(gate.arms(crates), reviewed)

    assert len(messages) == 1
    assert "the block behind `fn executable_file() -> bool` changed" in messages[0]


def test_a_bracket_in_prose_does_not_end_the_block_early(tmp_path: Path) -> None:
    """Unbalanced brackets in comments and literals must not truncate the digest."""
    stub = (
        "#[cfg(not(unix))]\n"
        "fn executable_file() -> bool {\n"
        "    // 1) open the handle before the mode is read\n"
        "    let marker = 0;\n"
        "    let _ = marker;\n"
        "    false\n"
        "}\n"
    )
    crates = _crate(tmp_path, stub)
    [arm] = gate.arms(crates)
    reviewed = [{**arm, "verdict": "windows-unsupported", "note": "fails closed"}]
    _rewrite(crates, stub.replace("    false", "    true"))

    messages = gate.problems(gate.arms(crates), reviewed)

    assert len(messages) == 1
    assert "the block behind `fn executable_file() -> bool` changed" in messages[0]


def test_a_bracket_in_a_literal_does_not_end_the_block_early(tmp_path: Path) -> None:
    """A closing bracket inside a char or string literal is data, not the end of the body."""
    stub = (
        "#[cfg(not(unix))]\n"
        "fn executable_file() -> bool {\n"
        "    let closer = ')';\n"
        "    let _ = closer;\n"
        "    false\n"
        "}\n"
    )
    crates = _crate(tmp_path, stub)
    [arm] = gate.arms(crates)
    reviewed = [{**arm, "verdict": "windows-unsupported", "note": "fails closed"}]
    _rewrite(crates, stub.replace("    false", "    true"))

    messages = gate.problems(gate.arms(crates), reviewed)

    assert len(messages) == 1
    assert "the block behind `fn executable_file() -> bool` changed" in messages[0]


def test_a_declaration_without_a_body_ends_at_its_semicolon(tmp_path: Path) -> None:
    """A `mod` or a `use` must not be keyed on whatever follows it."""
    crates = _crate(tmp_path, "#[cfg(not(unix))]\nmod windows_pytest;\nfn unrelated() -> bool {\n    true\n}\n")
    [first] = gate.arms(crates)
    _rewrite(crates, "#[cfg(not(unix))]\nmod windows_pytest;\nfn unrelated() -> bool {\n    false\n}\n")
    [second] = gate.arms(crates)

    assert first["body"] == second["body"]


def test_a_reviewed_declaration_keeps_its_verdict_when_a_neighbour_arrives(tmp_path: Path) -> None:
    """Adding an arm above a reviewed one must not renumber it into a fresh review."""
    crates = _crate(
        tmp_path,
        "#[cfg(not(unix))]\nfn first() -> bool {\n    true\n}\n#[cfg(not(unix))]\nfn second() -> bool {\n    true\n}\n",
    )
    reviewed = [
        {
            "file": "rust/crates/guard-demo/src/lib.rs",
            "item": "fn second() -> bool",
            "cfg": "not(unix)",
            "verdict": "windows-equivalent",
            "note": "reads the extension",
        }
    ]
    inventory = _inventory(tmp_path, reviewed)

    gate.write(inventory, gate.arms(crates), reviewed)

    entries = {entry["item"]: entry for entry in gate.load(inventory)}
    assert entries["fn second() -> bool"]["note"] == "reads the extension"
    assert entries["fn first() -> bool"]["note"] == gate.UNREVIEWED


def test_a_new_arm_is_reported(tmp_path: Path) -> None:
    """The case both shipped gaps would have hit: a Windows arm added with no review."""
    crates = _crate(tmp_path, "#[cfg(not(unix))]\nfn sink() -> Option<PathBuf> {\n    None\n}\n")

    messages = gate.problems(gate.arms(crates), [])

    assert len(messages) == 1
    assert "fn sink() -> Option<PathBuf>" in messages[0]
    assert "--write" in messages[0]


def test_a_removed_arm_is_reported(tmp_path: Path) -> None:
    """A stale entry hides the next new arm behind a passing count, so it fails too."""
    crates = _crate(tmp_path, "fn probe() {}\n")
    reviewed = [
        {
            "file": "rust/crates/guard-demo/src/lib.rs",
            "item": "fn gone() -> bool",
            "cfg": "not(unix)",
            "verdict": "windows-unsupported",
            "note": "left behind by a fold",
        }
    ]

    assert gate.problems(gate.arms(crates), reviewed) == [
        "rust/crates/guard-demo/src/lib.rs: reviewed arm `fn gone() -> bool` no longer exists; drop the entry."
    ]


def test_a_widened_cfg_is_reported(tmp_path: Path) -> None:
    """`not(unix)` and `all(not(unix), not(windows))` are different platforms, so re-review."""
    crates = _crate(tmp_path, "#[cfg(not(unix))]\nfn probe() -> bool {\n    true\n}\n")
    [arm] = gate.arms(crates)
    reviewed = [
        {
            **arm,
            "cfg": "all(not(unix), not(windows))",
            "verdict": "other-platform",
            "note": "Windows takes its own arm",
        }
    ]

    messages = gate.problems(gate.arms(crates), reviewed)

    assert len(messages) == 1
    assert "is now `#[cfg(not(unix))]`" in messages[0]


def test_an_unreviewed_verdict_is_not_a_review(tmp_path: Path) -> None:
    """`--write` seeds a placeholder; the placeholder must not pass the gate."""
    crates = _crate(tmp_path, "#[cfg(not(unix))]\nfn probe() -> bool {\n    true\n}\n")
    inventory = _inventory(tmp_path, [])
    gate.write(inventory, gate.arms(crates), [])

    messages = gate.problems(gate.arms(crates), gate.load(inventory))

    assert len(messages) == 1
    assert "has no reason" in messages[0]


def test_an_unknown_verdict_is_rejected(tmp_path: Path) -> None:
    """The verdict list is the vocabulary a reader of the inventory can rely on."""
    crates = _crate(tmp_path, "#[cfg(not(unix))]\nfn probe() -> bool {\n    true\n}\n")
    [arm] = gate.arms(crates)
    reviewed = [{**arm, "verdict": "fine", "note": "looks fine"}]

    assert gate.problems(gate.arms(crates), reviewed) == ["rust/crates/guard-demo/src/lib.rs: unknown verdict 'fine'"]


def test_the_audit_job_runs_the_gate() -> None:
    """Keep the workflow wired to the gate it is named for."""
    workflow = yaml.safe_load((ROOT / WORKFLOW).read_text(encoding="utf-8"))
    [job] = workflow["jobs"].values()
    assert workflow["permissions"] == {"contents": "read"}
    checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False
    assert "python3 scripts/ci/platform_arm_inventory.py --root ." in [step.get("run", "") for step in job["steps"]]


def test_the_audit_job_watches_the_tree_it_guards() -> None:
    """A new arm arrives with a Rust change, so the path filter must include it."""
    workflow = yaml.safe_load((ROOT / WORKFLOW).read_text(encoding="utf-8"))
    # PyYAML resolves the unquoted `on:` key to True.
    triggers = workflow[True]
    for event in ("pull_request", "push"):
        assert "rust/**" in triggers[event]["paths"]
        assert str(gate.INVENTORY) in triggers[event]["paths"]
