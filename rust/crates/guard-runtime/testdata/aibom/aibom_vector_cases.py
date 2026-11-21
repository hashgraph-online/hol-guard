"""Workspace-artifact and plan cases for the AIBOM parity vector recorder."""

from __future__ import annotations

import json

from aibom_vector_helpers import HOME, MARKETPLACE, SKILL, USER_HOME, WORK, file, link, skill


def cases() -> list[dict]:
    w = f"{WORK}/"
    out: list[dict] = []

    def add(name: str, kind: str, harness: str, **fields: object) -> None:
        out.append({"name": name, "kind": kind, "harness": harness, **fields})

    add("workspace_empty", "workspace_artifacts", "codex")
    add(
        "workspace_standards_claude_code",
        "workspace_artifacts",
        "claude-code",
        files=[
            file(w + "AGENTS.md", "agents\n"),
            file(w + "CLAUDE.md", "claude\n"),
            file(w + "DESIGN.md"),
            file(w + "PRODUCT.md"),
            file(w + "ROADMAP.md"),
            file(w + "SECURITY.md"),
            file(w + "POLICY.md"),
            file(w + "POLICIES.md"),
            file(w + "STANDARDS.md"),
            file(w + "docs/ROADMAP.md", "docs roadmap\n"),
            file(w + "docs/SECURITY.md", "docs security\n"),
            file(w + ".agents/context/PRODUCT.md", "context product\n"),
            file(w + ".agents/context/STANDARDS.md", "context standards\n"),
        ],
    )
    add(
        "workspace_standards_other_harness_has_no_legacy_claude_id",
        "workspace_artifacts",
        "gemini",
        files=[file(w + "CLAUDE.md", "claude\n"), file(w + "AGENTS.md", "agents\n")],
    )
    add(
        "workspace_doc_directories",
        "workspace_artifacts",
        "codex",
        files=[
            file(w + "docs/design/a.md", "a\n"),
            file(w + "docs/design/sub/b.md", "b\n"),
            file(w + "docs/design/sub/deeper/z.md", "z\n"),
            file(w + "docs/design/skip.txt", "not markdown\n"),
            file(w + "docs/standards/x.md", "x\n"),
            file(w + "docs/policy/p.md", "p\n"),
            file(w + "docs/policies/q.md", "q\n"),
            file(w + "docs/security/s.md", "s\n"),
            file(w + "docs/roadmap/r.md", "r\n"),
            file(w + "docs/product/pr.md", "pr\n"),
            file(w + "docs/Design/upper.md", "upper\n"),
            file(w + ".agents/context/docs/design/c.md", "context docs\n"),
            file(w + "docs/docs/design/nested.md", "nested docs\n"),
            file(w + "docs/design/B.md", "B\n"),
            file(w + "docs/design/b2.md", "b2\n"),
        ],
    )
    add(
        "workspace_doc_directory_symlinks_are_skipped",
        "workspace_artifacts",
        "codex",
        files=[
            file(w + "docs/design/real.md", "real\n"),
            file(w + "docs/product/p.md", "product\n"),
            file(w + "AGENTS.md", "agents\n"),
            file("outside/secret.md", "outside\n"),
        ],
        symlinks=[
            link(w + "docs/design/link.md", "../../AGENTS.md"),
            link(w + "docs/design/linkdir", "../product"),
            link(w + "docs/design/escape.md", "<ROOT>/outside/secret.md"),
        ],
    )
    add(
        "workspace_symlink_instruction_files_are_skipped",
        "workspace_artifacts",
        "claude-code",
        files=[file("outside/AGENTS.md", "outside\n"), file(w + "real/CLAUDE.md", "inside\n")],
        symlinks=[
            link(w + "AGENTS.md", "<ROOT>/outside/AGENTS.md"),
            link(w + "CLAUDE.md", "real/CLAUDE.md"),
            link(w + "docs", "<ROOT>/outside"),
        ],
    )
    add(
        "workspace_cursor_rules",
        "workspace_artifacts",
        "cursor",
        files=[
            file(w + ".cursor/rules/alpha.mdc", "alpha\n"),
            file(w + ".cursor/rules/beta.md", "beta\n"),
            file(w + ".cursor/rules/Gamma.mdc", "gamma\n"),
            file(w + ".cursor/rules/sub/delta.mdc", "delta\n"),
            file(w + ".cursor/rules/notes.txt", "ignored\n"),
            file("outside/escape.mdc", "escape\n"),
        ],
        symlinks=[link(w + ".cursor/rules/escape.mdc", "<ROOT>/outside/escape.mdc")],
    )
    add(
        "workspace_cursor_rules_symlinked_directory_escapes",
        "workspace_artifacts",
        "cursor",
        files=[file("outside/rules/a.mdc", "a\n")],
        symlinks=[link(w + ".cursor/rules", "<ROOT>/outside/rules")],
    )
    skills_root = w + ".agents/skills"
    add(
        "workspace_skills_codex",
        "workspace_artifacts",
        "codex",
        files=[
            *skill(skills_root, "review", file(skills_root + "/review/scripts/run.sh", "#!/bin/sh\nexit 0\n", 0o755)),
            *skill(skills_root, "nested/deep"),
            *skill(skills_root, "zeta", file(skills_root + "/zeta/notes.md", "notes\n")),
        ],
    )
    add(
        "workspace_skill_directly_at_the_root_is_named_dot",
        "workspace_artifacts",
        "codex",
        files=[
            file(skills_root + "/SKILL.md", SKILL.format(name="root-skill")),
            *skill(skills_root, "shadowed"),
        ],
    )
    add(
        "workspace_skills_claude_code_with_instructions",
        "workspace_artifacts",
        "claude-code",
        files=[file(w + "AGENTS.md", "agents\n"), *skill(skills_root, "one")],
    )
    for harness in ("hermes", "copilot", "zcode"):
        add(
            f"workspace_skills_excluded_for_{harness}",
            "workspace_artifacts",
            harness,
            files=[file(w + "AGENTS.md", "agents\n"), *skill(skills_root, "one")],
        )
    add(
        "workspace_skills_incomplete_identity",
        "workspace_artifacts",
        "codex",
        files=[
            *skill(skills_root, "sealed", file(skills_root + "/sealed/secret.txt", "hidden\n", 0o000)),
            *skill(skills_root, "outward"),
            file("outside/target.txt", "outside\n"),
        ],
        symlinks=[link(skills_root + "/outward/escape.txt", "<ROOT>/outside/target.txt")],
    )
    add(
        "workspace_skills_symlinked_skill_directory_is_not_followed",
        "workspace_artifacts",
        "codex",
        files=[*skill("outside/skills", "linked")],
        symlinks=[link(skills_root + "/linked", "<ROOT>/outside/skills/linked")],
    )
    market = w + MARKETPLACE
    plugins = {
        "plugins": [
            {"name": "alpha", "source": {"source": "local", "path": "./plugins/alpha"}},
            {"name": "beta", "source": {"source": "local", "path": "./plugins/beta"}, "enabled": False},
            {"source": "github:example/gamma"},
            {"name": "  ", "source": {"path": "./plugins/missing"}},
            "not-a-dict",
            {"name": "escape", "source": {"source": "local", "path": "./../outside"}},
            {"name": "absolute", "source": {"source": "local", "path": "/etc"}},
            {"name": "no-source"},
            {"name": "emptyref", "source": {"source": "", "path": ""}},
            {"name": "dirmanifest", "source": {"source": "local", "path": "./plugins/dir"}},
            {"name": "enabled-null", "enabled": None, "source": "x"},
        ]
    }
    add(
        "workspace_marketplace_plugins",
        "workspace_artifacts",
        "codex",
        files=[
            file(market, json.dumps(plugins, indent=2)),
            file(w + "plugins/alpha/plugin.json", '{"name": "alpha"}\n'),
            file(w + "plugins/beta/.codex-plugin/plugin.json", '{"name": "beta"}\n'),
            file(w + "plugins/dir/plugin.json/inner.txt", "plugin.json is a directory\n"),
        ],
        marketplace_files=[market],
    )
    add(
        "workspace_marketplace_legacy_root_file",
        "workspace_artifacts",
        "codex",
        files=[file(w + "marketplace.json", json.dumps({"plugins": [{"name": "legacy", "source": "x"}]}))],
        marketplace_files=[w + "marketplace.json"],
    )
    add(
        "workspace_marketplace_preferred_beats_legacy",
        "workspace_artifacts",
        "codex",
        files=[
            file(market, json.dumps({"plugins": [{"name": "preferred", "source": "x"}]})),
            file(w + "marketplace.json", json.dumps({"plugins": [{"name": "legacy", "source": "x"}]})),
        ],
        marketplace_files=[market],
    )
    add(
        "workspace_marketplace_plugins_not_a_list",
        "workspace_artifacts",
        "codex",
        files=[file(market, json.dumps({"plugins": 3}))],
    )
    add(
        "workspace_marketplace_invalid_json_is_refused",
        "workspace_artifacts",
        "codex",
        files=[file(market, "{not json")],
    )
    add(
        "workspace_marketplace_not_an_object_is_refused",
        "workspace_artifacts",
        "codex",
        files=[file(market, "[]")],
    )
    add(
        "workspace_marketplace_symlink_escape_is_refused",
        "workspace_artifacts",
        "codex",
        files=[file("outside/marketplace.json", json.dumps({"plugins": []}))],
        symlinks=[link(market, "<ROOT>/outside/marketplace.json")],
    )
    add(
        "workspace_marketplace_empty_plugins_has_root_artifact",
        "workspace_artifacts",
        "codex",
        files=[file(market, json.dumps({"plugins": []}))],
        marketplace_files=[market],
    )

    existing_mcp = {
        "artifact_id": "claude-code:project:mcp:server",
        "artifact_type": "mcp_server",
        "harness": "claude-code",
        "config_path": "<ROOT>/work/.mcp.json",
    }
    add("merge_no_extra_returns_detection_unchanged", "merge_plan", "codex", existing=[existing_mcp])
    add(
        "merge_appends_new_artifacts",
        "merge_plan",
        "codex",
        existing=[existing_mcp],
        config_paths=["<ROOT>/work/.mcp.json"],
        files=[file(w + "AGENTS.md", "agents\n"), file(w + "docs/SECURITY.md", "sec\n")],
    )
    add(
        "merge_skips_duplicate_artifact_id",
        "merge_plan",
        "codex",
        existing=[
            {
                "artifact_id": "codex:project:instruction:agents_md:AGENTS.md",
                "artifact_type": "instruction",
                "harness": "codex",
                "config_path": "<ROOT>/work/AGENTS.md",
            }
        ],
        config_paths=["<ROOT>/work/AGENTS.md", "<ROOT>/other"],
        files=[file(w + "AGENTS.md", "agents\n"), file(w + "DESIGN.md", "design\n")],
    )
    legacy_id = "claude-code:project:instruction:claude-md"
    add(
        "merge_claude_md_replaces_legacy_rules_collision",
        "merge_plan",
        "claude-code",
        existing=[
            {
                "artifact_id": legacy_id,
                "artifact_type": "instruction",
                "harness": "claude-code",
                "config_path": "<ROOT>/work/.claude/rules/claude-md.md",
            }
        ],
        config_paths=["<ROOT>/work/.claude/rules/claude-md.md"],
        files=[file(w + "CLAUDE.md", "claude\n"), file(w + ".claude/rules/claude-md.md", "rules\n")],
    )
    add(
        "merge_claude_md_does_not_replace_mcp_server",
        "merge_plan",
        "claude-code",
        existing=[
            {
                "artifact_id": legacy_id,
                "artifact_type": "mcp_server",
                "harness": "claude-code",
                "config_path": "<ROOT>/work/.claude/rules/claude-md.md",
            }
        ],
        files=[file(w + "CLAUDE.md", "claude\n"), file(w + ".claude/rules/claude-md.md", "rules\n")],
    )
    add(
        "merge_claude_md_does_not_replace_instruction_outside_rules",
        "merge_plan",
        "claude-code",
        existing=[
            {
                "artifact_id": legacy_id,
                "artifact_type": "instruction",
                "harness": "claude-code",
                "config_path": "<ROOT>/work/elsewhere/claude-md.md",
            }
        ],
        files=[file(w + "CLAUDE.md", "claude\n")],
    )
    add(
        "merge_claude_md_does_not_replace_other_harness_instruction",
        "merge_plan",
        "claude-code",
        existing=[
            {
                "artifact_id": legacy_id,
                "artifact_type": "instruction",
                "harness": "codex",
                "config_path": "<ROOT>/work/.claude/rules/claude-md.md",
            }
        ],
        files=[file(w + "CLAUDE.md", "claude\n")],
    )
    add(
        "merge_non_claude_md_collision_never_replaces",
        "merge_plan",
        "claude-code",
        existing=[
            {
                "artifact_id": "claude-code:project:instruction:agents_md:AGENTS.md",
                "artifact_type": "instruction",
                "harness": "claude-code",
                "config_path": "<ROOT>/work/.claude/rules/a.md",
            }
        ],
        files=[file(w + "AGENTS.md", "agents\n"), file(w + ".claude/rules/a.md", "rules\n")],
    )
    add(
        "merge_existing_without_config_path",
        "merge_plan",
        "codex",
        existing=[{**existing_mcp, "config_path": None}],
        files=[file(w + "AGENTS.md", "agents\n")],
    )

    h = f"{HOME}/"
    codex_home_skills = h + ".codex/skills"
    agents_home_skills = h + ".agents/skills"
    add(
        "codex_skills_global_only_without_workspace",
        "codex_skills",
        "codex",
        no_workspace=True,
        files=[*skill(codex_home_skills, "lint"), *skill(agents_home_skills, "shared")],
    )
    add(
        "codex_skills_project_and_global_without_rules",
        "codex_skills",
        "codex",
        files=[
            *skill(skills_root, "proj"),
            *skill(codex_home_skills, "lint"),
            *skill(agents_home_skills, "shared"),
            *skill(agents_home_skills, "proj"),
        ],
    )
    toml_home = (
        '[[skills.config]]\npath = "home-skill"\nenabled = false\n\n'
        '[[skills.config]]\nname = "LINT"\nenabled = false\n\n'
        '[[skills.config]]\nname = "ignored-no-enabled"\n\n'
        "[[skills.config]]\nenabled = false\n\n"
        '[[skills.config]]\nname = "string-false"\nenabled = "false"\n\n'
        '[[skills.config]]\npath = "~/tilde-skill"\nenabled = false\n'
    )
    toml_work = (
        '[[skills.config]]\nname = "proj"\nenabled = false\n\n'
        '[[skills.config]]\nname = "lint"\nenabled = true\n\n'
        '[[skills.config]]\npath = "  .agents/skills/spaced  "\nenabled = false\n'
    )
    add(
        "codex_skills_rules_from_home_and_workspace",
        "codex_skills",
        "codex",
        files=[
            file(h + ".codex/config.toml", toml_home),
            file(w + ".codex/config.toml", toml_work),
            *skill(skills_root, "proj"),
            *skill(skills_root, "spaced"),
            *skill(skills_root, "string-false"),
            *skill(codex_home_skills, "lint"),
            *skill(codex_home_skills, "home-skill"),
            *skill(agents_home_skills, "shared"),
            *skill(USER_HOME, "tilde-skill"),
        ],
    )
    add(
        "codex_skills_path_rules_match_directory_and_suffix",
        "codex_skills",
        "codex",
        files=[
            file(
                h + ".codex/config.toml",
                '[[skills.config]]\npath = "<ROOT>/home/.codex/skills/exact"\nenabled = false\n\n'
                '[[skills.config]]\npath = "skills/suffix"\nenabled = false\n\n'
                '[[skills.config]]\npath = "<ROOT>/home/.codex/skills/by-file/SKILL.md"\nenabled = false\n',
            ),
            *skill(codex_home_skills, "exact"),
            *skill(codex_home_skills, "suffix"),
            *skill(codex_home_skills, "by-file"),
            *skill(codex_home_skills, "untouched"),
        ],
    )
    add(
        "codex_skills_invalid_toml_means_no_rules",
        "codex_skills",
        "codex",
        files=[file(h + ".codex/config.toml", "[[skills.config\nbroken"), *skill(codex_home_skills, "lint")],
    )
    add(
        "codex_skills_rules_without_skills_table",
        "codex_skills",
        "codex",
        files=[file(h + ".codex/config.toml", "[other]\nvalue = 1\n"), *skill(codex_home_skills, "lint")],
    )
    add(
        "codex_skills_incomplete_identity_is_inventory_artifact",
        "codex_skills",
        "codex",
        files=[
            file(h + ".codex/config.toml", '[[skills.config]]\nname = "Incomplete skill discovery"\nenabled = false\n'),
            *skill(codex_home_skills, "sealed", file(codex_home_skills + "/sealed/secret.txt", "hidden\n", 0o000)),
        ],
    )
    add(
        "codex_skills_later_rule_overrides_earlier",
        "codex_skills",
        "codex",
        files=[
            file(
                h + ".codex/config.toml",
                '[[skills.config]]\nname = "lint"\nenabled = false\n\n'
                '[[skills.config]]\nname = "lint"\nenabled = true\n',
            ),
            *skill(codex_home_skills, "lint"),
        ],
    )
    return out
