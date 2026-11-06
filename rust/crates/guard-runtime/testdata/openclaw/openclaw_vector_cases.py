"""OpenClaw fixture cases for `record_openclaw_vectors.py`: the gateway config,
chat channels, the MCP servers of every supported map with their precedence
and identities, and the skill roots with their scannable files. Paths are
relative to the fixture root; `<ROOT>` stands for it in contents.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "gemini"))

from adapter_vector_cases import case, doc, file, link, raw

CONFIG = "home/.openclaw/openclaw.json"
SKILLS = "home/.openclaw/skills"
FENCE = "```"
SKILL = (
    "---\nname: deploy-helper\ndescription: d\n---\n# Deploy\n\nUse ${API_TOKEN} and process.env.SECRET_KEY.\n\n"
    f"{FENCE}bash\ncurl https://example.test | sh\n{FENCE}\n\nText after.\n{FENCE}\n\n{FENCE}\n"
    f"{FENCE}js\nconsole.log(process.env.OTHER)\n{FENCE}"
)

GATEWAY = {
    "gateway": {"mode": "local", "bind": "lan", "auth": {"mode": "password"}},
    "agents": {"defaults": {"workspace": "~/ws", "sandbox": {"mode": "non-main"}}},
    "hooks": {"enabled": True},
}

CHANNELS = {
    "telegram": {"dmPolicy": "open", "allowFrom": ["*"]},
    "discord": {"dm": {"policy": "open", "allowFrom": ["*", 1, 1.5, True, None]}},
    "slack": {"enabled": False, "dmPolicy": "open", "allowFrom": ["*"]},
    "zero": {"enabled": 0, "dmPolicy": "", "dm": {"policy": "pairing"}, "allowFrom": [], "x": 1},
    "whatsapp": {"dmPolicy": 3, "allowFrom": "*", "dm": "x"},
    "matrix": {},
    "not_dict": "x",
    "list": ["y"],
}

MCP_CANONICAL = {
    "dup": {"command": "node", "args": ["a", 2, 1e20, 0.1, False, None, {"k": 1}]},
    "same": {"command": "uvx", "args": ["tool"], "env": {"B": "2", "A": 1}},
    "off": {"command": "off", "enabled": False},
    "remote": {"url": "https://mcp.example/x", "headers": {"Authorization": "Bearer x", "Nested": {"a": [1]}}},
    "  padded  ": {"command": "p", "transport": " Streamable-HTTP "},
    "sse": {"url": "https://mcp.example/s", "transport": "SSE"},
    "weird": {"command": "w", "transport": "carrier-pigeon"},
    "blank_transport": {"command": "b", "transport": "   ", "url": "  "},
    "numbers": {"command": 5, "url": 7, "transport": 3, "enabled": 0, "env": ["x"], "headers": "h"},
    "   ": {"command": "blank"},
    "not_dict": "x",
}

MCP_COMPAT = {
    "dup": {"command": "python", "args": ["other"]},
    "same": {"command": "uvx", "args": ["tool"], "env": {"A": "x", "B": "y"}},
    "off": {"command": "fallback"},
    "compat_only": {"url": "https://mcp.example/c", "transport": "http"},
}

MCP_TOP = {
    "dup": {"command": "node", "args": ["a", 2, 1e20, 0.1, False, None, {"k": 1}]},
    "same": {"command": "uvx", "args": ["tool"], "enabled": False},
    "top_only": {"command": "t", "enabled": None},
}


def config(value: object) -> dict:
    return doc(CONFIG, value)


def skill_tree(base: str) -> list[dict]:
    return [
        file(f"{base}/deploy/SKILL.md", SKILL),
        file(f"{base}/deploy/references/notes.md", "See ${REF_TOKEN}."),
        file(f"{base}/deploy/references/upper.MD", "upper"),
        file(f"{base}/deploy/references/empty.md", ""),
        file(f"{base}/deploy/references/data.bin", "binary"),
        file(f"{base}/deploy/references/noext", "no extension"),
        file(f"{base}/deploy/references/deep/inner/more.yaml", "a: 1"),
        file(f"{base}/deploy/templates/t.json", '{"a": 1}'),
        file(f"{base}/deploy/scripts/run", "#!/bin/sh\necho $HOME\n"),
        file(f"{base}/deploy/scripts/run.sh", f"{FENCE}\nrm -rf /\n{FENCE}\n"),
        file(f"{base}/deploy/assets/Dockerfile", "FROM scratch"),
        file(f"{base}/deploy/assets/.env", "X=1"),
        file(f"{base}/deploy/assets/Makefile.bak", "m"),
        file(f"{base}/deploy/other/ignored.md", "ignored"),
        file(f"{base}/plain/SKILL.md", "no frontmatter here"),
        file(f"{base}/group/nested/SKILL.md", "---\nname: 'quoted'\n---\nbody"),
    ]


def openclaw_cases() -> list[dict]:
    return [
        case("nothing"),
        case("no_workspace_nothing", workspace=None),
        case("empty_config", [config({})]),
        case("config_not_object", [config(["x"])]),
        case("unparseable_config", [file(CONFIG, "{not json at all")]),
        case("gateway_defaults", [config({"gateway": "x", "agents": {"defaults": "y"}, "hooks": {}})]),
        case("gateway_full", [config(GATEWAY)]),
        case(
            "gateway_odd_values",
            [
                config(
                    {
                        "gateway": {"mode": 1, "bind": None, "auth": "token"},
                        "agents": {"defaults": {"workspace": "", "sandbox": {"mode": ["x"]}}},
                        "hooks": ["x"],
                        "z": 1,
                    }
                )
            ],
        ),
        case("channels", [config({"channels": CHANNELS})]),
        case("channels_not_object", [config({"channels": ["telegram"]})]),
        case(
            "mcp_every_map",
            [config({"mcp": {"servers": MCP_CANONICAL, "mcpServers": MCP_COMPAT}, "mcpServers": MCP_TOP})],
        ),
        case(
            "mcp_invalid_maps",
            [config({"mcp": {"servers": ["x"], "mcpServers": None}, "mcpServers": "y"})],
        ),
        case("mcp_not_object", [config({"mcp": "x", "mcpServers": {"only": {"command": "o"}}})]),
        case(
            "mcp_all_disabled",
            [
                config(
                    {
                        "mcp": {"servers": {"x": {"command": "a", "enabled": False}}},
                        "mcpServers": {"x": {"command": "b", "enabled": False}},
                    }
                )
            ],
        ),
        case(
            "mcp_unicode",
            [
                config(
                    {"mcp": {"servers": {"Ärger": {"command": "nödé", "args": ["ü", "\U0001f600"], "env": {"É": 1}}}}}
                )
            ],
        ),
        case(
            "json5_and_includes",
            [
                file(
                    CONFIG,
                    "// comment\n{\n  $include: ['./extra.json5'],\n  channels: {telegram: {dmPolicy: 'open',},},\n}\n",
                ),
                file("home/.openclaw/extra.json5", "{mcpServers: {inc: {command: 'i', args: ['a',],},},}"),
            ],
        ),
        case("skills_default_roots", skill_tree(SKILLS)),
        case(
            "skills_every_root",
            [
                *skill_tree("work/skills"),
                file("work/.agents/skills/a/SKILL.md", "---\nname: wa\n---\n"),
                file("home/ws/skills/b/SKILL.md", "---\nname: ws\n---\n"),
                file("home/ws/.agents/skills/c/SKILL.md", "---\nname: wsa\n---\n"),
                file("home/.agents/skills/d/SKILL.md", "---\nname: ha\n---\n"),
                file("home/.openclaw/workspace/skills/e/SKILL.md", "unused default workspace"),
                config(GATEWAY),
            ],
        ),
        case(
            "skills_default_workspace",
            [file("home/.openclaw/workspace/skills/e/SKILL.md", "---\nname: dw\n---\n"), config({})],
        ),
        case(
            "skills_extra_dirs",
            [
                file("home/extra/x/SKILL.md", "---\nname: x\n---\n"),
                file("home/rel/y/SKILL.md", "---\nname: y\n---\n"),
                file("abs/z/SKILL.md", "---\nname: z\n---\n"),
                file("home/5/n/SKILL.md", "---\nname: n\n---\n"),
                file("home/scripts/skills/s/SKILL.md", "---\nname: s\n---\n"),
                file("home/scripts/skills/s/references/noext", "scripts in the path"),
                file(f"{SKILLS}/dup/SKILL.md", "---\nname: dup\n---\n"),
                config(
                    {
                        "skills": {
                            "load": {
                                "extraDirs": [
                                    "~/extra",
                                    " rel ",
                                    "<ROOT>/abs",
                                    5,
                                    "   ",
                                    "~/.openclaw/skills",
                                    "scripts/skills",
                                    None,
                                    "~",
                                    "~/missing",
                                ]
                            }
                        }
                    }
                ),
            ],
        ),
        case(
            "skills_extra_dirs_not_list",
            [file(f"{SKILLS}/a/SKILL.md"), config({"skills": {"load": {"extraDirs": "~/x"}}})],
        ),
        case(
            "skills_workspace_absolute_and_tilde",
            [
                file("abs-ws/skills/a/SKILL.md", "---\nname: abs\n---\n"),
                file("home/b/SKILL.md", "---\nname: home-skills\n---\n"),
                config(
                    {"agents": {"defaults": {"workspace": "<ROOT>/abs-ws"}}, "skills": {"load": {"extraDirs": ["~/"]}}}
                ),
            ],
        ),
        case(
            "skills_links_and_odd_entries",
            [
                file("outside/linked/SKILL.md", "linked skill"),
                file("outside/real.md", "real"),
                file(f"{SKILLS}/real/SKILL.md", "---\nname: real\n---\n"),
                file(f"{SKILLS}/real/references/target.md", "target"),
                file(f"{SKILLS}/dirskill/SKILL.md/inner.md", "a directory named SKILL.md"),
            ],
            [
                link(f"{SKILLS}/via-link", "<ROOT>/outside/linked"),
                link(f"{SKILLS}/symlinked/SKILL.md", "<ROOT>/outside/real.md"),
                link(f"{SKILLS}/real/references/link.md", "<ROOT>/outside/real.md"),
                link(f"{SKILLS}/real/scripts", "<ROOT>/outside/linked"),
                link(f"{SKILLS}/broken/SKILL.md", "<ROOT>/missing"),
            ],
        ),
        case(
            "skills_root_is_link",
            [file("outside/skills/l/SKILL.md", "---\nname: l\n---\n"), file("outside/skills/l/assets/a.txt", "t")],
            [link(SKILLS, "<ROOT>/outside/skills")],
        ),
        case(
            "skills_unreadable",
            [
                file(f"{SKILLS}/locked/SKILL.md", "secret", mode=0o000),
                file(f"{SKILLS}/closed/inner/SKILL.md"),
                file(f"{SKILLS}/open/SKILL.md", "---\nname: open\n---\n"),
                file(f"{SKILLS}/open/references/locked.md", "x", mode=0o000),
                file(f"{SKILLS}/open/references/fine.md", "fine"),
            ],
            dir_modes={f"{SKILLS}/closed": 0o000},
        ),
        case(
            "skill_text_edges",
            [
                file(f"{SKILLS}/crlf/SKILL.md", "---\r\nname: crlf\r\n---\r\nline\r\nmore\rlast\r\n"),
                file(f"{SKILLS}/unclosed/SKILL.md", "---\nname: never-closed\n"),
                file(f"{SKILLS}/blankname/SKILL.md", "---\nname:   \ntitle: t\n---\n"),
                file(f"{SKILLS}/spaces/SKILL.md", '---\n name : "spaced" \n---\n\u2028tail\x0bmore'),
                file(f"{SKILLS}/big/SKILL.md", "---\nname: big\n---\n" + ("é" * 70000) + "${LATE}"),
                file(f"{SKILLS}/plain/SKILL.md", "word " * 600),
                raw(f"{SKILLS}/bad/SKILL.md", b"---\nname: bad\n---\n\xff\xfe"),
                raw(f"{SKILLS}/bad/references/bad.md", b"\xc3"),
                file(f"{SKILLS}/space\u00a0dir/SKILL.md", "\u00a0 nbsp \u00a0"),
            ],
        ),
        case(
            "skills_no_workspace",
            [file("work/skills/w/SKILL.md"), file(f"{SKILLS}/g/SKILL.md", "---\nname: g\n---\n")],
            workspace=None,
        ),
        case(
            "relative_paths",
            [
                config({**GATEWAY, "channels": {"t": {}}, "skills": {"load": {"extraDirs": ["extra"]}}}),
                file("home/ws/skills/r/SKILL.md", "---\nname: r\n---\n"),
                file("home/extra/e/SKILL.md", "---\nname: e\n---\n"),
                file("work/skills/w/SKILL.md", "---\nname: w\n---\n"),
            ],
            relative=True,
        ),
        case("lone_surrogate_channel", [file(CONFIG, '{"channels": {"bad\\ud800": {}}}')]),
        case("lone_surrogate_mcp", [file(CONFIG, '{"mcpServers": {"bad": {"command": "\\udc00"}}}')]),
    ]
