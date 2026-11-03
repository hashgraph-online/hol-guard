"""Record `opencode_config_normalize` replay vectors from the ORIGINAL Python helpers.

Run it with the source tree of the commit before the native kind replaced
`_normalized_config_payload` on `PYTHONPATH`, on a POSIX host:

    python record_config_normalize_vectors.py > config_normalize_vectors.json

Every case is normalized by the original Python with the working directory at
`/`, against the Guard home and config path below, which need not exist.
"""

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard.adapters._modules.opencode import opencode_install_snapshot as m
from codex_plugin_scanner.guard.adapters.mcp_servers import ManagedMcpServer, stable_mcp_server_identifier

os.chdir("/")
HOME = "/opt/hg-test/home"
CFG = "/opt/hg-test/work/opencode.json"
ctx = SimpleNamespace(guard_home=Path(HOME))
PY = ["python3", "-m", "codex_plugin_scanner.cli", "guard", "opencode-mcp-proxy"]


def sid(name, scope, command, args, transport="local"):
    return stable_mcp_server_identifier(
        ManagedMcpServer(
            harness="opencode",
            name=name,
            source_scope=scope,
            config_path=CFG,
            command=command,
            args=tuple(args),
            transport=transport,
            env={},
            enabled=True,
        )
    )


def proxy(name, scope, command, args, *, transport="local", home=HOME, cfg=CFG, server_id=None, env_keys=()):
    argv = [
        *PY,
        "--guard-home",
        home,
        "--server-name",
        name,
        "--server-id",
        server_id or sid(name, scope, command, args, transport),
        "--source-scope",
        scope,
        "--config-path",
        cfg,
        "--transport",
        transport,
        "--command",
        command,
    ]
    argv += [f"--arg={a}" for a in args]
    argv += [f"--server-env-key={k}" for k in env_keys]
    return argv


cases = []


def case(label, config, scope="global"):
    out = m._normalized_config_payload(config, context=ctx, scope=scope, config_path=Path(CFG))
    cases.append({"label": label, "scope": scope, "config": json.dumps(config), "expected": json.dumps(out)})


case("no mcp", {"b": 1, "a": [1.5, None]})
case("mcp not an object", {"mcp": [1], "z": True})
args = ["--config=/srv/x.json", "./rel", "/help", "/verbose/x", "C:/w", "plain", "dir=/a"]
case(
    "trusted companion folds into its server",
    {
        "x": 0,
        "mcp": {
            "srv": {"type": "local", "command": ["node", *args], "enabled": True, "environment": {"A": "1"}},
            "hol-guard::srv": {"type": "local", "command": proxy("srv", "global", "node", args), "enabled": False},
            "other": "dropped",
        },
        "y": 1,
    },
)
case(
    "companion without server rebuilds it",
    {
        "mcp": {
            "hol-guard::Lone": {
                "type": "local",
                "command": proxy(
                    "Lone", "project", "/usr/bin/Tool.EXE", ["a"], transport="stdio", env_keys=("K", "MISSING", "N")
                ),
                "environment": {"K": "v", "N": 3, "Z": "z"},
            }
        }
    },
    scope="project",
)
case(
    "wrong server id restores the wrapper",
    {
        "mcp": {
            "srv": {"command": "node", "args": ["a"]},
            "hol-guard::srv": {
                "type": "local",
                "command": proxy("srv", "global", "node", ["a"], server_id="mcp_server:opencode:global:srv:0000"),
                "environment": {"E": "1"},
            },
        }
    },
)
case(
    "relative config path is not trusted",
    {"mcp": {"hol-guard::srv": {"command": proxy("srv", "global", "node", [], cfg="opt/hg-test/work/opencode.json")}}},
)
case(
    "dotted config path resolves equal",
    {
        "mcp": {
            "hol-guard::srv": {
                "command": proxy(
                    "srv",
                    "global",
                    "node",
                    [],
                    cfg="/opt/hg-test/work/../work/./opencode.json",
                    home="/opt/hg-test/x/../home",
                )
            }
        }
    },
)
case(
    "other guard home is not trusted",
    {"mcp": {"hol-guard::srv": {"command": proxy("srv", "global", "node", [], home="/opt/hg-test/other")}}},
)
case(
    "server that differs from the binding keeps the companion",
    {
        "mcp": {
            "srv": {"command": ["deno", "run"]},
            "hol-guard::srv": {"command": proxy("srv", "global", "node", ["run"])},
        }
    },
)
case(
    "legacy in-place wrapper restored",
    {
        "mcp": {
            "srv": {
                "type": "remote",
                "command": [*PY, "--command", "uvx", "--arg=tool", "--arg=--flag"],
                "enabled": 0,
                "environment": {"A": "b"},
            },
            "plain": {"command": ["ls"]},
        }
    },
)
case(
    "double prefix and empty name are not companions",
    {"mcp": {"hol-guard::": {"command": ["x"]}, "hol-guard::hol-guard::a": {"command": ["y"]}}},
)
case(
    "bad transport is not trusted",
    {"mcp": {"hol-guard::srv": {"command": proxy("srv", "global", "node", [], transport="sse")}}},
)
case(
    "guarded server listed after its companion keeps its place",
    {
        "mcp": {
            "hol-guard::srv": {"command": proxy("srv", "global", "node", ["a"])},
            "srv": {"command": "node", "args": ["a"], "enabled": False},
        }
    },
)
case(
    "lone surrogate round trips",
    {
        "mcp": {
            "s\udc80": {"command": ["n\udc81", "--root=x\udc82"]},
            "hol-guard::s\udc80": {"command": proxy("s\udc80", "global", "n\udc81", ["--root=x\udc82"])},
        }
    },
)
case(
    "names and scopes are stripped and lowered",
    {
        "mcp": {
            "hol-guard:: My Srv ": {
                "command": proxy(" My Srv ", "global", "C:\\Tools\\Node.exe", ["~/x", "--Work_Dir=/q", "-/path= /r"])
            }
        }
    },
)
json.dump(cases, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
