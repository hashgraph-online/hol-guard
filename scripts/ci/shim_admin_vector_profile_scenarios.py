"""Scenario builders for shell profiles, activation and intercept probes."""

from __future__ import annotations

import base64

from shim_admin_vector_scenarios import (
    SHIM_BIN,
    Scenario,
    Step,
    base_facts,
    call,
    env,
    manifest_step,
    mkdir,
    real_binary,
    scenario,
    symlink,
    write,
)
from shim_admin_vector_state_scenarios import PROTECTED_PATH, append, protected_facts

PKG = "# HOL Guard package manager shims"
GUARD = "# HOL Guard harness launchers"
EXPORT = f"export PATH={SHIM_BIN}:$PATH"
FISH = f"fish_add_path --prepend -- {SHIM_BIN}"


def write_b64(path: str, data: bytes) -> Step:
    return {"op": "write", "path": path, "b64": base64.b64encode(data).decode("ascii"), "exec": False}


PROFILE_CONTENTS: list[tuple[str, str]] = [
    ("empty", ""),
    ("user-only", "alias ll='ls -l'\n"),
    ("user-no-trailing-newline", "alias ll='ls -l'"),
    ("correct-block", f"{PKG}\n{EXPORT}\n"),
    ("correct-block-plus-user", f"alias a=b\n{PKG}\n{EXPORT}\nalias c=d\n"),
    ("stale-path-block", f"{PKG}\nexport PATH=/old/dir:$PATH\n"),
    ("two-blocks", f"{PKG}\nexport PATH=/a:$PATH\nuser\n{PKG}\nexport PATH=/b:$PATH\n"),
    ("blank-sandwich", f"before\n\n{PKG}\n{EXPORT}\n\nafter\n"),
    ("blank-runs-kept", "a\n\n\nb\n\n\n"),
    ("marker-last-line", f"user\n{PKG}\n"),
    ("marker-padded", f"  {PKG}  \n{EXPORT}\n"),
    ("legacy-guard-block", f"{GUARD}\nexport PATH=/legacy:$PATH\n"),
    ("legacy-and-package", f"{GUARD}\nexport PATH=/legacy:$PATH\n{PKG}\n{EXPORT}\n"),
    ("crlf", f"user\r\n{PKG}\r\n{EXPORT}\r\nmore\r\n"),
    ("cr-only", f"user\r{PKG}\r{EXPORT}\rmore\r"),
    ("unicode-separators", f"user {PKG}\n{EXPORT}\n\x0cx\x0b\n"),
    ("commented-reference", f"# {SHIM_BIN}\n"),
    ("active-reference", f"PATH={SHIM_BIN}:$PATH\n"),
    ("active-fish-reference", f"{FISH}\n"),
    ("indented-export", f"  {EXPORT}\n"),
    ("marker-inside-text", f"echo '{PKG}'\n"),
    ("only-blank-lines", "\n\n\n"),
    ("tab-lines", f"\t\n{PKG}\n{EXPORT}\n\t\n"),
]


def profile_content_scenarios() -> list[Scenario]:
    scenarios: list[Scenario] = []
    for label, content in PROFILE_CONTENTS:
        for shell in ("/bin/zsh", "/bin/bash", "/usr/bin/fish"):
            name = shell.rsplit("/", 1)[1]
            profile = "home/.config/fish/config.fish" if name == "fish" else f"home/.{name}rc"
            scenarios.append(
                scenario(
                    f"profile-{label}-{name}",
                    [
                        write(profile, content),
                        call("status"),
                        call("ensure_package_shim_profile"),
                        call("ensure_package_shim_profile"),
                        call("status"),
                        call("remove_guard_profile_blocks"),
                        call("remove_guard_profile_blocks"),
                    ],
                    facts=base_facts(environ=env(shell=shell)),
                    durable=True,
                )
            )
    return scenarios


def profile_layout_scenarios() -> list[Scenario]:
    scenarios: list[Scenario] = []
    for label, shell in (("empty", ""), ("unset", None), ("tcsh", "/usr/bin/tcsh"), ("bare-bash", "bash"), ("trailing-slash", "/bin/bash/"), ("path-fish", "/opt/fish/bin/fish")):
        scenarios.append(scenario(f"profile-shell-{label}", [call("ensure_package_shim_profile"), call("status")], facts=base_facts(environ=env(shell=shell)), durable=True))
    for label, files in (
        ("bash-profile-exists", ["home/.bash_profile"]),
        ("bash-login-exists", ["home/.bash_login"]),
        ("both-exist", ["home/.bash_profile", "home/.bash_login"]),
        ("profile-exists", ["home/.profile"]),
        ("all-exist", ["home/.bashrc", "home/.bash_profile", "home/.bash_login", "home/.profile", "home/.zshrc"]),
    ):
        scenarios.append(scenario(f"profile-bash-login-{label}", [*[write(path, "user\n") for path in files], call("ensure_package_shim_profile"), call("status"), call("remove_guard_profile_blocks")], facts=base_facts(environ=env(shell="/bin/bash")), durable=True))
    scenarios += [
        scenario("profile-windows", [call("ensure_package_shim_profile"), call("remove_guard_profile_blocks")], facts=base_facts(windows=True, environ=env(path="{root}/real1")), durable=True),
        scenario("profile-transient-guard-home", [call("ensure_package_shim_profile"), call("status")], guard_home="{root}/tmp/guard"),
        scenario("profile-transient-var-folders", [call("ensure_package_shim_profile")], guard_home="{root}/var/folders/x/guard"),
        scenario("profile-transient-pytest", [call("ensure_package_shim_profile")], guard_home="{root}/pytest-of-me/guard"),
        scenario("profile-transient-temp", [call("ensure_package_shim_profile")], guard_home="{root}/Temp/guard"),
    ]
    for var in ("TMPDIR", "TEMP", "TMP"):
        scenarios.append(scenario(f"profile-transient-env-{var}", [mkdir("scratch"), call("ensure_package_shim_profile")], facts=base_facts(environ=env(**{var: "{root}/scratch"})), guard_home="{root}/scratch/guard"))
    scenarios += [
        scenario("profile-transient-env-padded", [mkdir("scratch"), call("ensure_package_shim_profile")], facts=base_facts(environ=env(TMPDIR="  {root}/scratch  ")), guard_home="{root}/scratch/guard"),
        scenario("profile-transient-env-blank", [call("ensure_package_shim_profile")], facts=base_facts(environ=env(TMPDIR="   ")), durable=True),
        scenario("profile-transient-env-other", [call("ensure_package_shim_profile")], facts=base_facts(environ=env(TMPDIR="{root}/elsewhere")), durable=True),
        scenario("profile-transient-env-symlink", [mkdir("real-scratch"), symlink("scratch", "{root}/real-scratch"), call("ensure_package_shim_profile")], facts=base_facts(environ=env(TMPDIR="{root}/scratch")), guard_home="{root}/real-scratch/guard"),
        scenario("profile-transient-env-tilde", [mkdir("home/st"), call("ensure_package_shim_profile")], facts=base_facts(environ=env(TMPDIR="~/st")), guard_home="{root}/home/st/guard"),
        scenario("profile-transient-env-nonexistent", [call("ensure_package_shim_profile")], facts=base_facts(environ=env(TMPDIR="{root}/never")), guard_home="{root}/never/guard"),
        scenario("profile-guard-home-equals-tmpdir", [call("ensure_package_shim_profile")], facts=base_facts(environ=env(TMPDIR="{root}/guard/package-shims/bin"))),
        scenario("profile-dir-in-the-way", [mkdir("home/.zshrc"), call("ensure_package_shim_profile")], durable=True),
        scenario("profile-fish-dir-is-file", [write("home/.config", "x"), call("ensure_package_shim_profile")], facts=base_facts(environ=env(shell="/usr/bin/fish")), durable=True),
        scenario("profile-invalid-utf8", [write_b64("home/.zshrc", b"\xff\xfe"), call("ensure_package_shim_profile"), call("status")], durable=True),
        scenario("profile-remove-invalid-utf8", [write_b64("home/.bashrc", b"\xff"), call("remove_guard_profile_blocks")], durable=True),
        scenario("profile-remove-only-managed-deletes-file", [call("ensure_package_shim_profile"), call("remove_guard_profile_blocks"), call("status")], durable=True),
        scenario("profile-remove-all-profiles", [*[write(f"home/{name}", f"{PKG}\n{EXPORT}\nuser\n") for name in (".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".config/fish/config.fish")], call("remove_guard_profile_blocks")], durable=True),
        scenario("profile-remove-legacy-only", [write("home/.zshrc", f"{GUARD}\nexport PATH=/x:$PATH\n")] + [call("remove_guard_profile_blocks")], durable=True),
        scenario("profile-remove-nothing", [write("home/.zshrc", "user\n"), call("remove_guard_profile_blocks")], durable=True),
        scenario("profile-remove-windows", [write("home/.zshrc", f"{PKG}\n{EXPORT}\n"), call("remove_guard_profile_blocks")], facts=base_facts(windows=True, environ=env(path="{root}/real1")), durable=True),
        scenario("profile-home-symlink", [mkdir("realhome"), symlink("homelink", "{root}/realhome"), call("ensure_package_shim_profile")], home_dir="{root}/homelink", durable=True),
        scenario("profile-guard-home-quoted", [call("ensure_package_shim_profile"), call("status")], guard_home="{root}/it's guard $x", durable=True),
        scenario("profile-guard-home-quoted-fish", [call("ensure_package_shim_profile"), call("status")], guard_home="{root}/it's guard $x", facts=base_facts(environ=env(shell="/usr/bin/fish")), durable=True),
    ]
    return scenarios


def activate_scenarios() -> list[Scenario]:
    scenarios: list[Scenario] = []
    for shell in ("/bin/zsh", "/bin/bash", "/usr/bin/fish", "/bin/sh"):
        name = shell.rsplit("/", 1)[1]
        for repair in (False, True):
            scenarios.append(scenario(f"activate-{name}-{'repair' if repair else 'install'}", [call("activate", managers=["npm", "pip"], repair=repair), call("activate", managers=["npm"], repair=repair)], facts=base_facts(environ=env(shell=shell)), durable=True))
    scenarios += [
        scenario("activate-in-path", [call("activate"), call("status")], facts=protected_facts(), durable=True),
        scenario("activate-repair-broken", [call("install", managers=["npm"]), append("guard/package-shims/bin/npm", "# x"), call("activate", repair=True), call("status")], durable=True),
        scenario("activate-transient", [call("activate", managers=["npm"])], guard_home="{root}/tmp/guard"),
        scenario("activate-windows", [call("activate", managers=["npm"])], facts=base_facts(windows=True, environ=env(path="{root}/real1")), durable=True),
        scenario("activate-profile-error", [mkdir("home/.zshrc"), call("activate", managers=["npm"])], durable=True),
        scenario("activate-default-managers", [call("activate")], durable=True),
    ]
    return scenarios


def fake_manifest(managers: list[str]) -> Step:
    return manifest_step({"installed_managers": managers, "content_hashes": {}, "last_test_at": {}})


def fake_shim(manager: str, body: str, executable: bool = True) -> Step:
    return write(f"guard/package-shims/bin/{manager}", f"#!/bin/sh\n{body}\n", executable)


def verdict(action: str = "allow", source: str = "guard") -> str:
    return f'{{"verdict":{{"action":"{action}","source":"{source}"}}}}'


def printf(text: str, code: int = 0) -> str:
    return f"printf '%s' '{text}'\nexit {code}"


def probe_scenarios() -> list[Scenario]:
    facts = protected_facts()
    npm = lambda body, **kw: [fake_manifest(["npm"]), fake_shim("npm", body, **kw)]  # noqa: E731
    full = '{"verdict":{"action":"block","source":"v"},"supply_chain_evaluation":{"evidence_ids":["e1",2,null,"e3"],"source":"sc","policy_action":"warn"}}'
    cases: list[tuple[str, list[Step], dict[str, object]]] = [
        ("allow", npm(printf(verdict())), {}),
        ("full-payload", npm(printf(full, 2)), {}),
        ("block-exit-2", npm(printf(verdict("block"), 2)), {}),
        ("garbage-stdout", npm("echo not json; exit 1"), {}),
        ("empty-stdout", npm("exit 0"), {}),
        ("json-list", npm(printf("[1,2]")), {}),
        ("leading-whitespace-trailing-junk", npm("printf '  \\n  %s trailing' '" + verdict() + "'"), {}),
        ("decision-source", npm(printf('{"supply_chain_evaluation":{"decision_source":"ds","policy_action":"allow"}}')), {}),
        ("blank-source", npm(printf('{"supply_chain_evaluation":{"source":"  ","decision_source":""},"verdict":{"source":"vs","action":"warn"}}')), {}),
        ("no-source-at-all", npm(printf('{"supply_chain_evaluation":{}}')), {}),
        ("verdict-only-block", npm(printf('{"verdict":{"action":"block"}}')), {}),
        ("policy-action-not-str", npm(printf('{"supply_chain_evaluation":{"policy_action":5},"verdict":{"action":"allow"}}')), {}),
        ("evidence-not-list", npm(printf('{"verdict":{},"supply_chain_evaluation":{"evidence_ids":"x"}}')), {}),
        ("evidence-floats", npm(printf('{"verdict":{},"supply_chain_evaluation":{"evidence_ids":[1.5,true,{"a":1},[2]]}}')), {}),
        ("unicode", npm(printf('{"verdict":{"action":"allow","source":"é中"}}')), {}),
        ("exit-137", npm("exit 137"), {}),
        ("stderr-noise", npm("echo oops >&2; " + printf(verdict())), {}),
        ("sees-probe-env", npm('printf \'{"verdict":{"action":"allow","source":"%s"}}\' "$HOL_GUARD_SHIM_PROBE-$FOO"'), {}),
        ("sees-args", npm('printf \'{"verdict":{"action":"allow","source":"%s"}}\' "$*"'), {}),
        ("cwd-home-fallback", npm('printf \'{"verdict":{"action":"allow","source":"%s"}}\' "$(pwd -P)"'), {}),
        ("not-executable", npm("exit 0", executable=False), {}),
        ("timeout", npm("exec /bin/sleep 5"), {"timeout_seconds": 1}),
        ("shim-missing", [fake_manifest(["npm"])], {}),
        ("shim-dir-not-file", [fake_manifest(["npm"]), mkdir("guard/package-shims/bin/npm")], {}),
        ("tampered-skipped", [manifest_step({"installed_managers": ["npm"], "content_hashes": {"npm": "f" * 64}}), fake_shim("npm", "exit 0")], {}),
        ("not-installed", npm("exit 0"), {"managers": ["pip", "npm"]}),
        ("only-not-installed", npm("exit 0"), {"managers": ["bogus", "cargo"]}),
        ("empty-managers-list", npm(printf(verdict())), {"managers": []}),
        ("duplicate-managers", npm(printf(verdict())), {"managers": ["npm", "npm"]}),
        ("nonexistent-workspace", npm(printf(verdict())), {"workspace_dir": "{root}/missing"}),
        ("explicit-workspace", [mkdir("ws"), *npm('printf \'{"verdict":{"action":"allow","source":"%s"}}\' "$(pwd -P)"')], {"workspace_dir": "{root}/ws"}),
    ]
    scenarios: list[Scenario] = []
    for label, steps, args in cases:
        options = {"timeout_seconds": 20, **args}
        environ = env(path=PROTECTED_PATH, FOO="bar")
        scenarios.append(scenario(f"probe-{label}", [*steps, call("probe_intercepts", **options), call("status")], facts=base_facts(environ=environ)))
    scenarios += [
        scenario("probe-context-workspace", [mkdir("ctxws"), *npm('printf \'{"verdict":{"action":"allow","source":"%s"}}\' "$(pwd -P)"'), call("probe_intercepts", timeout_seconds=20)], facts=facts, workspace_dir="{root}/ctxws"),
        scenario("probe-path-inactive", [*npm(printf(verdict())), call("probe_intercepts", timeout_seconds=20)], facts=base_facts(environ=env(path="{root}/real1"))),
        scenario("probe-path-inactive-allowed", [*npm(printf(verdict())), call("probe_intercepts", timeout_seconds=20, allow_inactive_path=True)], facts=base_facts(environ=env(path="{root}/real1"))),
        scenario("probe-project-shell-profile", [*npm(printf(verdict())), call("ensure_package_shim_profile"), call("probe_intercepts", timeout_seconds=20, project_shell_profile=True)], facts=base_facts(environ=env(path="{root}/real1")), durable=True),
        scenario("probe-project-shell-profile-projected", [call("install", managers=["npm"]), fake_shim("npm", printf(verdict())), call("ensure_package_shim_profile"), call("probe_intercepts", timeout_seconds=20, project_shell_profile=True), call("probe_intercepts", timeout_seconds=20)], facts=base_facts(environ=env(path="{root}/real1")), durable=True),
        scenario("probe-nothing-installed", [call("probe_intercepts", timeout_seconds=20)], facts=facts),
        scenario("probe-two-managers", [fake_manifest(["npm", "pip"]), fake_shim("npm", printf(verdict())), fake_shim("pip", printf(verdict("warn"), 1)), call("probe_intercepts", timeout_seconds=20), call("probe_intercepts", timeout_seconds=20, managers=["pip"])], facts=facts),
        scenario("probe-all-managers-args", [fake_manifest(["bun", "bunx", "cargo", "go", "gradle", "uv"]), *[fake_shim(name, 'printf \'{"verdict":{"action":"allow","source":"%s"}}\' "$*"') for name in ("bun", "bunx", "cargo", "go", "gradle", "uv")], call("probe_intercepts", timeout_seconds=20)], facts=facts),
        scenario("probe-records-last-test", [manifest_step({"installed_managers": ["npm"], "content_hashes": {}, "last_test_at": {"npm": "old", "pip": "keep", "x": 3}, "extra": 1}), fake_shim("npm", printf(verdict())), call("probe_intercepts", timeout_seconds=20)], facts=facts),
        scenario("probe-real-binary-before-shim", [real_binary("real1", "npm"), *npm(printf(verdict())), call("probe_intercepts", timeout_seconds=20)], facts=base_facts(environ=env(path="{root}/real1:" + SHIM_BIN))),
    ]
    return scenarios


def all_profile_scenarios() -> list[Scenario]:
    return [*profile_content_scenarios(), *profile_layout_scenarios(), *activate_scenarios(), *probe_scenarios()]
