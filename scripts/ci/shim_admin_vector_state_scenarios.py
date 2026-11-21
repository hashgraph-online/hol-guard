"""Scenario builders for shim integrity, repair, uninstall and dashboard projection."""

from __future__ import annotations

import hashlib

from shim_admin_vector_scenarios import (
    MANAGERS,
    SHIM_BIN,
    Scenario,
    Step,
    base_facts,
    call,
    env,
    manifest_step,
    mkdir,
    real_binary,
    remove,
    scenario,
    symlink,
    write,
)

PROTECTED_PATH = f"{SHIM_BIN}:{{root}}/real1"
ZSHRC = "home/.zshrc"


def append(path: str, text: str) -> Step:
    return {"op": "append", "path": path, "text": text}


def fake_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def protected_facts(**override: object) -> dict[str, object]:
    return base_facts(environ=env(path=PROTECTED_PATH), **override)


def integrity_scenarios() -> list[Scenario]:
    install_two = call("install", managers=["npm", "pip"])
    shim = "guard/package-shims/bin"
    stale_text = "#!/bin/sh\necho stale\n"
    scenarios = [
        scenario("integrity-ok", [install_two, call("status")], facts=protected_facts()),
        scenario("integrity-tampered-append", [install_two, append(f"{shim}/npm", "\n# evil\n"), call("status"), call("repair")], facts=protected_facts()),
        scenario("integrity-tampered-replaced", [install_two, write(f"{shim}/npm", "#!/bin/sh\necho hi\n", True), call("status"), call("repair")], facts=protected_facts()),
        scenario("integrity-missing", [install_two, remove(f"{shim}/npm"), call("status"), call("repair"), call("status")], facts=protected_facts()),
        scenario("integrity-binary-content", [install_two, write(f"{shim}/npm", "ÿþ", True), call("status")], facts=protected_facts()),
        scenario("integrity-crlf-normalised", [install_two, call("install", managers=["pip"])], facts=protected_facts()),
        scenario(
            "integrity-unknown-no-hash",
            [manifest_step({"installed_managers": ["npm"]}), write(f"{shim}/npm", stale_text, True), call("status"), call("repair")],
            facts=protected_facts(),
        ),
        scenario(
            "integrity-stale-matching-hash",
            [manifest_step({"installed_managers": ["npm"], "content_hashes": {"npm": fake_hash(stale_text)}}), write(f"{shim}/npm", stale_text, True), call("status"), call("repair")],
            facts=protected_facts(),
        ),
        scenario(
            "integrity-tampered-other-hash",
            [manifest_step({"installed_managers": ["npm"], "content_hashes": {"npm": "f" * 64}}), write(f"{shim}/npm", stale_text, True), call("status")],
            facts=protected_facts(),
        ),
        scenario("integrity-stale-bad-shebang", [install_two, write(f"{shim}/npm", "#!{root}/nonexistent\nprint(1)\n", True), call("status"), call("repair")], facts=protected_facts()),
        scenario("integrity-shebang-sh-only", [install_two, write(f"{shim}/npm", "#!/bin/sh\nexit 0\n", True), call("status")], facts=protected_facts()),
        scenario("integrity-manifest-missing-files", [manifest_step({"installed_managers": ["npm", "pip", "cargo"]}), call("status"), call("repair"), call("dashboard_status")], facts=protected_facts()),
        scenario("integrity-last-test-at", [manifest_step({"installed_managers": ["npm"], "last_test_at": {"npm": "2026-02-02T00:00:00+00:00", "pip": "x"}}), call("status")]),
        scenario("integrity-last-test-at-bad-type", [manifest_step({"installed_managers": ["npm"], "last_test_at": ["x"]}), call("status")]),
        scenario("status-unreadable-manifest", [mkdir("guard/package-shims/manifest.json"), call("status"), call("install", managers=["npm"])]),
        scenario("status-no-home-profile-state", [call("status")], facts=protected_facts()),
    ]
    for label, executable in (("frozen-space", "{root}/py bin/python 3"),):
        scenarios.append(scenario(f"integrity-{label}-sidecar-states", [write("py bin/python 3", "#!/bin/sh\n", True), install_two, remove(f"{shim}/.npm.py"), call("status"), symlink(f"{shim}/.npm.py", "{root}/py/python3"), call("status"), call("repair"), call("status")], facts=protected_facts(executable=executable)))
        scenarios.append(scenario(f"integrity-{label}-sidecar-tampered", [write("py bin/python 3", "#!/bin/sh\n", True), install_two, append(f"{shim}/.npm.py", "\n# x\n"), call("status"), call("repair")], facts=protected_facts(executable=executable)))
    frozen = protected_facts(frozen=True)
    scenarios.append(scenario("integrity-frozen-ok", [install_two, call("status"), call("dashboard_status")], facts=frozen))
    scenarios.append(scenario("integrity-frozen-old-launcher", [install_two, write(f"{shim}/npm", '#!/bin/sh\nexec {root}/frozen/old {root}/guard/package-shims/bin/.npm.py "$@"\n', True), call("status"), call("repair"), call("status")], facts=frozen))
    scenarios.append(scenario("integrity-frozen-wrapper-untrusted", [install_two, write(f"{shim}/npm", '#!/bin/sh\nexec /bin/sh {root}/guard/package-shims/bin/.npm.py "$@"\n', True), call("status")], facts=frozen))
    scenarios.append(scenario("integrity-frozen-sidecar-garbage", [install_two, write(f"{shim}/.npm.py", "not python (", False), call("status"), call("repair")], facts=frozen))
    scenarios.append(scenario("integrity-frozen-sidecar-other-base-command", [install_two, write(f"{shim}/.npm.py", "base_command = ['x', 'y']\n", False), call("status")], facts=frozen))
    return scenarios


def dashboard_scenarios() -> list[Scenario]:
    profile = ["home/.zshrc", "home/.bashrc", "home/.profile"]
    block = f"# HOL Guard package manager shims\nexport PATH={SHIM_BIN}:$PATH\n"
    shim = "guard/package-shims/bin"
    scenarios = []
    for shell in ("/bin/zsh", "/bin/bash", "/usr/bin/fish"):
        scenarios.append(
            scenario(
                f"dashboard-projection-{shell.rsplit('/', 1)[1]}",
                [call("install", managers=["npm", "pip"]), call("ensure_package_shim_profile"), call("status"), call("dashboard_status"), call("cloud_coverage")],
                facts=base_facts(environ=env(shell=shell, path="{root}/real1")),
                durable=True,
            )
        )
    scenarios.append(
        scenario(
            "dashboard-profiles-configured-manually",
            [*[write(path, block) for path in profile], call("install", managers=["npm"]), call("dashboard_status"), call("status")],
            durable=True,
        )
    )
    scenarios.append(scenario("dashboard-tampered-keeps-status", [call("install", managers=["npm", "pip"]), call("ensure_package_shim_profile"), append(f"{shim}/pip", "# x"), call("dashboard_status")], durable=True))
    scenarios.append(scenario("dashboard-missing-keeps-status", [call("install", managers=["npm", "pip"]), call("ensure_package_shim_profile"), remove(f"{shim}/pip"), call("dashboard_status")], durable=True))
    scenarios.append(scenario("dashboard-no-install", [call("dashboard_status"), call("cloud_coverage", generated_at=""), call("cloud_coverage", generated_at="custom")]))
    scenarios.append(scenario("dashboard-in-path", [call("install", managers=["npm", "pip"]), call("dashboard_status"), call("cloud_coverage")], facts=protected_facts()))
    scenarios.append(scenario("dashboard-foreign-bypass", [call("install", managers=["npm"]), write("foreign/package-shims/bin/npm", "x", True), call("status", path_env="{root}/foreign/package-shims/bin:" + SHIM_BIN), call("cloud_coverage")]))
    return scenarios


def repair_and_uninstall_scenarios() -> list[Scenario]:
    shim = "guard/package-shims/bin"
    scenarios = [
        scenario("repair-nothing-installed", [call("repair")]),
        scenario("repair-nothing-to-repair", [call("install", managers=["npm"]), call("repair"), call("repair", managers=["npm"])], facts=protected_facts()),
        scenario("repair-path-inactive", [real_binary("real1", "npm"), call("install", managers=["npm", "pip"]), call("repair"), call("repair", path_env="{root}/real1")], facts=base_facts(environ=env(path="{root}/real1"))),
        scenario("repair-subset", [call("install", managers=["npm", "pip", "yarn"]), remove(f"{shim}/npm"), remove(f"{shim}/pip"), call("repair", managers=["Pip", "bogus"]), call("status")], facts=protected_facts()),
        scenario("repair-empty-subset", [call("install", managers=["npm"]), remove(f"{shim}/npm"), call("repair", managers=[])], facts=protected_facts()),
        scenario("repair-all-managers", [call("install"), *[remove(f"{shim}/{name}") for name in MANAGERS[:5]], call("repair"), call("status")], facts=protected_facts()),
        scenario("repair-unknown-only", [call("install", managers=["npm"]), remove(f"{shim}/npm"), call("repair", managers=["bogus"])]),
        scenario("uninstall-nothing", [call("uninstall"), call("uninstall", managers=["npm"])]),
        scenario("uninstall-all", [call("install"), call("uninstall"), call("status")]),
        scenario("uninstall-subset", [call("install", managers=["npm", "pip", "yarn"]), call("uninstall", managers=["PIP", "bogus"]), call("status")]),
        scenario("uninstall-unknown-only", [call("install", managers=["npm"]), call("uninstall", managers=["bogus"])]),
        scenario("uninstall-empty-list", [call("install", managers=["npm", "pip"]), call("uninstall", managers=[])]),
        scenario("uninstall-keeps-last-test-at", [manifest_step({"installed_managers": ["npm", "pip"], "content_hashes": {"npm": "a" * 64, "pip": "b" * 64}, "last_test_at": {"npm": "t1", "pip": "t2"}}), call("uninstall", managers=["npm"])]),
        scenario("uninstall-removes-cmd-and-sidecar", [call("install", managers=["npm"]), write(f"{shim}/npm.cmd", "x"), write(f"{shim}/.npm.py", "y"), call("uninstall", managers=["npm"])]),
        scenario("uninstall-frozen", [call("install", managers=["npm", "pip"]), call("uninstall", managers=["npm"]), call("status")], facts=base_facts(frozen=True)),
        scenario("uninstall-manager-not-on-disk", [manifest_step({"installed_managers": ["npm", "pip"]}), call("uninstall")]),
        scenario("uninstall-invalid-manifest", [manifest_step("{bad"), call("uninstall", managers=["npm"]), call("uninstall")]),
        scenario("uninstall-dir-in-way", [call("install", managers=["npm"]), remove(f"{shim}/npm.cmd"), mkdir(f"{shim}/npm.cmd"), call("uninstall", managers=["npm"])]),
    ]
    return scenarios


def guard_home_scenarios() -> list[Scenario]:
    scenarios = []
    for label, guard_home in (("quote", "{root}/it's \"guard\""), ("unicode", "{root}/gärd-中"), ("space", "{root}/my guard"), ("dollar", "{root}/$HOME/`x`"), ("trailing-slash", "{root}/guard/"), ("relative-parts", "{root}/a/../guard")):
        scenarios.append(scenario(f"guard-home-{label}", [call("install", managers=["npm", "pip"]), call("status"), call("uninstall", managers=["npm"])], guard_home=guard_home))
    for label, home in (("space", "{root}/my home"), ("quote", "{root}/it's home")):
        scenarios.append(scenario(f"home-dir-{label}", [call("install", managers=["npm"]), call("status"), call("ensure_package_shim_profile"), call("remove_guard_profile_blocks")], home_dir=home, durable=True))
    scenarios.append(scenario("workspace-dir-set", [call("install", managers=["npm"]), call("status")], workspace_dir="{root}/work"))
    return scenarios


def all_state_scenarios() -> list[Scenario]:
    return [*integrity_scenarios(), *dashboard_scenarios(), *repair_and_uninstall_scenarios(), *guard_home_scenarios()]
