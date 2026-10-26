#![cfg(unix)]

use crate::pretool_lockfile_install::{
    Lab, BUN, BUN_LOCK, NPM, PACKAGE_JSON, PACKAGE_LOCK, PNPM, PNPM_LOCK,
};

const ALLOWED: &str = "native_exact_safe_lockfile_install";

#[test]
fn bun_installs_moved_with_cwd_proceed_from_a_proven_directory() {
    let lab = Lab::new();
    let portal = lab.project(
        "app-portal",
        &[("package.json", PACKAGE_JSON), ("bun.lock", BUN_LOCK)],
    );
    let dir = portal.display();
    let mut refused = Vec::new();
    for command in [
        format!("bun install --cwd {dir} --frozen-lockfile --ignore-scripts"),
        format!("bun install --cwd={dir} --frozen-lockfile --ignore-scripts"),
        format!("bun install --frozen-lockfile --ignore-scripts --cwd {dir} 2>&1 | tail -8"),
        format!("cd {dir} && {BUN} 2>&1 | tail -8"),
    ] {
        let result = lab.classify(&lab.home, &command, &[]);
        if result.reason_code != ALLOWED {
            refused.push(format!("{command}: {}", result.reason_code));
        }
    }
    assert!(refused.is_empty(), "{}", refused.join("\n"));
}

#[test]
fn cwd_moves_the_proof_cannot_follow_stay_reviewed() {
    let lab = Lab::new();
    let portal = lab.project(
        "app-portal",
        &[("package.json", PACKAGE_JSON), ("bun.lock", BUN_LOCK)],
    );
    let plain = lab.project("notes", &[("package.json", PACKAGE_JSON)]);
    let hidden = lab.project(
        ".private-tools/portal",
        &[("package.json", PACKAGE_JSON), ("bun.lock", BUN_LOCK)],
    );
    let (dir, plain, hidden) = (portal.display(), plain.display(), hidden.display());
    for command in [
        format!("bun install --cwd {plain} --frozen-lockfile --ignore-scripts"),
        format!("bun install --cwd {hidden} --frozen-lockfile --ignore-scripts"),
        format!("bun install --cwd {dir} --frozen-lockfile"),
        format!("bun install --cwd {dir} --cwd {dir} --frozen-lockfile --ignore-scripts"),
        String::from("bun install --cwd= --frozen-lockfile --ignore-scripts"),
        format!("bun install --cwd {dir}/.. --frozen-lockfile --ignore-scripts"),
        format!("cd {dir} && bun install --cwd {dir} --frozen-lockfile --ignore-scripts"),
        format!("npm ci --cwd {dir} --ignore-scripts"),
        format!("bun add --cwd {dir} left-pad --ignore-scripts"),
    ] {
        let result = lab.classify(&lab.home, &command, &[]);
        assert_ne!(result.minimum_action, "allow", "{command}");
    }
}

#[test]
fn bunfig_lockfile_table_is_inert_only_for_save_and_print() {
    let lab = Lab::new();
    for (name, bunfig, allowed) in [
        ("save", "[install.lockfile]\nsave = true\n", true),
        (
            "print",
            "[install.lockfile]\nsave = false\nprint = \"yarn\"\n",
            true,
        ),
        (
            "print-other",
            "[install.lockfile]\nprint = \"npm\"\n",
            false,
        ),
        (
            "registry",
            "[install.lockfile]\nsave = true\nregistry = \"https://registry.example.invalid\"\n",
            false,
        ),
        ("scalar", "[install]\nlockfile = true\n", false),
        ("cache-off", "[install.cache]\ndisable = true\n", true),
        (
            "release-age",
            "[install]\nminimumReleaseAge = 259200\n",
            true,
        ),
        (
            "cache-dir",
            "[install.cache]\ndir = \"/tmp/elsewhere\"\n",
            false,
        ),
        ("top-preload", "preload = [\"./setup.ts\"]\n", false),
        (
            "test-preload",
            "[test]\npreload = [\"./setup.ts\"]\n",
            false,
        ),
        (
            "smol",
            "smol = true\n[install]\nlinker = \"hoisted\"\n",
            true,
        ),
        (
            "install-smol",
            "[install]\nlinker = \"hoisted\"\nsmol = true\n\n[install.lockfile]\nsave = false\n",
            true,
        ),
        (
            "install-registry",
            "[install]\nregistry = \"https://registry.example.invalid\"\n",
            false,
        ),
    ] {
        let project = lab.project(
            name,
            &[
                ("package.json", PACKAGE_JSON),
                ("bun.lock", BUN_LOCK),
                ("bunfig.toml", bunfig),
            ],
        );
        let result = lab.classify(&project, BUN, &[]);
        assert_eq!(result.reason_code == ALLOWED, allowed, "{name}");
    }
}

#[test]
fn an_inherited_npm_cache_setting_leaves_the_install_proven() {
    let lab = Lab::new();
    let portal = lab.project(
        "app-portal",
        &[("package.json", PACKAGE_JSON), ("bun.lock", BUN_LOCK)],
    );
    for (names, allowed) in [
        (&["npm_config_cache", "NPM_CONFIG_LOGLEVEL"][..], true),
        (&["npm_config_cache", "npm_config_registry"][..], false),
        (&["NPM_CONFIG_USERCONFIG"][..], false),
        (&["BUN_CONFIG_REGISTRY"][..], false),
    ] {
        let result = lab.classify(&portal, BUN, names);
        assert_eq!(result.reason_code == ALLOWED, allowed, "{names:?}");
    }
}

#[test]
fn quiet_flags_follow_the_same_proof() {
    let lab = Lab::new();
    let pnpm = lab.project(
        "pnpm",
        &[
            ("package.json", PACKAGE_JSON),
            ("pnpm-lock.yaml", PNPM_LOCK),
        ],
    );
    let npm = lab.project(
        "npm",
        &[
            ("package.json", PACKAGE_JSON),
            ("package-lock.json", PACKAGE_LOCK),
        ],
    );
    let cases = [
        (
            &pnpm,
            format!("{PNPM} --reporter=default --loglevel=error"),
            true,
        ),
        (&pnpm, format!("{PNPM} --ignore-pnpmfile"), true),
        (
            &pnpm,
            format!("{PNPM} --registry=https://registry.example.invalid"),
            false,
        ),
        (
            &npm,
            format!("{NPM} --loglevel=error --progress=false"),
            true,
        ),
        (&npm, format!("{NPM} --global"), false),
        (&npm, String::from("npm ci --loglevel=error"), false),
    ];
    for (project, command, allowed) in cases {
        let result = lab.classify(project, &command, &[]);
        assert_eq!(result.reason_code == ALLOWED, allowed, "{command}");
        if !allowed {
            assert_ne!(result.minimum_action, "allow", "{command}");
        }
    }
}

#[test]
fn an_install_for_a_lockfile_the_project_lacks_names_the_one_it_has() {
    let lab = Lab::new();
    let bun = lab.project(
        "bun-only",
        &[("package.json", PACKAGE_JSON), ("bun.lock", BUN_LOCK)],
    );
    let npm = lab.project(
        "npm-only",
        &[
            ("package.json", PACKAGE_JSON),
            ("package-lock.json", PACKAGE_LOCK),
        ],
    );
    let both = lab.project(
        "bun-and-npm",
        &[
            ("package.json", PACKAGE_JSON),
            ("bun.lock", BUN_LOCK),
            ("package-lock.json", PACKAGE_LOCK),
        ],
    );
    let bare = lab.project("no-lockfile", &[("package.json", PACKAGE_JSON)]);
    let binary = lab.project(
        "bun-binary-lock",
        &[
            ("package.json", PACKAGE_JSON),
            ("bun.lock", BUN_LOCK),
            ("bun.lockb", "binary"),
        ],
    );
    for (project, install, hint) in [
        (
            &bun,
            PNPM,
            "This folder has no `pnpm-lock.yaml`. It has `bun.lock`, so the install that \
             fits it is `bun install --frozen-lockfile --ignore-scripts`.",
        ),
        (
            &npm,
            BUN,
            "This folder has no `bun.lock`. It has `package-lock.json`, so the install \
             that fits it is `npm ci --ignore-scripts`.",
        ),
    ] {
        let result = lab.classify(project, install, &[]);
        assert_eq!(result.reason_code, "native_package_review", "{install}");
        assert!(
            result.reason.ends_with(hint),
            "{install}: {}",
            result.reason
        );
        // The named form is one the proof settles.
        let form = hint.rsplit('`').nth(1).unwrap();
        assert_eq!(
            lab.classify(project, form, &[]).reason_code,
            ALLOWED,
            "{form}"
        );
    }
    // Two other lockfiles, none at all, the manager's own lockfile beside a
    // file that fails the check, or another lockfile beside a file that would
    // send its install to review too give no advice.
    for (project, install) in [(&both, PNPM), (&bare, BUN), (&binary, BUN), (&binary, PNPM)] {
        let result = lab.classify(project, install, &[]);
        assert_ne!(result.reason_code, ALLOWED, "{install}");
        assert!(
            !result.reason.contains("This folder has no"),
            "{install}: {}",
            result.reason
        );
    }
}
