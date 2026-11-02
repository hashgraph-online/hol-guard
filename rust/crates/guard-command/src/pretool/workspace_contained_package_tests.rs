//! Which package-manager spellings the workspace sandbox bounds.
//!
//! `pnpm exec` and `yarn exec` run only what the project already installed, so
//! a run spelled with them is the local work the sandbox bounds. What the verb
//! runs decides the rest: a fetching program behind it reaches the registry the
//! verb does not. Helpers are shared with the containment tests they sit beside
//! in [`super::workspace_contained_tests`].

use super::workspace_contained_tests::{host, reason, workspace, CONTAINED};

/// pnpm and yarn run only what the project installed, so their `exec` reaches
/// no registry and the run it spells is the local work the sandbox bounds.
/// The selector that pins such a run to one package of the workspace, and the
/// `-r` that fans it across all of them, name projects the sandbox already
/// holds.
#[test]
fn pnpm_and_yarn_exec_run_in_the_workspace_sandbox() {
    let ws = workspace("local-exec", true);
    for command in [
        "pnpm exec echo hi",
        "pnpm --filter app exec vitest run",
        "pnpm --filter=app exec vitest run",
        "pnpm -F @acme/web exec vitest run",
        "pnpm --filter app exec tsc --noEmit",
        "pnpm -r exec vitest run",
        "yarn workspace web exec vitest run",
        "pnpm recursive exec vitest run",
        // A script of the project's own named `exec` is the script it is.
        "pnpm run exec",
        // The target is read past a `--` separator, and reading it there must
        // not cost the local tool behind one its containment.
        "pnpm exec -- vitest run",
        "pnpm --filter app exec vitest run -- --reporter=json",
    ] {
        let got = reason("omp", command, &ws, true);
        if host() {
            assert_eq!(got, CONTAINED, "{command}");
        } else {
            assert_ne!(got, CONTAINED, "{command}");
        }
    }
}

/// `npm exec` installs the package it names when the project does not hold
/// it, so it keeps its admission whichever package it is pinned to. A
/// selector reaching past the workspace, and a registry verb behind pnpm's
/// own `exec`, keep theirs too.
#[test]
fn exec_that_can_reach_a_registry_keeps_its_review() {
    let ws = workspace("registry-exec", true);
    for command in [
        "npm --workspace web exec vitest run",
        "npm -w web exec vitest run",
        "npm x foo",
        "pnpm --filter ../sibling exec vitest run",
        "pnpm --filter app exec npm install zod",
        "pnpm exec pnpm add zod",
        // A fetching program behind the verb reaches the registry the verb
        // itself does not, whichever word spells the fetch.
        "pnpm exec npm exec cowsay",
        "pnpm --filter app exec npm exec --yes cowsay",
        "pnpm exec npx cowsay",
        "pnpm exec bunx cowsay",
        "yarn exec npx cowsay",
        // Yarn runs its `exec` argument through a shell, so the install is
        // spelled inside one word rather than beside it.
        "yarn exec 'npm install zod'",
        // A `--` separator hides the target from the argument list the rest
        // of this route reads, so the fetch behind one must still be read.
        "pnpm exec -- npx cowsay",
        "pnpm --filter app exec -- npm install zod",
        "yarn exec -- npx cowsay",
        // A launcher's own argument is the program that runs, so the word
        // after the verb is not the effect.
        "pnpm exec env npx cowsay",
        "pnpm exec env npm exec cowsay",
        "pnpm exec sh -c 'npm install zod'",
        "pnpm exec timeout 5 npx cowsay",
        "pnpm exec xargs npm install zod",
        // A workspace selector stands in front of the verb, so the program
        // behind the `exec` it carries is read there rather than left unread.
        "yarn workspace web exec npx cowsay",
        "yarn workspace web exec env npx cowsay",
        "yarn workspace web exec 'npm install zod'",
        "pnpm recursive exec npx cowsay",
        // An `exec` naming no program at all runs nothing this can read.
        "pnpm exec",
        "pnpm exec --",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
}
