use super::neuters_git_hooks;

#[test]
fn hooks_switched_off_for_good_are_found() {
    for text in [
        "cat > .githooks/pre-commit <<'SH'\n#!/bin/sh\nexit 0\nSH\nchmod +x .githooks/pre-commit && git status --short",
        "git status --short; cat > .githooks/pre-commit <<'EOF'\n#!/bin/sh\nexit 0\nEOF\nchmod +x .githooks/pre-commit; git diff -- .githooks/pre-commit",
        "cat >.husky/pre-push <<EOF\n#!/usr/bin/env sh\n# disabled\ntrue\nEOF",
        "printf '#!/bin/sh\\nexit 0\\n' > .git/hooks/pre-commit",
        "echo 'exit 0' > .husky/commit-msg && chmod +x .husky/commit-msg",
        ": > .githooks/pre-commit",
        "perl -e 'rename q(.githooks/pre-commit),q(.githooks/pre-commit.off)'",
        "python3 -c \"import os; os.rename('.husky/pre-commit', '.husky/pre-commit.bak')\"",
        "node -e \"require('fs').renameSync('.githooks', '.githooks-disabled')\"",
        "mv .githooks .githooks.off && git commit -m wip",
        "mv -f .husky/pre-commit /tmp/pre-commit",
        "mv repo/.git/hooks/pre-push repo/.git/hooks/pre-push.disabled",
    ] {
        assert!(neuters_git_hooks(text), "{text}");
    }
}

#[test]
fn ordinary_hook_work_is_not_neutering() {
    for text in [
        "cat > .githooks/pre-commit <<'SH'\n#!/bin/sh\nnpm test\nSH\nchmod +x .githooks/pre-commit",
        "printf '#!/bin/sh\\nnpx lint-staged\\n' > .husky/pre-commit",
        "echo 'npm run lint' >> .husky/pre-commit",
        "mv .git/hooks/pre-commit.sample .git/hooks/pre-commit && git commit -m 'enable hook'",
        "cp .githooks/pre-commit .git/hooks/pre-commit",
        "cat .githooks/pre-commit",
        "git commit --no-verify -m 'wip'",
        "HUSKY=0 git commit -m 'release metadata'",
        "echo 'exit 0' > scripts/noop.sh",
        "mv src/hooks/useAuth.ts src/hooks/useSession.ts",
        "git config core.hooksPath .githooks",
    ] {
        assert!(!neuters_git_hooks(text), "{text}");
    }
}
