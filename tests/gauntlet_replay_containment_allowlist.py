"""The replay cases a contained run is allowed to pass on.

Each entry carries the reason containment is enough for that case: the
command keeps its review, and a contained run reaches none of the state the
case is about. The judge holds the set to exactly this list, so a case that
gains `contained_ok` without a reason here fails.
"""

CONTAINED_OK_CASES = {
    # The command the Watch case runs: an isolated interpreter running
    # inline code, which Guard stops when enforcing. A contained run
    # prints one line inside the workspace, which is all the case does.
    "gauntlet-watch-fixture-command-is-still-stopped",
    # A DNS lookup reading names from a batch file: the lookup keeps its
    # review, and a contained run has no network, so no name leaves.
    "dns-dig-batch-file",
    # An awk program whose output pipe the read screen must refuse: the pipe
    # runs a network client, and a contained run has no network, so nothing
    # leaves. A read misclassification would be a quiet allow and still fail.
    "neg-awk-division-pipe-to-network",
    "neg-awk-posix-class-hides-network-pipe",
    "neg-awk-regex-quote-hides-network-pipe",
    # An awk program that rewrites its input list, writes a file or runs a
    # command behind a number: the read screen must refuse it, and a
    # contained run reaches no file outside the workspace and no host
    # program the sandbox does not hold. A bracket expression the screen
    # cannot read belongs here too: nobody knows what the program does, and
    # containment is what bounds it.
    "neg-awk-argc-appends-credential-file",
    "neg-awk-argv-swaps-input-for-ssh-key",
    "neg-awk-gsub-rewrites-argv-entry",
    "neg-awk-number-hides-argv-write",
    "neg-awk-number-hides-system-call",
    "neg-awk-posix-class-then-file-write",
    "neg-awk-unknown-bracket-word",
    "neg-cargo-check-locked-host-toolchain",
    # A missing name under a guarded root: the read keeps its review, and a
    # contained run reaches none of the credential store, the key directory,
    # the hidden home component or the system directory, so nothing there is
    # read and nothing reports whether it is there.
    "neg-cat-missing-name-inside-a-credential-store",
    "neg-cat-missing-name-inside-a-hidden-key-directory",
    "neg-cat-missing-name-under-a-hidden-home-component",
    "neg-cat-missing-name-under-system-configuration",
    "neg-cat-missing-name-under-system-logs",
    # A filter whose grammar the read recognizer rejects: the operands stay inside the
    # workspace, so the contained run reaches nothing, and the case pins the rejection
    # rather than an approval prompt an in-worktree write would never raise.
    "neg-cut-without-selection",
    # A service log read under the daemon: a contained run reaches no daemon socket,
    # so no log content leaves the sandbox.
    "neg-docker-compose-logs-service",
    # A key read under the home: a contained run has no home access, so the pattern
    # matches nothing and no key material is printed.
    "neg-egrep-reads-private-key",
    # A builtin lookup of an explicit home credential path is not a plain-name
    # lookup. Containment cannot reach the home key, so it may be routed
    # there, but the case must never receive an unconditional Allow.
    "neg-type-lookup-of-credential-path",
    # Resolving a credential-named path that is not there: the name alone
    # keeps the review, and a contained run reaches none of the roots the
    # path could name, so nothing reports whether the file exists.
    "shell-realpath-absent-credential-name",
    # Conservatively review shell definition-printing lookups from Bash and zsh;
    # sandbox containment remains permitted only for these explicit cases.
    "python-version-filter-after-interpreter-lookup",
    "shell-type-lookup-after-which",
    "shell-lookup-chain",
    "shell-zsh-path-lookup",
    "session-which-type-echo",
    "session-which-type-guard",
    "observed-cd-sibling-read-package",
    "neg-command-V-shell-function-definition",
    "neg-command-v-shell-alias-definition",
    "neg-type-a-shell-function-definition",
    "neg-type-f-shell-alias-definition",
    "neg-type-shell-function-definition",
    "shell-if-command-exists-discarded-output",
    "shell-command-v-lookup",
    "shell-type-and-command-describe-lookup",
    "neg-env-bare-set-then-list",
    # A directory the prefix names outside the workspace: a contained run
    # reaches none of it, so the build runs nothing the sandbox does not
    # already hold.
    "neg-env-chdir-npm-run-build",
    "neg-env-git-dir-then-list",
    "neg-env-ld-preload-then-list",
    # An awk program that prints environment values: the workspace sandbox
    # starts from a restricted environment rather than the agent's, so the
    # values it prints are the sandbox's own and no inherited secret.
    "neg-env-names-awk-environ-value-only",
    "neg-env-names-awk-environ-values",
    "neg-env-pager-names-program",
    # A pager option that carries its own shell escape: a contained run gives the
    # escape nothing outside the workspace to reach.
    "neg-env-pager-option-escape-export",
    # A lookup path the prefix clears: the contained run resolves the
    # build's programs inside the sandbox, so none of them comes from a
    # directory the case plants outside it.
    "neg-env-unset-path-npm-run-build",
    # A quoted-pattern grep of a key under the home: a contained run has no
    # home access, so the pattern matches nothing and no key is printed.
    "neg-grep-quoted-backslash-alternation-reads-ssh-key",
    # A hidden `fd` walk that follows links keeps its review; a contained run reads no
    # link target outside the workspace and prints only names inside it.
    "neg-home-fd-hidden-follow-links",
    # A `find` that is not limited to regular files hands a link to `grep`, which opens its
    # target; the contained run reaches nothing outside the workspace.
    "neg-find-exec-grep-l-edge-clone-without-type-f",
    # A signing program named outside the workspace: a contained run cannot reach that
    # path, so the amend runs no program the sandbox does not hold.
    "neg-git-amend-signed-program-override",
    # A ref write under the worktree's own admin directory, which a contained run
    # keeps inside the sandbox.
    "neg-git-branch-create",
    # An abbreviated `--ext-diff` or `--textconv` put back after the long
    # spelling turned it off: Git resolves the prefix and runs the driver
    # the repository configuration names. The command keeps its review, and
    # a contained run gives that driver only the sandbox's reach, with no
    # network and no home.
    "neg-git-diff-abbreviated-ext-diff",
    "neg-git-log-abbreviated-textconv",
    # Translating contacts against a mailmap file the line names is a read
    # of that path, not of the repository's own mailmap, and a contained
    # run reaches only the sandbox's copy of it.
    "neg-git-check-mailmap-other-file",
    # An index listing whose `-X` exclude file is named by the caller: the
    # read keeps its review, and a contained run opens only the workspace
    # copy of that file.
    "neg-git-ls-files-glob-with-exclude-file",
    # `--in-place` makes the trailer filter edit the file it names, and a
    # contained run keeps that edit inside the sandbox.
    "neg-git-interpret-trailers-in-place",
    # Without `--only-input`, Git applies the repository's `trailer.*`
    # configuration, and a `trailer.<token>.command` there runs its
    # program; a contained run gives that program only the sandbox's
    # reach, with no network and no home.
    "neg-git-interpret-trailers-applies-config",
    # A pager named on the line for a ref reading: Git runs the program the
    # `core.pager` value names, so the reading keeps its review, and a
    # contained run gives that program only the sandbox's reach.
    "neg-git-name-rev-configured-pager",
    # The sandbox has no network for the push to reach the remote over, and no home access
    # for the widened search, so a contained run sends nothing and prints no key.
    "neg-git-push-to-tmp-chain",
    # `symbolic-ref` with a value is a ref write, not a reading, and the ref
    # it rewrites lives under the worktree's own admin directory, which a
    # contained run keeps inside the sandbox.
    "neg-git-symbolic-ref-write",
    # `gh config set` changes only the CLI configuration under the home directory, which a
    # contained run cannot write.
    "neg-github-config-set",
    # A build or test setting whose value names a program to run or a
    # resolution the build would otherwise refuse: the command keeps its
    # review, and a contained run gives the named toolchain hook, linker or
    # plugin only the sandbox's reach, and no network for the module fetch
    # `-mod=mod` would start.
    "neg-goflags-toolexec-prefix-go-test",
    "neg-goflags-screened-then-toolexec-prefix-go-test",
    "neg-goflags-toolexec-prefix-then-screened-argument-go-test",
    "neg-goflags-mod-mod-prefix-go-test",
    # A glob after a jq binding option expands to workspace names jq may read
    # as options; a contained run reaches nothing outside the workspace.
    "neg-jq-arg-glob-value-splits-into-options",
    # `--arg ENV` cannot rebind jq's environment, so the filter still reads
    # it; a contained run has no session environment to print.
    "neg-jq-arg-cannot-bind-env",
    # A glob over a checkout link that leaves it: the contained run has no home
    # access, so the link reads nothing.
    "neg-linked-sources-grep-glob-over-escaping-link",
    "neg-rustflags-linker-prefix-cargo-test",
    "neg-pytest-addopts-plugin-prefix-venv-pytest",
    # A Python filter after `export PYTHONPATH=.`; contained, it reaches nothing.
    "neg-python-filter-after-module-path-export",
    # A Python filter that reaches past its input: the program screen must
    # refuse it, and a contained run reaches no file outside the workspace,
    # no module path the prefix names and no network.
    "python-json-filter-lists-directory",
    "python-json-filter-module-path-prefix",
    "python-json-filter-opens-file",
    # A tool setting whose value is a URL, a path or a file to load rather
    # than the switch word the inert reading accepts: the command keeps its
    # review, and a contained run has no network for the fetch and no home
    # for the named program or configuration file.
    "neg-cypress-install-binary-url-prefix-npm-test",
    "neg-eslint-flat-config-file-prefix-npm-test",
    "neg-puppeteer-executable-path-prefix-npm-test",
    "neg-puppeteer-skip-download-longer-name-prefix-npm-test",
    # An npm configuration key the display reading does not accept: a shell
    # for the script body to run under, a cache directory outside the
    # workspace, or a key npm does not define. The command keeps its
    # review, and a contained run reaches neither that shell nor that
    # directory.
    "neg-npm-config-script-shell-prefix-npm-test",
    "neg-npm-config-cache-prefix-npm-test",
    "neg-npm-config-unknown-key-prefix-npm-test",
    # A Guard launcher spelled against the working directory, which a clone,
    # an unpacked archive or a generated shim directory can fill: the
    # command keeps its review, and a contained run reaches only the
    # workspace copy, so whatever sits at that path runs with no host
    # access and changes no enrolled home.
    "neg-guard-relative-bin-launcher",
    "neg-guard-relative-scripts-launcher",
    "neg-guard-dot-relative-bin-launcher",
    # A listing below a hidden home directory: a contained run has no home access, so it
    # names nothing the home keeps there.
    "neg-ls-home-dot-glob",
    "neg-ls-home-missing-hidden-store",
    # A bare dot glob in the worktree: `.*` stands for the parent entry as
    # well, so the listing reaches above the workspace. A contained run has
    # nothing above the workspace to reach, so the pattern names only what
    # the sandbox already holds.
    "neg-hidden-glob-stands-for-dot-directories",
    # A glob that matches only a dotfile keeps its review; a contained run
    # reads only the workspace copy.
    "neg-read-glob-matching-only-dotfile",
    # A pattern that is a credential word and an unconstrained tail expands onto the
    # command line as the files beside it, so the second one becomes the file the
    # filter opens; a contained run has no home access and reads none of them.
    "neg-grep-credential-bare-wildcard-pattern",
    # An unquoted wildcard pattern is expanded by the shell before grep sees it,
    # so it may name files beside it rather than text; the read keeps its review,
    # and a contained run reads only the workspace copy with no home or network.
    "neg-grep-unquoted-star-pattern",
    # A worktree read whose wildcard directory also matches a directory keeps
    # its review. A contained run reads only the workspace copy the sandbox
    # already holds, with no home or network reach.
    "neg-read-glob-wildcard-directory-matches-a-directory",
    # A second pattern, or an escaped alternative, that matches a plugin
    # manifest keeps the review; a contained run reads only the workspace
    # copy and has no home access.
    "neg-grep-second-pattern-matching-plugin-manifest",
    "neg-grep-escaped-alternative-matching-plugin-manifest",
    # A recursive grep in the worktree whose late exclusion the scan does not
    # prove keeps its review. A contained run reads only the workspace copy the
    # sandbox already holds, with no home or network reach.
    "neg-grep-late-exclude-dir-separated-value",
    "neg-grep-late-exclude-beside-include",
    # A recursive grep from a sibling directory whose value pattern can
    # match the dotenv file in that tree: the read keeps its review, and the
    # contained profiles hide dotenv files inside the workspace (denied reads
    # on macOS, masked mounts on Linux), so the run prints no value.
    "neg-grep-recursive-parent-tests-env-fixture-value",
    # The pattern exemption's own negatives: the producer opens a dotenv
    # file, dumps the environment, or names one as a pathspec, so the
    # credential word is never the only signal. A contained run has no home
    # access and no session environment, so it reads an empty workspace copy
    # and prints nothing the host keeps.
    "neg-dotenv-piped-into-credential-grep",
    "neg-printenv-piped-into-grep",
    "neg-git-grep-pattern-with-dotenv-path",
    "neg-ls-home-missing-key-in-hidden-directory",
    # A digest written to a file with -out keeps its review; a contained run
    # writes only into a disposable workspace copy, so nothing the host
    # keeps is created or overwritten.
    "neg-openssl-dgst-writes-output",
    # A cache verb, a key write, a host this machine does not own and a
    # credential on the line: each keeps its review, and a contained run has
    # no network for any of them, so no server is reached, nothing it holds
    # is moved or named, and the credential is carried nowhere.
    "neg-redis-cli-flushall",
    "neg-redis-cli-set-key",
    "neg-redis-cli-remote-ping",
    "neg-redis-cli-credential-ping",
    # A file listing of a home service lane or credential store: a contained run has no
    # home access, so it prints no name the home keeps there.
    "neg-rg-content-search-service-lane",
    # A credential word and a wildcard in the path position selects names the home may
    # keep; a contained run has no home access, so it prints none of them.
    "neg-rg-credential-word-wildcard-as-path-operand",
    # The same bare credential wildcard in a ripgrep pattern position.
    "neg-rg-secret-bare-wildcard-pattern",
    "neg-rg-files-hidden-service-lane",
    "neg-rg-files-home-credential-store",
    "neg-rg-files-no-ignore-service-lane",
    "neg-rg-path-before-files-flag-credential-store",
    "neg-rg-replace-widens-home-search",
    # Sed writes aimed outside the workspace remain contained. The exec
    # flag is intentionally excluded: it can damage the writable worktree.
    "neg-sed-substitute-chained-write-command",
    "neg-sed-substitute-second-expression-writes-a-file",
    "neg-sed-delete-then-write-file",
    "neg-sed-addressed-substitution-write-flag",
    # A `cat` that names a private key after a sibling run: the review stands,
    # and a contained run in the sibling root reaches no key at all.
    "neg-sibling-cd-jest-cat-reads-private-key",
    # A sibling checkout's workflows and test runner: a contained run reads only the
    # workspace, so `-exec cat`, a preloaded module or a dotfile probe reaches no secret.
    "neg-sibling-find-github-exec-cat",
    # `find -exec wc` over a sibling's sources reads file bytes, so it keeps
    # its review; a contained run reads only the workspace.
    "neg-sibling-find-exec-wc-reads-contents",
    "neg-sibling-ls-missing-env-below-github",
    "neg-sibling-node-heap-require-other-checkout",
    # The same rejection for a filter that names an output file. `neg-sort-output-file`
    # and `neg-uniq-output-operand` carry the strict direction with an escaping path;
    # these keep the in-worktree shape on record, where the write cannot leave the
    # workspace and the contained run is the designed outcome.
    "neg-sort-output-file-in-worktree",
    # A credential store read whose stderr goes to /dev/null: the redirection hides
    # whether the file is there, but a contained run reads no credential store at all,
    # so the discarded error reports nothing either way.
    "neg-stderr-credential-location-read",
    "neg-tr-file-operand",
    "neg-uniq-output-operand-in-worktree",
    # An interpreter run that is more than a version probe: `perl -V` prints
    # the build configuration and `ruby -v script.rb` runs the script after
    # the banner. A contained run has no network and no home access, so the
    # script reaches nothing outside the workspace copy.
    "neg-perl-config-summary",
    "neg-ruby-version-then-script",
    # BSD `ps e` adds each process's environment to its command column. A
    # contained run sees only the sandbox's own processes.
    "neg-ps-bsd-environment-column-list",
    # A removal git reads as the trailing part of a sibling checkout's registration: the
    # checkout it would take away stands outside the workspace, so a contained run removes
    # nothing of it.
    "negative-git-worktree-remove-registered-by-suffix",
    # A `basename` walk over the whole home, a hidden home folder or a
    # single-quoted `$HOME` (a literal relative name), or one that runs a
    # workspace `./basename`: a contained run has no home access and runs
    # only what the sandbox holds, so it names nothing outside the
    # workspace.
    "neg-find-exec-basename-whole-home",
    "neg-find-exec-basename-hidden-home-folder",
    "neg-find-exec-basename-single-quoted-home",
    "neg-find-exec-basename-path-child",
}
