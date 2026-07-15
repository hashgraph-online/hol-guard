# Package command extension coverage

Guard exposes package ecosystems as command safety extensions while keeping the existing package firewall as the
single enforcement engine. The extension registry supplies stable IDs, setup detection, and inspectable metadata. It
does not duplicate package intent parsing, shim behavior, advisory policy, provenance checks, approvals, or receipts.

## Setup detection

Run a read-only workspace preview:

```bash
hol-guard command setup --detect --workspace .
```

Project marker names drive recommendations. Package managers found on `PATH` appear as available context but do not
cause unrelated ecosystems to be recommended. Detection does not read manifest contents, package credentials, source
configuration, or secret files, and it does not change Guard settings.

## Coverage matrix

| Extension | Managers | Project markers | Enforcement owner |
| --- | --- | --- | --- |
| `command.package.node` | npm, npx, pnpm, yarn, bun, bunx | `package.json` and Node lockfiles | Package firewall |
| `command.package.python` | pip, pipx, uv, uvx, Poetry, Pipenv | `pyproject.toml`, requirements, and Python lockfiles | Package firewall |
| `command.package.rust` | Cargo | `Cargo.toml`, `Cargo.lock` | Package firewall |
| `command.package.go` | Go modules and tools | `go.mod`, `go.sum`, `go.work` | Package firewall |
| `command.package.jvm` | Maven, Gradle | Maven and Gradle build or lock files | Package firewall |
| `command.package.ruby` | RubyGems, Bundler | Gem manifests and lockfiles | Package firewall |
| `command.package.php` | Composer | `composer.json`, `composer.lock` | Package firewall |
| `command.package.system` | apt, yum, dnf, apk, pacman, zypper, Homebrew | `Brewfile` | Package firewall |

## Command references

The metadata and fixtures follow primary command documentation:

- Node: [npm install](https://docs.npmjs.com/cli/install/), [pnpm add](https://pnpm.io/cli/add),
  [Yarn add](https://yarnpkg.com/cli/add), and [Bun add](https://bun.sh/docs/pm/cli/add).
- Python: [pip install](https://pip.pypa.io/en/stable/cli/pip_install/),
  [uv CLI](https://docs.astral.sh/uv/reference/cli/), [Poetry CLI](https://python-poetry.org/docs/cli/), and
  [Pipenv commands](https://pipenv.pypa.io/en/latest/commands.html).
- Rust: [cargo install](https://doc.rust-lang.org/cargo/commands/cargo-install.html).
- Go: [Go modules reference](https://go.dev/ref/mod#go-install).
- JVM: [Maven dependency management](https://maven.apache.org/plugins/maven-dependency-plugin/examples/managing-dependencies.html)
  and [Gradle dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html).
- Ruby: [RubyGems command reference](https://guides.rubygems.org/command-reference/#gem-install) and
  [bundle install](https://bundler.io/man/bundle-install.1.html).
- PHP: [Composer commands](https://getcomposer.org/doc/03-cli.md#require-r).
- System packages: [Homebrew manual](https://docs.brew.sh/Manpage#install-options-formulacask-) and
  [apt-get manual](https://manpages.debian.org/bookworm/apt/apt-get.8.en.html).

## Security invariants

- A command-local `PATH` override invalidates Guard package-shim trust, including explicit local-only runner flags.
- Project markers and lockfiles can support package intent decisions, but repository-controlled files never prove that a
  shim or executable is trusted by themselves.
- Package extension metadata cannot own command rules while protection is delegated to the package firewall.
- External extension sources cannot replace required built-in command protections or become final policy authority.
