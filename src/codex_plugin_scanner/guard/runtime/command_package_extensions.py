"""Package ecosystem metadata delegated to Guard's package firewall."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PackageCommandExtensionSpec:
    """Static package ecosystem metadata used by setup and inspection."""

    extension_id: str
    name: str
    description: str
    ecosystem_ids: tuple[str, ...]
    executables: tuple[str, ...]
    project_markers: tuple[str, ...]
    reference_urls: tuple[str, ...]


PACKAGE_COMMAND_EXTENSION_SPECS = (
    PackageCommandExtensionSpec(
        extension_id="command.package.node",
        name="Node package protection",
        description="Routes Node package installs and one-shot execution through Guard's package firewall.",
        ecosystem_ids=("npm",),
        executables=("npm", "npx", "pnpm", "yarn", "bun", "bunx"),
        project_markers=(
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lock",
            "bun.lockb",
        ),
        reference_urls=(
            "https://docs.npmjs.com/cli/install/",
            "https://pnpm.io/cli/add",
            "https://yarnpkg.com/cli/add",
            "https://bun.sh/docs/pm/cli/add",
        ),
    ),
    PackageCommandExtensionSpec(
        extension_id="command.package.python",
        name="Python package protection",
        description=(
            "Routes Python dependency installs and isolated package execution through Guard's package firewall."
        ),
        ecosystem_ids=("pypi",),
        executables=("pip", "pip3", "pipx", "uv", "uvx", "poetry", "pipenv"),
        project_markers=(
            "pyproject.toml",
            "requirements.txt",
            "requirements-dev.txt",
            "Pipfile",
            "Pipfile.lock",
            "poetry.lock",
            "uv.lock",
        ),
        reference_urls=(
            "https://pip.pypa.io/en/stable/cli/pip_install/",
            "https://docs.astral.sh/uv/reference/cli/",
            "https://python-poetry.org/docs/cli/",
            "https://pipenv.pypa.io/en/latest/commands.html",
        ),
    ),
    PackageCommandExtensionSpec(
        extension_id="command.package.rust",
        name="Rust package protection",
        description="Routes Cargo dependency and binary installation requests through Guard's package firewall.",
        ecosystem_ids=("cargo",),
        executables=("cargo",),
        project_markers=("Cargo.toml", "Cargo.lock"),
        reference_urls=("https://doc.rust-lang.org/cargo/commands/cargo-install.html",),
    ),
    PackageCommandExtensionSpec(
        extension_id="command.package.go",
        name="Go package protection",
        description="Routes Go module and tool installation requests through Guard's package firewall.",
        ecosystem_ids=("go",),
        executables=("go",),
        project_markers=("go.mod", "go.sum", "go.work", "go.work.sum"),
        reference_urls=("https://go.dev/ref/mod#go-install",),
    ),
    PackageCommandExtensionSpec(
        extension_id="command.package.jvm",
        name="JVM package protection",
        description="Routes Maven and Gradle dependency operations through Guard's package firewall.",
        ecosystem_ids=("maven",),
        executables=("mvn", "mvnw", "gradle", "gradlew"),
        project_markers=(
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
            "gradle.lockfile",
        ),
        reference_urls=(
            "https://maven.apache.org/plugins/maven-dependency-plugin/examples/managing-dependencies.html",
            "https://docs.gradle.org/current/userguide/dependency_locking.html",
        ),
    ),
    PackageCommandExtensionSpec(
        extension_id="command.package.ruby",
        name="Ruby package protection",
        description="Routes RubyGem and Bundler dependency operations through Guard's package firewall.",
        ecosystem_ids=("rubygems",),
        executables=("gem", "bundle", "bundler"),
        project_markers=("Gemfile", "Gemfile.lock", "gems.rb", "gems.locked"),
        reference_urls=(
            "https://guides.rubygems.org/command-reference/#gem-install",
            "https://bundler.io/man/bundle-install.1.html",
        ),
    ),
    PackageCommandExtensionSpec(
        extension_id="command.package.php",
        name="PHP package protection",
        description="Routes Composer dependency operations through Guard's package firewall.",
        ecosystem_ids=("composer",),
        executables=("composer",),
        project_markers=("composer.json", "composer.lock"),
        reference_urls=("https://getcomposer.org/doc/03-cli.md#require-r",),
    ),
    PackageCommandExtensionSpec(
        extension_id="command.package.system",
        name="System package protection",
        description="Routes operating-system package installation requests through Guard's package firewall.",
        ecosystem_ids=("system", "homebrew"),
        executables=("apt", "apt-get", "yum", "dnf", "apk", "pacman", "zypper", "brew"),
        project_markers=("Brewfile",),
        reference_urls=(
            "https://docs.brew.sh/Manpage#install-options-formulacask-",
            "https://manpages.debian.org/bookworm/apt/apt-get.8.en.html",
        ),
    ),
)
