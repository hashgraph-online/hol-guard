"""Structured coverage for common Docker lifecycle and execution commands."""

from __future__ import annotations

from .command_common_extension_helpers import executable_matcher, help_variant, rule
from .command_rules import AnyMatcher

_DOCKER = frozenset({"docker"})
_DOCKER_GLOBAL_OPTIONS = frozenset({"--config", "--context", "--host", "-h", "--log-level"})
_DOCKER_COMPOSE_OPTIONS = frozenset(
    {
        "--ansi",
        "--env-file",
        "--file",
        "-f",
        "--parallel",
        "--profile",
        "--progress",
        "--project-directory",
        "--project-name",
        "-p",
    }
)
_DOCKER_COMPOSE_FLAGS = frozenset({"--all-resources", "--compatibility"})
_EXEC_OPTIONS = frozenset({"--detach-keys", "--env", "-e", "--env-file", "--user", "-u", "--workdir", "-w"})


def _docker(*subcommands: str, **kwargs: object):
    return executable_matcher(
        _DOCKER,
        *subcommands,
        leading_options_with_values=_DOCKER_GLOBAL_OPTIONS,
        **kwargs,
    )


def _compose(*subcommands: str, **kwargs: object):
    return _docker(
        "compose",
        *subcommands,
        interspersed_options_with_values=_DOCKER_COMPOSE_OPTIONS,
        interspersed_flags=_DOCKER_COMPOSE_FLAGS,
        **kwargs,
    )


_CONTAINER_REMOVE = AnyMatcher(
    matchers=(
        _docker("rm", forbidden_flags=frozenset({"--force", "-f"})),
        _docker("container", "rm", forbidden_flags=frozenset({"--force", "-f"})),
    )
)
_CONTAINER_STOP = AnyMatcher(matchers=(_docker("stop"), _docker("container", "stop")))
_CONTAINER_KILL = AnyMatcher(matchers=(_docker("kill"), _docker("container", "kill")))
_CONTAINER_PRUNE = _docker("container", "prune")
_IMAGE_REMOVE = AnyMatcher(matchers=(_docker("rmi"), _docker("image", "rm"), _docker("image", "remove")))
_IMAGE_PRUNE = _docker("image", "prune")
_VOLUME_REMOVE = AnyMatcher(matchers=(_docker("volume", "rm"), _docker("volume", "remove")))
_VOLUME_PRUNE = _docker("volume", "prune")
_NETWORK_REMOVE = AnyMatcher(matchers=(_docker("network", "rm"), _docker("network", "remove")))
_NETWORK_PRUNE = _docker("network", "prune")
_BUILD_CACHE_PRUNE = AnyMatcher(matchers=(_docker("builder", "prune"), _docker("buildx", "prune")))
_BUILDX_REMOVE = _docker("buildx", "rm")
_COMPOSE_DOWN = _compose("down")
_COMPOSE_REMOVE = _compose("rm")
_CONTAINER_EXEC = AnyMatcher(
    matchers=(
        _docker("exec", forbidden_flags=frozenset({"--privileged"}), options_with_values=_EXEC_OPTIONS),
        _docker("container", "exec", forbidden_flags=frozenset({"--privileged"}), options_with_values=_EXEC_OPTIONS),
    )
)
_PRIVILEGED_EXEC = AnyMatcher(
    matchers=(
        _docker("exec", required_flags=frozenset({"--privileged"}), options_with_values=_EXEC_OPTIONS),
        _docker(
            "container",
            "exec",
            required_flags=frozenset({"--privileged"}),
            options_with_values=_EXEC_OPTIONS,
        ),
        _compose("exec", required_flags=frozenset({"--privileged"}), options_with_values=_EXEC_OPTIONS),
    )
)
_SWARM_REMOVE = AnyMatcher(
    matchers=tuple(
        _docker(resource, "rm") for resource in ("config", "node", "secret", "service", "stack")
    )
)


CONTAINER_COMMON_COMMAND_RULES = (
    rule(
        rule_id="command.container-runtime.container-removal",
        title="Container removal",
        description="Identifies removal of named containers after they have been stopped.",
        matcher=_CONTAINER_REMOVE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Inspect the named container and preserve any required logs or data before removal.",
        example_command="docker rm api",
        safe_variants=(help_variant(_CONTAINER_REMOVE),),
    ),
    rule(
        rule_id="command.container-runtime.container-stop",
        title="Container stop",
        description="Identifies stopping running containers, which can interrupt active workloads.",
        matcher=_CONTAINER_STOP,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Verify the exact container and its workload dependencies before stopping it.",
        example_command="docker stop api",
        safe_variants=(help_variant(_CONTAINER_STOP),),
    ),
    rule(
        rule_id="command.container-runtime.container-kill",
        title="Container kill",
        description="Identifies immediate signal delivery to running containers, including the default SIGKILL.",
        matcher=_CONTAINER_KILL,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Use a graceful stop with an appropriate timeout unless an immediate signal is required.",
        example_command="docker kill api",
        severity="critical",
        safe_variants=(help_variant(_CONTAINER_KILL),),
    ),
    rule(
        rule_id="command.container-runtime.container-prune",
        title="Stopped-container prune",
        description="Identifies bulk deletion of stopped containers.",
        matcher=_CONTAINER_PRUNE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="List stopped containers and remove only reviewed container IDs.",
        example_command="docker container prune",
        safe_variants=(help_variant(_CONTAINER_PRUNE),),
    ),
    rule(
        rule_id="command.container-runtime.image-removal",
        title="Container image removal",
        description="Identifies deletion of local container images by ID, tag, or alias command.",
        matcher=_IMAGE_REMOVE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="List image references and remove only the exact reviewed image or tag.",
        example_command="docker image rm app:old",
        safe_variants=(help_variant(_IMAGE_REMOVE),),
    ),
    rule(
        rule_id="command.container-runtime.image-prune",
        title="Container image prune",
        description="Identifies bulk deletion of unused container images.",
        matcher=_IMAGE_PRUNE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="List dangling or unused images and remove reviewed image IDs explicitly.",
        example_command="docker image prune -a",
        safe_variants=(help_variant(_IMAGE_PRUNE),),
    ),
    rule(
        rule_id="command.container-runtime.volume-removal",
        title="Container volume removal",
        description="Identifies deletion of named local volumes and their persisted data.",
        matcher=_VOLUME_REMOVE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Inspect volume consumers and back up required persistent data before deletion.",
        example_command="docker volume rm app-data",
        severity="critical",
        safe_variants=(help_variant(_VOLUME_REMOVE),),
    ),
    rule(
        rule_id="command.container-runtime.volume-prune",
        title="Container volume prune",
        description="Identifies bulk deletion of unused local volumes.",
        matcher=_VOLUME_PRUNE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="List unused volumes and remove only reviewed names after confirming data retention.",
        example_command="docker volume prune -a",
        severity="critical",
        safe_variants=(help_variant(_VOLUME_PRUNE),),
    ),
    rule(
        rule_id="command.container-runtime.network-removal",
        title="Container network removal",
        description="Identifies deletion of Docker networks that can disconnect dependent workloads.",
        matcher=_NETWORK_REMOVE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect connected containers and remove only the exact unused network.",
        example_command="docker network rm app-net",
        safe_variants=(help_variant(_NETWORK_REMOVE),),
    ),
    rule(
        rule_id="command.container-runtime.network-prune",
        title="Container network prune",
        description="Identifies bulk deletion of unused Docker networks.",
        matcher=_NETWORK_PRUNE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="List unused networks and remove reviewed network names explicitly.",
        example_command="docker network prune",
        safe_variants=(help_variant(_NETWORK_PRUNE),),
    ),
    rule(
        rule_id="command.container-runtime.build-cache-prune",
        title="Container build-cache prune",
        description="Identifies deletion of Docker builder or Buildx cache data.",
        matcher=_BUILD_CACHE_PRUNE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Inspect builder disk usage and prune only cache that is safe to rebuild.",
        example_command="docker buildx prune -a",
        safe_variants=(help_variant(_BUILD_CACHE_PRUNE),),
    ),
    rule(
        rule_id="command.container-runtime.buildx-builder-removal",
        title="Buildx builder removal",
        description="Identifies removal of Buildx builder instances and their local state.",
        matcher=_BUILDX_REMOVE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Inspect active builders and switch away from the target builder before removal.",
        example_command="docker buildx rm old-builder",
        safe_variants=(help_variant(_BUILDX_REMOVE),),
    ),
    rule(
        rule_id="command.container-runtime.compose-down",
        title="Compose project teardown",
        description="Identifies Docker Compose teardown that removes service containers and project networks.",
        matcher=_COMPOSE_DOWN,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Review the Compose project and omit volume or image removal unless explicitly required.",
        example_command="docker compose down --volumes",
        safe_variants=(help_variant(_COMPOSE_DOWN),),
    ),
    rule(
        rule_id="command.container-runtime.compose-removal",
        title="Compose container removal",
        description="Identifies removal of stopped service containers through Docker Compose.",
        matcher=_COMPOSE_REMOVE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell",),
        safer_alternative="Inspect the selected services and preserve required volumes before removal.",
        example_command="docker compose rm -f api",
        safe_variants=(help_variant(_COMPOSE_REMOVE),),
    ),
    rule(
        rule_id="command.container-runtime.container-exec",
        title="Container command execution",
        description="Identifies arbitrary command execution inside an existing running container.",
        matcher=_CONTAINER_EXEC,
        action_class="docker-sensitive command",
        risk_classes=("execution",),
        safer_alternative="Use a read-only inspection command and avoid exposing host or credential material.",
        example_command="docker exec api sh -lc 'id'",
    ),
    rule(
        rule_id="command.container-runtime.privileged-exec",
        title="Privileged container command execution",
        description="Identifies command execution with extended privileges inside an existing container or service.",
        matcher=_PRIVILEGED_EXEC,
        action_class="docker-sensitive command",
        risk_classes=("execution", "destructive_shell"),
        safer_alternative="Run without --privileged and grant only the narrowly required capability.",
        example_command="docker exec --privileged api sh",
        severity="critical",
    ),
    rule(
        rule_id="command.container-runtime.swarm-resource-removal",
        title="Swarm resource removal",
        description="Identifies deletion of Swarm services, stacks, nodes, secrets, or configs.",
        matcher=_SWARM_REMOVE,
        action_class="docker-sensitive command",
        risk_classes=("destructive_shell", "network_egress"),
        safer_alternative="Inspect the exact Swarm object and dependent workloads before removing it.",
        example_command="docker service rm api",
        severity="critical",
        safe_variants=(help_variant(_SWARM_REMOVE),),
    ),
)
