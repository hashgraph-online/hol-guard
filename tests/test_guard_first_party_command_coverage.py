"""Explicit ownership and help boundaries for first-party CLI command gaps."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.native_command_test_support import inspect_command_native_test as inspect_command
from tests.native_github_capability_support import github_cli_assessment

MAPPED_COMMANDS = (
    ("docker --future-global value restart api", "container-runtime.container-restart"),
    ("kubectl --future-global value proxy --port=8001", "kubernetes-operations.api-proxy"),
    (
        "docker buildx --builder fixture imagetools create -t example/app:latest example/app:v1",
        "container-runtime.image-publication",
    ),
    ("docker restart api", "container-runtime.container-restart"),
    ("docker container restart api", "container-runtime.container-restart"),
    ("docker --context development restart api", "container-runtime.container-restart"),
    ("docker.exe pause api", "container-runtime.container-pause"),
    ("docker container unpause api", "container-runtime.container-pause"),
    ("docker update --memory 512m api", "container-runtime.container-update"),
    ("docker container rename api api-old", "container-runtime.container-update"),
    ("docker create --label test=value alpine", "container-runtime.container-create"),
    ("docker container create alpine", "container-runtime.container-create"),
    ("docker container run alpine id", "container-runtime.container-create"),
    ("docker cp api:/app/output ./output", "container-runtime.container-copy"),
    ("docker container cp ./input api:/app/input", "container-runtime.container-copy"),
    ("docker commit api app:snapshot", "container-runtime.image-state-change"),
    ("docker container commit api app:snapshot", "container-runtime.image-state-change"),
    ("docker tag app:v1 app:latest", "container-runtime.image-state-change"),
    ("docker image tag app:v1 app:latest", "container-runtime.image-state-change"),
    ("docker load -i image.tar", "container-runtime.image-state-change"),
    ("docker image load -i image.tar", "container-runtime.image-state-change"),
    ("docker import image.tar app:v1", "container-runtime.image-state-change"),
    ("docker image import image.tar app:v1", "container-runtime.image-state-change"),
    ("docker image push example/app:v1", "container-runtime.image-publication"),
    ("docker manifest push example/app:v1", "container-runtime.image-publication"),
    ("docker buildx imagetools create -t example/app:latest example/app:v1", "container-runtime.image-publication"),
    ("docker network create app-net", "container-runtime.network-change"),
    ("docker network connect app-net api", "container-runtime.network-change"),
    ("docker network disconnect app-net api", "container-runtime.network-change"),
    ("docker volume create app-data", "container-runtime.volume-create"),
    ("docker volume update --availability drain app-data", "container-runtime.volume-create"),
    ("docker swarm init", "container-runtime.swarm-change"),
    ("docker swarm join --token synthetic node.example.test:2377", "container-runtime.swarm-change"),
    ("docker swarm leave --force", "container-runtime.swarm-change"),
    ("docker swarm update --task-history-limit 5", "container-runtime.swarm-change"),
    ("docker service create --name api alpine", "container-runtime.swarm-change"),
    ("docker service update --image alpine:3 api", "container-runtime.swarm-change"),
    ("docker service scale api=0", "container-runtime.swarm-change"),
    ("docker service rollback api", "container-runtime.swarm-change"),
    ("docker stack deploy -c compose.yaml app", "container-runtime.swarm-change"),
    ("docker logout registry.example.com", "container-runtime.logout"),
    ("kubectl rollout pause deployment/api", "kubernetes-operations.rollout-pause-resume"),
    ("kubectl.exe rollout resume deployment/api", "kubernetes-operations.rollout-pause-resume"),
    ("kubectl --context development rollout pause deployment/api", "kubernetes-operations.rollout-pause-resume"),
    ("kubectl --profile cpu rollout pause deployment/api", "kubernetes-operations.rollout-pause-resume"),
    ("kubectl --profile=cpu config use-context development", "kubernetes-operations.config-write"),
    ("kubectl --profile cpu auth reconcile -f roles.yaml", "kubernetes-operations.auth-reconcile"),
    ("kubectl --profile cpu proxy --port=8001", "kubernetes-operations.api-proxy"),
    ("kubectl config set clusters.local.server https://cluster.example.test", "kubernetes-operations.config-write"),
    ("kubectl config set-cluster local --server=https://cluster.example.test", "kubernetes-operations.config-write"),
    ("kubectl config set-context development --cluster=local", "kubernetes-operations.config-write"),
    ("kubectl config set-credentials fixture --exec-command=fixture-login", "kubernetes-operations.config-write"),
    ("kubectl config use-context development", "kubernetes-operations.config-write"),
    ("kubectl config unset current-context", "kubernetes-operations.config-write"),
    ("kubectl config delete-cluster local", "kubernetes-operations.config-write"),
    ("kubectl config delete-context development", "kubernetes-operations.config-write"),
    ("kubectl config delete-user fixture", "kubernetes-operations.config-write"),
    ("kubectl config rename-context development old-development", "kubernetes-operations.config-write"),
    ("kubectl auth reconcile -f roles.yaml", "kubernetes-operations.auth-reconcile"),
    ("kubectl proxy --port=8001", "kubernetes-operations.api-proxy"),
)


@pytest.mark.parametrize(("command", "owner"), MAPPED_COMMANDS)
def test_missing_commands_have_explicit_permissions(command: str, owner: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    assert payload["status"] == "review", payload
    assert f"command.{owner}" in {rule["rule_id"] for rule in payload["rules"]}, payload


@pytest.mark.parametrize(
    "command",
    (
        "docker restart --help",
        "docker container create --help",
        "docker network connect --help",
        "docker buildx imagetools create --help",
        "docker buildx --builder fixture imagetools create --help",
        "kubectl rollout pause --help",
        "kubectl config set-credentials --help",
        "kubectl auth reconcile --help",
        "kubectl proxy --help",
        "kubectl --profile cpu rollout pause --help",
        "kubectl --profile cpu config use-context --help",
        "kubectl --profile cpu auth reconcile --help",
        "kubectl --profile cpu proxy --help",
    ),
)
def test_help_does_not_trigger_the_new_operation_rules(command: str, tmp_path: Path) -> None:
    added = {f"command.{owner}" for _, owner in MAPPED_COMMANDS}
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    assert added.isdisjoint(rule["rule_id"] for rule in payload["rules"]), payload


@pytest.mark.parametrize(
    ("command", "owner"),
    (
        ("docker create --label --help alpine", "container-runtime.container-create"),
        ("docker container run alpine echo --help", "container-runtime.container-create"),
        ("docker restart --help=false api", "container-runtime.container-restart"),
        ("docker restart -- --help api", "container-runtime.container-restart"),
        ("kubectl rollout pause -- --help deployment/api", "kubernetes-operations.rollout-pause-resume"),
        ("kubectl config set-credentials fixture --exec-command=--help", "kubernetes-operations.config-write"),
        ("kubectl config use-context development --help=false", "kubernetes-operations.config-write"),
        ("kubectl auth reconcile -f roles.yaml --dry-run=none", "kubernetes-operations.auth-reconcile"),
    ),
)
def test_help_values_and_payload_arguments_keep_review(command: str, owner: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    assert f"command.{owner}" in {rule["rule_id"] for rule in payload["rules"]}, payload


@pytest.mark.parametrize(
    ("args", "capability"),
    (
        (("secret", "list"), "read_remote"),
        (("cache", "list", "--limit", "5"), "read_remote"),
        (("label", "list"), "read_remote"),
        (("variable", "list"), "read_remote"),
        (("codespace", "list"), "read_remote"),
        (("org", "list"), "read_remote"),
        (("project", "list", "--owner", "example-org"), "read_remote"),
        (("alias", "list"), "read_local"),
        (("extension", "list"), "read_local"),
        (("config", "get", "editor"), "read_local"),
        (("config", "set", "editor", "vi"), "write_local"),
        (("pr", "update-branch", "12"), "mutate_remote"),
        (("pr", "revert", "12"), "content_remote"),
        (("release", "delete-asset", "v1", "asset.zip"), "delete_remote"),
        (("project", "item-delete", "1", "--id", "PVTI_fixture"), "delete_remote"),
    ),
)
def test_github_command_ownership(args: tuple[str, ...], capability: str) -> None:
    assert github_cli_assessment(args).capability == capability


@pytest.mark.parametrize(
    ("option", "value"),
    (
        ("--as-user-extra", "scope=example"),
        ("--kuberc", "preferences.yaml"),
        ("--log-flush-frequency", "5s"),
        ("--vmodule", "component=2"),
        ("--proxy-url", "http://proxy.example.test"),
        ("--storage-driver-buffer-duration", "1m"),
        ("--storage-driver-db", "fixture"),
        ("--storage-driver-host", "metrics.example.test"),
        ("--storage-driver-password", "fixture"),
        ("--storage-driver-table", "fixture"),
        ("--storage-driver-user", "fixture"),
    ),
)
def test_inherited_value_options_keep_operation_ownership(option: str, value: str, tmp_path: Path) -> None:
    payload = inspect_command(f"kubectl {option} {value} proxy --port=8001", cwd=tmp_path, home_dir=tmp_path)
    assert "command.kubernetes-operations.api-proxy" in {r["rule_id"] for r in payload["rules"]}, payload


@pytest.mark.parametrize(
    "command",
    (
        "docker --context restart ps",
        "kubectl --context proxy get pods",
        "kubectl --kuberc proxy get pods",
        "kubectl --profile-output proxy get pods",
    ),
)
def test_global_option_values_are_not_command_paths(command: str, tmp_path: Path) -> None:
    added = {f"command.{owner}" for _, owner in MAPPED_COMMANDS}
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)
    assert added.isdisjoint(r["rule_id"] for r in payload["rules"]), payload


@pytest.mark.parametrize("extension", ("command.container-runtime", "command.kubernetes-operations"))
def test_command_and_help_matchers_keep_opposite_uncertainty_polarity(extension: str) -> None:
    source = Path(__file__).resolve().parents[1] / "contributions" / "command-sources" / f"{extension}.json"
    rules = json.loads(source.read_text())["extension"]["rules"]
    for rule in rules:
        if (rule.get("matcher") or {}).get("op") == "executable-path-set.v1":
            assert rule["matcher"]["config"]["fail_secure_unknown_options"] is True, rule["rule_id"]
        for variant in rule["safe_variants"]:
            matcher = variant.get("matcher") or {}
            if matcher.get("op") == "executable-path-set.v1":
                assert matcher["config"]["fail_secure_unknown_options"] is False, rule["rule_id"]
                assert matcher["config"]["required_flags"] == ["--help"], rule["rule_id"]
                assert matcher["config"]["required_flags_in_all_arguments"] is True, rule["rule_id"]
