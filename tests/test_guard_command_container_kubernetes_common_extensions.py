"""Coverage and safety boundaries for common Docker, Kubernetes, and Helm commands."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.command_inspection import inspect_command
from codex_plugin_scanner.guard.runtime.secret_file_requests import extract_sensitive_tool_action_request


@pytest.mark.parametrize(
    ("command", "rule_id"),
    [
        ("docker rm api", "command.container-runtime.container-removal"),
        ("docker container stop api", "command.container-runtime.container-stop"),
        ("docker kill api", "command.container-runtime.container-kill"),
        ("docker container prune -f", "command.container-runtime.container-prune"),
        ("docker rmi app:old", "command.container-runtime.image-removal"),
        ("docker image remove app:old", "command.container-runtime.image-removal"),
        ("docker image prune -a -f", "command.container-runtime.image-prune"),
        ("docker volume rm app-data", "command.container-runtime.volume-removal"),
        ("docker volume prune -a -f", "command.container-runtime.volume-prune"),
        ("docker network remove app-net", "command.container-runtime.network-removal"),
        ("docker network prune -f", "command.container-runtime.network-prune"),
        ("docker builder prune -a -f", "command.container-runtime.build-cache-prune"),
        ("docker buildx prune -a -f", "command.container-runtime.build-cache-prune"),
        ("docker buildx rm old-builder", "command.container-runtime.buildx-builder-removal"),
        (
            "docker compose -f compose.yml down --volumes",
            "command.container-runtime.compose-destructive-cleanup",
        ),
        ("docker compose down --rmi=all", "command.container-runtime.compose-destructive-cleanup"),
        ("docker compose down --rmi local", "command.container-runtime.compose-destructive-cleanup"),
        ("docker exec api sh -lc 'id'", "command.container-runtime.container-exec"),
        ("docker container exec api id", "command.container-runtime.container-exec"),
        ("docker exec --privileged api sh", "command.container-runtime.privileged-exec"),
        ("docker compose exec --privileged api sh", "command.container-runtime.privileged-exec"),
        ("docker service rm api", "command.container-runtime.swarm-resource-removal"),
        ("docker stack rm prod", "command.container-runtime.swarm-resource-removal"),
        ("docker.exe volume rm app-data", "command.container-runtime.volume-removal"),
        ("docker.exe system prune", "command.container-runtime.system-prune"),
        ("docker.exe rm -f api", "command.container-runtime.forced-container-removal"),
        ("docker.exe run --privileged alpine", "command.container-runtime.privileged-run"),
        ("docker -c prod volume rm app-data", "command.container-runtime.volume-removal"),
        ("docker -H tcp://daemon volume rm app-data", "command.container-runtime.volume-removal"),
        ("docker --tlscacert ca.pem volume rm app-data", "command.container-runtime.volume-removal"),
        ("docker -D --context prod image rm app:old", "command.container-runtime.image-removal"),
        ("kubectl apply -f deployment.yaml", "command.kubernetes-operations.apply-resources"),
        ("kubectl create -f service.yaml", "command.kubernetes-operations.create-resources"),
        ("kubectl replace -f deployment.yaml", "command.kubernetes-operations.replace-resources"),
        (
            "kubectl replace --force -f deployment.yaml",
            "command.kubernetes-operations.force-replace-resources",
        ),
        (
            "kubectl patch deployment api -p '{\"spec\":{\"replicas\":2}}'",
            "command.kubernetes-operations.patch-resources",
        ),
        ("kubectl edit deployment api", "command.kubernetes-operations.edit-resources"),
        ("kubectl scale deployment api --replicas=0", "command.kubernetes-operations.scale-resources"),
        (
            "kubectl autoscale deployment api --min=2 --max=10 --cpu-percent=80",
            "command.kubernetes-operations.autoscale-resources",
        ),
        (
            "kubectl expose deployment api --port=80 --type=LoadBalancer",
            "command.kubernetes-operations.expose-resources",
        ),
        ("kubectl run debug --image=alpine -- sh", "command.kubernetes-operations.run-pod"),
        (
            "kubectl annotate deployment api owner=platform --overwrite",
            "command.kubernetes-operations.annotate-resources",
        ),
        (
            "kubectl label namespace prod environment=restricted --overwrite",
            "command.kubernetes-operations.label-resources",
        ),
        (
            "kubectl taint nodes node-a dedicated=ops:NoExecute",
            "command.kubernetes-operations.taint-nodes",
        ),
        ("kubectl cordon node-a", "command.kubernetes-operations.node-scheduling"),
        (
            "kubectl set image deployment/api api=registry.example.com/api:v2",
            "command.kubernetes-operations.set-resources",
        ),
        (
            "kubectl rollout restart deployment/api",
            "command.kubernetes-operations.rollout-restart",
        ),
        (
            "kubectl rollout undo deployment/api --to-revision=2",
            "command.kubernetes-operations.rollout-undo",
        ),
        ("kubectl exec deployment/api -- id", "command.kubernetes-operations.exec"),
        ("kubectl debug node/node-a -it --image=busybox", "command.kubernetes-operations.debug"),
        (
            "kubectl port-forward service/api 8080:80",
            "command.kubernetes-operations.port-forward",
        ),
        (
            "kubectl cp ./config.json default/api:/tmp/config.json",
            "command.kubernetes-operations.copy-files",
        ),
        (
            "kubectl certificate approve agent-access",
            "command.kubernetes-operations.certificate-decision",
        ),
        ("helm install api ./chart --namespace prod", "command.kubernetes-operations.helm-install"),
        ("helm upgrade api ./chart --namespace prod", "command.kubernetes-operations.helm-upgrade"),
        ("helm rollback api 2 --namespace prod", "command.kubernetes-operations.helm-rollback"),
        ("helm delete api --namespace prod", "command.kubernetes-operations.helm-uninstall-alias"),
        ("kubectl.exe --context prod apply -f deployment.yaml", "command.kubernetes-operations.apply-resources"),
        ("kubectl.exe delete pod api", "command.kubernetes-operations.delete-resources"),
        ("kubectl.exe drain node-a", "command.kubernetes-operations.drain-node"),
        ("helm.exe uninstall api", "command.kubernetes-operations.helm-uninstall"),
        ("helm.exe --namespace prod upgrade api ./chart", "command.kubernetes-operations.helm-upgrade"),
        ("kubectl --as-uid 1000 apply -f deployment.yaml", "command.kubernetes-operations.apply-resources"),
        (
            "kubectl --insecure-skip-tls-verify --context prod scale deployment api --replicas=2",
            "command.kubernetes-operations.scale-resources",
        ),
    ],
)
def test_common_container_and_kubernetes_operations_emit_structured_rules(
    command: str,
    rule_id: str,
    tmp_path: Path,
) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert rule_id in {rule["rule_id"] for rule in payload["rules"]}
    request = extract_sensitive_tool_action_request(
        "Shell",
        {"command": command},
        cwd=tmp_path,
        home_dir=tmp_path,
    )
    assert request is not None


@pytest.mark.parametrize(
    "command",
    [
        "docker rm --help",
        "docker container stop --help",
        "docker kill --help",
        "docker container prune --help",
        "docker image rm --help",
        "docker image prune --help",
        "docker volume rm --help",
        "docker volume prune --help",
        "docker network rm --help",
        "docker network prune --help",
        "docker buildx prune --help",
        "docker buildx rm --help",
        "docker compose down",
        "docker compose rm -f api",
        "kubectl apply -f deployment.yaml --dry-run=client",
        "kubectl apply -f deployment.yaml --dry-run client",
        "kubectl create -f service.yaml --dry-run=server",
        "kubectl replace -f deployment.yaml --dry-run=client",
        "kubectl replace --force -f deployment.yaml --dry-run=server",
        "kubectl patch deployment api -p '{}' --dry-run=client",
        "kubectl patch deployment api -p '{}' --local",
        "kubectl scale deployment api --replicas=0 --dry-run=client",
        "kubectl autoscale deployment api --min=2 --max=4 --dry-run=server",
        "kubectl expose deployment api --port=80 --dry-run=client",
        "kubectl run debug --image=alpine --dry-run=client",
        "kubectl annotate deployment api owner=platform --local",
        "kubectl label namespace prod environment=restricted --dry-run=client",
        "kubectl taint nodes node-a dedicated=ops:NoSchedule --dry-run=server",
        "kubectl cordon node-a --dry-run=client",
        "kubectl set image deployment/api api=example/api:v2 --local",
        "kubectl rollout undo deployment/api --dry-run=client",
        "kubectl.exe delete pod api --dry-run client",
        "kubectl.exe drain node-a --dry-run=server",
        "helm install api ./chart --dry-run",
        "helm install api ./chart --dry-run=client",
        "helm upgrade api ./chart --dry-run",
        "helm upgrade api ./chart --dry-run server",
        "helm rollback api 2 --dry-run",
        "helm delete api --dry-run",
        "helm.exe uninstall api --dry-run=client",
        "kubectl get pods -A",
        "kubectl describe deployment api",
        "kubectl logs deployment/api",
        "kubectl rollout status deployment/api",
        "kubectl rollout history deployment/api",
        "helm list -A",
        "helm status api",
        "helm template api ./chart",
    ],
)
def test_safe_and_read_only_forms_remain_unreviewed(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )


@pytest.mark.parametrize(
    "command",
    [
        "kubectl apply -f deployment.yaml --dry-run=none",
        "kubectl apply -f deployment.yaml --dry-run=client --dry-run=none",
        "kubectl patch deployment api -p '{}' --local=false",
        "kubectl patch deployment api -p '{}' --local --local=false",
        "helm upgrade api ./chart --dry-run=false",
        "helm upgrade api ./chart --dry-run=client --dry-run=false",
        "helm install api ./chart --dry-run=none",
        "docker compose down --volumes --help=false",
        "docker exec api sh -- --help",
        "kubectl exec deployment/api -- sh -lc 'echo --dry-run=client'",
    ],
)
def test_false_preview_flags_and_payload_tokens_cannot_bypass_review(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "review"
    assert (
        extract_sensitive_tool_action_request(
            "Shell",
            {"command": command},
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is not None
    )


@pytest.mark.parametrize(
    "command",
    [
        "kubectl apply -f deployment.yaml --dry-run=none --dry-run=client",
        "kubectl patch deployment api -p '{}' --local=false --local",
        "helm upgrade api ./chart --dry-run=false --dry-run",
        "helm upgrade api ./chart --dry-run=false --dry-run=server",
    ],
)
def test_effective_final_safe_flag_remains_unreviewed(command: str, tmp_path: Path) -> None:
    payload = inspect_command(command, cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"


def test_legacy_compose_compatibility_is_not_registered(tmp_path: Path) -> None:
    payload = inspect_command("docker-compose down --volumes", cwd=tmp_path, home_dir=tmp_path)

    assert payload["status"] == "no_match"


def test_safe_segment_cannot_hide_later_destructive_segment(tmp_path: Path) -> None:
    payload = inspect_command(
        "kubectl apply -f deployment.yaml --dry-run=client && docker volume rm app-data",
        cwd=tmp_path,
        home_dir=tmp_path,
    )

    rule_ids = {rule["rule_id"] for rule in payload["rules"]}
    assert payload["status"] == "review"
    assert "command.kubernetes-operations.apply-resources" not in rule_ids
    assert "command.container-runtime.volume-removal" in rule_ids


@pytest.mark.parametrize(
    "command",
    [
        "printf '%s\\n' 'docker volume rm app-data'",
        "printf '%s\\n' 'kubectl apply -f prod.yaml'",
        "grep -R 'kubectl exec|docker buildx prune' docs/",
    ],
)
def test_quoted_examples_and_search_patterns_remain_data(command: str, tmp_path: Path) -> None:
    assert inspect_command(command, cwd=tmp_path, home_dir=tmp_path)["status"] == "no_match"


def test_extension_metadata_declares_new_action_and_risk_classes() -> None:
    container = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.container-runtime")
    kubernetes = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.kubernetes-operations")

    assert container is not None
    assert kubernetes is not None
    assert "execution" in container.risk_classes
    assert {"execution", "local_secret_read"} <= set(kubernetes.risk_classes)
    assert {
        "Kubernetes remote execution command",
        "Kubernetes network tunnel command",
        "Kubernetes remote file transfer command",
        "Kubernetes security administration command",
    } <= set(kubernetes.action_classes)
    assert all(url.startswith("https://") for url in (*container.reference_urls, *kubernetes.reference_urls))
