# Protect AI-assisted k0s and k0rdent operations with HOL Guard

This use case shows how a platform engineer can put HOL Guard in front of an AI coding agent that has access to a k0s cluster or a cluster managed by k0rdent.

The goal is simple: let the agent perform normal Kubernetes troubleshooting while forcing risky `kubectl` actions through Guard before the shell command runs.

HOL Guard does not need to run as a DaemonSet and does not replace Kubernetes RBAC. It runs on the workstation, jump host, or automation host where the AI agent runs. Kubernetes RBAC remains the cluster authorization boundary. Guard adds a local pre-execution policy and evidence layer for the agent's proposed commands.

## What this demonstrates

A short demo can show three different command classes without changing the cluster:

```bash
hol-guard command test 'kubectl get pods -A'
hol-guard command test 'kubectl get secret -A -o yaml'
hol-guard command test 'kubectl delete namespace demo'
```

`command test` classifies the command without executing it or creating an approval request. The second command exercises Guard's Kubernetes secret-read coverage. The third exercises destructive Kubernetes mutation coverage.

For the full agent path, install Guard's Codex hooks and launch Codex through Guard. Guard receives the complete Bash tool command through the native pre-tool hook before the shell starts.

## Prerequisites

You need:

- Python 3.10 or newer and `pipx`
- HOL Guard
- a supported AI coding agent such as Codex
- `kubectl`
- a working kubeconfig for a k0s cluster or a k0rdent-managed cluster

Install Guard:

```bash
pipx install hol-guard
hol-guard --version
```

For a live demo, use a disposable cluster or a dedicated demo namespace. Use a least-privilege kubeconfig. Do not use production credentials simply to demonstrate Guard.

## Option A: k0s

k0s is a CNCF-certified Kubernetes distribution. Once the cluster is running, use the normal Kubernetes client path:

```bash
kubectl get nodes
kubectl config current-context
```

If you are on a k0s controller where the bundled client is the configured path, the equivalent health check is:

```bash
sudo k0s kubectl get nodes
```

For an AI-agent demo, prefer a normal `kubectl` binary and an explicit kubeconfig on the host where the agent runs. This keeps the command surface visible to Guard and avoids giving the agent broader host privileges than it needs.

## Option B: k0rdent

k0rdent provisions and manages Kubernetes clusters through `ClusterDeployment` objects. After a child cluster is ready, retrieve its kubeconfig using the normal k0rdent workflow, then point `kubectl` at that cluster.

For example, after obtaining the child-cluster kubeconfig:

```bash
export KUBECONFIG="$PWD/kubeconfig"
kubectl get nodes
kubectl config current-context
```

The Guard workflow is the same whether the target cluster was created directly with k0s or provisioned through k0rdent. Guard evaluates the agent's local `kubectl` command before Kubernetes receives it.

## Fast meetup demo: no cluster mutation

The repository includes a small classification-only script:

```bash
bash examples/kubernetes/k0s-k0rdent/demo.sh
```

It tests representative Kubernetes commands through `hol-guard command test`. It does not execute those `kubectl` commands.

If a real k0s or k0rdent-managed cluster is available, separately prove the context with a read-only command:

```bash
kubectl get nodes
```

Then run the classification demo. This separates the cluster proof from the intentionally dangerous examples.

## Full agent demo with Codex

Install Guard's native Codex integration:

```bash
hol-guard install codex
hol-guard doctor codex
hol-guard run codex --dry-run
```

Launch the protected agent:

```bash
hol-guard run codex
```

A safe demo prompt is:

```text
Inspect the current Kubernetes cluster and summarize unhealthy workloads.
Do not modify resources and do not read Secret payloads.
```

The useful security moment comes when an agent, tool result, or injected instruction tries to expand the task. Examples of commands worth testing with `hol-guard command test` before any live agent demo include:

```bash
hol-guard command test 'kubectl get secret -A -o yaml'
hol-guard command test 'kubectl delete namespace demo'
hol-guard command test 'kubectl apply -f unreviewed.yaml'
```

Guard's native Codex `PreToolUse` hook receives the complete Bash tool command before shell execution. Depending on the command, evidence, and local policy, Guard can allow it, warn, block it, or require review. Kubernetes RBAC still decides whether an allowed command is authorized by the cluster.

## Recommended demo policy

Keep Kubernetes permissions narrow even with Guard enabled. For a meetup, create a dedicated namespace and grant only the permissions the scenario needs.

A useful operating model is:

1. Kubernetes RBAC limits what the identity can do.
2. HOL Guard reviews what the AI agent is trying to do before execution.
3. The agent integration pauses or blocks commands that need review.
4. Guard receipts preserve evidence of the decision.

Do not grant cluster-admin simply to make the demo more dramatic.

## Show the evidence

After the protected session, inspect Guard's local evidence:

```bash
hol-guard status
hol-guard receipts
hol-guard events
hol-guard abom --format json
```

For a queued approval in a non-interactive environment:

```bash
hol-guard approvals
```

This gives the meetup audience a concrete before-and-after story: the AI agent can still perform ordinary Kubernetes work, but sensitive secret access and destructive cluster changes are visible to an independent local policy layer before execution.

## Why this fits k0s and k0rdent

The integration is intentionally Kubernetes-native rather than distribution-specific:

- k0s provides the Kubernetes runtime.
- k0rdent can provision and manage fleets of Kubernetes clusters.
- `kubectl` remains the operator and automation surface.
- HOL Guard sits on the AI-agent execution host and evaluates the proposed command before it reaches that surface.

That means the same Guard policy can follow an operator across a local k0s lab, a k0rdent management environment, and k0rdent-managed child clusters without adding a privileged cluster component.

## Related documentation

- [Guard Get Started](./get-started.md)
- [Harness support matrix](./harness-support.md)
- [Command extension coverage](./command-domain-extension-coverage.md)
- [k0s documentation](https://docs.k0sproject.io/)
- [k0rdent documentation](https://docs.k0rdent.io/)
