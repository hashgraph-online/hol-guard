# k0s and k0rdent demo

Use this example for a classification-only HOL Guard demo around Kubernetes operations on k0s or k0rdent-managed clusters.

The script does not execute `kubectl`. It passes representative commands to `hol-guard command test` so the risky examples cannot mutate a live cluster.

```bash
bash examples/kubernetes/k0s-k0rdent/demo.sh
```

For the complete setup, Codex hook flow, k0s and k0rdent context, least-privilege guidance, and evidence commands, see [Protect AI-assisted k0s and k0rdent operations with HOL Guard](../../../docs/guard/k0s-k0rdent-use-case.md).
