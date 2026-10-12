"""Record pinned original sensitivity outcomes; never use as a runtime oracle."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib
import json
import subprocess
import sys
import types
from dataclasses import asdict, is_dataclass
from pathlib import Path
from types import SimpleNamespace


def record(repo: Path, base: str, destination: Path) -> None:
    sys.path.insert(0, str(repo / "src"))
    modules = {}
    hashes = {}
    for leaf in ("secret_sensitivity", "structured_data_sensitivity", "structured_output_mediation"):
        name = "codex_plugin_scanner.guard.runtime." + leaf
        path = "src/codex_plugin_scanner/guard/runtime/" + leaf + ".py"
        source = subprocess.check_output(["git", "show", base + ":" + path], cwd=repo)
        hashes[path] = hashlib.sha256(source).hexdigest()
        importlib.import_module("codex_plugin_scanner.guard.runtime")
        module = types.ModuleType(name)
        module.__file__ = path
        module.__package__ = "codex_plugin_scanner.guard.runtime"
        sys.modules[name] = module
        exec(compile(source, path, "exec"), module.__dict__)
        modules[leaf] = module
    secret, data, output = (modules[k] for k in modules)
    vectors = []

    def plain(value):
        if is_dataclass(value):
            return plain(asdict(value))
        if isinstance(value, dict):
            return {k: plain(v) for k, v in value.items()}
        if isinstance(value, (tuple, list)):
            return [plain(v) for v in value]
        if isinstance(value, (set, frozenset)):
            return sorted(plain(v) for v in value)
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return value

    def add(query, body, call):
        try:
            result = {"ok": plain(call())}
        except (ValueError, TypeError) as exc:
            result = {"error": str(exc), "type": type(exc).__name__}
        vectors.append({"query": query, "body": body, "expected": result})

    for path in (
        None,
        "",
        "  ",
        "README.md",
        ".env",
        ".env.example",
        "./.npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        "private-key.pem",
        "private.key",
        "wallet.key",
        "wallet.dat",
        "id_rsa",
        ".../id_rsa",
        "./.ssh/id_ed25519",
        "x/.gnupg/pubring.kbx",
        "x/.aws/config",
        "x/.aws/credentials",
        "x/.docker/config.json",
        "x/.kube/config",
        "terraform.tfvars",
        ".terraform.tfvars",
        "a/../.env",
        "'~/.ssh/id_rsa'",
        '"~/.env"',
        "C:\\Users\\fixture\\.env",
        "a\\.aws\\credentials",
        "xPRIVATE_KEYx.txt",
        "é/.ENV",
        ".envs",
        "x/.ssh/config",
        "./.../id_ecdsa",
    ):
        for cwd in ("/workspace/project", "/workspace/other"):
            body = {"path": path, "cwd": cwd, "home_dir": "/fixture/home"}
            add(
                "path",
                body,
                lambda b=body: secret.classify_secret_path(b["path"], cwd=Path(b["cwd"]), home_dir=Path(b["home_dir"])),
            )
    for text in (
        "",
        ".ENV and .npmrc",
        ".aws/credentials .ssh/file",
        ".docker/config.json .kube/config",
        "ordinary.txt",
        ".gnupg/key .git-credentials",
    ):
        add("legacy", {"text": text}, lambda t=text: secret.classify_legacy_secret_path_families(t))
    contents = [
        None,
        "",
        "ordinary text",
        "token=fixture-only",
        "token=example",
        "password=dummy",
        "token=realvalue",
        "token=get_secret(config.key)",
        'token=f"{response.value}"',
        "token={proc.stdout}",
        "token='{proc.stderr}'",
        "token='realvalue',",
        'token: "placeholder"',
        "bearer fixture-token-value",
        "bearer " + "A" * 24,
        "bearer example-123456789012345678901234",
        "fake_secret",
        "fake-credential",
        "npm_token=test",
        "npm_token=realvalue",
        "_authToken=fixture-only",
        "ghp_" + "A" * 24,
        "github_pat_" + "B" * 24 + "_" + "C" * 24,
        "AKIA" + "A" * 16,
        "ASIA" + "B" * 16,
        "sk-" + "A" * 24,
        "sk-proj-" + "B" * 24,
        "sk-ant-api03-" + "C" * 24,
        "private_key=" + "a" * 64,
        "hedera_operator_private_key='0x" + "b" * 96 + "'",
        "-----BEGIN RSA PRIVATE KEY-----",
        "x\ntoken: actual\npassword=second",
        "token=\"get_secret('key')\"",
        "token=f'{value}'",
        'password="line one\nline two"',
        "é token = valeur",
        "TOKEN=example-value",
    ]
    for text in contents:
        for suppress in (False, True):
            for documentation in (False, True):
                body = {"text": text, "suppress_samples": suppress, "documentation_sample_context": documentation}
                add("content", body, lambda b=body: secret.classify_secret_content(**b))
    add("content_version", {}, secret.secret_content_rule_version)
    schema_wire = [
        {
            "path": ["employee", "email"],
            "role": "protected_personal",
            "value_type": "string",
            "category": "email_address",
        },
        {"path": ["employee", "id"], "role": "protected_personal", "value_type": "integer", "category": "employee_id"},
        {"path": ["note"], "role": "ordinary", "value_type": "string", "category": None},
    ]
    schema = data.DeclaredSchema(
        tuple(data.DeclaredField(tuple(f["path"]), f["role"], f["value_type"], f["category"]) for f in schema_wire)
    )
    for fields, instance in ((None, None), (schema_wire, schema)):
        add("classifier_version", {"schema": fields}, lambda s=instance: data.classifier_rule_version(s))
        samples = [
            "{}",
            '{"note":"ordinary"}',
            '{"employee":{"email":"casey@example.invalid","id":0}}',
            '{"employee":{"email":" "}}',
            '{"employee":{"id":true}}',
            '{"employee":{"id":1.5}}',
            '{"other":"ordinary"}',
            '{"note":[]}',
            '{"note":{}}',
            '{"note":null}',
            '{"employee":{}}',
            '{"employee":{"other":"ordinary"}}',
            '{"note":"a","note":"b"}',
            '{"note":NaN}',
            '["ordinary"]',
            "null",
            "not JSON",
            '{"note":"a\\nb"}',
            '{"note":"é"}',
            '{"note":""}',
            '{"employee":{"id":9007199254740993}}',
            '{"employee":{"id":1208925819614629174706176}}',
            '{"employee":{"id":-1208925819614629174706176}}',
            "ghp_" + "A" * 24,
            "token=fixture-only",
            "token=get_secret(value)",
            "a" * 4095 + "ghp_" + "B" * 24,
            " " * 65537,
        ]
        for content in samples:
            body = {"content": content, "schema": fields}
            add("declared", body, lambda c=content, s=instance: data.classify_declared_content(c, schema=s))
    for value in (
        None,
        {},
        1,
        "",
        "{}",
        " {}",
        '{"note":"ordinary"}',
        '{"note":"é"}',
        '{"b":1,"a":2}',
        '{"a":2,"b":1}',
        '{"a":1.0}',
        '{"a":-0}',
        '{"a":9007199254740991}',
        '{"a":9007199254740992}',
        '{"a":true}',
        '{"a":null}',
        '{"a":[1,2]}',
        '{"a":"a\\nb"}',
        '{"a":1,"a":2}',
        "[1]",
        "NaN",
    ):
        add("canonical", {"value": value}, lambda v=value: output.canonical_structured_content_bytes(v))
    policy = {
        "version": "hol-guard-structured-output-policy.v1",
        "enabled": True,
        "harnesses": ["pi", "omp"],
        "event": "PostToolUse",
        "destinationRole": "model_visible_tool_result",
        "schema": {
            "fields": [
                {
                    "path": f["path"],
                    "role": f["role"],
                    "valueType": f["value_type"],
                    **({"category": f["category"]} if f["category"] else {}),
                }
                for f in schema_wire
            ]
        },
        "onMatch": "withhold",
        "onUnsupported": "withhold",
    }
    policies = [policy, None, {}, {**policy, "extra": True}]
    for key in policy:
        missing = copy.deepcopy(policy)
        missing.pop(key)
        policies.append(missing)
    for key, value in [
        ("version", "unknown"),
        ("enabled", 1),
        ("enabled", False),
        ("harnesses", ["pi", "pi"]),
        ("harnesses", ["codex"]),
        ("harnesses", []),
        ("event", "PreToolUse"),
        ("onMatch", "forward"),
    ]:
        policies.append({**policy, key: value})
    for p in policies:
        add("policy", {"value": p}, lambda v=p: output.parse_structured_output_policy(v))
    for harness in ("pi", "pi_agent", "pi-coding-agent", "oh-my-pi", "OMP", "codex", " unknown "):
        add("harness", {"value": harness}, lambda h=harness: output.canonical_harness_name(h))
        for status in (
            None,
            "absent",
            "active",
            "invalid",
            "inaccessible",
            "tampered",
            "revoked",
            "removed",
            "expired",
            "stale",
            "unknown",
        ):
            for mode in ("enrolled", "unlocked", "missing", "hash_mismatch"):
                config = {
                    "managed_policy_status": status,
                    "managed_policy_hash": "a" * 64,
                    "managed_locked_settings": [output.STRUCTURED_OUTPUT_SETTING_PATH] if mode != "unlocked" else [],
                    "managed_policy": None
                    if mode == "missing"
                    else {
                        "content_hash": ("b" if mode == "hash_mismatch" else "a") * 64,
                        "settings": {"data_control": {"structured_output": policy}},
                    },
                }
                obj = SimpleNamespace(**config)
                if config["managed_policy"] is not None:
                    obj.managed_policy = SimpleNamespace(**config["managed_policy"])
                add(
                    "resolution",
                    {"config": config, "harness": harness},
                    lambda c=obj, h=harness: output.resolve_managed_structured_output_resolution(c, harness=h),
                )
    binding = output.StructuredOutputBinding(
        "pi", "a" * 64, output.parse_structured_output_policy(policy), data.classifier_rule_version(schema)
    )
    for content in (
        '{"note":"ordinary"}',
        '{"employee":{"email":"casey@example.invalid"}}',
        '{"unknown":1}',
        '{"note":1.0}',
    ):
        for state in ("same", "changed", "missing", "no_callback", "raises"):
            for event, decision in (("PostToolUse", "allow"), ("PreToolUse", "allow"), ("PostToolUse", "block")):
                body = {
                    "harness": "pi",
                    "event_name": event,
                    "native_result": {"decision": decision, "model_output_action": "allow_original"},
                    "validated_receipt": {"decision": "allow", "decision_id": "fixture-decision"},
                    "structured_output_json": content,
                    "binding": plain(binding),
                    "recheck": state,
                }

                def callback(state=state):
                    if state == "raises":
                        raise ValueError("fixture_callback_failure")
                    return (
                        binding
                        if state == "same"
                        else (
                            None
                            if state == "missing"
                            else output.StructuredOutputBinding("omp", "b" * 64, binding.policy, binding.rule_version)
                        )
                    )

                add(
                    "mediate",
                    body,
                    lambda b=body, state=state, callback=callback: output.mediate_native_post_tool_content(
                        **{k: v for k, v in b.items() if k not in ("binding", "recheck")},
                        binding=binding,
                        recheck_binding=None if state == "no_callback" else callback,
                    ),
                )
    # Boundaries from the retired unit suites, recorded from the same old code.
    for raw in (
        b"\xff",
        b"x" * 65_537,
        '{"note":"\\u0061"}',
        '{"employee":{"email":{}}}',
        '{"other":{}}',
        '{"employee":{"other":{}}',
        '{"note":["a"]}',
        "\ud800",
        None,
    ):
        encoded = (
            raw
            if isinstance(raw, bytes)
            else raw.encode("utf-8", errors="surrogatepass")
            if isinstance(raw, str)
            else b""
        )
        body = {
            "schema": schema_wire,
            "content_type": "bytes" if isinstance(raw, bytes) else "str" if isinstance(raw, str) else "other",
            "content_length": len(encoded),
            "content_bytes": base64.b64encode(encoded[:65_537]).decode("ascii"),
        }
        add("declared_bytes", body, lambda raw=raw: data.classify_declared_content(raw, schema=schema))
    for raw_fields in (
        [],
        [{"path": [], "role": "ordinary", "value_type": "string", "category": None}],
        [{"path": ["dynamic-key"], "role": "ordinary", "value_type": "string", "category": None}],
        [{"path": ["note"], "role": "protected_personal", "value_type": "string", "category": "arbitrary_label"}],
        [{"path": ["note"], "role": "ordinary", "value_type": None, "category": None}],
        schema_wire + schema_wire,
    ):

        def old_schema(raw_fields=raw_fields):
            fields = tuple(
                data.DeclaredField(tuple(f["path"]), f["role"], f["value_type"], f["category"]) for f in raw_fields
            )
            return data.DeclaredSchema(fields).fields

        add("fields", {"schema": raw_fields}, old_schema)
    fields17 = [
        {"path": [f"person{i}"], "role": "protected_personal", "value_type": "string", "category": "person_name"}
        for i in range(17)
    ]
    schema17 = data.DeclaredSchema(
        tuple(data.DeclaredField(tuple(f["path"]), f["role"], f["value_type"], f["category"]) for f in fields17)
    )
    content17 = json.dumps({f"person{i}": f"Synthetic Person {i}" for i in range(17)})
    add(
        "declared",
        {"schema": fields17, "content": content17},
        lambda: data.classify_declared_content(content17, schema=schema17),
    )
    for mutate in (
        "schema_extra",
        "empty_fields",
        "field_extra",
        "field_bad_path",
        "wrong_destination",
        "permissive_disposition",
    ):
        candidate = copy.deepcopy(policy)
        if mutate == "schema_extra":
            candidate["schema"]["extra"] = True
        elif mutate == "empty_fields":
            candidate["schema"]["fields"] = []
        elif mutate == "field_extra":
            candidate["schema"]["fields"][0]["extra"] = True
        elif mutate == "field_bad_path":
            candidate["schema"]["fields"][0]["path"] = "bad"
        elif mutate == "wrong_destination":
            candidate["destinationRole"] = "other"
        else:
            candidate["onMatch"] = "forward"
        add("policy", {"value": candidate}, lambda v=candidate: output.parse_structured_output_policy(v))
    for candidate in (
        '{"value":1.5}',
        '{"value":NaN}',
        '{"value":[1]}',
        '{"value":"' + "x" * 65_536 + '"}',
        '{"value":1,"value":2}',
        '{"a":{"b":{"c":1}}}',
    ):
        add("canonical", {"value": candidate}, lambda v=candidate: output.canonical_structured_content_bytes(v))
    document = {
        "schema": "guard-content-sensitivity-parity.v1",
        "base": base,
        "source_sha256": hashes,
        "vectors": vectors,
    }
    destination.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n")
    print(f"Recorded {len(vectors)} original outcomes; hashes {len(hashes)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    record(args.repo, args.base, args.output)
