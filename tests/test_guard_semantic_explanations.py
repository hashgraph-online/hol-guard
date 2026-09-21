from __future__ import annotations

from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.runtime.semantic_explanations import (
    SEMANTIC_RULES,
    CommandSemanticInput,
    explain_command,
    stable_semantic_catalog_digest,
)


def _input(
    executable: str,
    *arguments: str,
    command: str | None = None,
    exact: bool = False,
    operands: tuple[str, ...] = (),
    target_paths: tuple[str, ...] = (),
    network_hosts: tuple[str, ...] = (),
    package_names: tuple[str, ...] = (),
) -> CommandSemanticInput:
    return CommandSemanticInput(
        action_identity=f"action:{executable}:{len(arguments)}",
        canonical_identity=f"canonical:{executable}:{len(arguments)}",
        actor_label="Cursor",
        executable=executable,
        arguments=tuple(arguments),
        operands=operands,
        target_paths=target_paths,
        network_hosts=network_hosts,
        package_names=package_names,
        command_display=command,
        normalized_command_display=command,
        dialect="posix",
        transport="shell_string",
        exact_details_authorized=exact,
    )


@pytest.mark.parametrize(
    ("executable", "arguments", "headline_fragment", "kind"),
    [
        ("rm", ("-rf", "./build"), "folder and everything", "file_delete"),
        ("rmdir", ("--recursive", "cache"), "folder and everything", "file_delete"),
        ("del.exe", ("notes.txt",), "Delete a file", "file_delete"),
        ("Remove-Item", ("-Recurse", "dist"), "folder and everything", "file_delete"),
        ("cp", ("a.txt", "backup/a.txt"), "Copy files", "file_write"),
        ("Copy-Item", ("a.txt", "backup"), "Copy files", "file_write"),
        ("mv", ("draft.txt", "final.txt"), "Move or rename", "file_move"),
        ("Rename-Item", ("draft.txt", "final.txt"), "Move or rename", "file_move"),
        ("chmod", ("777", "deploy.sh"), "Change who can access", "permission_change"),
        ("icacls.exe", ("report.txt", "/grant", "Everyone:F"), "Change who can access", "permission_change"),
        ("cat", ("~/.aws/credentials",), "Read saved credentials", "secret_read"),
        ("Get-Content", ("$HOME/.ssh/id_ed25519",), "Read saved credentials", "secret_read"),
        ("curl", ("https://example.com/status",), "Connect to a website", "network_read"),
        ("curl", ("-o", "tool.sh", "https://example.com/tool.sh"), "Download a file", "download"),
        ("curl", ("--data", "name=test", "https://example.com/api"), "Send data", "network_send"),
        ("Invoke-WebRequest", ("-OutFile", "tool.zip", "https://example.com/tool.zip"), "Download a file", "download"),
        ("scp", ("report.pdf", "alice@example.com:/tmp/report.pdf"), "Transfer files", "network_send"),
        ("npm", ("install", "left-pad@1.3.0"), "Install software", "package_install"),
        ("pnpm", ("add", "react@19"), "Install software", "package_install"),
        ("pip", ("install", "requests==2.32.0"), "Install software", "package_install"),
        ("uv", ("add", "httpx"), "Install software", "package_install"),
        ("cargo", ("install", "ripgrep"), "Install software", "package_install"),
        ("npm", ("uninstall", "left-pad"), "Remove software", "package_remove"),
        ("pip", ("uninstall", "requests"), "Remove software", "package_remove"),
        ("npm", ("publish",), "Publish a software", "network_send"),
        ("cargo", ("publish",), "Publish a software", "network_send"),
    ],
)
def test_known_commands_have_deterministic_everyday_explanations(
    executable: str,
    arguments: tuple[str, ...],
    headline_fragment: str,
    kind: str,
) -> None:
    explanation = explain_command(_input(executable, *arguments))
    assert headline_fragment in explanation.everyday.headline
    assert explanation.kind == kind
    assert explanation.confidence in {"exact", "derived"}
    assert explanation.technical.available is False
    assert explanation.technical.command_display is None
    assert explanation.everyday.targets
    assert explanation.everyday.consequences
    assert explanation.everyday.safer_alternatives


def test_unknown_command_is_explicitly_limited_not_inferred_safe() -> None:
    explanation = explain_command(_input("future-cli", "quantum-delete", "--all"))
    assert explanation.kind == "unknown_action"
    assert explanation.confidence == "limited"
    assert "could not" in explanation.everyday.headline.casefold()
    assert "semantic_rule_unavailable" in explanation.uncertainty_reasons
    assert explanation.everyday.safer_alternatives[0].kind == "preview"


@pytest.mark.parametrize("name", ["secretary.txt", "tokenizer.py", "password-reset.md", "id_ed25519.pub"])
def test_ordinary_file_read_is_not_misclassified_as_credentials(name: str) -> None:
    explanation = explain_command(_input("cat", name))
    assert explanation.kind == "unknown_action"
    assert "credentials" not in explanation.everyday.headline.casefold()


def test_curl_fail_flag_is_not_misclassified_as_upload() -> None:
    explanation = explain_command(_input("curl", "-f", "https://example.com/status"))
    assert explanation.kind == "network_read"
    assert "Connect to a website" in explanation.everyday.headline


def test_everyday_projection_keeps_safe_destination_while_redacting_secret_payload() -> None:
    secret = "sk-abcdefghijklmnopqrstuvwxyz123456"
    explanation = explain_command(
        _input(
            "curl",
            "--data",
            f"token={secret}",
            "https://upload.example/private",
            command=f"curl --data token={secret} https://upload.example/private",
            exact=True,
        )
    )
    everyday = f"{explanation.everyday.headline} {explanation.everyday.summary} {explanation.everyday.impact}"
    assert secret not in everyday
    assert "/private" not in everyday
    assert "upload.example" in explanation.everyday.summary
    assert secret not in (explanation.technical.command_display or "")
    assert explanation.redaction.secret_like_values_removed is True


def test_bearer_credentials_are_redacted_from_command_and_arguments() -> None:
    token = "opaque-value-1234567890"
    command = f"curl -H 'Authorization: Bearer {token}' https://api.example.test/data"
    explanation = explain_command(
        _input(
            "curl",
            "-H",
            f"Authorization: Bearer {token}",
            "https://api.example.test/data",
            command=command,
            exact=True,
        )
    )
    assert token not in (explanation.technical.command_display or "")
    assert token not in " ".join(explanation.technical.arguments_display or ())
    assert explanation.redaction.secret_like_values_removed is True


def test_exact_details_require_retention_and_authorization() -> None:
    base = _input("rm", "-rf", "./build", command="rm -rf ./build", exact=True)
    visible = explain_command(base)
    assert visible.technical.available is True
    assert visible.technical.command_display == "rm -rf ./build"
    assert visible.technical.unavailable_reason is None

    unauthorized = explain_command(replace(base, exact_details_authorized=False))
    assert unauthorized.technical.available is False
    assert unauthorized.technical.command_display is None
    assert unauthorized.technical.unavailable_reason == "not_authorized"

    unretained = explain_command(replace(base, retained=False))
    assert unretained.technical.available is False
    assert unretained.technical.unavailable_reason == "not_retained"


def test_windows_executable_suffixes_and_paths_are_normalized() -> None:
    explanation = explain_command(_input(r"C:\Windows\System32\del.exe", r"C:\Temp\notes.txt"))
    assert "Delete a file" in explanation.everyday.headline
    assert "C:\\Temp" not in explanation.everyday.summary
    assert "notes.txt" in explanation.everyday.summary


def test_windows_slash_options_and_option_values_do_not_become_targets() -> None:
    acl = explain_command(_input("icacls.exe", "report.txt", "/grant", "Everyone:F"))
    assert "report.txt" in acl.everyday.summary
    assert "Everyone:F" not in acl.everyday.summary

    delete = explain_command(_input("del.exe", "target.txt", "/s"))
    assert "target.txt" in delete.everyday.summary
    assert "item named s" not in delete.everyday.summary


def test_typed_operands_take_precedence_over_heuristic_argument_selection() -> None:
    explanation = explain_command(
        _input(
            "chmod",
            "755",
            "wrong.txt",
            operands=("actual.txt",),
            target_paths=("/workspace/actual.txt",),
        )
    )
    assert "actual.txt" in explanation.everyday.summary
    assert "wrong.txt" not in explanation.everyday.summary


def test_typed_network_host_takes_precedence_and_never_exposes_path() -> None:
    explanation = explain_command(
        _input(
            "curl",
            "--data",
            "name=test",
            "https://wrong.example/path",
            network_hosts=("typed.example",),
        )
    )
    assert "typed.example" in explanation.everyday.summary
    assert "wrong.example" not in explanation.everyday.summary
    assert "/path" not in explanation.everyday.summary


def test_safer_alternatives_are_projected_with_valid_kinds() -> None:
    explanation = explain_command(_input("cp", "a.txt", "b.txt"))
    kinds = {item.kind for item in explanation.everyday.safer_alternatives}
    messages = {item.message for item in explanation.everyday.safer_alternatives}
    assert {"preview", "backup"}.issubset(kinds)
    assert any("conflict" in message.casefold() for message in messages)


def test_catalog_digest_is_stable_content_addressed_and_covers_output_fields() -> None:
    first = stable_semantic_catalog_digest()
    second = stable_semantic_catalog_digest()
    assert first == second
    assert len(first) == 64
    int(first, 16)

    mutated = list(SEMANTIC_RULES)
    mutated[0] = replace(mutated[0], recommendation="A different recommendation")
    assert stable_semantic_catalog_digest(tuple(mutated)) != first

    mutated[0] = replace(SEMANTIC_RULES[0], safer_alternatives=(("cancel", "Do not continue."),))
    assert stable_semantic_catalog_digest(tuple(mutated)) != first


def test_builder_is_side_effect_free(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("side effect attempted")

    monkeypatch.setattr("subprocess.run", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    explanation = explain_command(_input("rm", "-rf", "./build"))
    assert explanation.everyday.headline
