"""Shared credential-path expressions for restricted operating-system profiles."""

from __future__ import annotations

from pathlib import Path


def _read_only_credential_patterns() -> tuple[str, ...]:
    # Deny rules dominate workspace/runtime read grants, including paths reached
    # through symlinks. Match case variants consistently with native path policy.
    def literal(value: str) -> str:
        escaped: list[str] = []
        for character in value:
            if character.isascii() and character.isalpha():
                escaped.append(f"[{character.lower()}{character.upper()}]")
            elif character in ".-":
                escaped.append("\\" + character)
            else:
                escaped.append(character)
        return "".join(escaped)

    names = (
        ".envrc",
        ".authrc",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        "terraform.tfvars",
        "private.key",
        "wallet.key",
    )
    return (
        f"(^|/){literal('.env')}($|[./])",
        f"(^|/)[^/]*{literal('.key')}$",
        f"(^|/){literal('krb5cc_')}[^/]*$",
        "(^|/)(" + "|".join(literal(name) for name in names) + ")$",
        "(^|/)[^/]*("
        + "|".join(
            literal(name)
            for name in (
                "private-key",
                "private_key",
                "wallet-key",
                "wallet_key",
            )
        )
        + ")[^/]*$",
        "(^|/)("
        + "|".join(
            literal(name)
            for name in (
                ".ssh",
                ".aws",
                ".docker",
                ".kube",
                ".gnupg",
                ".hol-guard",
            )
        )
        + ")(/|$)",
    )


def _seatbelt_string(path: Path | str) -> str:
    value = str(path)
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'


def _read_only_credential_denials(*, hide_metadata: bool = False) -> tuple[str, ...]:
    operation = "file-read*" if hide_metadata else "file-read-data"
    return tuple(
        f"(deny {operation} (regex {_seatbelt_string(pattern)}))" for pattern in _read_only_credential_patterns()
    )
